"""One billable record per logical call. D-4, and the three cases it settles.

A *logical call* is one model invocation as the vendor charges for it. It is routinely observed
more than once:

* **2.6 double instrumentation** — the customer runs ``ddtrace`` and/or OpenLLMetry beside us.
  ``wrapt`` nests safely, so nothing crashes; three layers each emit a span carrying the same token
  counts, and a naive bridge bills the call three times.
* **2.8 layered SDKs** — ``langchain_anthropic`` calls ``anthropic``. One call, two layers, both
  instrumented, both reporting usage.
* **2.14 vendor-internal retries** — the ``anthropic`` / ``openai`` clients retry inside a single
  ``create()``. One logical call, N HTTP attempts. Billing per attempt turns a flaky network into a
  cost anomaly that never happened.

The rule, decided in D-4 and implemented here: **the innermost observation wins.** Not the first,
not the most detailed — the innermost, because it is the only one positioned to see the vendor's
internal retries and the real HTTP exchange. Everything outside it is real information about
structure (which framework, how deep, how long, who else was watching) and is folded into the one
record as such, never as spend.

Why this is filed as a correctness bug rather than a nicety: exact cost is the differentiator. A
customer running Datadog alongside us would see tokens counted twice and check the number against
their vendor invoice. Being wrong in that specific direction is worse than not reporting at all,
because it is wrong *confidently*.

Everything here is pure bookkeeping over :class:`~nexus.otel.semconv.SpanFacts`. It holds no
references to spans, imports no provider library, and emits nothing itself — the bridge owns
emission so that the selection rule can be tested without a client, a transport or a collector.
"""
from __future__ import annotations

import typing as t
from dataclasses import dataclass, field

from ..otel.semconv import KIND_LLM, SpanFacts


@dataclass
class Observation:
    """One instrumentation's view of a logical call."""

    facts: SpanFacts
    depth: int
    #: True when this observation is an HTTP attempt *inside* the call rather than a view *of* the
    #: call. Attempts are counted, never billed — see :meth:`LogicalCall.attempts`.
    is_attempt: bool = False

    @property
    def has_usage(self) -> bool:
        return self.facts.has_usage

    @property
    def observer(self) -> str:
        """Who produced this view. The instrumentation scope where there is one, else the span's
        own name — enough to answer "was somebody else watching?", which is all we need."""
        return self.facts.scope or self.facts.name or "unknown"


@dataclass
class LogicalCall:
    """A nest of observations that all describe the same billable model invocation."""

    key: str
    trace_id: str
    root_span_id: str
    observations: list[Observation] = field(default_factory=list)
    emitted: bool = False
    #: Set when the call was closed by something other than its root span ending — an abandoned
    #: stream, a process shutdown, a span garbage-collected mid-flight (case 2.12).
    incomplete_reason: t.Optional[str] = None

    def add(self, obs: Observation) -> None:
        self.observations.append(obs)

    # -- selection ----------------------------------------------------------------------------

    def billable(self) -> t.Optional[Observation]:
        """The single observation that may carry spend.

        Deepest observation with usage. Ties (two instrumentations wrapping the same method at the
        same nesting level, which is what 2.6 actually looks like when both use ``wrapt``) break on
        insertion order, so the choice is deterministic across runs rather than dependent on dict
        ordering — a billing figure that changes between two identical runs is unauditable.

        When nothing carries usage the call still gets a record: the deepest non-attempt
        observation, marked incomplete by the caller. "No event" is indistinguishable from "the
        service was idle", which is how streaming bugs stay invisible for months (case 2.12).
        """
        with_usage = [o for o in self.observations if o.has_usage and not o.is_attempt]
        if with_usage:
            return max(with_usage, key=lambda o: o.depth)
        # Nothing that *views* the call reported usage, but an attempt did — a gateway or proxy
        # mirroring the response body, which happens. The attempt is still not "the call", so it is
        # only reached once no view of the call has numbers; preferring it earlier would bill one
        # retry of a retried call. Reached here it is the only measurement that exists, and
        # discarding it in favour of a zero would be a fabricated number rather than a missing one.
        attempts_with_usage = [o for o in self.observations if o.has_usage]
        if attempts_with_usage:
            return max(attempts_with_usage, key=lambda o: o.depth)
        structural = [o for o in self.observations if not o.is_attempt]
        if structural:
            return max(structural, key=lambda o: o.depth)
        return self.observations[-1] if self.observations else None

    @property
    def attempts(self) -> int:
        """HTTP attempts for this one logical call — case 2.14.

        Two sources, whichever is larger: attempt-shaped child spans actually observed, and an
        explicit counter where the instrumentation emits one. Neither is reliable alone —
        OpenLLMetry emits no attempt spans, and most instrumentations emit no counter.
        """
        observed = sum(1 for o in self.observations if o.is_attempt)
        declared = max((o.facts.attempts or 0) for o in self.observations) if self.observations else 0
        return max(observed, declared, 1)

    @property
    def observers(self) -> list[str]:
        """Distinct instrumentations that saw this call, innermost last. Structure, not spend."""
        out: list[str] = []
        for o in sorted(self.observations, key=lambda x: x.depth):
            if o.is_attempt:
                continue
            name = o.observer
            if name not in out:
                out.append(name)
        return out

    @property
    def double_instrumented(self) -> bool:
        """More than one non-attempt observer saw this call — 2.6/2.8 actually happening."""
        return len([o for o in self.observations if not o.is_attempt]) > 1

    def structure(self) -> dict:
        """What the losing observations contribute: parentage, breadth, depth, timing.

        This is D-4 step 3 made concrete. The outer layers are not discarded — discarding them
        would lose the fact that a LangChain chain wrapped this call, which is exactly the sort of
        attribution a customer needs to reduce their bill. They are recorded as *shape*.
        """
        bill = self.billable()
        outer = [o for o in self.observations if not o.is_attempt and o is not bill]
        return {
            "observers": self.observers,
            "observations": len([o for o in self.observations if not o.is_attempt]),
            "billed_depth": bill.depth if bill else None,
            "double_instrumented": self.double_instrumented,
            # The framework layer, when there is one: the shallowest non-billed observer.
            "framework": (min(outer, key=lambda o: o.depth).observer if outer else None),
            "trace_id": self.trace_id or None,
            "root_span_id": self.root_span_id or None,
        }


def is_attempt_observation(facts: SpanFacts, parent_is_llm: bool) -> bool:
    """Does this span describe an HTTP attempt inside a call rather than the call itself?

    An HTTP span nested under an LLM span is a transport attempt: the vendor client issuing (and
    possibly re-issuing) the request. An explicit resend/retry counter says the same thing outright.
    Getting this wrong in either direction is a billing error, which is why it is one named
    predicate rather than an ``if`` inside the bridge.
    """
    # An explicit resend/attempt counter is checked first and outranks everything below it. Such a
    # span *is* one HTTP attempt by definition, and some gateways mirror the response body onto it,
    # so the usage heuristic underneath would otherwise promote a single retry to "the call" and
    # bill the retry instead of the aggregate.
    for key in ("http.request.resend_count", "gen_ai.request.attempt", "http.resend_count"):
        if facts.attributes.get(key) is not None:
            return True
    if facts.kind == KIND_LLM and facts.has_usage:
        return False          # a real view of the call, however deep it sits
    return bool(facts.is_http and parent_is_llm)
