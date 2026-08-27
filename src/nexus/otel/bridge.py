"""The bridge: OTel / OpenInference spans in, nexus events out.

This is WP-5's whole answer to provider coverage, and the answer is *consume, do not replicate*.
One OpenLLMetry provider adapter measures 931 lines across 8 files; there are ~30 of them, three
funded projects maintain them, and all three ship permissive licences. Writing our own would be
15–25k lines of worse. What upstream cannot give us is not extraction — it is the four things this
module adds on ingest:

1. **An epistemic class on every event.** ``classify.py``. Nothing unclassified reaches the ledger.
2. **Our privacy tier, re-applied here.** Upstream redaction is somebody else's promise about
   somebody else's code path; a tier the customer chose is only meaningful if *we* enforce it at
   the boundary. Content arrives, content is re-gated, and at ``metadata_only`` no free text is
   transmitted at all — see ``_content_fragment``.

   Re-gating is the second step, not the first. Content only ever reaches a gate through a field
   that is *declared* to carry content: ``_emit_content``'s prompt and completion fragments, and
   the three free-text fields ``contract.tool_action`` tiers by name. Everything else the reader
   produces is structure — an identifier, a count, a type — because a payload sitting in front of
   a gate is one bug away from being a payload on the wire, and that bug has happened here once
   already (``tool.parameters`` and ``input.value`` read as ``tool_target``). ``semconv``'s job is
   to make sure the gate is never the only thing standing there.
3. **Exact cost from the real usage breakdown**, cache split included, against the same rate card
   as ``nexus_devtools/pricing.py``. Never a flat per-token estimate.
4. **One billable record per logical call.** ``billing.py``, D-4. This is the correctness property
   the exact-cost claim rests on when the customer also runs Datadog.

Structural, not typed: nothing here imports ``opentelemetry``. A span is read through
``semconv.normalise``, so the bridge is fully testable — and fully *usable* — with the ``[otel]``
extra absent. The only code that needs the package is ``processor.py``, which builds the
``SpanProcessor`` subclass that feeds this, and it is imported lazily.

Case coverage, so the next reader can find the code from the case number:

* **2.6** double instrumentation — :meth:`Bridge._join` + ``LogicalCall.billable``
* **2.8** layered SDKs — same path; the outer layer becomes ``structure.framework``
* **2.12** abandoned streams — :meth:`Bridge.abandon`, the ``weakref.finalize`` in :meth:`_on_start`,
  and :meth:`flush_open`
* **2.14** vendor-internal retries — ``billing.is_attempt_observation`` + ``LogicalCall.attempts``
* **2.19** recursive instrumentation — ``selfexclude`` on every entry point
"""
from __future__ import annotations

import threading
import typing as t
import weakref
from dataclasses import dataclass

from .. import _counters, contract
from .._safety import guard
from ..integrations import billing, pricing, selfexclude
from . import classify as _classify
from .semconv import (
    KIND_AGENT, KIND_CHAIN, KIND_EMBEDDING, KIND_GUARDRAIL, KIND_LLM, KIND_RERANKER,
    KIND_RETRIEVER, KIND_TOOL, SpanFacts, normalise,
)

# Counter names. Literals in this codebase, never span-derived — case 3.5 (cardinality) applies to
# metric *names* too, and a counter named after an attribute value is how a metrics bill explodes.
SPANS_SEEN = "bridge_spans_seen"
SPANS_SELF_EXCLUDED = "bridge_self_excluded"
SPANS_UNCLASSIFIED = "bridge_unclassified"
SPANS_IGNORED = "bridge_spans_ignored"
CALLS_BILLED = "bridge_calls_billed"
CALLS_INCOMPLETE = "bridge_calls_incomplete"
OBSERVATIONS_MERGED = "bridge_observations_merged"
REENTRY_BLOCKED = "bridge_reentry_blocked"
OPEN_EVICTED = "bridge_open_evicted"

#: Span kinds that open a billable logical call.
_LLM_FAMILY = frozenset({KIND_LLM})
#: Span kinds that describe an observed effect and emit a ``tool_action``.
_TOOL_FAMILY = frozenset({KIND_TOOL, KIND_RETRIEVER, KIND_EMBEDDING, KIND_RERANKER, KIND_GUARDRAIL})
#: Orchestration. Recorded as ancestry and folded into a call's structure; emits nothing of its own,
#: because a run with an outcome is what ``nexus.agent()`` exists to record and a duplicate
#: framework-shaped event would compete with it in the ledger.
_STRUCTURE_FAMILY = frozenset({KIND_CHAIN, KIND_AGENT})

FAMILY_LLM = "llm"
FAMILY_TOOL = "tool"
FAMILY_ATTEMPT = "attempt"
FAMILY_STRUCTURE = "structure"


@dataclass
class _Node:
    span_id: str
    parent_span_id: t.Optional[str]
    family: str
    call_key: t.Optional[str]
    depth: int
    #: What the span said at ``on_start``, and a weak reference to the span itself. Both are kept
    #: and neither is sufficient alone. A call closed by shutdown or by the span's garbage
    #: collection never reaches ``on_end``, so the only observation that will ever exist for it is
    #: one reconstructed here (see :meth:`Bridge._backfill`). The weakref yields the *current*
    #: attributes while the span is alive — a stream still open at shutdown has accumulated its
    #: usage by then — and the snapshot is what remains when it is not. The reference is weak
    #: because holding spans alive would make this SDK the reason a customer's trace leaks.
    facts: t.Optional[SpanFacts] = None
    span_ref: t.Any = None


class Bridge:
    """Ingests spans, emits nexus events. One per process is plenty; more is harmless.

    ``strict`` controls what happens to a GenAI span with no epistemic class: raise (tests) or
    drop-and-count (production). It defaults to on under pytest — see ``classify.strict_default``.
    """

    #: Hard cap on tracked in-flight spans. A trace that never ends must cost bounded memory; the
    #: alternative is an SDK that turns a customer's leaked spans into our OOM.
    MAX_OPEN = 4096

    def __init__(self, client: t.Any = None, *, strict: t.Optional[bool] = None) -> None:
        self._client = client
        self._strict = _classify.strict_default() if strict is None else bool(strict)
        self._lock = threading.RLock()
        self._nodes: dict[str, _Node] = {}
        self._calls: dict[str, billing.LogicalCall] = {}
        self._finalizers: dict[str, t.Any] = {}

    # -- client -------------------------------------------------------------------------------

    def _get_client(self) -> t.Any:
        if self._client is not None:
            return self._client
        from ..client import ensure_client
        return ensure_client()

    # -- public entry points ------------------------------------------------------------------
    #
    # Each has a guarded twin. In strict mode the raw path is used so a classification failure is a
    # red test rather than a swallowed one; in production the guard is what keeps the promise that
    # this SDK never raises into a host application (case 4.7).

    def on_start(self, span: t.Any) -> None:
        return self._on_start(span) if self._strict else self._on_start_guarded(span)

    def on_end(self, span: t.Any) -> None:
        return self._on_end(span) if self._strict else self._on_end_guarded(span)

    def ingest(self, span: t.Any) -> None:
        """Start and end in one call — for exporter-shaped integrations that only see finished
        spans, and for leaf spans in tests. Nesting cannot be reconstructed from a finished span
        alone (children finish before parents), so a bridge fed only through here bills each span
        as its own logical call. That is why ``processor.py`` uses ``on_start``/``on_end``."""
        self.on_start(span)
        self.on_end(span)

    @guard("otel.bridge.on_start")
    def _on_start_guarded(self, span: t.Any) -> None:
        self._on_start(span)

    @guard("otel.bridge.on_end")
    def _on_end_guarded(self, span: t.Any) -> None:
        self._on_end(span)

    @guard("otel.bridge.abandon")
    def abandon(self, span: t.Any, reason: str = "abandoned") -> None:
        """Close whatever call this span belongs to as incomplete — case 2.12.

        The abandoned stream is the most commonly missed streaming bug precisely because it is
        invisible: the generator is never exhausted, the span never ends, and the absence of a
        record is indistinguishable from an idle service.
        """
        facts = normalise(span) if not isinstance(span, str) else None
        span_id = span if isinstance(span, str) else facts.span_id  # type: ignore[union-attr]
        with self._lock:
            node = self._nodes.get(span_id)
            call = self._calls.get(node.call_key) if node and node.call_key else None
            if call is None:
                return
            if facts is not None and node is not None:
                call.add(billing.Observation(facts, node.depth,
                                             is_attempt=node.family == FAMILY_ATTEMPT))
            call.incomplete_reason = reason
        self._close_call(call, incomplete=True)

    @guard("otel.bridge.flush_open", default=0)
    def flush_open(self, reason: str = "shutdown") -> int:
        """Emit a partial for every call still open. Returns how many.

        Called at shutdown. A process that exits mid-stream would otherwise take the record with
        it, and "no event" is the one outcome case 2.12 forbids.
        """
        with self._lock:
            calls = [c for c in self._calls.values() if not c.emitted]
        n = 0
        for call in calls:
            call.incomplete_reason = call.incomplete_reason or reason
            if self._close_call(call, incomplete=True):
                n += 1
        return n

    def stats(self) -> dict:
        with self._lock:
            return {"open_spans": len(self._nodes),
                    "open_calls": len([c for c in self._calls.values() if not c.emitted]),
                    "strict": self._strict}

    def reset(self) -> None:
        """Drop all in-flight state without emitting. Test/fork helper only."""
        with self._lock:
            self._nodes.clear()
            self._calls.clear()
            for fin in self._finalizers.values():
                try:
                    fin.detach()
                except Exception:  # noqa: BLE001
                    pass
            self._finalizers.clear()

    # -- ingest -------------------------------------------------------------------------------

    def _admit(self, facts: SpanFacts, parent_is_llm: bool) -> bool:
        """Common gate. ``False`` means the span is not ours or must not be ingested.

        Takes ``parent_is_llm`` rather than working from the span alone because one admissible
        category cannot be recognised without it — see the transport-attempt branch.
        """
        cfg = getattr(self._get_client(), "cfg", None)
        if selfexclude.is_self_span(facts, cfg):
            # Case 2.19. The span describing our own egress must never become an event, because
            # that event becomes egress, which becomes a span. Unbounded, not slow.
            _counters.incr(SPANS_SELF_EXCLUDED)
            return False
        if parent_is_llm and billing.is_attempt_observation(facts, True):
            # A transport attempt inside a call we are already recording — case 2.14. Admitted
            # without any GenAI marker on purpose: the vendor clients retry through a plain HTTP
            # client (``httpx``, ``requests``) whose span carries nothing but ``http.*``, so a
            # GenAI-marker gate would drop exactly the spans that explain a retry storm and
            # ``attempts`` would read 1 on the traffic the field exists for. It is admitted as
            # *structure* — ``_family_of`` routes it to ``FAMILY_ATTEMPT``, which can never be
            # selected as billable.
            return True
        if not _classify.is_ours(facts):
            _counters.incr(SPANS_IGNORED)      # a DB or HTTP span from the customer's app
            return False
        cls = _classify.classify_span(facts, strict=self._strict)
        if cls is None:
            # GenAI-shaped, unrecognised kind. Counted loudly rather than defaulted: defaulting is
            # how unverified content acquires the class the product sells as evidence.
            _counters.incr(SPANS_UNCLASSIFIED)
            return False
        return True

    def _family_of(self, facts: SpanFacts, parent_is_llm: bool) -> str:
        # Attempt first, and the order matters. A retry span carrying a mirrored response body
        # infers kind=llm from its usage attributes, so an LLM-first test would promote one HTTP
        # attempt to "the call" and bill the retry instead of the aggregate. The predicate itself
        # refuses to call a genuine usage-bearing LLM view an attempt, so nothing is lost.
        if billing.is_attempt_observation(facts, parent_is_llm):
            return FAMILY_ATTEMPT
        if facts.kind in _LLM_FAMILY:
            return FAMILY_LLM
        if facts.kind in _TOOL_FAMILY:
            return FAMILY_TOOL
        return FAMILY_STRUCTURE

    def _nearest(self, parent_span_id: t.Optional[str], families: t.Collection[str]) -> t.Optional[_Node]:
        """Nearest ancestor node in one of ``families``. Bounded: a malformed parent chain must not
        become a loop on somebody's request path."""
        cur, seen = parent_span_id, 0
        while cur and seen < 64:
            node = self._nodes.get(cur)
            if node is None:
                return None
            if node.family in families:
                return node
            cur, seen = node.parent_span_id, seen + 1
        return None

    def _on_start(self, span: t.Any) -> None:
        with selfexclude.no_reentry() as ok:
            if not ok:
                _counters.incr(REENTRY_BLOCKED)
                return
            facts = normalise(span)
            _counters.incr(SPANS_SEEN)
            with self._lock:
                parent_llm = self._nearest(facts.parent_span_id, (FAMILY_LLM,))
                if not self._admit(facts, parent_llm is not None):
                    return
                self._evict_if_needed()
                family = self._family_of(facts, parent_llm is not None)
                node = self._join(facts, family, parent_llm)
                node.facts = facts
                try:
                    node.span_ref = weakref.ref(span)
                except TypeError:
                    pass          # a span type without weakref support; the snapshot still stands
                self._nodes[facts.span_id] = node
            self._arm_finalizer(span, facts.span_id)

    def _join(self, facts: SpanFacts, family: str, parent_llm: t.Optional[_Node]) -> _Node:
        """Attach a span to a logical call — the deduplication decision, cases 2.6/2.8/2.14.

        A span of a billable family nested inside an open call of the *same* family is another
        observer of that same call, not a second call. That single sentence is what stops
        ``langchain_anthropic`` → ``anthropic`` billing twice, and what stops a customer's ddtrace
        span and ours from billing twice. A tool span under an LLM span is a *different* family and
        correctly opens its own record: function calling is a real second thing that happened.
        """
        if family == FAMILY_ATTEMPT and parent_llm is not None and parent_llm.call_key:
            return _Node(facts.span_id, facts.parent_span_id, family,
                         parent_llm.call_key, parent_llm.depth + 1)
        if family in (FAMILY_LLM, FAMILY_TOOL):
            anchor = parent_llm if family == FAMILY_LLM else self._nearest(
                facts.parent_span_id, (FAMILY_TOOL,))
            anchor_call = self._calls.get(anchor.call_key) if anchor and anchor.call_key else None
            # ``.get``, not ``[]``: an ancestor whose call was already closed (flushed at shutdown,
            # evicted, or finished out of order) leaves a node pointing at a key that is gone, and
            # a KeyError here would raise on a customer's request path. A stale anchor simply
            # means this span opens its own call, which is the honest reading.
            if anchor_call is not None and not anchor_call.emitted:
                _counters.incr(OBSERVATIONS_MERGED)
                return _Node(facts.span_id, facts.parent_span_id, family,
                             anchor.call_key, anchor.depth + 1)  # type: ignore[union-attr]
            key = f"{facts.trace_id}:{facts.span_id}"
            self._calls[key] = billing.LogicalCall(key=key, trace_id=facts.trace_id,
                                                   root_span_id=facts.span_id)
            return _Node(facts.span_id, facts.parent_span_id, family, key, 0)
        return _Node(facts.span_id, facts.parent_span_id, family, None, 0)

    def _on_end(self, span: t.Any) -> None:
        with selfexclude.no_reentry() as ok:
            if not ok:
                _counters.incr(REENTRY_BLOCKED)
                return
            facts = normalise(span)
            _counters.incr(SPANS_SEEN)
            with self._lock:
                parent_llm = self._nearest(facts.parent_span_id, (FAMILY_LLM,))
                if not self._admit(facts, parent_llm is not None):
                    return
                node = self._nodes.pop(facts.span_id, None)
                fin = self._finalizers.pop(facts.span_id, None)
                if fin is not None:
                    try:
                        fin.detach()
                    except Exception:  # noqa: BLE001
                        pass
                if node is None:
                    # Ended without a start — an exporter-only feed, or a span that began before
                    # the bridge was attached. Treat it as its own logical call rather than drop
                    # it: an unattributed record beats a missing one.
                    node = self._join(facts, self._family_of(facts, parent_llm is not None),
                                      parent_llm)
                call = self._calls.get(node.call_key) if node.call_key else None
                if call is not None:
                    call.add(billing.Observation(facts, node.depth,
                                                 is_attempt=node.family == FAMILY_ATTEMPT))
                is_root = call is not None and call.root_span_id == facts.span_id
            if call is not None and is_root:
                self._close_call(call, incomplete=False)

    def _arm_finalizer(self, span: t.Any, span_id: str) -> None:
        """Case 2.12's safety net: a span object garbage-collected without ever ending.

        An abandoned streaming response is exactly this — the caller stops iterating, drops the
        reference, and the span dies unrecorded. A finalizer is the only hook that fires for it.
        """
        try:
            fin = weakref.finalize(span, self._on_span_gc, span_id)
            fin.atexit = False   # atexit flushing is `flush_open`'s job, with a deadline
            self._finalizers[span_id] = fin
        except TypeError:
            pass                 # a span type that does not support weak references; flush_open covers it

    def _on_span_gc(self, span_id: str) -> None:
        try:
            with self._lock:
                node = self._nodes.get(span_id)     # left in place so `_backfill` can still see it
                self._finalizers.pop(span_id, None)
                call = self._calls.get(node.call_key) if node and node.call_key else None
                if call is None or call.emitted:
                    return
                call.incomplete_reason = "span_gc"
            self._close_call(call, incomplete=True)
        except Exception:  # noqa: BLE001
            pass             # runs at GC time, possibly during interpreter teardown

    def _evict_if_needed(self) -> None:
        # Oldest-first eviction of the tracking maps. Deliberately *not* emitting: a span the
        # bridge lost track of has no trustworthy usage, and a flood of invented partials during a
        # span leak would be a second incident on top of the customer's first.
        if len(self._nodes) > self.MAX_OPEN:
            for span_id in list(self._nodes)[: len(self._nodes) - self.MAX_OPEN]:
                self._nodes.pop(span_id, None)
                fin = self._finalizers.pop(span_id, None)
                if fin is not None:
                    try:
                        fin.detach()
                    except Exception:  # noqa: BLE001
                        pass
                _counters.incr(OPEN_EVICTED)
        # The call map needs its own cap. Evicting nodes alone would leave the calls they opened
        # behind forever, so an application leaking spans would still leak here — slower, which is
        # worse, because it presents as a memory problem nobody attributes to telemetry.
        if len(self._calls) > self.MAX_OPEN:
            for key in list(self._calls)[: len(self._calls) - self.MAX_OPEN]:
                self._calls.pop(key, None)
                _counters.incr(OPEN_EVICTED)

    def _backfill(self, call: billing.LogicalCall) -> None:
        """Reconstruct observations for a call that never reached ``on_end`` — case 2.12.

        Observations are normally added at ``on_end``, so a call closed by process shutdown or by
        the span dying under GC has an empty list and would produce *no record at all*. That is the
        one outcome 2.12 forbids: the absence is indistinguishable from an idle service, which is
        how abandoned-stream bugs survive for months.

        Caller holds the lock.
        """
        for node in self._nodes.values():
            if node.call_key != call.key:
                continue
            facts = None
            ref = node.span_ref
            if ref is not None:
                span = ref()
                if span is not None:
                    try:
                        facts = normalise(span)   # current attributes beat the start-time snapshot
                    except Exception:  # noqa: BLE001
                        facts = None
            facts = facts or node.facts
            if facts is not None:
                call.add(billing.Observation(facts, node.depth,
                                             is_attempt=node.family == FAMILY_ATTEMPT))

    # -- emission -----------------------------------------------------------------------------

    def _close_call(self, call: billing.LogicalCall, *, incomplete: bool) -> bool:
        with self._lock:
            if call.emitted:
                return False
            call.emitted = True
            if not call.observations:
                self._backfill(call)
            obs = call.billable()
            structure = call.structure()
            attempts = call.attempts
            for span_id, node in list(self._nodes.items()):
                if node.call_key == call.key:
                    self._nodes.pop(span_id, None)
            self._calls.pop(call.key, None)
        if obs is None:
            return False
        try:
            self._emit(obs.facts, structure=structure, attempts=attempts,
                       incomplete=incomplete or not obs.has_usage,
                       reason=call.incomplete_reason, family_llm=obs.facts.kind in _LLM_FAMILY)
        except Exception:  # noqa: BLE001
            if self._strict:
                raise
            _counters.incr(_counters.BUILD_FAILED)
        return True

    def _emit(self, facts: SpanFacts, *, structure: dict, attempts: int, incomplete: bool,
              reason: t.Optional[str], family_llm: bool) -> None:
        client = self._get_client()
        cfg = client.cfg
        from ..context import current
        ref = current()
        run_id = ref.run_id if ref else None
        session_id = client.session_id

        if family_llm:
            cost, source = self._cost(facts)
            ev = contract.token_usage(
                session_id, cfg, model=facts.model or "unknown", provider=facts.provider,
                input_tokens=facts.input_tokens or 0, output_tokens=facts.output_tokens or 0,
                cache_read_tokens=facts.cache_read_tokens,
                cache_write_tokens=self._cache_write_total(facts),
                cost_usd=cost, cost_source=source, run_id=run_id,
                attempts=attempts, incomplete=incomplete)
            # The losing observations, recorded as shape rather than spend (D-4 step 3). These ride
            # as an extra key because ``contract.token_usage``'s signature is fixed and owned by
            # WP-4 — a patch to the upstream instrumentation would make these
            # first-class. The contract schema is ``additionalProperties: true``, so this is
            # additive rather than a violation.
            ev["bridge"] = dict(structure, semconv=_SEMCONV_TAG,
                                incomplete_reason=reason,
                                cache_write_1h_tokens=facts.cache_write_1h_tokens)
            client.emit(ev)
            _counters.incr(CALLS_INCOMPLETE if incomplete else CALLS_BILLED)
            self._emit_content(client, cfg, session_id, facts, run_id)
        else:
            # ``target`` is an identifier or nothing — ``semconv._identifier`` guarantees that, and
            # it is the reason this call no longer hands the model's own arguments to a text gate.
            # What the arguments contributed that was worth keeping — how many, named what, of
            # what types — rides in ``effect`` as ``arg_shape``, which is a behaviour trace and
            # carries no values at any depth. See ``semconv.shape_of``.
            effect = {"observers": structure.get("observers") or [],
                      "incomplete": bool(incomplete)}
            if facts.tool_arg_shape:
                effect["arg_shape"] = facts.tool_arg_shape
            client.emit(contract.tool_action(
                session_id, cfg, tool_name=facts.tool_name or facts.name or "tool",
                action="invoke", target=facts.tool_target, duration_ms=facts.duration_ms,
                run_id=run_id, error=facts.error, effect=effect))

    def _emit_content(self, client: t.Any, cfg: t.Any, session_id: str, facts: SpanFacts,
                      run_id: t.Optional[str]) -> None:
        """Model-authored text, re-gated by *our* tier and split by epistemic class.

        The split is the point. A completion is ``interaction_narrative`` — what the user was told.
        A reasoning trace is ``rationalisation`` — what the model said about its own process.
        Folding the second into the first would launder a claim into the record beside the answer
        it is supposed to justify.
        """
        frag = self._content_fragment(facts.output_text, cfg)
        if frag:
            client.emit(contract.base(
                "model_response", session_id, cfg,
                epistemic_class=_classify.classify_payload(_classify.PAYLOAD_OUTPUT),
                model=facts.model, provider=facts.provider, prompt_id=run_id,
                answer=frag.get("text") or frag.get("preview"),
                answer_chars=frag.get("chars"), answer_fingerprint=frag.get("fingerprint"),
                tokens_est=frag.get("tokens_est"),
                redacted=frag.get("text_redacted") or frag.get("preview_redacted") or None,
                truncated=frag.get("preview_truncated") or None))
        frag = self._content_fragment(facts.reasoning_text, cfg)
        if frag:
            client.emit(contract.base(
                "model_thinking", session_id, cfg,
                epistemic_class=_classify.classify_payload(_classify.PAYLOAD_REASONING),
                model=facts.model, provider=facts.provider, prompt_id=run_id,
                thinking=frag.get("text") or frag.get("preview"),
                thinking_chars=frag.get("chars"), thinking_fingerprint=frag.get("fingerprint"),
                truncated=frag.get("preview_truncated") or None,
                redacted=frag.get("text_redacted") or frag.get("preview_redacted") or None))

    @staticmethod
    def _content_fragment(text: t.Optional[str], cfg: t.Any) -> t.Optional[dict]:
        """The tier gate, applied on ingest. **Upstream redaction is not trusted.**

        Every instrumentation in this space has its own content-capture switch and its own idea of
        what a secret looks like. Some have none. Whether text may leave this process is our
        customer's tier decision, so it is re-decided here against ``contract.redact_preview``,
        which is the same gate ``events._wire_text`` applies in the wrapper: at ``metadata_only``
        shape only, at ``hashed`` a redacted truncated preview, at ``full`` the redacted text.
        Note that even ``full`` is redacted — a tier is a decision about *content*, never a waiver
        on credentials.
        """
        if not text:
            return None
        return contract.redact_preview(text, cfg.tier)

    @staticmethod
    def _cache_write_total(facts: SpanFacts) -> t.Optional[int]:
        total = (facts.cache_write_5m_tokens or 0) + (facts.cache_write_1h_tokens or 0)
        return total or None

    @staticmethod
    def _cost(facts: SpanFacts) -> tuple[t.Optional[float], t.Optional[str]]:
        """Exact dollars for this call, with provenance.

        A cost the provider reported wins: it is evidence. Ours is arithmetic over the provider's
        token breakdown against the pinned rate card, including the cache split — cached input is
        10× cheaper and cache writes 1.25–2× dearer, so a bridge that ignores the split is not
        imprecise, it is wrong by multiples on exactly the cache-heavy traffic agents generate.
        An unpriced model yields ``None``, never an estimate.
        """
        if facts.reported_cost_usd is not None:
            return facts.reported_cost_usd, pricing.SOURCE_PROVIDER
        if not facts.model or not facts.has_usage:
            return None, None
        cost = pricing.cost_from_usage(facts.model, facts.usage_dict())
        return (cost, pricing.SOURCE_USAGE) if cost is not None else (None, None)


_SEMCONV_TAG = None  # filled below; kept out of the class so it is one string per process


def _semconv_tag() -> dict:
    from .semconv import GENAI_SEMCONV_STABILITY, GENAI_SEMCONV_VERSION
    return {"genai": GENAI_SEMCONV_VERSION, "stability": GENAI_SEMCONV_STABILITY}


_SEMCONV_TAG = _semconv_tag()


# --------------------------------------------------------------------------------------------
# Process-wide default
# --------------------------------------------------------------------------------------------

_default: t.Optional[Bridge] = None
_default_lock = threading.Lock()


def get_bridge() -> Bridge:
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = Bridge()
    return _default


def _reset_for_tests() -> None:
    global _default
    with _default_lock:
        if _default is not None:
            _default.reset()
        _default = None
    selfexclude.reset_for_fork()
