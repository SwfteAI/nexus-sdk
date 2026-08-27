"""Epistemic classification — the thing the upstream vocabulary has no concept of.

D-3 rejected an OTLP-native model for exactly one reason: an OTel span has nowhere to put the
distinction between *what the system did*, *what the model said it did*, and *what the user was
told*. Every span attribute in the GenAI conventions is agnostic on that question, because
observability does not need to answer it and governance cannot proceed without it.

The mapping is small enough to state in full:

* **model output → ``interaction_narrative``.** A completion is what the user was told. It may be
  true. It is not evidence that anything happened.
* **observed tool execution → ``behavior_trace``.** A tool span is the runtime reporting an effect
  it carried out. That is fact, and the only class admissible as evidence.
* **model-authored reasoning → ``rationalisation``.** A model's account of its own process is the
  weakest class of all, and the one most often mistaken for the strongest.

Token accounting is ``behavior_trace``: the number of tokens billed is measured, not asserted. It
is emitted by ``contract.token_usage``, which hard-codes the class, so it cannot drift from here.

**The invariant this module exists to hold: an unclassified span must never reach the ledger.**
Two failure modes are being ruled out at once, and they call for opposite handling:

* *Silently mislabelling* — defaulting an unknown span to ``behavior_trace`` would put unverified
  content into the class the product sells as evidence. Never do this.
* *Silently dropping* — dropping without counting turns a coverage gap into an invisible one.

So the runtime behaviour is **drop and count**, and the test behaviour is **raise**. ``strict``
defaults to on under pytest (and under ``NEXUS_BRIDGE_STRICT=1``) so a new span kind fails a build
rather than quietly thinning the ledger in production six months later.
"""
from __future__ import annotations

import os
import sys
import typing as t

from ..contract import EPISTEMIC_BEHAVIOR, EPISTEMIC_NARRATIVE, EPISTEMIC_RATIONALISATION
from .semconv import (
    KIND_AGENT, KIND_CHAIN, KIND_EMBEDDING, KIND_EVALUATOR, KIND_GUARDRAIL, KIND_LLM,
    KIND_RERANKER, KIND_RETRIEVER, KIND_TOOL, KNOWN_KINDS, SpanFacts,
)

#: The classes the ledger accepts. Anything else is a bug, not a new category.
VALID_CLASSES = frozenset({EPISTEMIC_BEHAVIOR, EPISTEMIC_NARRATIVE, EPISTEMIC_RATIONALISATION})

#: Canonical span kind → the class of the *span itself*. Per-payload classes are decided by
#: :func:`classify_payload`, because one LLM span legitimately produces records of two classes:
#: its usage (measured, behaviour) and its completion (asserted, narrative).
_SPAN_CLASS: dict[str, str] = {
    KIND_LLM: EPISTEMIC_NARRATIVE,
    KIND_TOOL: EPISTEMIC_BEHAVIOR,
    KIND_RETRIEVER: EPISTEMIC_BEHAVIOR,
    KIND_EMBEDDING: EPISTEMIC_BEHAVIOR,
    KIND_RERANKER: EPISTEMIC_BEHAVIOR,
    KIND_GUARDRAIL: EPISTEMIC_BEHAVIOR,
    # A chain/agent span is the framework's own record of orchestration it performed — an observed
    # execution, not a claim about one.
    KIND_CHAIN: EPISTEMIC_BEHAVIOR,
    KIND_AGENT: EPISTEMIC_BEHAVIOR,
    # An evaluator is a model judging output. Its verdict is produced text about a process, which
    # is the definition of a rationalisation however confident the score looks.
    KIND_EVALUATOR: EPISTEMIC_RATIONALISATION,
}

# Payload kinds the bridge can emit.
PAYLOAD_USAGE = "usage"
PAYLOAD_OUTPUT = "output"
PAYLOAD_REASONING = "reasoning"
PAYLOAD_TOOL = "tool"

_PAYLOAD_CLASS: dict[str, str] = {
    PAYLOAD_USAGE: EPISTEMIC_BEHAVIOR,          # measured, from the provider's own accounting
    PAYLOAD_OUTPUT: EPISTEMIC_NARRATIVE,        # what the user was told
    PAYLOAD_REASONING: EPISTEMIC_RATIONALISATION,  # what the model said about its own process
    PAYLOAD_TOOL: EPISTEMIC_BEHAVIOR,           # an effect the runtime observed
}


class UnclassifiedSpan(RuntimeError):
    """Raised in strict mode when a GenAI span cannot be assigned an epistemic class.

    Never escapes the bridge in production: the bridge entry points are guarded and strict is off.
    It exists so the classification gap is a red test rather than a quiet decrease in a dashboard.
    """


def strict_default() -> bool:
    """Strict under test, lenient in production — the two places want opposite failure modes."""
    if os.environ.get("NEXUS_BRIDGE_STRICT", "").strip() in ("1", "true", "yes", "on"):
        return True
    if os.environ.get("NEXUS_BRIDGE_STRICT", "").strip() in ("0", "false", "no", "off"):
        return False
    return "pytest" in sys.modules


def classify_span(facts: SpanFacts, *, strict: t.Optional[bool] = None) -> t.Optional[str]:
    """The epistemic class of a span, or ``None`` when it has none.

    ``None`` means two different things and the caller must treat them differently, which is why
    :func:`is_ours` exists alongside this:

    * a span that is not GenAI at all (an HTTP call, a DB query) — not ours, ignore in silence;
    * a GenAI span whose kind we do not recognise — ours, and a coverage failure. Counted, dropped,
      and in strict mode raised.
    """
    if not facts.is_genai:
        return None
    cls = _SPAN_CLASS.get(facts.kind)
    if cls is None:
        if strict is None:
            strict = strict_default()
        if strict:
            raise UnclassifiedSpan(
                f"span {facts.name!r} (kind={facts.kind!r}, vocabulary={facts.vocabulary!r}, "
                f"scope={facts.scope!r}) carries GenAI attributes but no epistemic class is "
                f"defined for it. Add it to _SPAN_CLASS — do NOT default it.")
        return None
    if cls not in VALID_CLASSES:      # unreachable; a typo in the table must not reach the wire
        raise UnclassifiedSpan(f"{cls!r} is not an epistemic class")
    return cls


def classify_payload(payload_kind: str) -> str:
    """The class of one emitted record. Raises on an unknown payload kind — a caller inventing a
    payload without deciding its class is the exact mislabelling this module forbids."""
    cls = _PAYLOAD_CLASS.get(payload_kind)
    if cls is None:
        raise UnclassifiedSpan(f"no epistemic class defined for payload {payload_kind!r}")
    return cls


def is_ours(facts: SpanFacts) -> bool:
    """True when this span belongs to the GenAI vocabulary at all — recognised kind or not."""
    return bool(facts.is_genai)


def is_coverage_gap(facts: SpanFacts) -> bool:
    """A GenAI span of a kind we do not model. The number worth alerting on."""
    return bool(facts.is_genai) and facts.kind not in KNOWN_KINDS
