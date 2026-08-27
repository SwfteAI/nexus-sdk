"""One normalised view over three GenAI span vocabularies.

We do not write provider adapters. ``REPLICATION-EFFORT.md`` measured one OpenLLMetry provider
adapter at 931 lines across 8 files, over ~30 packages — 15–25k lines of maintained, permissively
licensed work that three funded projects already do. Re-implementing it would be the most expensive
way possible to arrive at a worse version of somebody else's tested extraction logic.

So this module is a *reader*, not an adapter. It takes a span produced by whichever instrumentation
the customer already runs and reduces it to :class:`SpanFacts` — the small set of things the nexus
ledger actually needs. Three vocabularies are read:

* **OpenTelemetry GenAI semantic conventions**, targeted at **v1.42.0**.

  .. warning::

     ``semantic-conventions-genai`` is **still pre-stable**. v1.42.0 is a moving target: content
     capture moved from ``gen_ai.prompt``/``gen_ai.completion`` to ``gen_ai.input.messages``/
     ``gen_ai.output.messages``, and ``gen_ai.system`` was renamed to ``gen_ai.provider.name``.
     Both spellings are read here on purpose. Reading a superseded key costs one dict lookup;
     failing to read it costs a customer their token counts for however long it takes someone to
     notice a number went quietly to zero. Expect churn, and expect this table to grow rather than
     shrink.

* **OpenInference** (Arize, Apache-2.0) — the structural base. ``openinference.span.kind`` is the
  only vocabulary of the three that states what a span *is* rather than leaving it to be inferred
  from the instrumentation's name, which is why classification keys off it first.
* **OpenLLMetry** (Traceloop) / **OpenLIT** — breadth. Where they disagree with OpenInference on a
  field, OpenLLMetry is the older implementation and usually the safer read.

Nothing here imports ``opentelemetry``. A span is read structurally (``.attributes``, ``.context``,
``.parent``), so the bridge works against a real ``ReadableSpan``, against an OpenInference span,
and against a test double, without the ``[otel]`` extra installed at all.

**One rule about content.** Every attribute this module reads was written by instrumentation the
customer installed, not by us, and a good deal of it is the customer's own text and the model's own
output. Three fields — ``input_text``, ``output_text``, ``reasoning_text`` — are *declared* to be
content: the bridge emits the last two only through the tier gate, and emits ``input_text``
nowhere at all. Every other field this reader produces must be structure: an identifier, a number,
a type, a count. Structure is not a smaller amount of content, it is a different thing, and a
field that holds "an id or whatever the instrumentation felt like" is content wearing a label.
The rule is written down because it was broken: ``tool.parameters`` (a tool call's arguments) and
``input.value`` (a span's raw input) were read into ``tool_target``, which the contract treats as
an identifier and tiers with a text gate — and at the default tier that gate returned its input
unchanged. The fix is not a better gate. It is not putting a payload in front of one. See
:func:`_identifier`, which decides what may be a target, and :func:`shape_of`, which is what the
arguments contribute instead.

One caveat the rule does not cover: ``SpanFacts.attributes`` keeps the raw attribute mapping —
prompts included — for as long as its call is open, because billing re-reads resend counters from
it. Nothing emits it and it never leaves the process, but it is why a heap dump of a host running
this bridge contains prompts.
"""
from __future__ import annotations

import json
import re
import typing as t
from dataclasses import dataclass, field

#: The semconv release this module was written against. Pinned deliberately — see the warning
#: above; a pre-stable convention that silently drifts is worse than one that fails a test.
GENAI_SEMCONV_VERSION = "1.42.0"
GENAI_SEMCONV_STABILITY = "pre-stable"

# --------------------------------------------------------------------------------------------
# Attribute keys, grouped by the concept rather than by the vocabulary that spells it.
# First hit wins, so the order within each tuple is most-authoritative → most-legacy.
# --------------------------------------------------------------------------------------------

_KIND_KEYS = ("openinference.span.kind", "traceloop.span.kind", "gen_ai.operation.name")

_PROVIDER_KEYS = (
    "gen_ai.provider.name",      # semconv ≥1.36
    "gen_ai.system",             # semconv <1.36, still emitted by most shipped instrumentations
    "llm.provider",              # OpenInference
    "llm.system",
)

_REQUEST_MODEL_KEYS = ("gen_ai.request.model", "llm.model_name", "llm.request.model", "gen_ai.model")
_RESPONSE_MODEL_KEYS = ("gen_ai.response.model", "llm.response.model", "llm.model_name")

_INPUT_TOKEN_KEYS = (
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.prompt_tokens",          # OpenLLMetry / pre-1.27 semconv
    "llm.token_count.prompt",              # OpenInference
)
_OUTPUT_TOKEN_KEYS = (
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.completion_tokens",
    "llm.token_count.completion",
)

# Cache accounting. This is the field set that makes "exact cost" true rather than approximately
# true: cached input is an order of magnitude cheaper than fresh input, so a bridge that folds
# cache reads into `input_tokens` overstates a cache-heavy workload's bill by multiples. Case 2.16.
_CACHE_READ_KEYS = (
    "gen_ai.usage.cache_read_input_tokens",
    "gen_ai.usage.cached_input_tokens",
    "llm.token_count.prompt_details.cache_read",
    "gen_ai.usage.cache_read_tokens",
)
_CACHE_WRITE_5M_KEYS = (
    "gen_ai.usage.cache_creation.ephemeral_5m_input_tokens",
    "gen_ai.usage.cache_creation_input_tokens",
    "llm.token_count.prompt_details.cache_write",
    "gen_ai.usage.cache_write_tokens",
)
_CACHE_WRITE_1H_KEYS = (
    "gen_ai.usage.cache_creation.ephemeral_1h_input_tokens",
    # Flattened spelling. OTel attribute keys are a flat namespace, so instrumentations routinely
    # collapse Anthropic's nested `cache_creation.ephemeral_1h_input_tokens` rather than emit a
    # dotted sub-object. Reading both costs a dict lookup; reading only one prices a 1-hour write
    # at the 5-minute rate — a 1.6× understatement that looks like a plausible number.
    "gen_ai.usage.cache_creation_1h_tokens",
    "llm.token_count.prompt_details.cache_write_1h",
)

#: A cost the *provider* reported. Preferred over our rate-card arithmetic when present, because a
#: number from the vendor is evidence and a number from a rate card is an inference.
_REPORTED_COST_KEYS = ("gen_ai.usage.cost", "llm.cost.total", "gen_ai.usage.total_cost")

#: Explicit retry/attempt counters, where the instrumentation bothers to emit one. Case 2.14.
_ATTEMPT_KEYS = ("gen_ai.request.attempt", "llm.retry.count", "http.request.resend_count",
                 "retry.count")

_OUTPUT_TEXT_KEYS = (
    "gen_ai.output.messages",     # semconv 1.42 content capture (opt-in upstream)
    "gen_ai.completion",          # legacy semconv / OpenLLMetry
    "gen_ai.completion.0.content",
    "output.value",               # OpenInference
    "llm.output_messages.0.message.content",
)
_INPUT_TEXT_KEYS = (
    "gen_ai.input.messages",
    "gen_ai.prompt",
    "gen_ai.prompt.0.content",
    "input.value",
    "llm.input_messages.0.message.content",
)

#: Model-authored reasoning. Distinct from output text because it is a *different epistemic class*:
#: a model's account of its own process is ``rationalisation``, never ``behavior_trace``. Folding
#: it into the answer would launder a claim into the record as if it were an observation.
_REASONING_KEYS = (
    "gen_ai.output.reasoning",
    "gen_ai.completion.reasoning",
    "llm.output_messages.0.message.reasoning",
    "llm.reasoning",
    "traceloop.entity.thinking",
)

_TOOL_NAME_KEYS = ("gen_ai.tool.name", "tool.name", "traceloop.entity.name")

#: Keys that name *which* tool call this is. A target is an identifier — a call id, a tool id, an
#: endpoint — and nothing else. ``tool.parameters`` and ``input.value`` used to be read here and
#: are not identifiers: the first is the arguments the model chose, the second is OpenInference's
#: verbatim span input. Both are customer and model content, both landed in ``tool_action.target``,
#: and the only thing between that field and the collector was a text gate. Content must not be
#: standing in front of a gate in the first place — see :data:`_TOOL_ARG_KEYS`.
_TOOL_TARGET_KEYS = ("gen_ai.tool.call.id", "tool.id")

#: Keys whose value is the *payload* of a call. Never read as text, only ever reduced by
#: :func:`shape_of`. This tuple exists so that the payload keys are named and handled rather than
#: silently unread: the ledger still wants to know a tool was called with three arguments named
#: ``city``, ``units`` and ``when``, and that fact does not require their values.
_TOOL_ARG_KEYS = ("gen_ai.tool.call.arguments", "tool.parameters", "tool.arguments",
                  "input.value", "traceloop.entity.input")

_AGENT_NAME_KEYS = ("gen_ai.agent.name", "agent.name")

_HTTP_MARKERS = ("http.request.method", "http.method", "url.full", "http.url", "server.address")

#: Canonical span kinds. The bridge classifies against *these*, not against any one vocabulary, so
#: adding OpenLIT or a fourth convention later is a table edit rather than a classifier rewrite.
KIND_LLM = "llm"
KIND_TOOL = "tool"
KIND_CHAIN = "chain"
KIND_AGENT = "agent"
KIND_RETRIEVER = "retriever"
KIND_EMBEDDING = "embedding"
KIND_RERANKER = "reranker"
KIND_GUARDRAIL = "guardrail"
KIND_EVALUATOR = "evaluator"
KIND_UNKNOWN = "unknown"

KNOWN_KINDS = frozenset({
    KIND_LLM, KIND_TOOL, KIND_CHAIN, KIND_AGENT, KIND_RETRIEVER,
    KIND_EMBEDDING, KIND_RERANKER, KIND_GUARDRAIL, KIND_EVALUATOR,
})

_KIND_ALIASES: dict[str, str] = {
    # OpenInference `openinference.span.kind`
    "llm": KIND_LLM, "chain": KIND_CHAIN, "tool": KIND_TOOL, "agent": KIND_AGENT,
    "retriever": KIND_RETRIEVER, "embedding": KIND_EMBEDDING, "reranker": KIND_RERANKER,
    "guardrail": KIND_GUARDRAIL, "evaluator": KIND_EVALUATOR,
    # OTel GenAI `gen_ai.operation.name`
    "chat": KIND_LLM, "text_completion": KIND_LLM, "generate_content": KIND_LLM,
    "embeddings": KIND_EMBEDDING, "execute_tool": KIND_TOOL, "invoke_agent": KIND_AGENT,
    "create_agent": KIND_AGENT,
    # Traceloop `traceloop.span.kind`
    "workflow": KIND_CHAIN, "task": KIND_CHAIN, "tool_call": KIND_TOOL,
}

#: Any of these present means the span came from *some* GenAI instrumentation. The distinction
#: matters: a span we cannot classify but which is plainly GenAI is a coverage failure that must be
#: counted and surfaced, whereas a database span is simply not ours and deserves silence.
_GENAI_MARKER_PREFIXES = ("gen_ai.", "llm.", "openinference.", "traceloop.", "openlit.")


@dataclass
class SpanFacts:
    """Everything the ledger needs from a span, and nothing it does not."""

    trace_id: str = ""
    span_id: str = ""
    parent_span_id: t.Optional[str] = None
    name: str = ""
    scope: str = ""                      # instrumentation scope, e.g. "openinference.anthropic"
    kind: str = KIND_UNKNOWN
    vocabulary: str = "unknown"
    is_genai: bool = False
    is_http: bool = False

    provider: t.Optional[str] = None
    model: t.Optional[str] = None

    input_tokens: t.Optional[int] = None
    output_tokens: t.Optional[int] = None
    cache_read_tokens: t.Optional[int] = None
    cache_write_5m_tokens: t.Optional[int] = None
    cache_write_1h_tokens: t.Optional[int] = None
    reported_cost_usd: t.Optional[float] = None
    attempts: t.Optional[int] = None

    input_text: t.Optional[str] = None
    output_text: t.Optional[str] = None
    reasoning_text: t.Optional[str] = None

    tool_name: t.Optional[str] = None
    #: An identifier for the call, or ``None``. Never a payload: see :func:`_identifier`.
    tool_target: t.Optional[str] = None
    #: Content-free description of the call's arguments — types, counts, safe field names.
    #: This is what replaced reading ``tool.parameters`` / ``input.value`` as target text.
    tool_arg_shape: t.Optional[dict] = None
    agent_name: t.Optional[str] = None

    error: t.Optional[str] = None
    duration_ms: t.Optional[int] = None
    attributes: dict = field(default_factory=dict)

    @property
    def has_usage(self) -> bool:
        """True when this observation carries billable numbers, not merely structure."""
        return any(v for v in (self.input_tokens, self.output_tokens, self.cache_read_tokens,
                               self.cache_write_5m_tokens, self.cache_write_1h_tokens))

    def usage_dict(self) -> dict:
        """The breakdown in ``pricing.cost_from_usage``'s own field names.

        Deliberately the *transcript's* vocabulary rather than ours, so the parity test against
        ``nexus_devtools/pricing.py`` compares like with like instead of comparing two translations.
        """
        u: dict = {
            "input_tokens": self.input_tokens or 0,
            "output_tokens": self.output_tokens or 0,
            "cache_read_input_tokens": self.cache_read_tokens or 0,
        }
        if self.cache_write_1h_tokens:
            u["cache_creation"] = {
                "ephemeral_5m_input_tokens": self.cache_write_5m_tokens or 0,
                "ephemeral_1h_input_tokens": self.cache_write_1h_tokens or 0,
            }
        elif self.cache_write_5m_tokens:
            u["cache_creation_input_tokens"] = self.cache_write_5m_tokens
        return u


# --------------------------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------------------------

def _get(obj: t.Any, name: str, default: t.Any = None) -> t.Any:
    """``getattr`` that cannot raise.

    The three-argument ``getattr`` only defends against the attribute being *absent*: whatever a
    property raises still propagates. Every span here comes from instrumentation we do not own —
    a lazy ``.name``, a ``.status`` computed from a closed response, a ``.context`` on a span the
    exporter already recycled — and any of those exploding would put a ``RuntimeError`` on the
    host's request path from inside a telemetry reader. Degrade to "unknown" instead; that is the
    SDK's standing rule (`DECISIONS.md` cross-cutting rule 5) and the field being unreadable is
    itself the only honest thing we can say about it.
    """
    try:
        return getattr(obj, name, default)
    except Exception:  # noqa: BLE001
        return default


def _first(attrs: t.Mapping, keys: t.Sequence[str]) -> t.Any:
    for k in keys:
        v = attrs.get(k)
        if v is not None and v != "":
            return v
    return None


def _int(v: t.Any) -> t.Optional[int]:
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float(v: t.Any) -> t.Optional[float]:
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _text(v: t.Any, limit: int = 20000) -> t.Optional[str]:
    """Flatten whatever the convention put in a content attribute into a string.

    v1.42's ``gen_ai.output.messages`` is a JSON-ish structure, the legacy keys are plain strings,
    and OpenInference's ``output.value`` is either. Bounded because an unbounded ``str()`` of a
    conversation history is a memory event on somebody's request path.
    """
    if v is None:
        return None
    if isinstance(v, str):
        return v[:limit] or None
    if isinstance(v, (list, tuple)):
        parts = [_text(i, limit) for i in list(v)[:32]]
        joined = "\n".join(p for p in parts if p)
        return joined[:limit] or None
    if isinstance(v, dict):
        for k in ("content", "text", "value", "message"):
            if k in v:
                return _text(v[k], limit)
        return str(v)[:limit] or None
    return str(v)[:limit] or None


#: What an identifier is allowed to look like. Deliberately a whitelist and deliberately narrow:
#: call ids (``call_01H8XQ``, ``toolu_01ABC``), dotted symbol paths, URNs and bare endpoint URLs
#: all match; a sentence does not (spaces), an email does not (``@``), a query string does not
#: (``?`` and ``=``), and neither does anything with a newline or a quote in it. The rule is not
#: "this value is safe" — it is "a value that is not shaped like an identifier is not a target",
#: which is a property of the field rather than a guess about the content.
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")

#: Bounds on :func:`shape_of`. A summary of an unbounded payload has to be bounded or it is a
#: payload again by another route: 200 field names is not shape, it is data.
MAX_SHAPE_FIELDS = 16
MAX_SHAPE_DEPTH = 3
MAX_SHAPE_ITEMS = 32

#: A field name is emitted only if it looks like a field name. Argument names normally come from
#: the developer's own tool schema, which puts them in the same class as ``tool_name`` — but a
#: mapping keyed by customer data (an address book, a per-user index) would turn "names are safe"
#: into the same leak wearing a different hat, so the shape of the *name* is checked too.
_SAFE_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,39}\Z")

#: ``_SAFE_KEY_RE`` above states the right requirement and then does not enforce it.
#: It was written to stop "a mapping keyed by customer data" from turning field names into a leak,
#: and it catches the two cases somebody pictured while writing it — a key that is an email
#: address, a key that is bare digits — while ``{"patient_90210443": 1, "mrn_44521": 2}`` and
#: ``{"acme.customer.90210443": 1}`` walk straight through. Those are not exotic. A per-patient
#: index, a per-account rollup, a per-order dict is the ordinary shape of the payload an agent
#: hands a tool, and the names in it are the identifiers themselves.
#:
#: The distinction being drawn is between a *schema* name and an *instance* name. A schema name is
#: written once by a developer and reused for every call; an instance name is minted per record
#: and carries the record's identity. Nothing in the string says which it is — but identifiers are
#: made of digit runs and schema names, being words, are not. So: a run of four or more digits, or
#: six digits in total, means this is a value wearing a key's clothing.
#:
#: The threshold has a known and accepted cost. ``iso8601`` and ``rfc3339`` are legitimate schema
#: names with a four-digit run, and they now land in the anonymous bucket. That is the right side
#: to be wrong on twice over: the penalty for a false positive is that a field is reported by type
#: instead of by name, while the penalty for a false negative is a patient identifier on the wire
#: at the tier that promises no content. Nobody reads this ledger for the spelling of a field.
_IDENTIFIERISH_KEY_RE = re.compile(r"\d{4}|(?:\D*\d){6}")


def _identifier(v: t.Any, limit: int = 128) -> t.Optional[str]:
    """``v`` if it is shaped like an identifier, else ``None``.

    Rejecting is the whole function. Every value here was written by instrumentation we do not
    own, into a key whose *convention* says "id" and whose contents are whatever the library felt
    like putting there. Truncating a payload to 128 characters would still emit a payload.

    Known residual, stated rather than papered over: a bare number passes, because numeric call
    ids are ordinary and inventing a rule against them would break real instrumentation. So an
    instrumentation that wrote a national ID number into ``tool.id`` would still be believed. That
    is a narrower hole than a sentence-shaped one and it is the last thing standing after the
    identifier rule; the tier gate downstream is the layer that covers it.
    """
    if v is None or isinstance(v, bool):
        return None
    if not isinstance(v, (str, int, float)):
        return None
    s = str(v).strip()
    if not s or len(s) > limit:
        return None
    return s if _IDENTIFIER_RE.match(s) else None


def shape_of(v: t.Any, _depth: int = 0) -> t.Optional[dict]:
    """A bounded, content-free description of a payload: types, counts, and safe field names.

    This is the representation ``metadata_only`` is supposed to emit, applied at the reader rather
    than at the gate. It answers the questions a ledger actually asks of a tool call — was it
    called with arguments, how many, which named parameters, were any of them structured — and it
    cannot answer "what did they say", because no value ever enters the result.

    Three deliberate omissions:

    * **No values, at any depth or type.** Numbers are values too: an account number, a dose, a
      salary. ``{"type": "number"}`` is the whole of what a number contributes here.
    * **No fingerprint.** ``redact_preview`` pairs ``chars`` with a hash because a paragraph of
      prose has the entropy to make a hash one-way. Tool arguments frequently do not — a boolean,
      a zip code, a member of a five-value enum is recoverable from its digest by trying every
      input — so a fingerprint here would be a correlation handle over customer content wearing
      the costume of a safe one.
    * **No free-form key names.** See :data:`_SAFE_KEY_RE`.

    ``chars`` on a string is retained: it is exactly the shape signal ``contract.redact_preview``
    already emits at T0, so it is inside the tier's existing contract rather than an extension
    of it.
    """
    if _depth > MAX_SHAPE_DEPTH:
        return {"type": "..."}
    if v is None:
        return {"type": "null"}
    if isinstance(v, bool):
        return {"type": "bool"}
    if isinstance(v, (int, float)):
        return {"type": "number"}
    if isinstance(v, str):
        s = v.strip()
        if s[:1] in ("{", "[") and _depth < MAX_SHAPE_DEPTH:
            try:
                parsed = json.loads(s)
            except Exception:  # noqa: BLE001
                parsed = None
            if isinstance(parsed, (dict, list)):
                inner = shape_of(parsed, _depth) or {}
                return dict(inner, json=True)
        return {"type": "string", "chars": len(v)}
    if isinstance(v, (list, tuple, set)):
        items = list(v)[:MAX_SHAPE_ITEMS]
        types = sorted({(shape_of(i, _depth + 1) or {}).get("type", "?") for i in items})
        return {"type": "array", "count": len(v), "item_types": types}
    if isinstance(v, t.Mapping):
        out: dict = {"type": "object", "field_count": len(v)}
        fields: dict = {}
        unnamed = 0
        omitted = 0
        unnamed_types: list = []
        for key in list(v.keys()):
            name = key if isinstance(key, str) else str(key)
            if not _SAFE_KEY_RE.match(name) or _IDENTIFIERISH_KEY_RE.search(name):
                unnamed += 1
                # A rejected name is not a rejected field. The reason this function exists is to
                # answer "what shape was this call", and dropping the entry outright would make a
                # payload of eight per-patient numbers indistinguishable from an empty object —
                # which is both less useful and less honest than saying there were eight numbers
                # whose names could not be shown. The type is safe to emit for the same reason it
                # is safe for a named field: it is not a value. Reported as a sibling list rather
                # than as synthesised ``field_0``/``field_1`` entries inside ``fields``, because
                # ``field_0`` is itself a name ``_SAFE_KEY_RE`` would admit, and a real key spelled
                # that way would then silently collide with a placeholder.
                if len(unnamed_types) < MAX_SHAPE_FIELDS:
                    unnamed_types.append((shape_of(v[key], _depth + 1) or {}).get("type", "?"))
                continue
            if len(fields) >= MAX_SHAPE_FIELDS:
                omitted += 1
                continue
            fields[name] = shape_of(v[key], _depth + 1)
        out["fields"] = fields
        if unnamed:
            out["fields_unnamed"] = unnamed
            out["unnamed_types"] = sorted(unnamed_types)
        if omitted:
            out["fields_omitted"] = omitted
        return out
    return {"type": type(v).__name__}


def _tool_arg_shape(attrs: t.Mapping, rejected_target: t.Any) -> t.Optional[dict]:
    """The shape fragment for a tool span: its arguments, plus any target we refused.

    A refused target is reported rather than dropped in silence. "This span had a target-shaped
    key holding 4kB of string" is a fact about somebody's instrumentation that the reader of the
    ledger should be able to see; leaving it out would make a leak-prevention step look identical
    to an attribute that was never there.
    """
    frag: dict = {}
    payload = _first(attrs, _TOOL_ARG_KEYS)
    if payload is not None:
        shape = shape_of(payload)
        if shape:
            frag = dict(shape)
    if rejected_target is not None:
        rejected = shape_of(rejected_target)
        if rejected:
            frag["target"] = rejected
    return frag or None


def _hex(v: t.Any) -> str:
    if v is None:
        return ""
    if isinstance(v, int):
        return format(v, "032x")
    return str(v)


def _span_ids(span: t.Any) -> tuple[str, str, t.Optional[str]]:
    """``(trace_id, span_id, parent_span_id)`` from any span-shaped object.

    Structural rather than typed: a real ``ReadableSpan`` exposes ``.context``, an in-flight ``Span``
    exposes ``.get_span_context()``, and neither can be named here without importing
    ``opentelemetry`` into the core ring.
    """
    ctx = _get(span, "context")
    if ctx is None:
        getter = _get(span, "get_span_context")
        if callable(getter):
            try:
                ctx = getter()
            except Exception:  # noqa: BLE001
                ctx = None
    trace_id = _hex(_get(ctx, "trace_id")) if ctx is not None else ""
    span_id = _hex(_get(ctx, "span_id")) if ctx is not None else ""
    parent = _get(span, "parent")
    parent_id = None
    if parent is not None:
        pid = _get(parent, "span_id", parent)
        parent_id = _hex(pid) if pid is not None else None
    if not span_id:
        span_id = f"anon-{id(span):x}"
    return trace_id, span_id, (parent_id or None)


def _scope_name(span: t.Any) -> str:
    for attr in ("instrumentation_scope", "instrumentation_info"):
        scope = _get(span, attr)
        name = _get(scope, "name")
        if name:
            return str(name)
    return str(_get(span, "scope", "") or "")


def _kind_and_vocabulary(attrs: t.Mapping, scope: str) -> tuple[str, str]:
    raw = _first(attrs, _KIND_KEYS)
    vocab = "unknown"
    if attrs.get("openinference.span.kind") is not None:
        vocab = "openinference"
    elif attrs.get("traceloop.span.kind") is not None:
        vocab = "openllmetry"
    elif any(str(k).startswith("gen_ai.") for k in attrs):
        vocab = "genai"
    elif any(str(k).startswith("llm.") for k in attrs):
        vocab = "openinference"
    if raw is None:
        # No explicit kind. Infer from the token/model attributes rather than give up: several
        # shipped instrumentations emit usage on an unlabelled span, and dropping those would mean
        # losing the numbers we exist to record.
        if _first(attrs, _INPUT_TOKEN_KEYS) is not None or _first(attrs, _RESPONSE_MODEL_KEYS) is not None:
            return KIND_LLM, vocab
        if _first(attrs, _TOOL_NAME_KEYS) is not None:
            return KIND_TOOL, vocab
        return KIND_UNKNOWN, vocab
    return _KIND_ALIASES.get(str(raw).strip().lower(), KIND_UNKNOWN), vocab


def _error_of(span: t.Any) -> t.Optional[str]:
    status = _get(span, "status")
    code = _get(status, "status_code")
    name = _get(code, "name") or str(code or "")
    if "ERROR" in str(name).upper():
        desc = _get(status, "description")
        return str(desc or "error")
    return None


def _duration_ms(span: t.Any) -> t.Optional[int]:
    start, end = _get(span, "start_time"), _get(span, "end_time")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return int((end - start) / 1_000_000)     # OTel timestamps are nanoseconds
    return None


def normalise(span: t.Any) -> SpanFacts:
    """Read a span into :class:`SpanFacts`. Never raises — a malformed span yields empty facts."""
    try:
        attrs = dict(_get(span, "attributes") or {})
    except Exception:  # noqa: BLE001
        attrs = {}
    trace_id, span_id, parent_id = _span_ids(span)
    scope = _scope_name(span)
    kind, vocab = _kind_and_vocabulary(attrs, scope)
    is_genai = any(str(k).startswith(_GENAI_MARKER_PREFIXES) for k in attrs) or kind != KIND_UNKNOWN
    model = _first(attrs, _RESPONSE_MODEL_KEYS) or _first(attrs, _REQUEST_MODEL_KEYS)
    raw_target = _first(attrs, _TOOL_TARGET_KEYS)
    target = _identifier(raw_target)

    return SpanFacts(
        trace_id=trace_id, span_id=span_id, parent_span_id=parent_id,
        name=str(_get(span, "name", "") or ""), scope=scope,
        kind=kind, vocabulary=vocab, is_genai=bool(is_genai),
        is_http=any(k in attrs for k in _HTTP_MARKERS),
        provider=(str(_first(attrs, _PROVIDER_KEYS)) if _first(attrs, _PROVIDER_KEYS) else None),
        model=(str(model) if model else None),
        input_tokens=_int(_first(attrs, _INPUT_TOKEN_KEYS)),
        output_tokens=_int(_first(attrs, _OUTPUT_TOKEN_KEYS)),
        cache_read_tokens=_int(_first(attrs, _CACHE_READ_KEYS)),
        cache_write_5m_tokens=_int(_first(attrs, _CACHE_WRITE_5M_KEYS)),
        cache_write_1h_tokens=_int(_first(attrs, _CACHE_WRITE_1H_KEYS)),
        reported_cost_usd=_float(_first(attrs, _REPORTED_COST_KEYS)),
        attempts=_int(_first(attrs, _ATTEMPT_KEYS)),
        input_text=_text(_first(attrs, _INPUT_TEXT_KEYS)),
        output_text=_text(_first(attrs, _OUTPUT_TEXT_KEYS)),
        reasoning_text=_text(_first(attrs, _REASONING_KEYS)),
        tool_name=(str(_first(attrs, _TOOL_NAME_KEYS)) if _first(attrs, _TOOL_NAME_KEYS) else None),
        tool_target=target,
        tool_arg_shape=_tool_arg_shape(attrs, raw_target if target is None else None),
        agent_name=(str(_first(attrs, _AGENT_NAME_KEYS)) if _first(attrs, _AGENT_NAME_KEYS) else None),
        error=_error_of(span),
        duration_ms=_duration_ms(span),
        attributes=attrs,
    )
