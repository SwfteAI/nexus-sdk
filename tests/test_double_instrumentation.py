"""One billable record per logical call — cases 2.6, 2.8 and 2.14.

These three are one bug wearing three costumes: the same model invocation is observed more than
once, and a naive bridge bills each observation. It is filed as a correctness bug rather than a
nicety because exact cost is the differentiator. A customer running Datadog beside us would see
tokens counted twice, check the number against the vendor invoice, and stop believing the ledger —
and being confidently wrong is worse than not reporting at all.

D-4's rule: **the innermost observation wins.** Not the first, not the most detailed — the
innermost, because it is the only layer positioned to see the vendor client's internal retries and
the real HTTP exchange. Everything outside it is real information about *structure* (which
framework, how deep, who else was watching) and is folded into the same record as such.

Span doubles come from ``test_bridge`` so both files describe the same fake world; that file also
explains why the doubles exist rather than the real OTel SDK.
"""
from __future__ import annotations


from test_bridge import FakeSpan, bridge, genai_llm_span, llm_span, usage_events  # noqa: F401


# --------------------------------------------------------------------------------------------
# 2.6 — three SDKs wrapping the same method
# --------------------------------------------------------------------------------------------

def test_2_6_double_instrumentation_bills_once(bridge, collector, sdk):
    """ddtrace, OpenLLMetry and we all wrap the same ``Messages.create``.

    ``wrapt`` nests safely, so nothing crashes — which is exactly what makes this dangerous. Three
    spans carrying the same token counts must produce one billable record, and the innermost must
    be the one that wins.
    """
    outer = FakeSpan("anthropic.messages.create", {
        "gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic",
        "gen_ai.response.model": "claude-sonnet-4-5",
        "gen_ai.usage.input_tokens": 1000, "gen_ai.usage.output_tokens": 200,
    }, scope="ddtrace.contrib.anthropic")
    middle = genai_llm_span("claude-sonnet-4-5", input_tokens=1000, output_tokens=200,
                            parent=outer, scope="opentelemetry.instrumentation.anthropic")
    inner = llm_span("claude-sonnet-4-5", input_tokens=1000, output_tokens=200,
                     parent=middle, scope="openinference.anthropic")

    for s in (outer, middle, inner):
        bridge.on_start(s)
    for s in (inner, middle, outer):          # children end before parents, as OTel guarantees
        bridge.on_end(s)

    evs = usage_events(collector, sdk)
    assert len(evs) == 1, [e.get("bridge") for e in evs]
    e = evs[0]
    assert e["input_tokens"] == 1000 and e["output_tokens"] == 200
    b = e["bridge"]
    assert b["double_instrumented"] is True
    assert b["observations"] == 3
    assert b["billed_depth"] == 2, "the innermost observer must win — it sees vendor retries"
    assert b["observers"] == ["ddtrace.contrib.anthropic",
                              "opentelemetry.instrumentation.anthropic",
                              "openinference.anthropic"]


def test_2_6_the_losing_observers_are_kept_as_structure(bridge, collector, sdk):
    """Deduplication must not become deletion.

    "Which layer did this call come through" is the attribution a customer needs to act on a bill.
    Dropping the outer observations would make the ledger cheaper and useless.
    """
    outer = genai_llm_span("claude-sonnet-4-5", input_tokens=50, output_tokens=5,
                           scope="ddtrace.contrib.anthropic")
    inner = llm_span("claude-sonnet-4-5", input_tokens=50, output_tokens=5, parent=outer)
    for s in (outer, inner):
        bridge.on_start(s)
    for s in (inner, outer):
        bridge.on_end(s)
    b = usage_events(collector, sdk)[0]["bridge"]
    assert b["framework"] == "ddtrace.contrib.anthropic"
    assert b["trace_id"] and b["root_span_id"]
    assert b["semconv"] == {"genai": "1.42.0", "stability": "pre-stable"}


def test_2_6_ties_break_deterministically(bridge, collector, sdk):
    """Two instrumentations at the same nesting depth — what 2.6 actually looks like when both use
    ``wrapt`` and neither creates a child span. The rule breaks the tie on insertion order because
    a billing figure that changes between two identical runs is unauditable."""
    seen = []
    for _ in range(4):
        a = genai_llm_span("claude-sonnet-4-5", input_tokens=10, output_tokens=2,
                           scope="a.instrumentation", trace_id=0xF00D)
        b = llm_span("claude-sonnet-4-5", input_tokens=10, output_tokens=2,
                     parent=a, scope="b.instrumentation", trace_id=0xF00D)
        bridge.on_start(a)
        bridge.on_start(b)
        bridge.on_end(b)
        bridge.on_end(a)
        seen.append(usage_events(collector, sdk)[-1]["bridge"]["billed_depth"])
    assert len(set(seen)) == 1, f"billed depth varied across identical runs: {seen}"


def test_2_6_two_genuinely_separate_calls_are_not_merged(bridge, collector, sdk):
    """The dedup rule must not become "bill the first call in a trace".

    Two sibling model calls in one trace are two invocations the vendor charges for twice. Merging
    them would under-bill, which is the direction that looks fine right up until reconciliation.
    """
    for _ in range(2):
        s = llm_span("claude-sonnet-4-5", input_tokens=100, output_tokens=10, trace_id=0xBEEF)
        bridge.on_start(s)
        bridge.on_end(s)
    assert len(usage_events(collector, sdk)) == 2


def test_2_6_foreign_wrappers_are_detected_on_the_wrapped_chain():
    """The patch-time half of D-4 step 1. ``ddtrace`` and OpenLLMetry are not installed here, so
    the chain is built the way ``wrapt`` builds one and attributed by defining module."""
    from nexus.integrations import coexistence, foreign_wrappers

    def create(**kw):
        return "ok"

    def _wrap(fn, module):
        def w(*a, **k):
            return fn(*a, **k)
        w.__wrapped__ = fn
        w.__module__ = module
        return w

    dd = _wrap(create, "ddtrace.contrib.internal.anthropic.patch")
    llm = _wrap(dd, "opentelemetry.instrumentation.anthropic")
    ours = _wrap(llm, "nexus.integrations.anthropic")

    assert foreign_wrappers(ours) == ["opentelemetry.instrumentation.anthropic",
                                      "ddtrace.contrib.internal.anthropic.patch"]
    info = coexistence(ours)
    assert info["double_instrumented"] is True
    assert info["recognised"] == ["ddtrace", "opentelemetry"]
    assert info["depth"] == 3


def test_2_6_an_unwrapped_callable_is_not_reported_as_double_instrumented():
    from nexus.integrations import coexistence

    def create():
        return None

    assert coexistence(create) == {"foreign_wrappers": [], "recognised": [],
                                   "depth": 0, "double_instrumented": False}


def test_2_6_object_proxy_wrappers_are_attributed_to_the_wrapper_not_the_wrapped():
    """``wrapt.ObjectProxy`` forwards ``__module__`` to the object it wraps.

    Reading the instance therefore names the layer *below*, so a chain of proxies would be reported
    as the vendor library instrumenting itself. The class is the only honest source for these.
    """
    from nexus.integrations import foreign_wrappers

    class _Proxy:
        __module__ = "third_party.proxies"

        def __init__(self, wrapped):
            self.__wrapped__ = wrapped

        def __getattr__(self, item):
            return getattr(self.__wrapped__, item)

    def create():
        return None

    create.__module__ = "anthropic.resources.messages"
    assert foreign_wrappers(_Proxy(create)) == ["third_party.proxies"]


def test_2_6_cyclic_wrapped_chain_terminates():
    """A cyclic ``__wrapped__`` is possible when two SDKs patch each other's wrapper. Hanging on
    somebody's import is not an acceptable failure mode."""
    from nexus.integrations import foreign_wrappers, wrap_depth

    def a():
        return None

    def b():
        return None

    a.__wrapped__ = b
    b.__wrapped__ = a
    a.__module__ = b.__module__ = "third_party.thing"
    assert wrap_depth(a) <= 16
    assert len(foreign_wrappers(a)) <= 16


# --------------------------------------------------------------------------------------------
# 2.8 — layered SDKs
# --------------------------------------------------------------------------------------------

def test_2_8_layered_sdks_bill_once_and_keep_the_framework_as_structure(bridge, collector, sdk):
    """``langchain_anthropic`` → ``anthropic``: one call, seen twice.

    The framework layer must not vanish — knowing a call arrived through a LangChain chain is how a
    customer finds the thing to change. It becomes structure, never spend.
    """
    chain = FakeSpan("RunnableSequence", {"openinference.span.kind": "CHAIN"},
                     scope="openinference.langchain")
    framework = llm_span("claude-sonnet-4-5", input_tokens=800, output_tokens=120,
                         parent=chain, scope="openinference.langchain")
    vendor = llm_span("claude-sonnet-4-5", input_tokens=800, output_tokens=120,
                      parent=framework, scope="openinference.anthropic")

    for s in (chain, framework, vendor):
        bridge.on_start(s)
    for s in (vendor, framework, chain):
        bridge.on_end(s)

    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    b = evs[0]["bridge"]
    assert b["framework"] == "openinference.langchain"
    assert b["billed_depth"] == 1
    assert evs[0]["input_tokens"] == 800


def test_2_8_the_chain_span_emits_nothing_of_its_own(bridge, collector, sdk):
    """A chain/agent span is ancestry. ``nexus.agent()`` is what records a run with an outcome, and
    a duplicate framework-shaped event would compete with it in the ledger."""
    chain = FakeSpan("AgentExecutor", {"openinference.span.kind": "AGENT", "agent.name": "planner"},
                     scope="openinference.langchain")
    bridge.on_start(chain)
    bridge.on_end(chain)
    sdk.flush(2.0)
    assert collector.of_type("token_usage") == []
    assert collector.of_type("tool_action") == []


def test_2_8_a_tool_call_under_an_llm_span_is_a_separate_record(bridge, collector, sdk):
    """The dedup rule must not over-merge. Function calling is a real second thing that happened,
    and a bridge that folded it into the model call would lose every tool effect in an agent loop —
    which is the data enforcement is built on."""
    parent = llm_span(input_tokens=10, output_tokens=5)
    tool = FakeSpan("search", {"openinference.span.kind": "TOOL", "tool.name": "search",
                               "tool.parameters": "q=weather"},
                    parent=parent, scope="openinference.langchain")
    bridge.on_start(parent)
    bridge.on_start(tool)
    bridge.on_end(tool)
    bridge.on_end(parent)
    sdk.flush(2.0)
    assert len(collector.of_type("token_usage")) == 1
    actions = collector.of_type("tool_action")
    assert [a["tool_name"] for a in actions] == ["search"]
    assert actions[0]["epistemic_class"] == "behavior_trace"


def test_2_8_usage_only_on_the_outer_layer_is_still_billed(bridge, collector, sdk):
    """Common in practice: the framework reports tokens, the vendor span carries none.

    "Innermost wins" must mean *innermost that saw usage*, or this call would be billed at zero and
    the loss would look like a quiet service.
    """
    framework = llm_span("claude-sonnet-4-5", input_tokens=640, output_tokens=64,
                         scope="openinference.langchain")
    vendor = FakeSpan("messages.create", {
        "openinference.span.kind": "LLM", "llm.model_name": "claude-sonnet-4-5",
    }, parent=framework, scope="openinference.anthropic")
    for s in (framework, vendor):
        bridge.on_start(s)
    for s in (vendor, framework):
        bridge.on_end(s)
    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    assert evs[0]["input_tokens"] == 640
    assert evs[0]["bridge"]["billed_depth"] == 0


# --------------------------------------------------------------------------------------------
# 2.14 — vendor-internal retries
# --------------------------------------------------------------------------------------------

def _attempt_span(parent, i, *, genai_marker=True, scope="opentelemetry.instrumentation.httpx"):
    attrs = {
        "http.request.method": "POST",
        "url.full": "https://api.anthropic.com/v1/messages",
        "http.request.resend_count": i,
    }
    if genai_marker:
        attrs["gen_ai.provider.name"] = "anthropic"
    return FakeSpan(f"POST /v1/messages #{i}", attrs, parent=parent, scope=scope)


def test_2_14_internal_retries_bill_once_and_keep_the_attempt_count(bridge, collector, sdk):
    """Three HTTP attempts inside one ``messages.create``. Billing per attempt turns a flaky
    network into a cost anomaly that never happened."""
    call = llm_span("claude-sonnet-4-5", input_tokens=900, output_tokens=90)
    bridge.on_start(call)
    for i in range(3):
        attempt = _attempt_span(call, i)
        bridge.on_start(attempt)
        bridge.on_end(attempt)
    bridge.on_end(call)

    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    assert evs[0]["input_tokens"] == 900
    assert evs[0]["attempts"] == 3
    assert evs[0]["bridge"]["observations"] == 1, "attempts are structure, not observers"


def test_2_14_plain_http_attempts_without_genai_markers_are_still_counted(bridge, collector, sdk):
    """The realistic shape. ``anthropic`` retries through ``httpx``, and an ``httpx`` span carries
    nothing but ``http.*`` — no ``gen_ai.*`` at all. A GenAI-marker gate on ingest would drop
    exactly the spans that explain a retry storm, leaving ``attempts`` at 1 on the traffic the
    field exists for."""
    call = llm_span("claude-sonnet-4-5", input_tokens=120, output_tokens=12)
    bridge.on_start(call)
    for i in range(4):
        attempt = _attempt_span(call, i, genai_marker=False)
        bridge.on_start(attempt)
        bridge.on_end(attempt)
    bridge.on_end(call)
    assert usage_events(collector, sdk)[0]["attempts"] == 4


def test_2_14_an_http_span_outside_a_call_is_not_an_attempt(bridge, collector, sdk):
    """The customer's own outbound HTTP is not our business. Admitting it would put arbitrary
    request spans into a GenAI ledger."""
    from nexus import _counters
    span = FakeSpan("GET /health", {"http.request.method": "GET",
                                    "url.full": "https://example.internal/health"},
                    scope="opentelemetry.instrumentation.requests")
    bridge.on_start(span)
    bridge.on_end(span)
    assert usage_events(collector, sdk) == []
    assert _counters.get("bridge_spans_ignored") > 0


def test_2_14_declared_attempt_attribute_is_honoured(bridge, collector, sdk):
    """OpenLLMetry emits no attempt spans; some instrumentations emit a counter instead. Neither
    source is reliable alone, so the larger of the two wins."""
    span = llm_span(input_tokens=10, output_tokens=1, extra={"llm.retry.count": 5})
    bridge.on_start(span)
    bridge.on_end(span)
    assert usage_events(collector, sdk)[0]["attempts"] == 5


def test_2_14_observed_attempts_beat_a_smaller_declared_count(bridge, collector, sdk):
    call = llm_span("claude-sonnet-4-5", input_tokens=10, output_tokens=1,
                    extra={"llm.retry.count": 2})
    bridge.on_start(call)
    for i in range(3):
        a = _attempt_span(call, i)
        bridge.on_start(a)
        bridge.on_end(a)
    bridge.on_end(call)
    assert usage_events(collector, sdk)[0]["attempts"] == 3


def test_2_14_single_attempt_omits_the_field(bridge, collector, sdk):
    """``attempts=1`` is the normal case and ``contract.token_usage`` drops it. A field present on
    every event carries no information and costs storage on every row."""
    span = llm_span(input_tokens=10, output_tokens=1)
    bridge.on_start(span)
    bridge.on_end(span)
    assert "attempts" not in usage_events(collector, sdk)[0]


def test_2_14_attempts_are_never_selected_as_the_billable_observation(bridge, collector, sdk):
    """An attempt span that happens to carry usage — some proxies mirror the response body — must
    still not be billed. Otherwise a retried call bills the retry, not the call."""
    call = llm_span("claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    bridge.on_start(call)
    attempt = _attempt_span(call, 1)
    attempt.attributes["gen_ai.usage.input_tokens"] = 999999
    bridge.on_start(attempt)
    bridge.on_end(attempt)
    bridge.on_end(call)
    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    assert evs[0]["input_tokens"] == 1000
