"""Provider coverage: the four things upstream cannot give us.

WP-5's strategy is *consume, do not replicate*. One OpenLLMetry provider adapter measures 931 lines
across 8 files, there are ~30 of them, and three funded projects already maintain them under
permissive licences. What those projects do not have — what no observability vocabulary has, because
observability does not need it — is the four properties asserted here:

1. **An epistemic class on every event.** Nothing unclassified reaches the ledger.
2. **Our privacy tier, re-applied on ingest.** Upstream redaction is somebody else's promise about
   somebody else's code path.
3. **Exact cost from the real usage breakdown**, cache split included, against the same rate card
   as ``nexus_devtools/pricing.py``.
4. **A reader for three vocabularies** pinned to GenAI semconv v1.42.0, which is still pre-stable.

Plus the constraint underneath all of it: **no OpenTelemetry package is installed in this
environment, and everything above works anyway.** ``test_no_opentelemetry_package_is_installed``
asserts that rather than leaving it to luck — the failure mode is a suite that quietly acquires the
optional extra and stops testing the path most customers are on.
"""
from __future__ import annotations

import importlib.util
import os

import pytest

from test_bridge import FakeSpan, bridge, genai_llm_span, llm_span, usage_events  # noqa: F401

DEVTOOLS_PRICING = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "nexus-devtools", "nexus_devtools", "pricing.py")


# --------------------------------------------------------------------------------------------
# Zero required runtime dependencies
# --------------------------------------------------------------------------------------------

def test_no_opentelemetry_package_is_installed():
    """The premise of every other test in this file.

    If someone adds ``opentelemetry`` to the dev environment, the bridge starts being exercised
    only in the configuration where the extra is present — and the absent-extra path, which is the
    default install, stops being tested at the moment it stops working.
    """
    assert importlib.util.find_spec("opentelemetry") is None, (
        "the [otel] extra leaked into the test environment; the zero-dependency path is no longer "
        "being tested")


def test_bridge_is_fully_functional_without_the_extra(bridge, collector, sdk):
    from nexus import otel
    assert otel.available() is False
    assert otel.install() is False, "attach must decline, not raise, with no OTel installed"

    span = llm_span(input_tokens=10, output_tokens=2)
    bridge.on_start(span)
    bridge.on_end(span)
    assert len(usage_events(collector, sdk)) == 1


def test_span_processor_raises_a_named_error_rather_than_importerror():
    """``MissingOTel`` names the fix. A bare ``ModuleNotFoundError: opentelemetry.sdk.trace`` sends
    the reader to the wrong package."""
    from nexus.otel import processor
    assert processor.available() is False
    with pytest.raises(processor.MissingOTel) as exc:
        processor.span_processor()
    assert "nexus-sdk[otel]" in str(exc.value)


def test_otel_package_is_never_imported_at_module_scope():
    """A module-level ``from opentelemetry... import`` in any bridge module would make
    ``import nexus`` fail on a machine without the extra — which is most of them."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "nexus"
    offenders = []
    for path in list((root / "otel").glob("*.py")) + list((root / "integrations").glob("*.py")):
        for i, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("import opentelemetry", "from opentelemetry")):
                if not line.startswith((" ", "\t")):     # indented == inside a function
                    offenders.append(f"{path.name}:{i}")
    assert offenders == [], f"top-level opentelemetry import: {offenders}"


def test_flush_and_install_never_raise_on_the_automatic_path(monkeypatch):
    """``auto.install`` calls these and must not care about the answer."""
    from nexus import otel
    monkeypatch.setattr(otel, "bridge", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert otel.flush("shutdown") == 0


# --------------------------------------------------------------------------------------------
# Three vocabularies, one shape
# --------------------------------------------------------------------------------------------

def test_semconv_version_is_pinned_and_marked_pre_stable():
    """v1.42.0 is a moving target: content capture moved to ``gen_ai.input.messages`` /
    ``gen_ai.output.messages`` and ``gen_ai.system`` became ``gen_ai.provider.name``. Pinning the
    version in a constant is what makes the next drift a decision rather than a surprise."""
    from nexus.otel import semconv
    assert semconv.GENAI_SEMCONV_VERSION == "1.42.0"
    assert semconv.GENAI_SEMCONV_STABILITY == "pre-stable"


@pytest.mark.parametrize("attrs,vocab", [
    ({"gen_ai.operation.name": "chat", "gen_ai.provider.name": "anthropic",
      "gen_ai.response.model": "claude-sonnet-4-5",
      "gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 34}, "genai"),
    # The pre-1.36 spelling, still what most shipped instrumentations emit.
    ({"gen_ai.operation.name": "chat", "gen_ai.system": "anthropic",
      "gen_ai.request.model": "claude-sonnet-4-5",
      "gen_ai.usage.prompt_tokens": 120, "gen_ai.usage.completion_tokens": 34}, "genai"),
    ({"openinference.span.kind": "LLM", "llm.provider": "anthropic",
      "llm.model_name": "claude-sonnet-4-5",
      "llm.token_count.prompt": 120, "llm.token_count.completion": 34}, "openinference"),
    ({"traceloop.span.kind": "llm", "gen_ai.system": "anthropic",
      "gen_ai.response.model": "claude-sonnet-4-5",
      "gen_ai.usage.prompt_tokens": 120, "gen_ai.usage.completion_tokens": 34}, "openllmetry"),
])
def test_every_vocabulary_normalises_to_the_same_facts(attrs, vocab):
    """A customer's cost must not depend on which instrumentation they happened to install."""
    from nexus.otel.semconv import KIND_LLM, normalise
    f = normalise(FakeSpan("chat", attrs))
    assert f.kind == KIND_LLM
    assert f.provider == "anthropic"
    assert f.model == "claude-sonnet-4-5"
    assert f.input_tokens == 120
    assert f.output_tokens == 34
    assert f.vocabulary == vocab
    assert f.is_genai is True


def test_superseded_attribute_spellings_are_still_read():
    """Reading a superseded key costs one dict lookup. Failing to read one costs a customer's token
    counts for as long as it takes somebody to notice a number went quietly to zero."""
    from nexus.otel.semconv import normalise
    f = normalise(FakeSpan("chat", {"gen_ai.system": "openai",
                                    "gen_ai.usage.prompt_tokens": 7,
                                    "gen_ai.response.model": "gpt-4o"}))
    assert f.provider == "openai" and f.input_tokens == 7


def test_usage_on_an_unlabelled_span_is_not_thrown_away():
    """Several shipped instrumentations emit usage on a span with no kind attribute at all.
    Dropping those would mean losing exactly the numbers this bridge exists to record."""
    from nexus.otel.semconv import KIND_LLM, normalise
    f = normalise(FakeSpan("anthropic.create", {"gen_ai.usage.input_tokens": 42,
                                                "gen_ai.response.model": "claude-opus-4-5"}))
    assert f.kind == KIND_LLM and f.input_tokens == 42


def test_content_attributes_are_flattened_and_bounded():
    """``gen_ai.output.messages`` is structured; ``output.value`` may be anything. An unbounded
    ``str()`` of a conversation history would put the whole transcript in memory on a request
    path."""
    from nexus.otel.semconv import normalise
    f = normalise(FakeSpan("chat", {
        "openinference.span.kind": "LLM",
        "gen_ai.output.messages": [{"content": "hello"}, {"content": "world"}],
    }))
    assert "hello" in f.output_text and "world" in f.output_text
    big = normalise(FakeSpan("chat", {"openinference.span.kind": "LLM",
                                      "output.value": "x" * 100_000}))
    assert len(big.output_text) <= 20_000


def test_a_span_object_that_raises_is_absorbed():
    """The SDK never raises into the host application. A span whose attribute access explodes is a
    broken instrumentation, not our licence to break the request."""
    from nexus.otel.semconv import normalise

    class Hostile:
        @property
        def attributes(self):
            raise RuntimeError("nope")

        @property
        def name(self):
            raise RuntimeError("nope")

    f = normalise(Hostile())
    assert f.is_genai is False


# --------------------------------------------------------------------------------------------
# The epistemic-class invariant
# --------------------------------------------------------------------------------------------

def test_every_emitted_event_carries_a_valid_epistemic_class(bridge, collector, sdk, monkeypatch):
    """The invariant, asserted over everything the bridge can emit rather than per builder."""
    from nexus.otel.classify import VALID_CLASSES

    monkeypatch.setenv("NEXUS_TIER", "full")
    parent = llm_span(input_tokens=10, output_tokens=5, extra={
        "gen_ai.output.messages": "the answer is 4",
        "gen_ai.output.reasoning": "I considered several options",
    })
    tool = FakeSpan("search", {"openinference.span.kind": "TOOL", "tool.name": "search"},
                    parent=parent, scope="openinference.langchain")
    bridge.on_start(parent)
    bridge.on_start(tool)
    bridge.on_end(tool)
    bridge.on_end(parent)
    sdk.flush(2.0)

    assert collector.events, "nothing was emitted; this test would pass vacuously"
    for ev in collector.events:
        assert ev.get("epistemic_class") in VALID_CLASSES, ev


def test_model_output_and_reasoning_get_different_classes(bridge, collector, sdk, monkeypatch):
    """Folding a reasoning trace into the completion would launder a claim into the record beside
    the answer it is supposed to justify."""
    monkeypatch.setenv("NEXUS_TIER", "full")
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    span = llm_span(input_tokens=10, output_tokens=5, extra={
        "gen_ai.output.messages": "the answer is 4",
        "gen_ai.output.reasoning": "first I checked the arithmetic",
    })
    from nexus.client import get_client
    from nexus.otel.bridge import Bridge
    b = Bridge(get_client(), strict=True)
    b.on_start(span)
    b.on_end(span)
    sdk.flush(2.0)

    answer = collector.of_type("model_response")
    thinking = collector.of_type("model_thinking")
    assert len(answer) == 1 and answer[0]["epistemic_class"] == "interaction_narrative"
    assert len(thinking) == 1 and thinking[0]["epistemic_class"] == "rationalisation"
    # Token accounting is measured, not asserted — the one class admissible as evidence.
    assert collector.of_type("token_usage")[0]["epistemic_class"] == "behavior_trace"


def test_an_unclassified_genai_span_raises_in_strict_mode(bridge):
    """A new span kind must fail a build rather than quietly thin the ledger in production six
    months later."""
    from nexus.otel.classify import UnclassifiedSpan
    span = FakeSpan("mystery", {"gen_ai.operation.name": "teleport",
                                "gen_ai.provider.name": "anthropic"},
                    scope="opentelemetry.instrumentation.future")
    with pytest.raises(UnclassifiedSpan):
        bridge.on_start(span)


def test_an_unclassified_genai_span_is_dropped_and_counted_in_production(collector, sdk):
    """Runtime behaviour is the opposite of test behaviour on purpose. Defaulting to
    ``behavior_trace`` would put unverified content into the class the product sells as evidence;
    dropping without counting would turn a coverage gap into an invisible one."""
    from nexus import _counters
    from nexus.client import get_client
    from nexus.otel.bridge import Bridge

    b = Bridge(get_client(), strict=False)
    span = FakeSpan("mystery", {"gen_ai.operation.name": "teleport",
                                "gen_ai.provider.name": "anthropic"},
                    scope="opentelemetry.instrumentation.future")
    b.on_start(span)
    b.on_end(span)
    sdk.flush(2.0)
    assert _counters.get("bridge_unclassified") > 0
    assert usage_events(collector, sdk) == []


def test_the_class_table_covers_every_known_kind():
    """A kind added to ``semconv`` without a class in ``classify`` is a silent coverage hole; this
    is the test that turns it into a red build at the moment the constant is added."""
    from nexus.otel.classify import VALID_CLASSES, _SPAN_CLASS
    from nexus.otel.semconv import KNOWN_KINDS
    missing = sorted(KNOWN_KINDS - set(_SPAN_CLASS))
    assert missing == [], f"span kinds with no epistemic class: {missing}"
    assert set(_SPAN_CLASS.values()) <= VALID_CLASSES


def test_a_payload_without_a_declared_class_raises():
    from nexus.otel.classify import UnclassifiedSpan, classify_payload
    with pytest.raises(UnclassifiedSpan):
        classify_payload("something_new")


def test_coverage_gap_is_distinguishable_from_not_our_span():
    """Two different ``None`` results that must never be conflated: a DB span is not a coverage
    gap, and counting it as one makes the gap metric useless in the services that have the most
    spans."""
    from nexus.otel.classify import is_coverage_gap, is_ours
    from nexus.otel.semconv import normalise
    db = normalise(FakeSpan("SELECT", {"db.system": "postgresql"}))
    gap = normalise(FakeSpan("?", {"gen_ai.operation.name": "teleport"}))
    assert is_ours(db) is False and is_coverage_gap(db) is False
    assert is_ours(gap) is True and is_coverage_gap(gap) is True


# --------------------------------------------------------------------------------------------
# The privacy tier, re-applied on ingest
# --------------------------------------------------------------------------------------------

def _emit_with_tier(tier, collector, monkeypatch, text, *, reasoning=None):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_TIER", tier)
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    from nexus.client import get_client
    from nexus.otel.bridge import Bridge
    extra = {"gen_ai.output.messages": text}
    if reasoning:
        extra["gen_ai.output.reasoning"] = reasoning
    span = llm_span(input_tokens=10, output_tokens=5, extra=extra)
    b = Bridge(get_client(), strict=True)
    b.on_start(span)
    b.on_end(span)
    nexus.flush(2.0)
    return collector.of_type("model_response")


def test_tier_metadata_only_transmits_no_free_text(collector, monkeypatch):
    """T0 is the default, and the default must be the safe one. Shape and a one-way fingerprint
    leave the process; the content key is *absent* rather than blanked, so a reader can tell "not
    captured" from "captured empty"."""
    secret = "the launch code is hunter2"
    evs = _emit_with_tier("metadata_only", collector, monkeypatch, secret)
    assert len(evs) == 1
    ev = evs[0]
    assert ev.get("answer") is None
    assert ev["answer_chars"] == len(secret)
    assert ev["answer_fingerprint"]
    blob = repr(ev)
    assert "hunter2" not in blob and "launch code" not in blob


def test_tier_hashed_transmits_a_redacted_truncated_preview(collector, monkeypatch):
    text = "x" * 900 + " sk-ant-api03-DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    evs = _emit_with_tier("hashed", collector, monkeypatch, text)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["truncated"] is True
    assert len(ev["answer"]) <= 280
    assert "sk-ant-api03-DEADBEEF" not in repr(ev)


def test_tier_full_is_still_redacted(collector, monkeypatch):
    """A tier is a decision about *content*. It is never a waiver on credentials — and upstream
    redaction is not trusted to have made that distinction, or to exist at all."""
    evs = _emit_with_tier("full", collector, monkeypatch,
                          "here is my key sk-ant-api03-DEADBEEFDEADBEEFDEADBEEFDEADBEEF ok")
    assert len(evs) == 1
    ev = evs[0]
    assert "sk-ant-api03-DEADBEEFDEADBEEFDEADBEEFDEADBEEF" not in repr(ev)
    assert ev["redacted"] is True
    assert "here is my key" in ev["answer"]


def test_upstream_content_capture_does_not_override_our_tier(collector, monkeypatch):
    """The failure this guards: an instrumentation whose own capture switch is on, feeding us text
    a customer at T0 explicitly chose not to transmit. Whether content leaves this process is our
    boundary decision, so it is re-decided here rather than inherited."""
    evs = _emit_with_tier("metadata_only", collector, monkeypatch,
                          "OPENINFERENCE_HIDE_OUTPUTS was false and this leaked out")
    assert evs and evs[0].get("answer") is None


def test_reasoning_text_goes_through_the_same_gate(collector, monkeypatch):
    """Reasoning traces are where a model repeats back the sensitive parts of its input verbatim,
    so a gate that covered completions only would leak precisely the worst field."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    _emit_with_tier("metadata_only", collector, monkeypatch, "answer",
                    reasoning="the customer's card is 4111 1111 1111 1111")
    thinking = collector.of_type("model_thinking")
    assert len(thinking) == 1
    assert thinking[0].get("thinking") is None
    assert "4111" not in repr(thinking[0])


def test_tool_parameters_are_not_a_target_at_all(bridge, collector, sdk):
    """``tool.parameters`` is not gated free text, it is content that never becomes a field.

    This test used to assert that the same value arrived tier-gated, and it passed against code
    that shipped model arguments verbatim at the default tier. It passed on an accident: the only
    rule in ``redact`` that fires on this string is the ``key=value`` one, and the canary was
    written as ``token=s3cret``. Swap the query string for a sentence and the old assertion goes
    green while the whole argument list goes out on the wire. What replaced it is a claim the
    canary cannot fake — ``tool.parameters`` produces no ``target`` and no ``target_fingerprint``,
    because it is not a target — plus a shape that says what was actually observed.
    """
    tool = FakeSpan("http_get", {"openinference.span.kind": "TOOL", "tool.name": "http_get",
                                 "tool.parameters": "https://internal.example/?token=s3cret"},
                    scope="openinference.langchain")
    bridge.on_start(tool)
    bridge.on_end(tool)
    sdk.flush(2.0)
    actions = collector.of_type("tool_action")
    assert len(actions) == 1
    ev = actions[0]
    assert "s3cret" not in repr(ev)
    assert "internal.example" not in repr(ev)
    assert "target" not in ev and "target_fingerprint" not in ev
    assert ev["effect"]["arg_shape"] == {"type": "string", "chars": 38}


def test_a_tool_call_id_is_still_a_target_and_is_still_gated(bridge, collector, sdk):
    """The other half: dropping payloads from ``target`` must not empty the field of its real use.

    A call id is what a target is for, it survives the reader, and it still meets the tier gate on
    the way out — at T0 as shape and fingerprint, which is what makes repeated calls groupable.
    """
    tool = FakeSpan("http_get", {"openinference.span.kind": "TOOL", "tool.name": "http_get",
                                 "gen_ai.tool.call.id": "call_01H8XQ7"},
                    scope="openinference.langchain")
    bridge.on_start(tool)
    bridge.on_end(tool)
    sdk.flush(2.0)
    actions = collector.of_type("tool_action")
    assert len(actions) == 1
    assert actions[0]["target_fingerprint"]
    assert actions[0]["target_chars"] == len("call_01H8XQ7")


# --------------------------------------------------------------------------------------------
# Exact cost
# --------------------------------------------------------------------------------------------

def test_cost_is_computed_from_the_usage_breakdown_with_the_cache_split(bridge, collector, sdk):
    """Hand-computed, on purpose. Cached input is 10× cheaper and a 5-minute cache write is 1.25×
    dearer, so a bridge that folds cache tokens into ``input_tokens`` is not imprecise — it is
    wrong by multiples on exactly the cache-heavy traffic agents generate (case 2.16).
    """
    span = llm_span("claude-sonnet-4-5", input_tokens=1_000_000, output_tokens=1_000_000,
                    cache_read=1_000_000, cache_write=1_000_000)
    bridge.on_start(span)
    bridge.on_end(span)
    ev = usage_events(collector, sdk)[0]

    expected = 3.0 + 15.0 + (3.0 * 0.10) + (3.0 * 1.25)     # in + out + cache read + 5m write
    assert ev["cost_usd"] == pytest.approx(expected, rel=1e-9)
    assert ev["cost_source"] == "usage"
    assert ev["cache_read_tokens"] == 1_000_000
    assert ev["cache_write_tokens"] == 1_000_000


def test_cost_matches_devtools_pricing():
    """The parity test the mirrored rate card depends on.

    ``src/nexus/integrations/pricing.py`` is a deliberate copy: the SDK is Apache-2.0 and
    zero-dependency, so it cannot import the proprietary devtools package. A copy without a test is
    a copy that drifts, and cost drift between the wrapper and the SDK would show up as two
    different dollar figures for the same call in one ledger.
    """
    if not os.path.exists(DEVTOOLS_PRICING):
        pytest.skip("nexus-devtools not checked out beside this repo")
    spec = importlib.util.spec_from_file_location("_devtools_pricing", DEVTOOLS_PRICING)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)

    from nexus.integrations import pricing

    assert pricing._RATES == ref._RATES, "rate cards have diverged"
    assert (pricing._CACHE_WRITE_5M, pricing._CACHE_WRITE_1H, pricing._CACHE_READ) == \
           (ref._CACHE_WRITE_5M, ref._CACHE_WRITE_1H, ref._CACHE_READ)

    cases = [
        {"input_tokens": 1000, "output_tokens": 200},
        {"input_tokens": 0, "output_tokens": 0},
        {"input_tokens": 1234, "output_tokens": 99, "cache_read_input_tokens": 5000},
        {"input_tokens": 10, "output_tokens": 1, "cache_creation_input_tokens": 4096},
        {"input_tokens": 10, "output_tokens": 1,
         "cache_creation": {"ephemeral_5m_input_tokens": 2048, "ephemeral_1h_input_tokens": 512}},
    ]
    models = ["claude-sonnet-4-5", "claude-opus-4-1", "claude-3-5-haiku-20241022",
              "us.anthropic.claude-sonnet-4-5-v1:0", "something-unpriced"]
    for model in models:
        assert pricing.normalize(model) == ref.normalize(model), model
        assert pricing.rates(model) == ref.rates(model), model
        for usage in cases:
            assert pricing.cost_from_usage(model, usage) == ref.cost_from_usage(model, usage), \
                (model, usage)


def test_a_provider_reported_cost_wins_and_says_so(bridge, collector, sdk):
    """A figure the provider reported is evidence; ours is arithmetic. Both belong in the ledger,
    and which one a row holds has to be legible from the row."""
    span = llm_span(input_tokens=1000, output_tokens=100, extra={"gen_ai.usage.cost": 0.0425})
    bridge.on_start(span)
    bridge.on_end(span)
    ev = usage_events(collector, sdk)[0]
    assert ev["cost_usd"] == pytest.approx(0.0425)
    assert ev["cost_source"] == "provider"


def test_an_unpriced_model_reports_no_cost_rather_than_a_guess(bridge, collector, sdk):
    """A flat per-token estimate is worse than a blank: it is a number that looks reconcilable and
    is not, and nobody re-checks a populated column."""
    span = llm_span("some-new-model-nobody-has-priced", input_tokens=1000, output_tokens=100)
    bridge.on_start(span)
    bridge.on_end(span)
    ev = usage_events(collector, sdk)[0]
    assert "cost_usd" not in ev and "cost_source" not in ev
    assert ev["input_tokens"] == 1000, "usage is still recorded; only the dollars are unknown"


def test_the_one_hour_cache_write_is_priced_and_preserved(bridge, collector, sdk):
    """A 1-hour cache write is 2× input, not 1.25×. The two are indistinguishable once summed, so
    the split is carried through as structure alongside the aggregate the contract holds."""
    span = llm_span("claude-sonnet-4-5", input_tokens=0, output_tokens=0, extra={
        "gen_ai.usage.cache_creation_1h_tokens": 1_000_000,
    })
    bridge.on_start(span)
    bridge.on_end(span)
    ev = usage_events(collector, sdk)[0]
    assert ev["cost_usd"] == pytest.approx(3.0 * 2.0, rel=1e-9)
    assert ev["bridge"]["cache_write_1h_tokens"] == 1_000_000


def test_model_ids_are_normalised_before_pricing():
    """Bedrock and Vertex decorate the id with a region, a version suffix and a provider prefix.
    Failing to peel them is not a missing feature, it is a silently unpriced call."""
    from nexus.integrations import pricing
    for decorated in ("us.anthropic.claude-sonnet-4-5-v1:0",
                      "anthropic/claude-sonnet-4-5",
                      "claude-sonnet-4-5-20250929"):
        assert pricing.rates(decorated) == (3.0, 15.0), decorated


def test_cost_never_raises_on_hostile_usage():
    from nexus.integrations import pricing
    assert pricing.cost_from_usage("claude-sonnet-4-5", {"input_tokens": "many"}) is not None
    assert pricing.cost_from_usage("claude-sonnet-4-5", {"cache_creation": "nope"}) is not None
    assert pricing.cost_from_usage(None, {}) is None
