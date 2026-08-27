"""The span → event bridge, exercised without OpenTelemetry installed.

That absence is the point of the test double below rather than an inconvenience worked around.
Zero required runtime dependencies is a core-ring rule, and the way it decays is that a test suite
quietly installs the optional extra, every code path is then exercised with it present, and the
first customer without it finds the import error. ``FakeSpan`` is shaped like an OTel
``ReadableSpan`` — ``.attributes``, ``.context``, ``.parent``, ``.start_time``/``.end_time`` in
nanoseconds, ``.instrumentation_scope`` — because the bridge reads spans structurally and therefore
cannot tell the difference. ``test_providers.py`` asserts the absence itself.

Case coverage lives in the test names: 2.6, 2.8, 2.12, 2.14, 2.19.
"""
from __future__ import annotations

import gc
import itertools
import typing as t

import pytest

# --------------------------------------------------------------------------------------------
# Span test double
# --------------------------------------------------------------------------------------------

_ids = itertools.count(1)


class _Ctx:
    def __init__(self, trace_id: int, span_id: int) -> None:
        self.trace_id = trace_id
        self.span_id = span_id


class _Scope:
    def __init__(self, name: str) -> None:
        self.name = name


class _Status:
    def __init__(self, code: str = "OK", description: str = "") -> None:
        self.status_code = type("C", (), {"name": code})()
        self.description = description


class FakeSpan:
    """Duck-typed ``ReadableSpan``. Mutable so a test can set usage attributes at end time, which
    is exactly what a real streaming instrumentation does."""

    def __init__(self, name: str, attributes: dict, *, trace_id: int = 0xABC,
                 parent: "FakeSpan | None" = None, scope: str = "test.instrumentation",
                 duration_ms: int = 12, error: str | None = None) -> None:
        self.name = name
        self.attributes = dict(attributes)
        self.context = _Ctx(trace_id, next(_ids))
        self.parent = parent.context if parent is not None else None
        self.instrumentation_scope = _Scope(scope)
        self.start_time = 1_000_000_000
        self.end_time = self.start_time + duration_ms * 1_000_000
        self.status = _Status("ERROR", error) if error else _Status()


def llm_span(model="claude-sonnet-4-5", *, input_tokens=100, output_tokens=50,
             cache_read=None, cache_write=None, scope="openinference.anthropic",
             parent=None, trace_id=0xABC, extra: dict | None = None, **kw) -> FakeSpan:
    attrs = {
        "openinference.span.kind": "LLM",
        "llm.provider": "anthropic",
        "llm.model_name": model,
        "llm.token_count.prompt": input_tokens,
        "llm.token_count.completion": output_tokens,
    }
    if cache_read is not None:
        attrs["llm.token_count.prompt_details.cache_read"] = cache_read
    if cache_write is not None:
        attrs["llm.token_count.prompt_details.cache_write"] = cache_write
    attrs.update(extra or {})
    return FakeSpan("ChatAnthropic", attrs, scope=scope, parent=parent, trace_id=trace_id, **kw)


def genai_llm_span(model="claude-opus-4-5", *, input_tokens=10, output_tokens=5,
                   parent=None, scope="opentelemetry.instrumentation.anthropic",
                   trace_id=0xABC, extra: dict | None = None) -> FakeSpan:
    """The v1.42.0 spelling, to prove both vocabularies land in the same shape."""
    attrs = {
        "gen_ai.operation.name": "chat",
        "gen_ai.provider.name": "anthropic",
        "gen_ai.response.model": model,
        "gen_ai.usage.input_tokens": input_tokens,
        "gen_ai.usage.output_tokens": output_tokens,
    }
    attrs.update(extra or {})
    return FakeSpan("chat anthropic", attrs, scope=scope, parent=parent, trace_id=trace_id)


@pytest.fixture
def bridge(sdk):
    """A strict bridge bound to the initialised client from ``conftest``'s ``sdk`` fixture."""
    from nexus.client import get_client
    from nexus.otel.bridge import Bridge, _reset_for_tests
    b = Bridge(get_client(), strict=True)
    try:
        yield b
    finally:
        _reset_for_tests()


def usage_events(collector, sdk) -> list[dict]:
    sdk.flush(2.0)
    return [e for e in collector.of_type("token_usage") if e.get("bridge")]


# --------------------------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------------------------

def test_one_span_produces_one_usage_record(bridge, collector, sdk):
    span = llm_span(input_tokens=1000, output_tokens=200)
    bridge.on_start(span)
    bridge.on_end(span)
    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    e = evs[0]
    assert e["model"] == "claude-sonnet-4-5"
    assert e["provider"] == "anthropic"
    assert e["input_tokens"] == 1000 and e["output_tokens"] == 200
    assert e["epistemic_class"] == "behavior_trace"
    assert e["producer"] == "sdk"


def test_genai_and_openinference_vocabularies_agree(bridge, collector, sdk):
    """Two conventions, one shape. If they diverged, a customer's cost would depend on which
    instrumentation they happened to install."""
    from nexus.otel.semconv import normalise
    a = normalise(llm_span("claude-opus-4-5", input_tokens=7, output_tokens=3))
    b = normalise(genai_llm_span("claude-opus-4-5", input_tokens=7, output_tokens=3))
    for field in ("kind", "provider", "model", "input_tokens", "output_tokens"):
        assert getattr(a, field) == getattr(b, field), field


# --------------------------------------------------------------------------------------------
# 2.12 — abandoned streams
# --------------------------------------------------------------------------------------------

def test_2_12_span_never_ended_is_flushed_as_incomplete(bridge, collector, sdk):
    span = llm_span(input_tokens=500, output_tokens=0)
    bridge.on_start(span)
    assert bridge.flush_open("test") == 1
    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    assert evs[0]["incomplete"] is True
    assert evs[0]["bridge"]["incomplete_reason"] == "test"


def test_2_12_span_garbage_collected_without_ending_still_emits(bridge, collector, sdk):
    """The stream nobody closed. A finalizer is the only hook that fires."""
    span = llm_span(input_tokens=300, output_tokens=12)
    bridge.on_start(span)
    del span
    gc.collect()
    evs = usage_events(collector, sdk)
    assert len(evs) == 1
    assert evs[0]["incomplete"] is True
    assert evs[0]["bridge"]["incomplete_reason"] == "span_gc"


def test_2_12_abandoned_generator_still_produces_a_record(collector, sdk):
    """A generator the caller stops consuming. No span exists here at all — this is the direct
    path an adapter uses, and the one where "read the totals at stream end" has no end to read."""
    from nexus.integrations.streams import StreamRecord, instrument_stream

    def chunks():
        for i in range(100):
            yield {"text": f"chunk-{i}", "usage": {"output_tokens": 1, "input_tokens": 400}}

    rec = StreamRecord(model="claude-sonnet-4-5", provider="anthropic")
    stream = instrument_stream(chunks(), rec, usage_of=lambda c: c.get("usage"))
    taken = [next(iter(stream)) for _ in range(3)]
    assert len(taken) == 3
    del stream
    gc.collect()

    sdk.flush(2.0)
    evs = [e for e in collector.of_type("token_usage") if e.get("bridge")]
    assert len(evs) == 1, "an abandoned stream must still produce exactly one record"
    assert evs[0]["incomplete"] is True
    assert evs[0]["output_tokens"] == 3, "only what was actually consumed"
    assert evs[0]["input_tokens"] == 400
    assert evs[0]["bridge"]["stream_chunks"] == 3


def test_2_12_exhausted_generator_is_not_marked_incomplete(collector, sdk):
    from nexus.integrations.streams import StreamRecord, instrument_stream

    rec = StreamRecord(model="claude-sonnet-4-5")
    out = list(instrument_stream(
        [{"usage": {"output_tokens": 2}}, {"usage": {"output_tokens": 3}}],
        rec, usage_of=lambda c: c.get("usage")))
    assert len(out) == 2
    sdk.flush(2.0)
    evs = [e for e in collector.of_type("token_usage") if e.get("bridge")]
    assert len(evs) == 1
    assert "incomplete" not in evs[0]
    assert evs[0]["output_tokens"] == 5


def test_2_12_stream_emits_exactly_once_across_every_exit(collector, sdk):
    """Close, then GC, then close again. Three exits, one record — the guarantee is "at most once",
    not "once per exit path"."""
    from nexus.integrations.streams import StreamRecord, instrument_stream

    rec = StreamRecord(model="claude-sonnet-4-5")
    stream = instrument_stream(iter([{"usage": {"output_tokens": 1}}]), rec,
                               usage_of=lambda c: c.get("usage"))
    next(stream)
    stream.close()
    stream.close()
    del stream
    gc.collect()
    sdk.flush(2.0)
    assert len([e for e in collector.of_type("token_usage") if e.get("bridge")]) == 1


def test_2_13_stream_error_records_what_was_seen_and_re_raises(collector, sdk):
    from nexus.integrations.streams import StreamRecord, instrument_stream

    def boom():
        yield {"usage": {"output_tokens": 4}}
        raise ValueError("upstream died")

    rec = StreamRecord(model="claude-sonnet-4-5")
    with pytest.raises(ValueError):
        list(instrument_stream(boom(), rec, usage_of=lambda c: c.get("usage")))
    sdk.flush(2.0)
    evs = [e for e in collector.of_type("token_usage") if e.get("bridge")]
    assert len(evs) == 1
    assert evs[0]["incomplete"] is True
    assert evs[0]["output_tokens"] == 4
    assert "ValueError" in evs[0]["bridge"]["error"]


# --------------------------------------------------------------------------------------------
# 2.19 — recursive instrumentation
# --------------------------------------------------------------------------------------------

def test_2_19_spans_describing_our_own_egress_are_dropped(bridge, collector, sdk):
    """The loop: our POST → their HTTP instrumentation makes a span → we ingest it → we emit → we
    POST. Unbounded, not slow. The span comes from *their* instrumentation and carries none of our
    names, so destination matching is the defence that actually catches it."""
    from nexus import _counters
    from nexus.client import get_client

    host = get_client().cfg.collector_url.split("//", 1)[1]
    egress = FakeSpan("POST /v1/events", {
        "gen_ai.operation.name": "chat",           # deliberately GenAI-shaped: worst case
        "gen_ai.provider.name": "anthropic",
        "gen_ai.usage.input_tokens": 5,
        "http.request.method": "POST",
        "url.full": f"http://{host}/v1/events",
    }, scope="opentelemetry.instrumentation.urllib")
    before = _counters.get("bridge_self_excluded")
    bridge.on_start(egress)
    bridge.on_end(egress)
    assert _counters.get("bridge_self_excluded") > before
    assert usage_events(collector, sdk) == []


def test_2_19_spans_from_our_own_modules_are_dropped(bridge, collector, sdk):
    span = llm_span(scope="nexus.transport")
    bridge.on_start(span)
    bridge.on_end(span)
    assert usage_events(collector, sdk) == []


def test_2_19_our_egress_modules_can_never_be_registered():
    from nexus.integrations import is_excluded, register
    for name in ("nexus", "nexus.transport", "nexus.transport.http", "nexus.otel.bridge",
                 "nexus.integrations.streams"):
        assert is_excluded(name), name
        with pytest.raises(ValueError):
            register(name, lambda m: None)
    assert not is_excluded("anthropic")
    assert not is_excluded("nexustastic")     # prefix match must respect the dot boundary


def test_2_19_reentrant_emit_terminates_instead_of_recursing(collector, sdk, monkeypatch):
    """The pathological case: an instrumentation whose span callback fires *from inside* our emit.

    Without the latch this is unbounded recursion that consumes the process. The assertion is
    termination and a bounded event count, not a nice error message.
    """
    from nexus.client import get_client
    from nexus.otel import bridge as bridge_mod
    from nexus import _counters

    client = get_client()
    b = bridge_mod.Bridge(client, strict=False)
    depth_seen = []
    real_emit = client.emit

    def reentrant_emit(event):
        from nexus.integrations import selfexclude
        depth_seen.append(selfexclude.depth())
        if len(depth_seen) < 50:
            # Exactly what an HTTP instrumentation on our egress path would do.
            b.ingest(llm_span("claude-sonnet-4-5", input_tokens=1, output_tokens=1,
                              scope="opentelemetry.instrumentation.urllib"))
        return real_emit(event)

    monkeypatch.setattr(client, "emit", reentrant_emit)
    b.ingest(llm_span("claude-sonnet-4-5", input_tokens=1, output_tokens=1))
    monkeypatch.undo()

    assert _counters.get("bridge_reentry_blocked") > 0
    assert len(depth_seen) <= 2, f"re-entry was not contained: {len(depth_seen)} emissions"
    assert selfexclude_depth_is_zero()


def selfexclude_depth_is_zero() -> bool:
    from nexus.integrations import selfexclude
    return selfexclude.depth() == 0


# --------------------------------------------------------------------------------------------
# Lifecycle / robustness
# --------------------------------------------------------------------------------------------

def test_non_genai_spans_are_ignored_silently(bridge, collector, sdk):
    """A database span is not a coverage gap. Counting it as one would make the gap metric useless
    in exactly the services that have the most spans."""
    from nexus import _counters
    span = FakeSpan("SELECT users", {"db.system": "postgresql", "db.statement": "SELECT 1"},
                    scope="opentelemetry.instrumentation.psycopg")
    before = _counters.get("bridge_unclassified")
    bridge.on_start(span)
    bridge.on_end(span)
    assert _counters.get("bridge_unclassified") == before
    assert _counters.get("bridge_spans_ignored") > 0
    assert usage_events(collector, sdk) == []


def test_span_ending_without_a_start_is_still_recorded(bridge, collector, sdk):
    """Exporter-shaped feeds and spans that began before we attached. An unattributed record beats
    a missing one."""
    span = llm_span(input_tokens=42, output_tokens=7)
    bridge.on_end(span)
    evs = usage_events(collector, sdk)
    assert len(evs) == 1 and evs[0]["input_tokens"] == 42


def test_malformed_span_does_not_raise(bridge):
    class Broken:
        @property
        def attributes(self):
            raise RuntimeError("no")

    bridge.on_start(Broken())      # strict bridge: normalise must absorb this itself
    bridge.on_end(Broken())


def test_open_span_tracking_is_bounded(bridge):
    """A trace that never ends must cost bounded memory. An SDK that turns a customer's span leak
    into our OOM has made their incident worse."""
    bridge.MAX_OPEN = 32
    for i in range(200):
        bridge.on_start(llm_span(input_tokens=1, output_tokens=1, trace_id=0x1000 + i))
    st = bridge.stats()
    assert st["open_spans"] <= 64
    assert st["open_calls"] <= 64, "evicting nodes but not calls leaks slowly, which is worse"
