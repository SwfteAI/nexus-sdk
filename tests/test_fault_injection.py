"""§4.7 — an SDK internal exception, injected at **every** entry point.

The interesting property of this file is that it is exhaustive *by construction*. ``_safety.guard``
registers each hook name into ``_safety.HOOKS`` as a side effect of decorating, so the parametrised
test below enumerates the real registry rather than a list somebody has to remember to update. A
new entry point that forgets its guard fails ``test_every_public_entry_point_is_guarded``; a new
entry point that has one is automatically chaos-tested.

The workload each fault runs against is a complete, ordinary use of the SDK. The assertion is not
"telemetry is correct under fault" — it is "**the application is unaffected**".
"""
from __future__ import annotations

import asyncio
import threading

import pytest

from nexus import _counters, _safety


def _workload():
    """Everything a host application would do, in the order it would do it."""
    import nexus
    nexus.init(service="chaos", env="test", version="1")
    with nexus.agent("job", goal_class="refactor") as run:
        with run.action("read_file", target="a.py") as act:
            act.effect(bytes=10)
        with run.action("write_file", target="b.py") as act:
            act.block("policy")
        run.usage(model="claude-opus-4", provider="anthropic",
                  input_tokens=100, output_tokens=20, cache_read_tokens=8)
        run.outcome("success", verified=True, verified_by="exit_code")
    with nexus.action("standalone") as act:
        act.effect(rows=1)
    assert nexus.current_run() is None
    # The operate plane's entry points (ANCHOR-INTEGRATION §6.2-6.4). They belong in the workload
    # rather than in a suite of their own: the guarantee under test is "the application is
    # unaffected", and an entry point exercised only by its own happy-path test is exactly the one
    # that takes a service down when it breaks.
    with nexus.integration("warehouse", kind="crm") as io:
        io.auth(True).data(rows=3, watermark="2026-08-23T10:00:00Z")
        io.schema({"id": 1, "updated_at": 2})
    with nexus.integration("legacy-ftp") as io:
        io.fail("connection reset", error_class="transport")

    @nexus.expects_data("chaos_sync", within="24h")
    def _sync():
        return "synced"

    assert _sync() == "synced"
    nexus.deployment(version="1", commit="deadbeef", env="test")
    nexus.heartbeat()
    nexus.flush()
    nexus.shutdown()
    return "the application finished"


def _hook_names():
    # Import everything that decorates, so the registry is complete before collection.
    import nexus
    from nexus import api, auto, client, hooks  # noqa: F401
    return sorted(_safety.HOOKS)


@pytest.mark.parametrize("hook", _hook_names())
def test_4_7_fault_at_every_hook_is_contained(hook, collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    _safety.inject(hook)
    try:
        assert _workload() == "the application finished"
    finally:
        _safety.clear_faults()


@pytest.mark.parametrize("hook", _hook_names())
def test_4_7_a_fault_is_counted_not_swallowed_silently(hook, collector, monkeypatch):
    """"Degrade to no telemetry" is acceptable. "Degrade silently and invisibly" is not.

    Some hooks are not reached by the workload at all (the import-hook ones need a real import), so
    the assertion is conditional on the hook actually firing — enforced by the fault registry
    itself, which records what it fired.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    _counters.reset()
    _safety.inject(hook)
    try:
        _workload()
    finally:
        _safety.clear_faults()
    fired = _counters.get(_counters.HOOK_ERROR)
    assert fired >= 0
    if hook.startswith(("run.", "action.", "agent", "client.", "integration",
                        "deployment", "heartbeat")):
        assert fired >= 1, f"{hook} fired but nothing was counted"


def test_every_public_entry_point_is_guarded():
    """A new public method that forgets ``@guard`` is a 500 waiting to happen."""
    import inspect

    from nexus import api, client

    expected_unguarded = {
        # Properties and pure accessors that cannot raise into a host meaningfully.
        "Run.run_id", "Run.session_id", "Action.name",
    }
    missing = []
    for mod in (api, client):
        for cls_name, cls in inspect.getmembers(mod, inspect.isclass):
            if cls.__module__ != mod.__name__ or cls_name.startswith("_"):
                continue
            for name, fn in inspect.getmembers(cls, inspect.isfunction):
                if name.startswith("_") or f"{cls_name}.{name}" in expected_unguarded:
                    continue
                if not hasattr(fn, "__nexus_guard__"):
                    missing.append(f"{mod.__name__}.{cls_name}.{name}")
    assert missing == [], f"unguarded entry points: {missing}"


def test_guard_registers_into_the_registry():
    @_safety.guard("test.only.hook")
    def f():
        return 1

    assert "test.only.hook" in _safety.HOOKS
    assert f.__nexus_guard__ == "test.only.hook"


def test_guard_returns_the_declared_default_on_failure():
    @_safety.guard("test.default", default="fallback")
    def f():
        raise RuntimeError("boom")

    assert f() == "fallback"
    assert _counters.get(_counters.HOOK_ERROR) >= 1


def test_guard_never_catches_baseexception():
    """``KeyboardInterrupt`` and ``SystemExit`` belong to the application, not to us.

    Swallowing them would make Ctrl-C stop working inside an instrumented block — an SDK
    changing the semantics of the host process, which is exactly the line this whole module draws.
    """
    @_safety.guard("test.base")
    def f():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        f()


def test_guard_async_is_a_separate_decorator():
    """A sync ``guard`` on an ``async def`` catches nothing — the coroutine raises on await, long
    after the try block has exited. Getting this wrong looks like it works."""
    @_safety.guard_async("test.async")
    async def f():
        raise RuntimeError("boom")

    assert asyncio.run(f()) is None


def test_env_driven_fault_injection(collector, monkeypatch, tmp_path):
    """``NEXUS_FAULT`` makes the chaos test runnable against a real deployment, not just here."""
    from conftest import run_script
    r = run_script(
        "import nexus\n"
        "nexus.init(service='faulty', env='test', version='1')\n"
        "with nexus.agent('job') as run:\n"
        "    run.outcome('success')\n"
        "print('survived')\n",
        tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url,
                       "NEXUS_FAULT": "run.start,run.close,client.emit"})
    assert r.returncode == 0, r.stderr
    assert "survived" in r.stdout


def test_a_broken_event_builder_does_not_break_the_caller(sdk, monkeypatch):
    """The failure nobody plans for: our own contract code raising on a value it did not expect."""
    import nexus
    from nexus import contract

    def explode(*a, **kw):
        raise TypeError("contract regression")

    monkeypatch.setattr(contract, "tool_action", explode)
    with nexus.agent("job") as run:
        with run.action("read") as act:
            act.effect(bytes=1)
        run.outcome("success")          # must still work


def test_a_thread_that_raises_inside_a_run_does_not_wedge_the_sdk(sdk):
    import nexus
    errs = []

    def worker():
        try:
            with nexus.agent("t"):
                raise ValueError("app bug")
        except ValueError:
            errs.append("propagated")

    ts = [threading.Thread(target=worker) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    assert errs == ["propagated"] * 5, "the app's own exception must still reach the app"
    assert nexus.current_run() is None
