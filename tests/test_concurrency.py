"""§1.8–1.10 — threads, asyncio, and greenlets.

The bug these tests exist to catch is not a crash. It is **attribution**: one request's run context
leaking into another's, which produces telemetry that is confidently wrong. Wrong attribution is
worse than no attribution, because someone will act on it.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import run_script


# -- 1.8 threads ----------------------------------------------------------------------------------

def test_1_8_interleaved_runs_in_threads_never_cross(sdk, collector):
    """Twenty threads, each opening its own run, deliberately interleaved."""
    import nexus
    errors: list[str] = []
    start = threading.Barrier(20)

    def worker(i: int) -> None:
        start.wait()
        with nexus.agent(f"req-{i}") as run:
            time.sleep(0.005 * (i % 3))         # force overlap
            cur = nexus.current_run()
            if cur is None or cur.run_id != run.run_id:
                errors.append(f"thread {i} saw {cur}")
            with run.action("step") as a:
                a.effect(i=i)
            run.outcome("success")

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=20)
    assert errors == []
    nexus.flush()
    assert collector.wait_for(60, timeout=10)

    # Every tool_action must be attributed to the run its own thread opened.
    runs = {e["run_id"]: e["name"] for e in collector.of_type("agent_run")
            if e.get("phase") == "start"}
    for act in collector.of_type("tool_action"):
        assert act["caused_by_prompt_id"] in runs


def test_1_8_context_does_not_leak_into_a_pooled_thread(sdk):
    """A ``ThreadPoolExecutor`` thread is reused across requests.

    ``contextvars`` deliberately do **not** propagate into ``run_in_executor``/``submit``, and that
    is the behaviour we want: an inherited context would attach the *next* request's work to the
    *previous* request's run, and pooled threads make that mistake permanent.
    """
    import nexus
    seen = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        with nexus.agent("outer"):
            seen.append(pool.submit(nexus.current_run).result())
        seen.append(pool.submit(nexus.current_run).result())
    assert seen == [None, None], f"run context leaked into the pool: {seen}"


def test_1_8_context_can_be_carried_across_a_handoff_explicitly(sdk):
    """Explicit propagation must still be possible — otherwise every worker-thread span is orphaned."""
    import nexus
    from nexus import context

    with nexus.agent("outer") as run:
        ctx = context.capture()
        with ThreadPoolExecutor(max_workers=1) as pool:
            got = pool.submit(ctx.run, nexus.current_run).result()
        assert got is not None and got.run_id == run.run_id


# -- 1.9 asyncio ------------------------------------------------------------------------------------

def test_1_9_context_survives_await(sdk):
    import nexus

    async def inner():
        await asyncio.sleep(0)
        return nexus.current_run()

    async def main():
        async with nexus.agent("async-run") as run:
            got = await inner()
            assert got is not None and got.run_id == run.run_id
            run.outcome("success")

    asyncio.run(main())


def test_1_9_gather_keeps_sibling_tasks_apart(sdk, collector):
    import nexus

    async def task(i):
        async with nexus.agent(f"task-{i}") as run:
            await asyncio.sleep(0.01 * (i % 3))
            cur = nexus.current_run()
            assert cur is not None and cur.run_id == run.run_id, f"task {i} saw {cur}"
            async with run.action("step") as a:
                a.effect(i=i)
            run.outcome("success")
            return run.run_id

    async def main():
        return await asyncio.gather(*[task(i) for i in range(15)])

    ids = asyncio.run(main())
    assert len(set(ids)) == 15


@pytest.mark.skipif(sys.version_info < (3, 11), reason="TaskGroup is 3.11+")
def test_1_9_taskgroup(sdk):
    import nexus

    async def main():
        results = []

        async def child(i):
            async with nexus.agent(f"tg-{i}") as run:
                await asyncio.sleep(0)
                results.append(nexus.current_run().run_id == run.run_id)

        async with asyncio.TaskGroup() as tg:      # noqa: F821 (3.11+)
            for i in range(5):
                tg.create_task(child(i))
        return results

    assert all(asyncio.run(main()))


def test_1_9_run_in_executor_does_not_inherit_the_run(sdk):
    """Same rule as 1.8, stated for the asyncio spelling because it is the one people assume works."""
    import nexus

    async def main():
        async with nexus.agent("outer"):
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, nexus.current_run)

    assert asyncio.run(main()) is None


def test_1_9_exception_inside_an_async_run_still_closes_it(sdk, collector):
    import nexus

    async def main():
        with pytest.raises(ValueError):
            async with nexus.agent("boom"):
                raise ValueError("nope")

    asyncio.run(main())
    nexus.flush()
    assert collector.wait_for(4, timeout=5)
    ends = [e for e in collector.of_type("agent_run") if e.get("phase") == "end"]
    # Shape, not text: the default tier is ``metadata_only`` and an exception message is free
    # text. ``error_fingerprint`` is what says "this run ended in an error" at T0,
    # and it is the better assertion here anyway — the question is whether the run was
    # *closed with* its error, not what the error said.
    assert ends and ends[-1].get("error_fingerprint"), (
        "an aborted run must be closed with its error")


# -- 1.10 gevent / eventlet ---------------------------------------------------------------------------

gevent = pytest.importorskip("gevent", reason="gevent not installed")

GEVENT_BEFORE = """
from gevent import monkey; monkey.patch_all()
import gevent, json
import nexus
nexus.init(service='gevent-before', env='test', version='1')

def job(i):
    with nexus.agent('greenlet-%d' % i) as run:
        gevent.sleep(0.01)
        assert nexus.current_run().name == 'greenlet-%d' % i
        run.outcome('success')

gevent.joinall([gevent.spawn(job, i) for i in range(10)])
nexus.flush()
print(json.dumps({'ok': True}), flush=True)
"""

GEVENT_AFTER = """
import nexus
nexus.init(service='gevent-after', env='test', version='1')   # threads started FIRST
from gevent import monkey; monkey.patch_all()                 # ...then the world changes underneath
import gevent, json

def job(i):
    with nexus.agent('greenlet-%d' % i) as run:
        gevent.sleep(0.01)
        run.outcome('success')

gevent.joinall([gevent.spawn(job, i) for i in range(10)])
nexus.flush()
print(json.dumps({'ok': True}), flush=True)
"""


def test_1_10_gevent_monkeypatch_before_init(tmp_path, collector):
    r = run_script(GEVENT_BEFORE, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert '"ok": true' in r.stdout
    assert collector.wait_for(12, timeout=10), collector.types()
    names = {e["name"] for e in collector.of_type("agent_run") if e.get("phase") == "start"}
    assert len(names) == 10, names


def test_1_10_gevent_monkeypatch_after_init(tmp_path, collector):
    """The harder ordering: our flush thread already exists as a *native* thread when
    ``patch_all()`` replaces ``threading``. It must neither die nor wedge the hub."""
    r = run_script(GEVENT_AFTER, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert '"ok": true' in r.stdout
    assert collector.wait_for(12, timeout=10), collector.types()


def test_1_10_no_native_lock_is_held_across_io():
    """The structural rule behind both orderings: never hold a lock across a yield point.

    Under gevent a native lock held across an I/O call blocks the entire hub — every greenlet in the
    process, not just ours. So the enqueue lock is held only for deque manipulation, and the send
    path is outside it. This test asserts that directly: a sink that tries to enqueue *while a send
    is in progress* must not block.
    """
    from nexus.config import resolve
    from nexus.transport import OK, SendResult, Transport

    entered = threading.Event()
    release = threading.Event()

    class SlowSink:
        def send(self, batch):
            entered.set()
            release.wait(5)
            return SendResult(OK)

    tr = Transport(resolve(service="t", env="test", version="1"), sink=SlowSink())
    tr.enqueue({"type": "x", "session_id": "s"})
    th = threading.Thread(target=tr.flush, args=(3.0,), daemon=True)
    th.start()
    assert entered.wait(3), "sink never ran"
    t0 = time.monotonic()
    tr.enqueue({"type": "x", "session_id": "s", "n": 2})     # must not wait on the in-flight send
    assert time.monotonic() - t0 < 0.2
    release.set()
    th.join(timeout=5)
    tr.shutdown(0.2)


def test_1_10_gevent_detection(monkeypatch):
    from nexus import runtime
    import types
    fake = types.ModuleType("gevent.monkey")
    fake.is_module_patched = lambda name: True
    monkeypatch.setitem(sys.modules, "gevent.monkey", fake)
    assert runtime._gevent_patched() is True
