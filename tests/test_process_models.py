"""§1 — process and runtime models.

"Worked on my laptop, silent in prod" is almost always one of these. Where a case needs a runtime
we cannot install in CI (uWSGI's threading model, the Lambda freeze/thaw sandbox, Cloud Run's
SIGTERM), the test exercises **the mechanism the SDK actually relies on** and says so in its name
and docstring — see ``docs/RUNTIME-CASES-CHECKLIST.md``, which records e2e vs mechanism-tested per
case. Nothing is quietly downgraded.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from conftest import SRC, run_script


# -- 1.1 baseline -------------------------------------------------------------------------------

def test_1_1_single_sync_process(tmp_path, collector):
    r = run_script(
        "import nexus\n"
        "nexus.init(service='script', env='dev', version='1')\n"
        "with nexus.agent('do-a-thing') as run:\n"
        "    with run.action('read_file', target='x.py') as a:\n"
        "        a.effect(bytes=12)\n"
        "    run.usage(model='claude-opus-4', input_tokens=10, output_tokens=2)\n"
        "    run.outcome('success', verified=True, verified_by='exit_code')\n",
        tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(6), collector.types()
    types = collector.types()
    for want in ("session", "agent_run", "tool_action", "token_usage", "turn_outcome"):
        assert want in types, f"{want} missing from {types}"
    assert all(e["producer"] == "sdk" for e in collector.events)


# -- 1.2 / 1.3 gunicorn pre-fork ------------------------------------------------------------------

FORK_PROG = """
import os, sys, time, json
import nexus
nexus.init(service='forky', env='test', version='1')

# Buffered in the PARENT before the fork. Every child inherits a copy of this queue; if the fork
# hook does not empty it, this single event is delivered once per child (case 1.2).
with nexus.agent('parent-work') as run:
    run.outcome('success')

kids = []
for i in range(3):
    pid = os.fork()
    if pid == 0:
        try:
            import threading
            with nexus.agent('child-work-%d' % i) as run:
                run.outcome('success')
            nexus.flush()
            flushers = [t.name for t in threading.enumerate() if t.name == 'nexus-flush']
            c = nexus.current_run()
            print(json.dumps({'pid': os.getpid(), 'flushers': len(flushers),
                              'ctx': c is None}), flush=True)
        finally:
            os._exit(0)
    kids.append(pid)

nexus.flush()
for pid in kids:
    os.waitpid(pid, 0)
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_2_prefork_children_do_not_replay_the_parent_queue(tmp_path, collector):
    r = run_script(FORK_PROG, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(8, timeout=10), collector.types()
    time.sleep(0.5)

    runs = [e for e in collector.of_type("agent_run") if e.get("phase") == "start"]
    names = sorted(e["name"] for e in runs)
    assert names.count("parent-work") == 1, (
        f"the parent's buffered event was replayed by the children: {names}")
    assert sorted(n for n in names if n.startswith("child-")) == [
        "child-work-0", "child-work-1", "child-work-2"]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_2_no_duplicate_event_ids_across_the_fleet(tmp_path, collector):
    r = run_script(FORK_PROG, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(8, timeout=10)
    time.sleep(0.5)
    ids = [e["event_id"] for e in collector.events]
    assert len(ids) == len(set(ids)), "duplicate event_id — a child shipped inherited events"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_2_each_child_has_exactly_one_flusher_and_its_own_session(tmp_path, collector):
    r = run_script(FORK_PROG, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    reports = [json.loads(line) for line in r.stdout.strip().splitlines() if line.startswith("{")]
    assert len(reports) == 3
    for rep in reports:
        assert rep["flushers"] == 1, "a forked child must rebuild exactly one flush thread"
        assert rep["ctx"] is True, "inherited run context must be cleared in the child"

    assert collector.wait_for(8, timeout=10)
    time.sleep(0.5)
    sessions = {e["session_id"] for e in collector.events}
    assert len(sessions) >= 4, f"parent + 3 children should not share a session id: {sessions}"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_3_preload_shape_does_not_open_sockets_before_the_fork(tmp_path, collector):
    """``--preload``: init runs in the master, fully imported, long before any request.

    The requirement is that ``init()`` arms structures but performs no network I/O — a socket
    opened pre-fork is shared by every worker and corrupts on concurrent use.
    """
    r = run_script(
        "import nexus, time\n"
        "nexus.init(service='preload', env='test', version='1')\n"
        "time.sleep(0.4)\n"
        "import json, sys\n"
        "print(json.dumps({'requests_before_fork': None}), flush=True)\n",
        tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url, "NEXUS_FLUSH_INTERVAL_S": "30"})
    assert r.returncode == 0, r.stderr
    # init() itself performed no POST; only the atexit flush did.
    assert len(collector.requests) <= 1, (
        f"init() opened {len(collector.requests)} connections before any work happened")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_2_transport_reinit_replaces_locks_rather_than_acquiring_them():
    """The in-process half of the fork contract, asserted directly.

    A child that *acquires* an inherited lock deadlocks if the parent held it at fork time, which
    is exactly the state a threaded pre-fork server is in. The child must replace its locks.
    """
    from nexus import _counters
    from nexus.config import resolve
    from nexus.transport import Transport

    from conftest import free_port
    cfg = resolve(service="t", env="test", version="1",
                  collector_url=f"http://127.0.0.1:{free_port()}")
    tr = Transport(cfg)                     # a real HttpSink, so the socket state is real
    tr.start()
    for i in range(7):
        tr.enqueue({"type": "x", "session_id": "s", "n": i})
    old_lock, old_worker, old_sink = tr._lock, tr._worker, tr.sink

    tr._lock.acquire()          # simulate "the parent held this at the moment of fork"
    try:
        tr.reinit_after_fork()  # must not block
    finally:
        old_lock.release()

    assert tr._lock is not old_lock, "child kept the inherited lock"
    assert tr.depth() == 0, "child inherited the parent's buffered events"
    assert _counters.get(_counters.QUEUE_DROPPED) >= 7, "inherited events dropped but not counted"
    assert tr.sink is not old_sink, "child reused the parent's HTTP connection state"
    assert tr._worker is not old_worker
    tr.shutdown(0.2)


class _NullSink:
    def send(self, batch):
        from nexus.transport import OK, SendResult
        return SendResult(OK)


# -- 1.4 uWSGI ------------------------------------------------------------------------------------

def test_1_4_uwsgi_without_enable_threads_is_detected_MECHANISM(monkeypatch):
    """Mechanism-tested: we cannot run uWSGI in CI, so we synthesise the ``uwsgi`` module it injects.

    uWSGI kills Python threads unless started with ``--enable-threads``. Spinning a flush thread
    that will never be scheduled is worse than not having one — events accumulate in a queue nobody
    drains, and the process looks healthy while reporting nothing.
    """
    import types

    from nexus import runtime
    mod = types.ModuleType("uwsgi")
    mod.opt = {b"processes": b"4"}          # note: no enable-threads
    monkeypatch.setitem(sys.modules, "uwsgi", mod)
    prof = runtime.detect()
    assert prof.uwsgi is True
    assert prof.threads_available is False


def test_1_4_uwsgi_with_enable_threads_is_detected_MECHANISM(monkeypatch):
    import types

    from nexus import runtime
    for opt in ({b"enable-threads": b"1"}, {"enable-threads": True}):
        mod = types.ModuleType("uwsgi")
        mod.opt = opt
        monkeypatch.setitem(sys.modules, "uwsgi", mod)
        prof = runtime.detect()
        assert prof.uwsgi is True
        assert prof.threads_available is True, opt


def test_1_4_no_thread_is_started_when_threads_cannot_run_MECHANISM(monkeypatch):
    """The behavioural consequence: synchronous mode, and flush still works."""
    import types

    from nexus.config import resolve
    from nexus.transport import Transport

    mod = types.ModuleType("uwsgi")
    mod.opt = {b"processes": b"4"}
    monkeypatch.setitem(sys.modules, "uwsgi", mod)

    tr = Transport(resolve(service="t", env="test", version="1"), sink=_NullSink())
    tr.start()
    assert tr.mode == "sync"
    assert tr._worker is None, "started a thread uWSGI will never schedule"
    tr.enqueue({"type": "x", "session_id": "s"})
    assert tr.flush(1.0) is True, "synchronous mode must still deliver on an explicit flush"


# -- 1.6 celery / billiard -------------------------------------------------------------------------

@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork on this platform")
def test_1_6_billiard_style_fork_is_covered_by_the_same_hook_MECHANISM(tmp_path, collector):
    """Mechanism-tested: celery is not installed, but ``billiard`` forks through the same
    ``os.fork``/``os.register_at_fork`` path that our hook is registered on, and celery's
    ``worker_process_init`` fires *after* that. If the OS-level hook is correct, the celery
    adapter (WP-5) only has to add the run-boundary, not the safety.
    """
    r = run_script(
        "import os, json, nexus, threading\n"
        "nexus.init(service='celeryish', env='test', version='1')\n"
        "with nexus.agent('before-pool') as run:\n"
        "    run.outcome('success')\n"
        "pid = os.fork()\n"
        "if pid == 0:\n"
        "    try:\n"
        "        with nexus.agent('task-1') as run:\n"
        "            run.outcome('success')\n"
        "        nexus.flush()\n"
        "        print(json.dumps({'ok': True}), flush=True)\n"
        "    finally:\n"
        "        os._exit(0)\n"
        "nexus.flush()\n"
        "os.waitpid(pid, 0)\n",
        tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(6, timeout=10)
    time.sleep(0.4)
    names = [e["name"] for e in collector.of_type("agent_run") if e.get("phase") == "start"]
    assert names.count("before-pool") == 1
    assert names.count("task-1") == 1


# -- 1.7 multiprocessing: fork and spawn -----------------------------------------------------------

MP_PROG = """
import json, multiprocessing as mp, os, sys
import nexus

def work(i):
    import nexus
    nexus.init(service='mp', env='test', version='1')   # idempotent; re-import on spawn
    with nexus.agent('worker-%d' % i) as run:
        run.outcome('success')
    nexus.flush()
    return os.getpid()

if __name__ == '__main__':
    mp.set_start_method(sys.argv[1], force=True)
    nexus.init(service='mp', env='test', version='1')
    with nexus.agent('parent') as run:
        run.outcome('success')
    with mp.Pool(2) as pool:
        pids = pool.map(work, [0, 1])
    nexus.flush()
    print(json.dumps({'pids': pids}), flush=True)
"""


@pytest.mark.parametrize("method", ["fork", "spawn"])
def test_1_7_multiprocessing_both_start_methods(tmp_path, collector, method):
    if method == "fork" and not hasattr(os, "fork"):
        pytest.skip("no fork")
    r = run_script(MP_PROG, tmp_path, args=[method],
                   env={"NEXUS_COLLECTOR_URL": collector.url}, timeout=90)
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(6, timeout=15), collector.types()
    time.sleep(0.5)
    names = [e["name"] for e in collector.of_type("agent_run") if e.get("phase") == "start"]
    assert names.count("parent") == 1, f"parent run replayed by workers: {names}"
    assert "worker-0" in names and "worker-1" in names
    ids = [e["event_id"] for e in collector.events]
    assert len(ids) == len(set(ids))


# -- 1.11 AWS Lambda --------------------------------------------------------------------------------

def test_1_11_handler_flushes_before_returning_MECHANISM(collector, monkeypatch):
    """Mechanism-tested: no Lambda sandbox in CI, so the freeze is modelled as "nothing runs in the
    background between invocations" — which is exactly what the sandbox does.

    The assertion is that the flush happens *inside* the handler call, not on a timer.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
    monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")     # background flusher will never fire
    import nexus

    @nexus.instrument_lambda_handler
    def handler(event, context=None):
        with nexus.agent("invocation") as run:
            run.outcome("success")
        return {"ok": True}

    assert handler({"n": 1}) == {"ok": True}
    assert collector.wait_for(3, timeout=2), (
        "events were still queued when the handler returned; the sandbox would freeze them")
    n_after_first = len(collector.events)

    assert handler({"n": 2}) == {"ok": True}
    assert collector.wait_for(n_after_first + 3, timeout=2)
    nexus.shutdown()


def test_1_11_handler_exception_still_flushes_and_still_propagates(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
    monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")
    import nexus

    @nexus.instrument_lambda_handler
    def handler(event, context=None):
        with nexus.agent("invocation"):
            raise ValueError("business logic failed")

    with pytest.raises(ValueError):
        handler({})
    assert collector.wait_for(3, timeout=2), "a failing invocation must still ship its telemetry"
    nexus.shutdown()


def test_1_11_a_frozen_queue_resumes_on_the_next_invocation(collector, monkeypatch):
    """The collector is down during invocation 1 (events stay queued across the "freeze"), up for
    invocation 2. Nothing may be lost."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
    monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "3600")
    import nexus

    @nexus.instrument_lambda_handler
    def handler(event, context=None):
        with nexus.agent(f"inv-{event['n']}") as run:
            run.outcome("success")

    collector.status = 500
    handler({"n": 1})
    assert collector.events == []
    collector.status = 202
    handler({"n": 2})
    assert collector.wait_for(6, timeout=3)
    names = [e["name"] for e in collector.of_type("agent_run") if e.get("phase") == "start"]
    assert "inv-1" in names and "inv-2" in names, f"lost across the freeze: {names}"
    nexus.shutdown()


def test_1_11_lambda_runtime_is_detected(monkeypatch):
    from nexus import runtime
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-fn")
    assert runtime.detect().is_lambda is True


# -- 1.12 Cloud Run / Fargate: SIGTERM within the grace period ---------------------------------------

SIGTERM_PROG = """
import os, signal, sys, time
import nexus
nexus.init(service='cloudrun', env='test', version='1')
with nexus.agent('in-flight') as run:
    run.outcome('success')
print('ready', flush=True)
time.sleep(60)
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_1_12_sigterm_flushes_within_the_grace_period(tmp_path, collector):
    prog = tmp_path / "sigterm_prog.py"
    prog.write_text(SIGTERM_PROG)
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    env["NEXUS_COLLECTOR_URL"] = collector.url
    env["NEXUS_FLUSH_INTERVAL_S"] = "3600"      # only the signal handler can save us
    env["K_SERVICE"] = "svc"                   # Cloud Run marker → 10s default grace
    p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)
    assert p.stdout.readline().strip() == "ready"
    time.sleep(0.2)
    assert collector.events == [], "background flusher fired; the test is not testing SIGTERM"
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=20)
    assert collector.wait_for(4, timeout=5), collector.types()
    assert "turn_outcome" in collector.types()


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_1_12_sigterm_still_terminates_the_process(tmp_path, collector):
    """The flush must not swallow the signal. A container that ignores SIGTERM gets SIGKILLed and
    the operator blames the wrong thing."""
    prog = tmp_path / "sigterm_exit.py"
    prog.write_text(SIGTERM_PROG)
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    env["NEXUS_COLLECTOR_URL"] = collector.url
    p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)
    assert p.stdout.readline().strip() == "ready"
    t0 = time.monotonic()
    p.send_signal(signal.SIGTERM)
    rc = p.wait(timeout=20)
    assert time.monotonic() - t0 < 15
    assert rc != 0, "process survived SIGTERM"


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_1_12_a_short_grace_period_is_abandoned_cleanly(tmp_path, collector):
    """The collector never answers. The process must still die promptly, not hang until SIGKILL."""
    prog = tmp_path / "sigterm_slow.py"
    prog.write_text(SIGTERM_PROG)
    collector.delay = 30.0
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    env["NEXUS_COLLECTOR_URL"] = collector.url
    env["NEXUS_FLUSH_INTERVAL_S"] = "3600"
    env["NEXUS_GRACE_PERIOD_S"] = "2"
    env["NEXUS_HTTP_TIMEOUT_S"] = "1"
    p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)
    assert p.stdout.readline().strip() == "ready"
    p.send_signal(signal.SIGTERM)
    t0 = time.monotonic()
    p.wait(timeout=20)
    elapsed = time.monotonic() - t0
    assert elapsed < 12, f"hung for {elapsed:.1f}s trying to flush to a dead collector"
    collector.delay = 0.0


def test_1_12_sigterm_handler_chains_to_the_application(monkeypatch):
    """We are a guest. An application's own SIGTERM handler must be kept, and must go *first*.

    The ordering assertion was ``["flush", "app"]`` and is now ``app`` first. That is a deliberate
    behaviour change, not a test bent to fit the code: the application's handler is what drains
    connections and finishes in-flight requests, and it is racing the platform's grace period.
    Running our telemetry flush ahead of it spends a slice of a budget we do not own, so a slow
    collector became *their* dropped requests. The SDK now records intent, hands the signal
    straight on, and drains beside them (see ``_ShutdownDrainer``) — so "app" is first and "flush"
    lands from the drain thread shortly after.
    """
    from nexus import runtime
    called = []
    prev = signal.signal(signal.SIGTERM, lambda s, f: called.append("app"))
    try:
        assert runtime.install_sigterm_handler(lambda d: called.append("flush") or True, 5.0)
        os.kill(os.getpid(), signal.SIGTERM)
        deadline = time.monotonic() + 5.0
        while "flush" not in called and time.monotonic() < deadline:
            time.sleep(0.01)
        assert called[:1] == ["app"], f"the application's handler did not run first: {called}"
        assert "flush" in called, (
            f"the drain never ran — telemetry is now silently dropped on SIGTERM: {called}")
    finally:
        signal.signal(signal.SIGTERM, prev)
        runtime._reset_shutdown_hooks_for_tests()


def test_1_12_the_drain_thread_does_not_leak_across_installs():
    """Each install must retire the previous drainer's thread and fds, not abandon them.

    This is a test-harness leak rather than a production one — a process installs the handler once
    — but it is worth a test because of *where* it surfaces. A leaked drainer parks forever in
    ``select`` on a pipe nobody closes, holding two fds. Nothing fails at the leak site; the fd
    table just shrinks until some unrelated test opens a file and gets ``EMFILE``, which reads as a
    flake in whichever test drew the short straw. Ten installs is far below any real fd limit and
    still pins the invariant: installs are bounded by one live drainer, not by their own count.
    """
    import threading
    from nexus import runtime

    def live():
        return [t for t in threading.enumerate() if t.name == "nexus-sigterm-drain" and t.is_alive()]

    prev = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        before = len(live())
        for _ in range(10):
            assert runtime.install_sigterm_handler(lambda d: True, 5.0)
            runtime._reset_shutdown_hooks_for_tests()
        deadline = time.monotonic() + 2.0
        while len(live()) > before and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(live()) == before, (
            f"{len(live()) - before} drain thread(s) leaked across 10 installs; "
            f"_reset_shutdown_hooks_for_tests is not stopping the drainer")
        assert runtime._drainer is None
    finally:
        signal.signal(signal.SIGTERM, prev)
        runtime._reset_shutdown_hooks_for_tests()


# -- 1.13 Kubernetes ---------------------------------------------------------------------------------

def test_1_13_downward_api_identity_is_read(monkeypatch):
    from nexus import runtime
    monkeypatch.setenv("POD_NAME", "svc-7d9f-abcde")
    monkeypatch.setenv("POD_NAMESPACE", "payments")
    monkeypatch.setenv("NODE_NAME", "ip-10-0-1-7")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    prof = runtime.detect()
    assert prof.is_k8s is True
    assert prof.pod["pod_name"] == "svc-7d9f-abcde"
    assert prof.pod["namespace"] == "payments"
    assert prof.pod["node_name"] == "ip-10-0-1-7"


def test_1_13_sidecar_collector_is_not_hardcoded_to_loopback(monkeypatch):
    """§9's required change: a sidecar or a cluster service, not 127.0.0.1."""
    from nexus.config import resolve
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "nexus-collector.observability.svc.cluster.local")
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", "4318")
    cfg = resolve(service="s", env="prod", version="1")
    assert cfg.events_url == (
        "http://nexus-collector.observability.svc.cluster.local:4318/v1/events")

    monkeypatch.setenv("NEXUS_COLLECTOR_URL", "https://collector.internal/base/")
    cfg = resolve(service="s", env="prod", version="1")
    assert cfg.events_url == "https://collector.internal/base/v1/events"


def test_1_13_ipv6_host_is_bracketed(monkeypatch):
    from nexus.config import resolve
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "fd00::1")
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", "8791")
    assert resolve(service="s").events_url == "http://[fd00::1]:8791/v1/events"


def test_1_13_pod_eviction_looks_like_sigterm_then_sigkill_MECHANISM():
    """Eviction is SIGTERM + grace + SIGKILL, both of which have their own tests (1.12, 4.9).

    Recorded explicitly so the case is not silently absent from the checklist: there is no
    additional mechanism for eviction beyond those two, and asserting a third time would be
    theatre.
    """
    from nexus import runtime
    assert hasattr(runtime, "install_sigterm_handler")


# -- 1.14 Jupyter / REPL ------------------------------------------------------------------------------
#   see test_failure_modes.py::test_4_10_reload_of_the_package_does_not_double_wrap


# -- 1.5 ASGI multi-worker ------------------------------------------------------------------------

ASGI_PROG = """
import asyncio, json, os, sys
import nexus

# A minimal ASGI app with the lifespan protocol, driven below. This is the shape uvicorn and
# hypercorn present to an application; the SDK's contract with it is "arm on startup, drain on
# shutdown, and never let one request's run leak into another's".
class App:
    def __init__(self):
        self.armed = False

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    nexus.init(service="asgi", env="test", version="1")
                    self.armed = True
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    nexus.flush(deadline_s=3.0)
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        else:
            with nexus.agent("request") as run:
                await asyncio.sleep(0.01)          # a real await between start and finish
                with run.action("handle", target=scope["path"]) as act:
                    act.effect(status=200)
                # The run visible here must be this request's, not a sibling's.
                assert nexus.current_run().run_id == run.run_id, "run crossed ASGI scopes"
                run.outcome("success")

SENT = []

async def _send(message):
    SENT.append(message["type"])

async def main():
    app = App()
    inbox = asyncio.Queue()
    await inbox.put({"type": "lifespan.startup"})
    life = asyncio.create_task(app({"type": "lifespan"}, inbox.get, _send))
    await asyncio.sleep(0.1)
    assert app.armed, "lifespan startup never armed the SDK"
    # Concurrent requests, the thing a single-worker ASGI server actually does.
    await asyncio.gather(*[app({"type": "http", "path": f"/r{i}"}, None, None) for i in range(8)])
    await inbox.put({"type": "lifespan.shutdown"})
    await life
    print(json.dumps({"pid": os.getpid(), "sent": SENT}), flush=True)

asyncio.run(main())
"""


def test_1_5_asgi_lifespan_arms_and_drains_per_worker(tmp_path, collector):
    """Per-worker init through the lifespan protocol, with no shared state between request scopes.

    A multi-worker uvicorn is N independent interpreters (spawned or forked), so there is nothing
    to test about the supervisor that 1.2 and 1.7 do not already cover. What *is* specific to ASGI
    is the lifespan handshake — the only startup hook an ASGI app has — and the fact that many
    request scopes are in flight on one event loop at once. Both are exercised here.
    """
    r = run_script(ASGI_PROG, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout.strip().splitlines()[-1])
    assert payload["sent"] == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
    # 8 requests x (run start, action, outcome, run end) plus the session event.
    assert collector.wait_for(33, timeout=5), collector.types()
    actions = collector.of_type("tool_action")
    # Fingerprints, not paths: a request path is free text on ``tool_action.target`` and the
    # default tier does not put free text on the wire. The fingerprint is stable
    # and distinct per path, which is exactly what "did eight concurrent scopes stay eight
    # distinct runs" needs — the assertion is about attribution, never about the text.
    from nexus.contract import fingerprint
    assert {a["target_fingerprint"] for a in actions} == {
        fingerprint(f"/r{i}") for i in range(8)}, "lost request scopes"
    # Every action must be attributed to the run that was open in *its own* task.
    runs = {a["caused_by_prompt_id"] for a in actions}
    assert len(runs) == 8, f"concurrent ASGI scopes shared a run: {runs}"


def test_1_5_two_workers_have_independent_sessions(tmp_path, collector):
    """No shared state assumptions: each worker is its own session, whatever spawns it."""
    prog = ("import nexus\n"
            "nexus.init(service='asgi', env='test', version='1')\n"
            "with nexus.agent('w') as run:\n"
            "    run.outcome('success')\n"
            "nexus.flush(deadline_s=3.0)\n")
    for _ in range(2):
        r = run_script(prog, tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
        assert r.returncode == 0, r.stderr
    assert collector.wait_for(2, timeout=5)
    sessions = {e["session_id"] for e in collector.of_type("session")}
    assert len(sessions) == 2, f"workers shared a session id: {sessions}"


# -- 1.14 Jupyter / REPL --------------------------------------------------------------------------

def test_1_14_reexecuting_init_does_not_rewrap(collector, monkeypatch):
    """A notebook cell gets run four times. Nothing may accumulate.

    The REPL case is 4.10 under a different name, but the failure it guards is specific: a user
    re-executing a setup cell is the most common way an SDK ends up with four flush threads, four
    meta_path finders, and every event emitted four times.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import threading

    import nexus
    from nexus import client as client_mod

    finders_before = len(sys.meta_path)
    try:
        for i in range(4):
            nexus.init(service="notebook", env="test", version=f"1.{i}")

        flushers = [t for t in threading.enumerate() if t.name == "nexus-flush"]
        assert len(flushers) == 1, f"a flush thread per re-run: {len(flushers)}"
        assert len(sys.meta_path) <= finders_before + 1, "a meta_path finder per re-run"
        assert client_mod._client.cfg.version == "1.3", "identity was not updated in place"

        with nexus.agent("cell") as run:
            run.outcome("success")
        assert nexus.flush(deadline_s=3.0)
        assert collector.wait_for(1, timeout=3)
        runs = [e for e in collector.of_type("agent_run") if e["phase"] == "start"]
        assert len(runs) == 1, f"the run was emitted {len(runs)} times"
    finally:
        nexus.shutdown()


# -- 1.15 python -m -----------------------------------------------------------------------------------

def test_1_15_python_dash_m_entrypoint(tmp_path, collector):
    """``python -m yourapp`` is only covered because ``runpy._run_code`` is patched — the reason
    dd-trace's ``module.py`` does it, and the reason we lifted it."""
    pkg = tmp_path / "myapp"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(
        "import nexus\n"
        "with nexus.agent('module-main') as run:\n"
        "    run.outcome('success')\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([SRC, str(tmp_path)])
    env["NEXUS_COLLECTOR_URL"] = collector.url
    env["NEXUS_SERVICE"] = "dash-m"
    from nexus.bootstrap import path as bootstrap_path
    env["PYTHONPATH"] = os.pathsep.join([bootstrap_path(), env["PYTHONPATH"]])
    r = subprocess.run([sys.executable, "-m", "myapp"], capture_output=True, text=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(3, timeout=5), collector.types()
    assert collector.of_type("session")[0]["service"] == "dash-m", "zero-code identity not applied"


def test_1_15_post_run_module_hook_is_available():
    from nexus import hooks
    assert callable(hooks.on_main_module)


# -- 1.16 frozen apps -----------------------------------------------------------------------------------

def test_1_16_frozen_interpreter_degrades_to_explicit_api_MECHANISM(monkeypatch):
    """PyInstaller/Nuitka replace the import system. Installing a meta_path finder there ranges from
    useless to actively harmful, so we decline — silently at runtime, per the case."""
    from nexus import hooks
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    try:
        assert hooks.install() is False
        assert hooks.is_installed() is False
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)


def test_1_16_explicit_api_still_works_when_hooks_are_declined(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    import nexus
    try:
        nexus.init(service="frozen", env="test", version="1")
        with nexus.agent("still-works") as run:
            run.outcome("success")
        nexus.flush()
        assert collector.wait_for(3, timeout=3)
    finally:
        monkeypatch.delattr(sys, "frozen", raising=False)
        nexus.shutdown()
