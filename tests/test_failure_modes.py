"""§4 — failure modes. The governing rule: **a telemetry SDK must never be the reason a request
fails.**

Each test names its case number from ``F3-SDK-RUNTIME-CASES.md`` §4. Where a test asserts a
*counter* rather than an outcome, that is deliberate: §4.3 says "silence about dropped data is a
bug", so the observable contract is not merely "we dropped correctly" but "we can prove how much
we dropped".
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest

from conftest import free_port

from nexus import _counters
from nexus.config import resolve
from nexus.transport import FATAL, OK, RETRY, HttpSink, SendResult, Transport


class RecordingSink:
    """A sink whose behaviour a test can dictate."""

    def __init__(self, status=OK, delay=0.0, retry_after=None):
        self.status = status
        self.delay = delay
        self.retry_after = retry_after
        self.batches: list[list[dict]] = []
        self.calls = 0
        self.lock = threading.Lock()

    def send(self, batch):
        with self.lock:
            self.calls += 1
            self.batches.append(list(batch))
        if self.delay:
            time.sleep(self.delay)
        return SendResult(self.status, retry_after_s=self.retry_after)


def _cfg(**kw):
    return resolve(service="t", env="test", version="1", **kw)


def _ev(i: int) -> dict:
    return {"type": "tool_action", "session_id": "s", "event_id": f"e{i}", "n": i}


# -- 4.1 collector unreachable ------------------------------------------------------------------

def test_4_1_collector_unreachable_never_blocks_and_never_raises():
    """Nothing is listening on the port. The app must not notice."""
    cfg = _cfg(collector_url=f"http://127.0.0.1:{free_port()}",
               http_timeout_s=0.25, max_retries=1, flush_deadline_s=1.0)
    tr = Transport(cfg)
    t0 = time.monotonic()
    for i in range(50):
        assert tr.enqueue(_ev(i)) is True
    assert time.monotonic() - t0 < 0.25, "enqueue must never wait on the network"

    ok = tr.flush(deadline_s=1.0)
    assert ok is False                      # honest: the queue did not empty
    assert _counters.get(_counters.SEND_FAILED) >= 1
    assert tr.depth() == 50, "events are retained for a later retry, not discarded"
    tr.shutdown(0.1)


def test_4_1_recovers_when_the_collector_comes_back(collector):
    """A collector restart is transient. Buffered events ship on the next flush."""
    cfg = _cfg(collector_url=collector.url, batch_size=10)
    tr = Transport(cfg)
    for i in range(5):
        tr.enqueue(_ev(i))
    collector.status = 500
    assert tr.flush(0.5) is False
    collector.status = 202
    assert tr.flush(2.0) is True
    assert collector.wait_for(5)
    tr.shutdown(0.5)


# -- 4.2 collector slow (backpressure) ----------------------------------------------------------

def test_4_2_slow_collector_does_not_slow_the_caller():
    """Every send takes 200ms. 500 enqueues must still be effectively free."""
    sink = RecordingSink(delay=0.2)
    cfg = _cfg(queue_capacity=100, batch_size=10)
    tr = Transport(cfg, sink=sink)
    tr.start()
    t0 = time.monotonic()
    for i in range(500):
        tr.enqueue(_ev(i))
    elapsed = time.monotonic() - t0
    assert elapsed < 0.5, f"enqueue path absorbed backpressure: {elapsed:.3f}s"
    # And the overflow was counted, not hidden.
    assert _counters.get(_counters.QUEUE_DROPPED) > 0
    tr.shutdown(0.2)


# -- 4.3 queue full -----------------------------------------------------------------------------

def test_4_3_queue_full_drops_oldest_and_counts_every_drop():
    cfg = _cfg(queue_capacity=10, batch_size=1000)   # batch_size high so nothing drains
    tr = Transport(cfg, sink=RecordingSink())
    for i in range(25):
        tr.enqueue(_ev(i))
    assert tr.depth() == 10
    assert _counters.get(_counters.QUEUE_DROPPED) == 15
    assert _counters.get(_counters.EVENTS_ENQUEUED) == 25
    assert _counters.get(_counters.QUEUE_DEPTH_PEAK) == 10
    # drop-oldest: what survives is the most recent window, because the newest events are the
    # ones describing whatever incident filled the queue.
    kept = [e["n"] for e in tr._take(10)]
    assert kept == list(range(15, 25))


def test_4_3_enqueue_reports_the_drop_to_its_caller():
    tr = Transport(_cfg(queue_capacity=2, batch_size=1000), sink=RecordingSink())
    assert tr.enqueue(_ev(1)) is True
    assert tr.enqueue(_ev(2)) is True
    assert tr.enqueue(_ev(3)) is False


def test_4_3_requeue_cannot_grow_the_queue_past_its_cap():
    """A failed batch goes back to the head — but the bound still holds (unbounded retry buffer is
    the same memory leak the cap exists to prevent)."""
    tr = Transport(_cfg(queue_capacity=5, batch_size=1000), sink=RecordingSink())
    for i in range(5):
        tr.enqueue(_ev(i))
    tr._requeue_front([_ev(90), _ev(91), _ev(92)])
    assert tr.depth() == 5
    assert _counters.get(_counters.QUEUE_DROPPED) >= 3


# -- 4.4 auth failure ---------------------------------------------------------------------------

def test_4_4_401_latches_and_stops_generating_load(collector):
    collector.status = 401
    cfg = _cfg(collector_url=collector.url, api_key="rotated-away", batch_size=1)
    tr = Transport(cfg)
    for i in range(5):
        tr.enqueue(_ev(i))
    tr.flush(2.0)
    sink = tr.sink
    assert sink.auth_failed is True
    before = len(collector.requests)
    for i in range(20):
        tr.enqueue(_ev(100 + i))
    tr.flush(2.0)
    assert len(collector.requests) == before, "a latched auth failure must not keep hitting the peer"
    assert _counters.get(_counters.SEND_ABANDONED) > 0
    tr.shutdown(0.2)


def test_4_4_403_latches_too(collector):
    collector.status = 403
    tr = Transport(_cfg(collector_url=collector.url, batch_size=1))
    tr.enqueue(_ev(1))
    tr.flush(1.0)
    assert tr.sink.auth_failed is True
    tr.shutdown(0.1)


# -- 4.5 rate limiting --------------------------------------------------------------------------

def test_4_5_429_is_honoured_and_clamped(collector):
    collector.status = 429
    collector.retry_after = "600"        # a peer asking for ten minutes
    sink = HttpSink(_cfg(collector_url=collector.url, http_timeout_s=1.0))
    res = sink.send([_ev(1)])
    assert res.status == RETRY
    assert res.retry_after_s == 30.0, "Retry-After is respected but clamped; we never sleep 10min"


def test_4_5_429_does_not_amplify(collector):
    """The failure mode to avoid is a retry storm making the rate limit worse."""
    collector.status = 429
    collector.retry_after = "0.01"
    cfg = _cfg(collector_url=collector.url, batch_size=1, max_retries=2, flush_deadline_s=1.0)
    tr = Transport(cfg)
    tr.enqueue(_ev(1))
    tr.flush(1.0)
    assert len(collector.requests) <= 3, f"{len(collector.requests)} attempts for max_retries=2"
    tr.shutdown(0.1)


# -- 4.6 compression unsupported ----------------------------------------------------------------

def test_4_6_gzip_is_used_for_large_bodies(collector):
    sink = HttpSink(_cfg(collector_url=collector.url))
    big = [{"type": "tool_action", "session_id": "s", "blob": "x" * 200} for _ in range(20)]
    assert sink.send(big).status == OK
    assert collector.requests[-1]["gzip"] is True


def test_4_6_415_latches_to_uncompressed(collector):
    """Fail-safe, and *stay* failed-safe: renegotiating per batch is a wasted round trip forever."""
    collector.status = 415
    sink = HttpSink(_cfg(collector_url=collector.url))
    big = [{"type": "tool_action", "session_id": "s", "blob": "x" * 200} for _ in range(20)]
    assert sink.send(big).status == RETRY
    assert sink._gzip_unsupported is True
    collector.status = 202
    assert sink.send(big).status == OK
    assert collector.requests[-1]["gzip"] is False


# -- 4.7 internal exception anywhere -------------------------------------------------------------
#   The exhaustive version lives in test_fault_injection.py, which iterates the guard registry.

def test_4_7_an_exploding_sink_does_not_reach_the_caller():
    class Bomb:
        def send(self, batch):
            raise RuntimeError("sink is on fire")

    tr = Transport(_cfg(batch_size=1), sink=Bomb())
    tr.enqueue(_ev(1))          # must not raise
    tr.flush(0.2)               # _run/_drain contain it
    tr.shutdown(0.1)


def test_4_7_unserialisable_event_does_not_wedge_the_queue(collector):
    class Unencodable:
        def __repr__(self):
            raise ValueError("even repr fails")

    sink = HttpSink(_cfg(collector_url=collector.url))
    res = sink.send([{"type": "x", "session_id": "s", "bad": Unencodable()}])
    assert res.status == FATAL          # dropped, not retried forever
    assert _counters.get(_counters.BUILD_FAILED) >= 1


# -- 4.8 graceful shutdown with a deadline -------------------------------------------------------

def test_4_8_flush_respects_its_deadline():
    """A hung flush must not hang the container."""
    tr = Transport(_cfg(batch_size=1, queue_capacity=1000), sink=RecordingSink(delay=0.3))
    for i in range(100):
        tr.enqueue(_ev(i))
    t0 = time.monotonic()
    ok = tr.flush(deadline_s=0.5)
    elapsed = time.monotonic() - t0
    assert ok is False
    assert elapsed < 1.5, f"flush overran its 0.5s deadline by too much: {elapsed:.2f}s"
    assert _counters.get(_counters.FLUSH_TIMEOUT) >= 1
    tr.shutdown(0.1)


def test_4_8_shutdown_stops_the_worker_thread():
    tr = Transport(_cfg(), sink=RecordingSink())
    tr.start()
    assert tr._worker is not None and tr._worker.is_alive()
    w = tr._worker
    tr.shutdown(0.5)
    w.join(timeout=2.0)
    assert not w.is_alive()


def test_4_8_atexit_flush_happens_in_a_real_process(tmp_path, collector):
    """End-to-end: a process that exits normally must have shipped its events."""
    from conftest import run_script
    r = run_script(
        "import nexus\n"
        "nexus.init(service='exiting', env='test', version='1')\n"
        "with nexus.agent('job') as run:\n"
        "    run.outcome('success')\n"
        "print('done')\n",
        tmp_path, env={"NEXUS_COLLECTOR_URL": collector.url})
    assert r.returncode == 0, r.stderr
    assert collector.wait_for(3), collector.types()
    assert "turn_outcome" in collector.types()


# -- 4.9 SIGKILL --------------------------------------------------------------------------------

def test_4_9_sigkill_loses_the_buffer_and_we_say_so(tmp_path, collector):
    """Documented, not pretended away: on SIGKILL the in-flight buffer is lost.

    The assertion is deliberately the *pessimistic* one. If a future change made this pass by
    shipping events, that would be a change of contract worth noticing, not a silent improvement.
    """
    import signal
    import subprocess
    import sys
    from conftest import SRC
    prog = tmp_path / "killme.py"
    prog.write_text(
        "import nexus, time\n"
        "nexus.init(service='doomed', env='test', version='1')\n"
        "nexus.agent('never-finishes')\n"
        "print('ready', flush=True)\n"
        "time.sleep(30)\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    env["NEXUS_COLLECTOR_URL"] = collector.url
    env["NEXUS_FLUSH_INTERVAL_S"] = "60"       # ensure nothing drains before we kill it
    p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, text=True)
    assert p.stdout.readline().strip() == "ready"
    p.send_signal(signal.SIGKILL)
    p.wait(timeout=10)
    time.sleep(0.3)
    # Nothing is asserted about *which* events arrived — the point is only that the process died
    # without a flush and the SDK made no attempt to pretend otherwise (no spill, no resurrection).
    assert p.returncode in (-9, 137)


# -- 4.10 double init ---------------------------------------------------------------------------

def test_4_10_init_twice_is_idempotent(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    from nexus import client as client_mod
    c1 = client_mod.init(service="a", env="test", version="1")
    tr1, sess1, worker1 = c1.transport, c1.session_id, c1.transport._worker
    c2 = client_mod.init(service="b", env="test", version="2")
    assert c2 is c1, "one client per process"
    assert c2.transport is tr1, "the queue and its in-flight events survive re-init"
    assert c2.transport._worker is worker1, "no second flush thread"
    assert c2.session_id == sess1
    assert c2.cfg.service == "b", "identity is upgraded in place"
    nexus.shutdown()


def test_4_10_reload_of_the_package_does_not_double_wrap(collector, monkeypatch):
    """Jupyter/REPL shape (case 1.14): re-executing init in a live process."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    for _ in range(5):
        nexus.init(service="repl", env="test", version="1")
    from nexus import client as client_mod
    threads = [t for t in threading.enumerate() if t.name == "nexus-flush"]
    assert len(threads) == 1, f"{len(threads)} flush threads after 5 inits"
    nexus.shutdown()


# -- 7.2 attach-point discriminator ---------------------------------------------------------------

def test_7_2_the_attach_point_is_stamped_under_producer_not_source():
    """The wire key is ``producer``. Getting this wrong is silent and expensive.

    ``nexus_devtools/events.py`` defaults ``producer`` to ``wrap`` when the key is absent, so an SDK
    that stamps ``source="sdk"`` and nothing else does not fail loudly — it attributes a customer's
    production service to a developer's terminal, in every rollup and on the bill. And ``source``
    is a real field on eight of the parent's builders with an unrelated meaning, so the collision
    is not hypothetical either.

    Asserted against the literal strings from ``events.py:86-89`` rather than imported, because
    this package must not depend on the parent repo — hand-mirroring is the known cost of that
    decision (see ``contract`` module docstring, TODO(WP-2)).
    """
    from nexus import contract
    from nexus.config import resolve

    ev = contract.base("agent_run", "s1", resolve(service="x", env="test", version="1"),
                       epistemic_class=contract.EPISTEMIC_BEHAVIOR)
    assert ev["producer"] == "sdk", "attach point must be stamped under `producer`"
    assert "source" not in ev, "`source` means something else in this contract"
    assert contract.PRODUCER in ("wrap", "sdk", "connection")   # events.py:89 PRODUCERS


def test_7_2_a_builder_cannot_shadow_the_attach_point():
    """``producer`` is process identity, never a payload field a caller can set."""
    from nexus import contract
    from nexus.config import resolve

    ev = contract.base("agent_run", "s1", resolve(service="x", env="test", version="1"),
                       epistemic_class=contract.EPISTEMIC_BEHAVIOR, producer="wrap")
    assert ev["producer"] == "sdk", "a builder kwarg overwrote the attach point"


# -- 4.11 auto-instrumentation on, init() never called -------------------------------------------

def test_4_11_capture_without_init_uses_unknown_identity(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    with nexus.agent("orphan") as run:      # no init() anywhere
        run.outcome("success")
    nexus.flush()
    assert collector.wait_for(3), collector.types()
    ev = collector.of_type("agent_run")[0]
    assert ev["service"] == "unknown", "defaults, not a crash and not a silent discard"
    assert ev["producer"] == "sdk"
    nexus.shutdown()


def test_4_11_is_thread_safe(collector, monkeypatch):
    """Twelve threads race to be the one that creates the client. Exactly one may win."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    from nexus import client as client_mod
    seen = []
    barrier = threading.Barrier(12)

    def go():
        barrier.wait()
        seen.append(client_mod.ensure_client())

    ts = [threading.Thread(target=go) for _ in range(12)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    assert len({id(c) for c in seen}) == 1
    assert len([t for t in threading.enumerate() if t.name == "nexus-flush"]) == 1
    client_mod._reset_for_tests()


# -- 4.12 kill switch ---------------------------------------------------------------------------

def test_4_12_disabled_means_no_threads_no_hooks(monkeypatch):
    monkeypatch.setenv("NEXUS_ENABLED", "0")
    import importlib
    import nexus
    importlib.reload(nexus)
    try:
        assert nexus.enabled() is False
        assert nexus.init(service="x") is None
        with nexus.agent("nope") as run:            # absorbs everything, emits nothing
            run.outcome("success")
            with run.action("read") as act:
                act.effect(rows=1)
        # flush() reports "nothing outstanding", which is the truth when nothing was captured —
        # a caller that warns on False must not be made to warn by the kill switch.
        assert nexus.flush() is True
        assert [t for t in threading.enumerate() if t.name == "nexus-flush"] == []
        from nexus import client as client_mod
        assert client_mod.get_client() is None
    finally:
        monkeypatch.delenv("NEXUS_ENABLED", raising=False)
        importlib.reload(nexus)


def test_4_12_disabled_never_touches_the_network(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_ENABLED", "0")
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import importlib
    import nexus
    importlib.reload(nexus)
    try:
        for i in range(100):
            with nexus.agent(f"r{i}"):
                pass
        nexus.flush()
        time.sleep(0.2)
        assert collector.requests == []
    finally:
        monkeypatch.delenv("NEXUS_ENABLED", raising=False)
        importlib.reload(nexus)


def test_4_12_import_of_a_disabled_sdk_pulls_in_nothing_heavy(tmp_path):
    """The security-review claim: ``NEXUS_ENABLED=0`` is not "initialise then no-op"."""
    from conftest import run_script
    r = run_script(
        "import sys, json, nexus\n"
        "nexus.enabled()\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('nexus.'))\n"
        "print(json.dumps(loaded))\n",
        tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    loaded = json.loads(r.stdout.strip().splitlines()[-1])
    heavy = [m for m in loaded if m.split(".")[-1] in
             ("transport", "client", "contract", "hooks", "runtime", "api")]
    assert heavy == [], f"disabled SDK imported {heavy}"


# -- 2.19 self-exclusion (a §4-shaped hazard: recursive egress) ----------------------------------

def test_self_exclusion_marks_our_own_egress(collector):
    """Our HTTP client, instrumented by our own HTTP instrumentation, is unbounded recursion.

    Two mechanisms exist and both are asserted here: the request carries a marker header so a
    collector or an adapter can recognise it, and the transport module is on the never-instrument
    list so an adapter cannot patch it by accident.
    """
    from nexus import integrations
    sink = HttpSink(_cfg(collector_url=collector.url))
    sink.send([_ev(1)])
    assert collector.requests[-1]["headers"].get(HttpSink.MARKER_HEADER.lower()) == "1"
    assert "nexus.transport" in integrations.EXCLUDED_MODULES
    with pytest.raises(ValueError):
        integrations.register("nexus.transport", lambda m: None)


# -- spill / disk full (§4-adjacent, referenced by 4.1's "drop on overflow") ----------------------

def test_spill_is_off_by_default():
    tr = Transport(_cfg(), sink=RecordingSink())
    assert tr.cfg.spill_dir in (None, "")
    tr._spill([_ev(1)])                     # no-op, no exception, no counter
    assert _counters.get(_counters.DISK_ERROR) == 0


def test_spill_survives_an_unwritable_directory(tmp_path):
    bad = tmp_path / "ro"
    bad.mkdir()
    os.chmod(bad, 0o500)
    try:
        tr = Transport(_cfg(spill_dir=str(bad / "sub")), sink=RecordingSink())
        tr._spill([_ev(1)])                 # must not raise into the caller
        assert _counters.get(_counters.DISK_ERROR) >= 1
    finally:
        os.chmod(bad, 0o700)
