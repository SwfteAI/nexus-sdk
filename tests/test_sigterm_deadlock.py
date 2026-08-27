"""The SIGTERM handler must not take a lock the interrupted frame holds.

CPython runs a signal handler on the **main thread**, at a bytecode boundary, *inside whatever
frame was executing*. The handler used to call the flush directly, and the flush re-enters
``client.emit`` -> ``transport.enqueue``, which takes ``Transport._lock`` and sets
``Transport._wake`` (whose ``Event.set`` takes an internal condition lock). If the interrupted
frame already held either one — same thread — the handler blocked forever on a lock nothing would
release. A deadlock is not an exception, so no ``try/except`` in the chain could contain it.

The consequence is worse than lost telemetry: because the handler never returned, the
application's own SIGTERM handler never ran and ``atexit`` never ran. The pod wedged until the
orchestrator's SIGKILL, and the logs looked like a clean shutdown.

Two tests, because the finding has two halves and a test for one is not a test for the other:

* :func:`test_handler_returns_while_the_transport_lock_is_held` is the **mechanism**. It holds the
  lock deterministically, so it either passes or fails rather than flaking.
* :func:`test_ordinary_emit_loop_survives_sigterm` is the **reachability**. Holding the lock by
  hand proves a handler can wedge; it says nothing about whether real code ever gets into that
  state. This one never touches an internal — it just emits, which is what a service does.

Both run in a subprocess. A regression here is a *hang*, and a hang in-process would take the
whole suite with it and report nothing; out of process it is a timeout with a name attached.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from conftest import SRC


# -- the mechanism -----------------------------------------------------------------------------

# Arms the SDK, installs an application SIGTERM handler *first* so the SDK chains to it rather
# than taking the SIG_DFL branch (which deliberately waits for the drain and then re-raises to
# terminate — correct in production, and it would just kill this probe).
#
# Then: take the queue lock on the main thread and raise SIGTERM into our own frame. This is the
# real interleaving, made deterministic. Pre-fix the handler flushes here, re-enters enqueue,
# blocks on the lock this frame holds, and 'returned' is never printed.
LOCK_HELD_PROG = """
import os, signal, sys, threading, time
import nexus

app_ran = []
signal.signal(signal.SIGTERM, lambda s, f: app_ran.append(1))

nexus.init(service='deadlock-probe', env='test', version='1')
from nexus import client as _client_mod
c = _client_mod.get_client()

# Give the drain thread a moment to reach its blocking read, so a pass cannot be an artefact of
# the worker not having started.
time.sleep(0.2)

with c.transport._lock:
    signal.raise_signal(signal.SIGTERM)
    # If we reach here the handler returned while we still hold the lock, which is the property.
    print('returned', flush=True)

print('app_ran=%d' % len(app_ran), flush=True)
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
def test_handler_returns_while_the_transport_lock_is_held(tmp_path, collector):
    """The handler completes with ``Transport._lock`` held by the frame it interrupted."""
    prog = tmp_path / "sigterm_lock_held.py"
    prog.write_text(LOCK_HELD_PROG)
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    env["NEXUS_COLLECTOR_URL"] = collector.url
    env["NEXUS_FLUSH_INTERVAL_S"] = "3600"     # only the signal path may flush

    p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)
    try:
        out, err = p.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        pytest.fail(
            "the SIGTERM handler never returned while Transport._lock was held by the frame it "
            "interrupted — it is taking a lock again (self-deadlock; see _ShutdownDrainer)")

    assert "returned" in out, f"handler did not return.\nstdout={out!r}\nstderr={err!r}"
    # The application's handler must still have run. A fix that returns promptly but drops the
    # chained handler trades one outage for a worse one.
    assert "app_ran=1" in out, f"application SIGTERM handler was not chained.\nstdout={out!r}"


# -- the reachability --------------------------------------------------------------------------

# No internals. An ordinary high-rate emit loop against a collector that never answers — which is
# the state a service is in during the rolling restart that sends it a SIGTERM. The parent signals
# at a random-ish point inside that loop; the child must die on its own.
ORDINARY_PROG = """
import os, sys, time
import nexus

nexus.init(service='ordinary', env='test', version='1')
print('ready', flush=True)

deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    with nexus.agent('turn') as run:
        run.outcome('success')
"""


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.timeout(300)     # 12 trials x a 15s worst case exceeds the suite's 120s default
def test_ordinary_emit_loop_survives_sigterm(tmp_path):
    """SIGTERM during ordinary telemetry must not wedge the process.

    **This test's job is reachability, and its power is limited — say so rather than imply
    otherwise.** Measured against the pre-fix handler on this machine it caught the hang in 1 of
    12 trials, i.e. roughly 8% per trial, not the ~37.5% measured with a tighter
    ``client.emit`` loop; the ``nexus.agent`` context manager spends more of each iteration
    outside the lock, so the window is narrower here. At 24 trials that is ~87% power — good
    enough to notice a reintroduction, not good enough to be the only guard.

    :func:`test_handler_returns_while_the_transport_lock_is_held` is the deterministic guard. What
    this one adds is the part a hand-held lock cannot show: that ordinary code, touching no
    internals, actually reaches the state where the handler can wedge. A nonzero hang count on the
    pre-fix build is the whole point of it.

    The collector is a port that accepts nothing, so every flush blocks on a connection that does
    not answer — the same condition as the outage this bug shows up in.
    """
    prog = tmp_path / "sigterm_ordinary.py"
    prog.write_text(ORDINARY_PROG)
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    # 127.0.0.1:1 — connections are refused fast on some platforms and hang on others; either way
    # nothing is ever successfully delivered, which is what this needs.
    env["NEXUS_COLLECTOR_URL"] = "http://127.0.0.1:1/v1/events"
    env["NEXUS_FLUSH_INTERVAL_S"] = "0.01"     # keep the transport busy, widening the window

    TRIALS = 24
    hangs = []
    for i in range(TRIALS):
        p = subprocess.Popen([sys.executable, str(prog)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=env)
        assert p.stdout.readline().strip() == "ready"
        # Land the signal mid-loop, at a slightly different point each trial.
        time.sleep(0.05 + (i % 5) * 0.02)
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            hangs.append(i)
            p.kill()
            p.communicate()

    assert not hangs, (
        f"{len(hangs)}/{TRIALS} trials wedged on SIGTERM (trials {hangs}) — the handler is "
        f"re-entering the transport and blocking on a lock held by the frame it interrupted")
