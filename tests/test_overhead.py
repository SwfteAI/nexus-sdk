"""Published overhead numbers, asserted in CI.

An observability SDK that cannot state its own cost is asking to be taken on faith, and the first
engineer to profile a p99 regression will remove it. The numbers in ``docs/OVERHEAD.md`` come from
this file, and the thresholds are enforced here so they cannot drift silently.

Three deliberate choices about *how* these are measured, because a benchmark that measures the
wrong thing is worse than none:

1. **The hot path is measured against a null sink, not against the test collector.** The fake
   collector runs in the *same interpreter* as the benchmark, so its handler threads contend for
   the GIL with the code being timed. That contention is an artefact of the harness — in production
   the collector is another process — and including it would publish a number that says more about
   pytest than about the SDK. The egress path has its own tests; this one measures what the calling
   thread pays.
2. **The tail is charged to whoever caused it.** p50 and p95 are asserted on wall clock; they are
   stable enough on a shared runner to mean something. p99 is not — on a loaded machine a scheduler
   preemption lands in the 99th percentile of *any* loop, including an empty one, and a fixed wall
   p99 bound turns that into a red build. A flaky performance test is deleted within a month,
   taking the real signal with it. So every sample is timed on two clocks, and the CPU tail (which
   the SDK is responsible for) is always asserted while the wall tail (which the machine may be
   responsible for) is asserted only when the loop's own CPU/wall ratio shows the box was idle. See
   ``_assert_tail``, including why this uses ``process_time`` rather than the more obviously correct
   ``thread_time``.

   The wall bound is still the weakest assertion here, which is why
   ``test_the_hot_path_never_touches_the_network`` exists: the property "the calling thread does no
   I/O" is what the timings are a proxy for, and it can be asserted exactly.
3. **Import cost is wall-clock delta against a bare interpreter**, minimum of N runs, with the
   baseline re-measured inside the same test. ``-X importtime`` attributes cost per module but is
   dominated by first-run bytecode compilation and reports self-time in a column easily misread as
   cumulative; the minimum of repeated whole-process runs is the honest "what does this add to a
   cold start".

Run ``pytest -s tests/test_overhead.py`` to see every measured value.
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time

import pytest

from conftest import SRC, run_script

# Asserted. Loose enough for a shared runner, tight enough that a synchronous send fails them.
ACTION_P50_BUDGET_US = 40.0
ACTION_P95_BUDGET_US = 150.0
RUN_P50_BUDGET_US = 120.0
RUN_P95_BUDGET_US = 600.0

#: p99 ceiling. Applied unconditionally to CPU time, and to wall time only on a demonstrably idle
#: machine — see ``_assert_tail``.
P99_QUIET_CEILING_US = 3000.0

#: ``import nexus`` proper — the module that must stay trivially cheap in both modes.
IMPORT_ADDED_BUDGET_MS = 40.0
DISABLED_IMPORT_ADDED_BUDGET_MS = 10.0
DISABLED_CALL_BUDGET_US = 40.0
#: ``import nexus`` + ``init()``, i.e. the whole SDK armed. Measured ~55 ms on a 2023 laptop and
#: dominated by the standard library (``logging``, ``json``/``re``, ``dataclasses``/``inspect``) —
#: see ``docs/OVERHEAD.md`` for the breakdown. The budget carries headroom for a slower CI runner;
#: it is a regression guard, not a target.
ARMING_BUDGET_MS = 150.0


def _p(values, q):
    values = sorted(values)
    if not values:
        return 0.0
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))]


def _report(name: str, **vals) -> None:
    print(f"\n[overhead] {name}: " + "  ".join(f"{k}={v:.3f}" for k, v in vals.items()))


#: Below this CPU-to-wall ratio the measurement loop spent most of its life descheduled, i.e. the
#: machine was busy with something other than this test. The wall-clock tail then says nothing
#: about the SDK, so it is reported and not asserted.
QUIET_MACHINE_RATIO = 0.90


def _assert_tail(name: str, wall: list, cpu: list) -> tuple:
    """Assert the tail the SDK is responsible for; report the tail the machine is responsible for.

    Every sample is timed twice: ``perf_counter_ns`` (wall) and ``process_time_ns`` (CPU actually
    burned). Their difference is time the process was not running — a scheduler preemption, a
    hypervisor steal, another process on the box. None of that is added latency the SDK caused, and
    asserting on it is how a performance test becomes a coin flip on shared CI.

    ``process_time`` and not ``thread_time``, despite the latter being the obviously correct clock,
    because on macOS ``CLOCK_THREAD_CPUTIME_ID`` is wrong by more than an order of magnitude: a
    195 ms pure-CPU loop measured here reports 4.7 ms of thread time while ``process_time`` reports
    195.2 ms. ``time.get_clock_info`` cheerfully advertises 1 ns resolution for it. Using it would
    have made every machine look permanently contended and quietly disabled the wall assertion
    below — a green test asserting nothing, which is worse than a red one. The cost of
    ``process_time`` is that the flush worker's CPU counts too; that inflates our own numbers
    slightly, so the assertion errs strict.

    So the CPU tail is asserted tightly. The wall tail is asserted too, but only when the loop's own
    CPU/wall ratio shows the machine was actually idle enough for the number to mean something;
    otherwise it is printed with a note. That preserves the signal we care about — a flush that
    occasionally blocks the caller shows up as *wall* time with no CPU behind it, and on a quiet
    machine it fails the build.
    """
    cpu_p99, wall_p99 = _p(cpu, 0.99), _p(wall, 0.99)
    ratio = sum(cpu) / sum(wall) if sum(wall) else 1.0
    assert cpu_p99 < P99_QUIET_CEILING_US, (
        f"{name} CPU p99 {cpu_p99:.1f}us — the SDK is burning cycles on the caller's thread"
    )
    if ratio >= QUIET_MACHINE_RATIO:
        assert wall_p99 < P99_QUIET_CEILING_US, (
            f"{name} wall p99 {wall_p99:.1f}us on an otherwise-idle machine "
            f"(cpu/wall={ratio:.2f}, CPU p99 only {cpu_p99:.1f}us) — the caller is being blocked"
        )
    else:
        print(f"\n[overhead] NOTE: {name} wall p99 {wall_p99:.1f}us not asserted — machine was "
              f"contended (cpu/wall={ratio:.2f}); CPU p99 was {cpu_p99:.1f}us")
    return wall_p99, cpu_p99


@pytest.fixture
def offline_sdk(monkeypatch):
    """An armed client whose egress is a null sink: measures the caller's cost, nothing else."""
    from nexus import client as client_mod
    from nexus.config import resolve
    from nexus.transport import OK, SendResult, Transport

    class Null:
        def send(self, batch):
            return SendResult(OK)

    cfg = resolve(service="bench", env="test", version="1", queue_capacity=200_000)
    c = client_mod.Client(cfg, transport=Transport(cfg, sink=Null()))
    c.start()
    monkeypatch.setattr(client_mod, "_client", c, raising=False)
    import nexus
    yield nexus
    c.shutdown(0.5)


# -- added latency on the instrumented path -------------------------------------------------------

def test_added_latency_per_action(offline_sdk):
    """The number a customer cares about: what does wrapping one operation cost the caller?"""
    import nexus
    wall, cpu = [], []
    with nexus.agent("bench") as run:
        for _ in range(300):                     # warm-up, discarded
            with run.action("op") as act:
                act.effect(rows=1)
        for _ in range(5000):
            c0, t0 = time.process_time_ns(), time.perf_counter_ns()
            with run.action("op", target="x") as act:
                act.effect(rows=1)
            wall.append((time.perf_counter_ns() - t0) / 1000.0)
            cpu.append((time.process_time_ns() - c0) / 1000.0)
        run.outcome("success")

    p50, p95 = _p(wall, 0.5), _p(wall, 0.95)
    p99, cpu_p99 = _assert_tail("action", wall, cpu)
    _report("action span", p50_us=p50, p95_us=p95, p99_us=p99, cpu_p50_us=_p(cpu, 0.5),
            cpu_p99_us=cpu_p99, min_us=min(wall), mean_us=statistics.mean(wall))
    assert p50 < ACTION_P50_BUDGET_US, f"p50 {p50:.1f}us"
    assert p95 < ACTION_P95_BUDGET_US, f"p95 {p95:.1f}us"


def test_added_latency_per_run(offline_sdk):
    """A run is three events (start, outcome, end) plus a contextvar set and reset."""
    import nexus
    wall, cpu = [], []
    for _ in range(200):
        with nexus.agent("warm") as run:
            run.outcome("success")
    for _ in range(3000):
        c0, t0 = time.process_time_ns(), time.perf_counter_ns()
        with nexus.agent("bench") as run:
            run.outcome("success")
        wall.append((time.perf_counter_ns() - t0) / 1000.0)
        cpu.append((time.process_time_ns() - c0) / 1000.0)

    p50, p95 = _p(wall, 0.5), _p(wall, 0.95)
    p99, cpu_p99 = _assert_tail("run", wall, cpu)
    _report("run span (3 events)", p50_us=p50, p95_us=p95, p99_us=p99, cpu_p50_us=_p(cpu, 0.5),
            cpu_p99_us=cpu_p99, min_us=min(wall))
    assert p50 < RUN_P50_BUDGET_US, f"p50 {p50:.1f}us"
    assert p95 < RUN_P95_BUDGET_US, f"p95 {p95:.1f}us"


def test_the_hot_path_never_touches_the_network(offline_sdk, monkeypatch):
    """Structural companion to the timing tests: timings drift, this does not.

    If a future change makes ``action()`` send synchronously, the numbers above would regress on a
    fast local collector by an amount easily mistaken for noise. Here it fails outright.
    """
    import socket

    import nexus
    calls = []
    real = socket.socket.connect

    def spy(self, addr):
        calls.append(addr)
        return real(self, addr)

    monkeypatch.setattr(socket.socket, "connect", spy)
    with nexus.agent("bench") as run:
        for _ in range(100):
            with run.action("op") as act:
                act.effect(n=1)
        run.outcome("success")
    assert calls == [], f"the calling thread opened {len(calls)} connections"


def test_enqueue_is_constant_time_under_backpressure():
    """A full queue must not be slower than an empty one. Drop-oldest on a deque is O(1); a scan,
    a sort or a re-serialisation on overflow would show up here as a cliff."""
    from nexus.config import resolve
    from nexus.transport import OK, SendResult, Transport

    class Null:
        def send(self, batch):
            return SendResult(OK)

    tr = Transport(resolve(service="b", env="test", version="1",
                           queue_capacity=1000, batch_size=100000), sink=Null())
    ev = {"type": "tool_action", "session_id": "s"}

    empty = []
    for _ in range(1000):                       # fills it exactly
        t0 = time.perf_counter_ns()
        tr.enqueue(dict(ev))
        empty.append(time.perf_counter_ns() - t0)
    full = []
    for _ in range(5000):                       # every one of these evicts
        t0 = time.perf_counter_ns()
        tr.enqueue(dict(ev))
        full.append(time.perf_counter_ns() - t0)

    p95_empty, p95_full = _p(empty, 0.95) / 1000.0, _p(full, 0.95) / 1000.0
    _report("enqueue", p95_empty_us=p95_empty, p95_full_us=p95_full)
    assert p95_full < max(p95_empty * 6, 40.0), "the overflow path is not O(1)"


# -- import / cold-start cost ------------------------------------------------------------------------

def _startup_ms(statement: str, env: dict, runs: int = 7) -> float:
    """Added wall-clock startup cost of ``statement`` over a bare interpreter. Minimum of N."""
    e = dict(os.environ)
    e["PYTHONPATH"] = SRC
    e.update(env)

    def wall(stmt: str) -> float:
        best = float("inf")
        for _ in range(runs):
            t0 = time.perf_counter()
            r = subprocess.run([sys.executable, "-c", stmt], capture_output=True,
                               text=True, env=e, timeout=60)
            best = min(best, (time.perf_counter() - t0) * 1000.0)
            assert r.returncode == 0, r.stderr
        return best

    return max(0.0, wall(statement) - wall("pass"))


def test_import_cost_enabled():
    ms = _startup_ms("import nexus", {"NEXUS_ENABLED": "1"})
    _report("import nexus (enabled)", added_ms=ms)
    assert ms < IMPORT_ADDED_BUDGET_MS, f"import nexus adds {ms:.1f}ms to startup"


def test_import_cost_disabled_is_near_zero():
    """Case 4.12's real claim, and the reason ``nexus/__init__.py`` does not import ``typing``.

    A security reviewer who cannot audit the whole SDK can still accept it if switching it off is
    provably free. "Free" has to mean measured.
    """
    ms = _startup_ms("import nexus", {"NEXUS_ENABLED": "0"})
    _report("import nexus (disabled)", added_ms=ms)
    assert ms < DISABLED_IMPORT_ADDED_BUDGET_MS, f"disabled import adds {ms:.1f}ms"


def test_arming_cost():
    """``import nexus; nexus.init()`` — what a zero-code deployment pays at cold start.

    ``os._exit`` skips ``atexit``, deliberately: the exit-time flush is a real cost but it is a
    *shutdown* cost, and folding it into the arming number would hide both. It has its own test
    directly below.
    """
    ms = _startup_ms(
        "import os, nexus; nexus.init(service='b', env='t', version='1'); os._exit(0)",
        {"NEXUS_ENABLED": "1", "NEXUS_COLLECTOR_PORT": "1"})
    _report("import + init", added_ms=ms)
    assert ms < ARMING_BUDGET_MS, f"arming the SDK adds {ms:.1f}ms to startup"


def test_exit_is_bounded_when_the_collector_is_unreachable():
    """Case 4.8 at process scale: a job that finishes must not be held open by telemetry.

    Nothing is listening, so every send fails and retries. The exit-time flush has a deadline; if
    it did not, a short-lived CLI would appear to hang whenever the collector was down — the most
    visible way an observability SDK can make a system worse.
    """
    e = dict(os.environ)
    e["PYTHONPATH"] = SRC
    e["NEXUS_COLLECTOR_PORT"] = "1"
    e["NEXUS_HTTP_TIMEOUT_S"] = "0.3"
    stmt = ("import nexus\n"
            "nexus.init(service='b', env='t', version='1')\n"
            "with nexus.agent('job') as run:\n"
            "    run.outcome('success')\n")
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, "-c", stmt], capture_output=True, text=True,
                       env=e, timeout=60)
    elapsed = (time.perf_counter() - t0) * 1000.0
    assert r.returncode == 0, r.stderr
    _report("exit with dead collector", total_ms=elapsed)
    assert elapsed < 8000, f"process took {elapsed:.0f}ms to exit against a dead collector"


def test_the_disabled_sdk_imports_nothing_of_its_own(tmp_path):
    r = run_script(
        "import sys, json, nexus\n"
        "nexus.init(service='x'); nexus.agent('y'); nexus.flush()\n"
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('nexus'))))\n",
        tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == ["nexus"]


def test_disabled_call_overhead(tmp_path):
    """With the SDK off, an instrumented block must cost about what a bare ``with`` costs."""
    r = run_script(
        "import json, time, nexus\n"
        "N = 50000\n"
        "for i in range(2000):\n"
        "    with nexus.agent('x') as run:\n"
        "        run.outcome('success')\n"
        "t0 = time.perf_counter()\n"
        "for i in range(N):\n"
        "    with nexus.agent('x') as run:\n"
        "        run.outcome('success')\n"
        "print(json.dumps({'per_us': (time.perf_counter() - t0) / N * 1e6}))\n",
        tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    per = json.loads(r.stdout.strip().splitlines()[-1])["per_us"]
    _report("disabled run block", per_us=per)
    assert per < DISABLED_CALL_BUDGET_US, f"disabled path costs {per:.2f}us per block"


def test_version_matches():
    """``nexus.__version__`` is duplicated in ``__init__`` so the kill switch can stay import-free.
    Duplication is only safe if something checks it."""
    import nexus
    from nexus._version import __version__ as canonical
    assert nexus.__version__ == canonical


def test_publish_overhead_numbers(offline_sdk):
    """Writes ``overhead-latest.json``, which is what ``docs/OVERHEAD.md`` quotes. A receipt, not an
    assertion — CI uploads it so a regression can be dated."""
    import nexus
    samples = []
    with nexus.agent("bench") as run:
        for _ in range(200):
            with run.action("op") as act:
                act.effect(n=1)
        for _ in range(3000):
            t0 = time.perf_counter_ns()
            with run.action("op") as act:
                act.effect(n=1)
            samples.append((time.perf_counter_ns() - t0) / 1000.0)

    payload = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "action_p50_us": round(_p(samples, 0.5), 2),
        "action_p95_us": round(_p(samples, 0.95), 2),
        "action_p99_us": round(_p(samples, 0.99), 2),
        "import_enabled_added_ms": round(_startup_ms("import nexus",
                                                     {"NEXUS_ENABLED": "1"}, runs=5), 2),
        "import_disabled_added_ms": round(_startup_ms("import nexus",
                                                      {"NEXUS_ENABLED": "0"}, runs=5), 2),
    }
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "overhead-latest.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    _report("published", **{k: float(v) for k, v in payload.items()
                            if isinstance(v, (int, float))})
