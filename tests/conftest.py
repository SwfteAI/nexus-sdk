"""Shared fixtures.

Two things are worth stating up front because they shape every test in this suite.

**Global state is reset between tests, aggressively.** The SDK is a singleton with a background
thread, an ``atexit`` hook, a ``SIGTERM`` handler, fork hooks and process-wide counters. A test that
leaks any of those makes the *next* test flaky, and a flaky failure-mode suite is worse than none —
it trains everyone to re-run it. ``_isolate`` tears all of it down.

**The collector is a real HTTP server, not a mock.** The failure modes this SDK exists to survive
are HTTP failures: connection refused, slow responses, 429 with ``Retry-After``, 401, 415 on a
gzipped body. A mocked sink would assert our own beliefs about those back to us. ``FakeCollector``
speaks the same wire protocol as ``nexus_devtools/collector.py``'s ``POST /v1/events`` and can be
told to misbehave.
"""
from __future__ import annotations

import gzip
import json
import os
import socket
import sys
import threading
import time
import typing as t
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


class FakeCollector:
    """A ``POST /v1/events`` endpoint that can be told to fail in specific ways."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.requests: list[dict] = []
        self.status = 202
        self.delay = 0.0
        self.lock = threading.Lock()
        self._srv: t.Optional[ThreadingHTTPServer] = None
        self.retry_after: t.Optional[str] = None

    # -- lifecycle -----------------------------------------------------------------
    def start(self) -> "FakeCollector":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n)
                if outer.delay:
                    time.sleep(outer.delay)
                enc = self.headers.get("Content-Encoding")
                body = gzip.decompress(raw) if enc == "gzip" else raw
                status = outer.status
                parsed = None
                if status < 400:
                    try:
                        parsed = json.loads(body.decode("utf-8"))
                    except Exception:  # noqa: BLE001
                        status = 400
                with outer.lock:
                    outer.requests.append({
                        "path": self.path,
                        "gzip": enc == "gzip",
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "bytes": len(raw),
                    })
                    if parsed is not None:
                        outer.events.extend(parsed.get("events") or [])
                payload = json.dumps({"accepted": len(parsed.get("events", []))} if parsed
                                     else {"error": "nope"}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                if outer.retry_after is not None:
                    self.send_header("Retry-After", outer.retry_after)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):  # noqa: ANN002
                pass

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._srv.daemon_threads = True
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None

    # -- inspection ----------------------------------------------------------------
    @property
    def url(self) -> str:
        assert self._srv is not None
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def wait_for(self, n: int, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                if len(self.events) >= n:
                    return True
            time.sleep(0.01)
        with self.lock:
            return len(self.events) >= n

    def types(self) -> list[str]:
        with self.lock:
            return [e.get("type") for e in self.events]

    def of_type(self, name: str) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e.get("type") == name]


@pytest.fixture
def collector():
    c = FakeCollector().start()
    try:
        yield c
    finally:
        c.stop()


def free_port() -> int:
    """A port nothing is listening on — for the 'collector unreachable' cases."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
def _isolate():
    """Return the process to a pristine state around every test."""
    from nexus import _counters, _safety, client, context, hooks, runtime

    saved_env = {k: v for k, v in os.environ.items() if k.startswith("NEXUS_")}

    def cleanup():
        client._reset_for_tests()
        context.clear_for_fork()
        _counters.reset()
        _safety.clear_faults()
        # Policy holds process-global state (installed snapshot, registered approvers, settings,
        # the alert ring). Without this, one test that installs an enforcing deny leaks it into
        # every test after it. The try keeps this safe if policy is ever made optional at build time.
        try:
            from nexus import policy
            policy.reset_for_tests()
        except Exception:  # noqa: BLE001
            pass
        runtime._reset_fork_hooks_for_tests()
        runtime._reset_shutdown_hooks_for_tests()
        try:
            hooks.uninstall()
        except Exception:  # noqa: BLE001
            pass
        for k in [k for k in os.environ if k.startswith("NEXUS_")]:
            del os.environ[k]
        os.environ.update(saved_env)

    cleanup()
    try:
        yield
    finally:
        cleanup()


@pytest.fixture
def sdk(collector, monkeypatch):
    """An initialised client pointed at the fake collector."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    yield nexus
    try:
        nexus.shutdown()
    except Exception:  # noqa: BLE001
        pass


def run_script(body: str, tmp_path, env: t.Optional[dict] = None,
               args: t.Optional[list] = None, timeout: float = 60.0):
    """Run a script in a fresh interpreter. Returns ``CompletedProcess``.

    A subprocess is not paranoia here: fork hooks, ``sitecustomize``, ``SIGTERM`` handlers, gevent
    monkeypatching and import cost are all properties of *interpreter startup*, and none of them can
    be observed honestly from inside a process that has already started.
    """
    import subprocess
    p = tmp_path / f"prog_{abs(hash(body)) % 10**8}.py"
    p.write_text(body)
    e = dict(os.environ)
    e["PYTHONPATH"] = os.pathsep.join([SRC, e.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    e.setdefault("NEXUS_ENABLED", "1")
    e.update(env or {})
    return subprocess.run([sys.executable, str(p)] + list(args or []),
                          capture_output=True, text=True, env=e, timeout=timeout)


class _DrivenClock:
    """A `engine._perf` stand-in that is real until told otherwise, then pins a fixed elapsed.

    It has to be armed rather than always-on because the case-6.4 test needs one ordinary decision
    first — the ``enforce``-marked deny that the timeout is then shown to override. A clock that
    lied from the first read made that setup line fail, which is how this got written twice.
    """

    def __init__(self, elapsed_s):
        self._elapsed = elapsed_s
        self._t0 = None
        self.engaged = False

    def engage(self):
        self.engaged = True

    def __call__(self):
        import time as _t
        if not self.engaged:
            return _t.perf_counter()
        if self._t0 is None:
            self._t0 = _t.perf_counter()
            return self._t0
        return self._t0 + self._elapsed


@pytest.fixture
def driven_clock(monkeypatch):
    """Install a deadline clock pinned at an elapsed the test picks, in milliseconds.

    The elapsed is the whole point: a budget test can only distinguish two budgets by sitting
    between them. A clock that breaches everything proves only that fail-open exists, which is
    what let an over-correction (flooring the caller at the operator's budget, deleting the
    feature) survive the first version of this control.
    """
    from nexus.policy import engine

    def make(elapsed_ms, *, armed=True):
        clock = _DrivenClock(elapsed_ms / 1000.0)
        if armed:
            clock.engage()
        monkeypatch.setattr(engine, "_perf", clock)
        return clock

    return make


@pytest.fixture
def slow_evaluation(monkeypatch):
    """An evaluation that overruns whatever budget it was given, once armed.

    Case 6.4 is about an evaluation that takes too long. Every test of it used to reach that state
    by passing ``budget_ms=0.0``, which is not a slow evaluation — it is a budget that cannot be
    met, and it was also a hole (a caller could erase an enforcing deny into a record
    shaped like an infrastructure timeout). With the floor in place that route is gone, so the
    condition has to be produced honestly.

    Racing a real budget is not an option either: measured over 5000 samples on this hardware a
    50-rule decision has p50=0.06ms and a max of 31ms, so a test that waits for a budget to lapse
    is flaky in both directions. `engine._perf` exists to be driven instead.

    Call ``engage()`` when the slow decision is the next one. 100s of elapsed breaches any budget
    on the first deadline check, regardless of how often `first_match` looks.
    """
    from nexus.policy import engine

    clock = _DrivenClock(100.0)
    monkeypatch.setattr(engine, "_perf", clock)
    return clock


@pytest.fixture
def unhurried_evaluation(monkeypatch):
    """The opposite: a clock pinned at half a millisecond of elapsed, armed immediately.

    Used to prove the budget floor is load-bearing without a timing race. Under it a caller-
    nominated ``budget_ms=0.0`` must still reach its rule, because the floor lifts the budget to
    1.0ms and 0.5ms is inside it. Before the floor, 0.5ms against a 0.0ms budget expired at once —
    which is exactly the difference the negative control has to be able to see.
    """
    from nexus.policy import engine

    clock = _DrivenClock(0.0005)
    clock.engage()
    monkeypatch.setattr(engine, "_perf", clock)
    return clock
