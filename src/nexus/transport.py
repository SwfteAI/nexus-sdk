"""Bounded, non-blocking egress. The half of the SDK that is allowed to lose data, on purpose.

The governing rule of ``F3-SDK-RUNTIME-CASES.md`` §4 is that **a telemetry SDK must never be the
reason a request fails.** That has an unpopular corollary which this module implements literally:
when the collector is down, or slow, or the queue is full, *we throw telemetry away*. Blocking the
caller would be the alternative, and the alternative is an outage.

The part people get wrong is the second half of case 4.3: **drops are counted.** An SDK that drops
silently is not degrading gracefully, it is lying — every coverage figure, cost total and "no
policy violations this week" downstream becomes unfalsifiable. So ``_counters.QUEUE_DROPPED``
increments on every eviction and rides out in ``pipeline_health``.

Design notes that are not obvious:

* **Drop *oldest*, not newest.** Under sustained backpressure the newest events describe what is
  happening now; the oldest describe a minute of history nobody will look at. Dropping the newest
  also biases the loss toward exactly the incident you are trying to observe.
* **The queue is bounded in events, not bytes.** Byte-bounding requires serialising before the
  admission decision, i.e. paying the CPU cost of the event you are about to discard, on the
  request path.
* **Critical sections are two statements long and never do I/O.** Under gevent, ``threading.Lock``
  is a greenlet lock and any yield inside the section can be re-entered by another greenlet on the
  same OS thread (case 1.10). Serialisation, HTTP and retry sleeps all happen outside the lock.
* **The worker thread is a daemon.** A non-daemon thread keeps the interpreter alive; shutdown is
  handled explicitly by ``flush`` with a deadline (case 4.8) rather than by hoping the queue
  drains.
* **Sync mode is a first-class path, not a degraded one.** Under uWSGI without ``--enable-threads``
  and under Lambda there is no usable background thread, and a spun-up-but-never-scheduled worker
  looks healthy while delivering nothing (cases 1.4, 1.11).
"""
from __future__ import annotations

import collections
import gzip
import json
import logging
import threading
import time
import typing as t

from . import _counters
from .config import Config, _is_loopback, host_of
from .runtime import RuntimeProfile, detect

log = logging.getLogger("nexus.transport")

# Result of one send attempt. Three outcomes, because the retry policy differs for each and
# conflating "the collector is restarting" with "our key was revoked" produces either a hot retry
# loop against a 403 or a permanent data loss on a transient blip.
OK = "ok"
RETRY = "retry"        # transient: connection refused, 5xx, timeout, 429
FATAL = "fatal"        # do not retry this credential: 401, 403, 400-class contract error


class SendResult(t.NamedTuple):
    status: str
    retry_after_s: float = 0.0
    detail: str = ""


class Sink(t.Protocol):
    def send(self, batch: t.Sequence[dict]) -> SendResult: ...


_urlreq: t.Any = None
_urlerr: t.Any = None


def _load_urllib() -> tuple:
    """Import ``urllib`` on first send rather than at module scope.

    Measured on CPython 3.12, ``import urllib.request`` costs ~32 ms of wall clock on a cold
    interpreter — more than everything else in this SDK put together (see ``docs/OVERHEAD.md``).
    That is charged to the cold start of every Lambda and every short-lived job whether or not a
    single event is ever sent, which is the wrong place to spend it. Deferring it moves the cost
    onto the flush worker, off the application's startup path entirely.

    The import is idempotent and racy-safe: two threads arriving together both import (the import
    lock makes that cheap) and both assign the same module objects.
    """
    global _urlreq, _urlerr
    if _urlreq is None:
        import urllib.error as _e
        import urllib.request as _r
        _urlreq, _urlerr = _r, _e
    return _urlreq, _urlerr


_PROXIES: t.Optional[dict] = None


def _proxies() -> dict:
    """Resolve proxies from the **environment only** — never from the OS.

    ``urllib.request``'s default opener calls ``getproxies()``, which on macOS calls into
    ``_scproxy`` → SystemConfiguration → the Objective-C runtime. Doing that in a process forked
    from a *threaded* parent aborts the child outright:

        objc[…]: +[__NSCFConstantString initialize] may have been in progress in another thread
        when fork() was called.

    A gunicorn worker dying at its first telemetry flush is precisely the failure this SDK exists
    not to cause. Hoisting the lookup into the parent would fix the abort but not the cost, so we
    take the narrower door instead: ``getproxies_environment()`` reads ``HTTPS_PROXY``/``NO_PROXY``
    and nothing else. It is pure ``os.environ`` — safe in a forked child, safe under gevent, and
    free. The convention it implements is also the only one that exists in a container, which is
    where this SDK actually runs; a developer's macOS System Settings proxy is not something a
    telemetry client should silently route through in any case.

    Cached because the answer cannot change within a process. ``reinit_after_fork`` deliberately
    does not clear it — the environment is inherited.
    """
    global _PROXIES
    if _PROXIES is None:
        try:
            _PROXIES = _load_urllib()[0].getproxies_environment()
        except Exception:  # noqa: BLE001
            _PROXIES = {}
    return _PROXIES


def _effective_proxy(url: str) -> str:
    """The proxy that will actually carry ``url``, or ``""`` for a direct connection.

    **This function exists so that the credential guard and the opener cannot disagree.** The two
    have to answer the same question — does this request leave the machine, and to whom — and when
    they were answered separately the guard reasoned about the URL while the opener reasoned about
    the environment. A loopback URL therefore looked safe to one and got proxied to a third party
    by the other. Both now call this.

    Loopback is never proxied. That is both the correct behaviour (proxying a connection that does
    not leave the host is meaningless) and the reason a loopback collector can still carry a
    credential when ``HTTP_PROXY`` is set for everything else.
    """
    if _is_loopback(host_of(url)):
        return ""
    scheme = url.partition("://")[0].strip().lower()
    if not scheme:
        return ""
    proxy = _proxies().get(scheme, "")
    if not proxy:
        return ""
    try:
        # Honour NO_PROXY, so an operator who has already excluded the collector is not
        # silently downgraded to no-credential.
        if _load_urllib()[0].proxy_bypass_environment(host_of(url)):
            return ""
    except Exception:  # noqa: BLE001
        pass
    return proxy


class HttpSink:
    """``POST /v1/events`` to the local collector or to a sidecar.

    Uses ``urllib`` rather than ``requests`` because the core ring has zero dependencies, and
    rather than a persistent connection pool because the events-per-second of an agent workload is
    tens, not thousands — a keep-alive pool would be an extra failure mode (stale sockets across
    fork, half-open connections behind a load balancer) bought for no measurable gain.

    Case 2.19: this client must never itself be instrumented. Auto-instrumentation of HTTP
    libraries would otherwise make every flush generate events, which generate a flush. That is not
    a slowdown, it is an unbounded recursion — so the module is named in
    ``integrations.EXCLUDED_MODULES`` and the request carries a marker header the wrapper's own
    capture also skips on.
    """

    #: Requests carrying this header are the SDK's own egress. Anything instrumenting HTTP must
    #: skip them. Checked by ``tests/test_failure_modes.py::test_self_exclusion``.
    MARKER_HEADER = "X-Nexus-Sdk-Egress"

    def __init__(self, cfg: Config) -> None:
        self.url = cfg.events_url
        self.timeout = cfg.http_timeout_s
        self.api_key = cfg.api_key
        #: Latched once the peer has rejected gzip. The wrapper learned this the hard way with a
        #: WAF that 400s on Content-Encoding it does not expect; re-negotiating per request would
        #: mean one wasted round trip per batch forever.
        self._gzip_unsupported = False
        #: Latched on 401/403 — case 4.4. A rotated key must surface once and then stop
        #: generating load; hammering an auth endpoint from every worker in a fleet is how a
        #: telemetry SDK gets an entire customer's egress rate-limited.
        self.auth_failed = False
        #: Built on first send, not here — constructing an opener requires ``urllib``, and paying
        #: that import to *arm* the SDK charges startup for egress that may never happen. See
        #: ``_load_urllib``. Safe to build in a forked child because ``_proxies`` never touches
        #: the OS proxy APIs.
        self._opener: t.Any = None

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", self.MARKER_HEADER: "1",
             "User-Agent": "nexus-sdk"}
        if self.api_key and self._auth_allowed():
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _auth_allowed(self) -> bool:
        """Never put a bearer token on cleartext leaving the machine.

        Loopback plaintext is fine — the bytes do not cross a network. Remote
        plaintext is not: the key is readable by anything on the path, and it
        makes the redirect leak trivially exploitable, because injecting a redirect
        needs no collector compromise at all when the transport is cleartext.

        Withholding the header rather than refusing to send is deliberate. The
        collector answers 401, the SDK latches `auth_failed` and stops — so the
        operator gets a visible, diagnosable failure instead of a silent
        credential disclosure. Telemetry stopping is recoverable; a leaked key
        is not.
        """
        url = (self.url or "").strip()
        if url.partition("://")[0].lower() == "https":
            # End-to-end TLS. A proxy in the path sees a CONNECT and a hostname, not the header.
            return True
        if _effective_proxy(url):
            # For a cleartext destination urllib does not tunnel: it sends the whole
            # request — request line, headers, body — to the proxy. The destination being
            # loopback is then irrelevant, because the bytes are not going to the destination.
            # Measured: with HTTP_PROXY set and a loopback collector URL, the bearer token
            # arrived at the proxy in cleartext while ``send()`` returned ``ok``.
            return False
        return _is_loopback(host_of(url))

    def _ensure_opener(self) -> t.Any:
        """Build the opener, with redirects REFUSED rather than followed.

        A collector endpoint has no legitimate reason to redirect, and following
        one is a credential disclosure. Verified empirically on CPython 3.12.13
        against this exact class: with the default opener, a 302 from the
        configured collector to a DIFFERENT host replays
        ``Authorization: Bearer <api_key>`` to that host — and because urllib
        follows the redirect and the target answers 200, ``send()`` returns
        ``ok``. The customer's key reaches a third party and nothing reports it.

        The path is not exotic. ``NEXUS_COLLECTOR_URL`` is customer-configured:
        a typo, a stale CNAME, an expired domain someone else now owns, or a
        proxy that helpfully upgrades a scheme are all one redirect. The SDK
        runs inside their production process, so the blast radius is their key.

        A second bug rides along: urllib rewrites POST to GET on a 302, so the
        event body is dropped. Telemetry silently stops arriving while the
        transport reports success.

        Refusing is better than stripping the header on cross-host hops. An
        observability sink that quietly follows its endpoint somewhere else is
        wrong even when no credential moves — the operator should be told their
        URL is not the thing answering, and a surfaced ``http 302`` says so.
        """
        if self._opener is None:
            req = _load_urllib()[0]

            class _NoRedirect(req.HTTPRedirectHandler):
                def redirect_request(self, *_a: t.Any, **_kw: t.Any) -> None:
                    # None => urllib stops and returns the 3xx response itself,
                    # which `send` classifies as a retryable non-2xx. No new
                    # request is built, so no header can be replayed.
                    return None

            # ``{}`` disables proxying for this opener, which is right whenever
            # ``_effective_proxy`` says the request is direct — a sink has exactly one URL, so
            # there is no second destination this could wrongly apply to. Passing the raw
            # ``_proxies()`` here regardless was half of the same defect: the guard cleared a loopback URL
            # while this handler quietly routed it to ``HTTP_PROXY``.
            proxies = _proxies() if _effective_proxy(self.url or "") else {}
            self._opener = req.build_opener(req.ProxyHandler(proxies), _NoRedirect())
        return self._opener

    def send(self, batch: t.Sequence[dict]) -> SendResult:
        if self.auth_failed:
            return SendResult(FATAL, detail="auth latched")
        try:
            body = json.dumps({"events": list(batch)}, default=str).encode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 — an unserialisable event must not wedge the queue
            _counters.incr(_counters.BUILD_FAILED, len(batch))
            return SendResult(FATAL, detail=f"encode: {type(exc).__name__}: {exc}")
        headers = self._headers()
        if not self._gzip_unsupported and len(body) > 1024:
            body = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
        opener = self._ensure_opener()
        urlreq, urlerr = _load_urllib()
        req = urlreq.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                if 200 <= resp.status < 300:
                    return SendResult(OK)
                return SendResult(RETRY, detail=f"http {resp.status}")
        except urlerr.HTTPError as exc:
            if exc.code in (401, 403):
                self.auth_failed = True
                return SendResult(FATAL, detail=f"http {exc.code}")
            if exc.code == 429:
                try:
                    wait = float(exc.headers.get("Retry-After", "1"))
                except (TypeError, ValueError):
                    wait = 1.0
                return SendResult(RETRY, retry_after_s=min(wait, 30.0), detail="http 429")
            if exc.code == 415 and "Content-Encoding" in headers:
                self._gzip_unsupported = True     # fail-safe to uncompressed (case 4.6)
                return SendResult(RETRY, detail="gzip unsupported")
            if 400 <= exc.code < 500:
                return SendResult(FATAL, detail=f"http {exc.code}")
            return SendResult(RETRY, detail=f"http {exc.code}")
        except Exception as exc:  # noqa: BLE001 — URLError, socket.timeout, ssl, DNS, everything
            return SendResult(RETRY, detail=f"{type(exc).__name__}: {exc}")


class Transport:
    """The bounded queue and its drain.

    One instance per process. Rebuilt wholesale in a forked child — see ``reinit_after_fork``.
    """

    def __init__(self, cfg: Config, sink: t.Optional[Sink] = None,
                 profile: t.Optional[RuntimeProfile] = None) -> None:
        self.cfg = cfg
        # Detect rather than assume. A ``RuntimeProfile()`` default would silently claim threads
        # are available, which is the one wrong answer under uWSGI (case 1.4) — and it would be
        # wrong only in the deployment we cannot test locally.
        self.profile = profile if profile is not None else detect()
        self.sink: Sink = sink if sink is not None else HttpSink(cfg)
        self._lock = threading.Lock()
        self._q: collections.deque = collections.deque()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: t.Optional[threading.Thread] = None
        self._sending = threading.Lock()   # serialises flushes; never held across an enqueue
        self.last_send_ok: t.Optional[bool] = None
        self.mode = self._decide_mode()
        # -- worker-thread observers (ANCHOR-INTEGRATION §6.3) --------------------------------
        # ``on_batch`` sees every batch on its way out; ``on_tick`` fires once per loop iteration.
        # Both are set by ``Client`` and are the seam the ``service_health`` rollup hangs off, which
        # is why they live here rather than in ``Client``: this is the only code that runs on the
        # flush thread, and the rollup's whole claim is that it never runs anywhere else. Both are
        # optional and both are contained — an observer that raises degrades telemetry, it does not
        # stop the drain.
        self.on_batch: t.Optional[t.Callable[[t.Sequence[dict]], None]] = None
        self.on_tick: t.Optional[t.Callable[[], None]] = None

    # -- mode ---------------------------------------------------------------------------------

    def _decide_mode(self) -> str:
        """``"thread"`` or ``"sync"``. Never spin a thread that will not run (case 1.4)."""
        want = (self.cfg.transport_mode or "auto").lower()
        if want in ("thread", "sync"):
            return want
        if not self.profile.threads_available:
            return "sync"       # uWSGI without --enable-threads
        if self.profile.is_lambda:
            return "sync"       # the sandbox freezes between invocations (case 1.11)
        return "thread"

    # -- lifecycle ----------------------------------------------------------------------------

    def start(self) -> None:
        """Start the drain, if this runtime has one.

        Deliberately *not* called from ``__init__``: under ``gunicorn --preload`` (case 1.3) the
        SDK is constructed in the master before ``fork()``, and a thread or socket created there is
        either lost or, worse, shared. Construction is inert; starting is a separate, explicit step
        that the fork hook can repeat in each child.
        """
        if self.mode != "thread" or self._worker is not None:
            return
        self._stop.clear()
        w = threading.Thread(target=self._run, name="nexus-flush", daemon=True)
        self._worker = w
        w.start()

    def reinit_after_fork(self) -> None:
        """Rebuild everything that a ``fork()`` invalidated — case 1.2, and the reason this SDK
        does not hang a pre-fork worker on its first request.

        Three things are wrong in the child and only one of them is obvious:

        1. The worker thread does not exist. (Obvious.)
        2. ``self._lock`` may have been inherited *locked*, by a thread that no longer exists, so
           any acquire deadlocks forever. It is replaced, not acquired.
        3. The queue holds the **parent's** buffered events. If the child keeps them, all N
           workers ship the same pre-fork window and the ledger gets N duplicates of it — which
           reads as a traffic spike and corrupts every cost figure derived from that minute. The
           parent still owns them, so the child drops them and says so.
        """
        inherited = len(self._q)
        self._lock = threading.Lock()
        self._sending = threading.Lock()
        self._q = collections.deque()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker = None
        # A fresh connection state too: sockets and any latched peer facts belong to the parent.
        if isinstance(self.sink, HttpSink):
            self.sink = HttpSink(self.cfg)
        self.mode = self._decide_mode()
        if inherited:
            # Not a drop we caused, but a drop the ledger must be able to see; counting it under
            # the same name keeps "events in minus events out" reconcilable.
            _counters.incr(_counters.QUEUE_DROPPED, inherited)
        self.start()

    # -- enqueue ------------------------------------------------------------------------------

    def enqueue(self, event: dict) -> bool:
        """Admit one event. Returns False if it was dropped. Never blocks, never raises."""
        dropped = 0
        with self._lock:
            if len(self._q) >= self.cfg.queue_capacity:
                self._q.popleft()          # drop-oldest; see the module docstring
                dropped = 1
            self._q.append(event)
            depth = len(self._q)
            ready = depth >= self.cfg.batch_size
        # everything below is outside the lock, on purpose (gevent yields, case 1.10)
        if dropped:
            _counters.incr(_counters.QUEUE_DROPPED, dropped)
        _counters.incr(_counters.EVENTS_ENQUEUED)
        _counters.observe_max(_counters.QUEUE_DEPTH_PEAK, depth)
        if ready:
            if self.mode == "sync":
                self.flush(self.cfg.flush_deadline_s)
            else:
                self._wake.set()
        return not dropped

    def depth(self) -> int:
        with self._lock:
            return len(self._q)

    def _take(self, n: int) -> list[dict]:
        with self._lock:
            return [self._q.popleft() for _ in range(min(n, len(self._q)))]

    def _requeue_front(self, batch: t.Sequence[dict]) -> None:
        """Put a failed batch back at the head, respecting the bound.

        Requeueing is what makes a transient collector restart survivable (case 4.1), but it must
        not be able to grow the queue past its cap — an unbounded retry buffer is the same
        unbounded memory growth the cap exists to prevent, just spelled differently.
        """
        dropped = 0
        with self._lock:
            room = self.cfg.queue_capacity - len(self._q)
            keep = list(batch)[-room:] if room > 0 else []
            dropped = len(batch) - len(keep)
            for ev in reversed(keep):
                self._q.appendleft(ev)
        if dropped:
            _counters.incr(_counters.QUEUE_DROPPED, dropped)

    # -- drain --------------------------------------------------------------------------------

    def _in_worker(self) -> bool:
        """True only on the flush thread.

        Guards the observers below. ``_drain`` is reachable from the application's own thread via
        ``nexus.flush()`` and at shutdown, and the §6.3 promise is that aggregation happens on the
        worker and nowhere else. An identity comparison is the cheapest way to make that promise
        literally true instead of true-in-the-cases-we-tested.
        """
        return self._worker is not None and threading.current_thread() is self._worker

    def _observe(self, batch: t.Sequence[dict]) -> None:
        cb = self.on_batch
        if cb is None or not self._in_worker():
            return
        try:
            cb(batch)
        except Exception:  # noqa: BLE001 — an observer must never be why a batch stops flowing
            _counters.incr(_counters.HOOK_ERROR)

    def _tick(self) -> None:
        cb = self.on_tick
        if cb is None:
            return
        try:
            cb()
        except Exception:  # noqa: BLE001
            _counters.incr(_counters.HOOK_ERROR)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.cfg.flush_interval_s)
            self._wake.clear()
            try:
                self._drain(deadline=time.monotonic() + self.cfg.flush_deadline_s)
            except Exception:  # noqa: BLE001 — a flusher that can die is worse than useless
                _counters.incr(_counters.HOOK_ERROR)
            # After the drain, so a rolled-up event lands in the next batch rather than waiting a
            # full interval, and outside the try above so a failing drain still lets health tick.
            self._tick()

    def _drain(self, deadline: float) -> bool:
        """Send batches until the queue is empty or the deadline passes. Returns True if empty."""
        if not self._sending.acquire(blocking=False):
            return False        # another flush is in flight; two senders would reorder batches
        try:
            while time.monotonic() < deadline:
                batch = self._take(self.cfg.batch_size)
                if not batch:
                    return True
                if not self._send_with_retry(batch, deadline):
                    return False
                # **After** a successful send, never before. A failed send requeues the batch at the
                # head, and a batch observed on the way in would be observed again on every retry —
                # so a collector outage, the moment you least want invented numbers, would inflate
                # every span count in the rollup. Spans lost to queue overflow are likewise never
                # observed, which keeps the rollup reconcilable against the drop counters.
                self._observe(batch)
            _counters.incr(_counters.FLUSH_TIMEOUT)
            return False
        finally:
            self._sending.release()

    def _send_once(self, batch: list[dict]) -> SendResult:
        """Call the sink. **A sink may never raise into the caller.**

        The worker loop already contains exceptions, but ``flush()`` is called from the
        application's own thread — at shutdown, at the end of a Lambda handler, from a test — and on
        that path an exception out of the sink would be an exception out of ``nexus.flush()``. That
        is case 4.7 exactly, and it is not hypothetical: ``Sink`` is a Protocol, so the sink may be
        a customer's own class. Containment belongs at the boundary where the foreign code is
        called, not at each of the several places that call it.
        """
        try:
            return self.sink.send(batch)
        except Exception as exc:  # noqa: BLE001
            _counters.incr(_counters.HOOK_ERROR)
            log.debug("sink raised: %s", exc)
            return SendResult(RETRY, detail=type(exc).__name__)

    def _send_with_retry(self, batch: list[dict], deadline: float) -> bool:
        attempt = 0
        while True:
            res = self._send_once(batch)
            if res.status == OK:
                self.last_send_ok = True
                _counters.incr(_counters.SEND_OK)
                _counters.incr(_counters.EVENTS_SENT, len(batch))
                return True
            if res.status == FATAL:
                # Rotated key, or a contract error the peer will reject identically forever.
                # Surface once (the sink latches), drop the batch, keep the app healthy (case 4.4).
                self.last_send_ok = False
                _counters.incr(_counters.SEND_ABANDONED, len(batch))
                self._spill(batch)
                return True
            self.last_send_ok = False
            _counters.incr(_counters.SEND_FAILED)
            attempt += 1
            if attempt > self.cfg.max_retries:
                self._requeue_front(batch)
                return False
            # exponential backoff, honouring Retry-After, clamped by the caller's deadline so a
            # 429 with a huge Retry-After cannot extend a shutdown flush past the grace period
            wait = res.retry_after_s or min(0.1 * (2 ** (attempt - 1)), 2.0)
            remaining = deadline - time.monotonic()
            if wait >= remaining:
                self._requeue_front(batch)
                return False
            time.sleep(wait)

    def _spill(self, batch: t.Sequence[dict]) -> None:
        """Optional durable overflow. Off unless ``spill_dir`` is configured.

        Off by default because containers are frequently read-only and often have no writable
        volume; a telemetry SDK that raises ``OSError: [Errno 28] No space left on device`` into a
        request handler has become the reason the request failed. When it *is* configured, a full
        or read-only disk increments ``disk_error`` and is otherwise ignored — the events are lost,
        which is the correct trade against failing the host process, and the counter is what keeps
        that honest.
        """
        if not self.cfg.spill_dir:
            return
        import os
        try:
            os.makedirs(self.cfg.spill_dir, exist_ok=True)
            path = os.path.join(self.cfg.spill_dir, f"nexus-spill-{int(time.time())}.jsonl")
            with open(path, "a", encoding="utf-8") as fh:
                for ev in batch:
                    fh.write(json.dumps(ev, default=str) + "\n")
        except Exception:  # noqa: BLE001 — disk full, read-only fs, permissions, ENOSPC
            _counters.incr(_counters.DISK_ERROR)

    # -- explicit flush -----------------------------------------------------------------------

    def flush(self, deadline_s: t.Optional[float] = None) -> bool:
        """Drain synchronously within a hard deadline. Returns True if the queue emptied.

        The deadline is not advisory. This is called from ``atexit``, from the ``SIGTERM`` handler
        and from the Lambda return path, and in all three the caller is inside somebody else's
        budget: an unbounded flush turns container shutdown into a hang (4.8), and on Lambda it
        turns into billed wall-clock the customer pays for.
        """
        d = self.cfg.flush_deadline_s if deadline_s is None else deadline_s
        return self._drain(deadline=time.monotonic() + max(0.0, d))

    def shutdown(self, deadline_s: t.Optional[float] = None) -> bool:
        ok = self.flush(deadline_s)
        self._stop.set()
        self._wake.set()
        w = self._worker
        if w is not None and w.is_alive() and w is not threading.current_thread():
            w.join(timeout=0.5)
        self._worker = None
        return ok
