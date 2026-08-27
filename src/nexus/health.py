"""``service_health`` — derived from spans we already have, on the thread that already exists.

``ANCHOR-INTEGRATION.md`` §6.3. Availability, latency and error rate are the PRD's §8, and the
tempting way to get them is a new instrumentation ask: a ``nexus.request()`` wrapper the customer
threads through every handler. That ask is why most observability adoptions stall, and it is
unnecessary — the SDK already brackets every ``action`` span and already knows how long each took
and whether it ended in an exception. This module reads those spans and rolls them up.

**Where the work happens, and why it is not negotiable.** The rollup runs in the flush worker, on
the drain path, over batches that are on their way out anyway. Concretely:

* The calling thread does **nothing** extra. No counter, no timestamp, no lock — an action span
  costs exactly what it cost before this file existed, which the overhead suite enforces.
* ``observe()`` is called only when the *worker* thread is draining. An explicit ``nexus.flush()``
  from the application's own thread drains without aggregating, because the alternative is a
  guarantee ("the calling thread never performs I/O, and now: never aggregates") with a hole in it
  that only appears under a call pattern nobody tests.
* In ``sync`` transport mode there is no worker thread, so there is no rollup at all. That is the
  honest outcome rather than a fallback: uWSGI-without-threads and Lambda would have to pay for the
  aggregation on the request path, and a p99 is not worth a request's latency. Those runtimes get
  ``service_health`` from an APM connector or not at all.

**What is measured, stated plainly, because the wire key invites a stronger reading.** ``requests``
on this event, when the SDK is the producer, is *the number of action spans observed*, not the
number of HTTP requests served. An application that instruments one action per request makes the
two identical; one that instruments three makes them differ by 3×; one that instruments none emits
nothing at all. Which is the reason for the rule below.

**An empty window emits nothing.** Zero observed spans does not mean zero requests — it much more
often means "this service never calls ``run.action``". Writing ``requests: 0`` there would be the
exact fabricated zero the plane forbids, and it would read on the console as a measured outage.
``nexus.heartbeat()`` exists for the honest version of that statement: a window with a timestamp and
no quantities, which says *this process was alive and nothing was measured*.

**Percentiles.** Exact within the reservoir, which holds the most recent ``_RESERVOIR`` durations of
the window; ``requests`` and ``errors`` are always true counts. The contract carries no sample-count
field, so the approximation is recorded here rather than on the wire — at the default 60 s window a
service would need to sustain ~136 spans/second before the cap binds at all.
"""
from __future__ import annotations

import collections
import threading
import time
import typing as t

from . import contract
from .config import Config

#: Most recent durations retained per window for the percentile calculation. Bounded because a
#: window is wall-clock-bounded, not volume-bounded, and an unbounded list here would be a memory
#: leak with a traffic spike as its trigger.
_RESERVOIR = 8192

#: The span type we derive from. One name, in one place: the day ``tool_action`` is renamed on the
#: wire, this file must fail loudly rather than silently roll up nothing forever.
SPAN_TYPE = "tool_action"


def _pct(sorted_ms: t.Sequence[float], q: float) -> t.Optional[float]:
    """Nearest-rank percentile. ``None`` for an empty sample — never 0.0, which is a latency.

    ``rank = ceil(q * n)``, the textbook definition, spelled without importing ``math``: the p95 of
    a sample is an observation that was actually in the sample, not an interpolation between two.
    An interpolated p99 over twenty requests invents a latency nobody experienced.
    """
    n = len(sorted_ms)
    if n == 0:
        return None
    scaled = q * n
    rank = int(scaled)
    if scaled > rank:
        rank += 1
    rank = max(1, min(n, rank))
    return round(float(sorted_ms[rank - 1]), 3)


class HealthRollup:
    """Per-window accumulator. One per client; touched by the worker thread and by ``roll()``.

    The lock is held for the length of a list append and nothing else. It exists because
    ``heartbeat()`` and ``shutdown()`` can call ``roll()`` from the application's thread while the
    worker is mid-``observe()``, and a torn read there would produce a window whose ``requests``
    and percentiles describe different sets of spans — a subtle wrongness that would survive review.

    **``roll()`` acquires it non-blockingly, and that is not an optimisation.** The stop path is
    re-entrant on a *single* thread: ``runtime`` installs both an ``atexit`` hook and a ``SIGTERM``
    handler, and a container being stopped fires the signal while the exit hook is already running,
    so ``_flush_and_report`` re-enters itself one frame deep. A plain ``Lock`` taken there
    deadlocks the process against itself during shutdown — the SDK becoming the hang it exists to
    prevent, and only under a signal, which is to say only in production. Skipping the second roll
    is also the correct answer on the merits: whoever holds the lock is already publishing that
    window, and emitting it twice would double-count it.
    """

    __slots__ = ("_lock", "_durations", "_requests", "_errors", "_window_from", "_last_roll")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._durations: collections.deque = collections.deque(maxlen=_RESERVOIR)
        self._requests = 0
        self._errors = 0
        self._window_from = contract.now()
        self._last_roll = time.monotonic()

    # -- accumulate -------------------------------------------------------------------------

    def observe(self, batch: t.Iterable[dict]) -> None:
        """Fold one outbound batch into the current window. Worker thread only."""
        seen = 0
        errs = 0
        durations = []
        for ev in batch:
            if ev.get("type") != SPAN_TYPE:
                continue
            seen += 1
            if ev.get("error") is not None:
                errs += 1
            d = ev.get("duration_ms")
            if isinstance(d, (int, float)):
                durations.append(float(d))
        if not seen:
            return
        with self._lock:
            self._requests += seen
            self._errors += errs
            self._durations.extend(durations)

    def due(self, interval_s: float) -> bool:
        if interval_s <= 0:
            return False
        return (time.monotonic() - self._last_roll) >= interval_s

    # -- emit -------------------------------------------------------------------------------

    def roll(self, session_id: str, cfg: Config, *, empty_window: bool = False) -> t.Optional[dict]:
        """Close the window and build one ``service_health`` event, or ``None``.

        ``empty_window=True`` is ``heartbeat()``'s path: emit the window even with nothing in it, so
        that a process with no request loop can still say it is alive. Every quantity stays absent
        in that case — the event carries a timestamp and no numbers, which is precisely the claim.
        """
        if not self._lock.acquire(blocking=False):
            return None                     # see the class docstring: re-entered, or already rolling
        try:
            requests = self._requests
            errors = self._errors
            samples = sorted(self._durations)
            window_from = self._window_from
            self._durations = collections.deque(maxlen=_RESERVOIR)
            self._requests = 0
            self._errors = 0
            self._window_from = contract.now()
            self._last_roll = time.monotonic()
        finally:
            self._lock.release()

        if requests == 0 and not empty_window:
            return None

        measured = requests > 0
        return contract.service_health(
            session_id, cfg,
            service=cfg.service,
            app_id=cfg.application,
            env=cfg.env if cfg.env != "unknown" else None,
            window_from=window_from, window_to=contract.now(),
            # A window we watched and saw nothing in is a measured zero; a window we did not watch
            # (heartbeat) has no count at all. Two different facts, two different renderings.
            requests=requests if measured else None,
            errors=errors if measured else None,
            p50_ms=_pct(samples, 0.50), p95_ms=_pct(samples, 0.95), p99_ms=_pct(samples, 0.99),
            # Saturation is a runtime figure (pool depth, queue length, CPU share) that this SDK
            # does not measure. It stays absent rather than being approximated from latency, which
            # is the sort of derived-presented-as-measured the plane refuses.
            saturation=None,
            detected_by=contract.DETECTED_BY_SDK)
