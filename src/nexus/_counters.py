"""Self-telemetry counters — the SDK's account of its own failures.

Case 4.3 states the rule that shapes this module: *"Silence about dropped data is a bug."* An
observability SDK that quietly discards events is not degrading, it is lying — every downstream
coverage number, every cost total, every "no policy violations this week" is then unfalsifiable.
So every drop, every send failure, every swallowed exception increments something nameable here,
and those numbers are emitted as a ``pipeline_health`` event (the same shape the wrapper already
uses) rather than kept as a private debug detail.

Deliberately a flat ``dict[str, int]`` behind one lock, not a metrics library:

* it must work with zero dependencies;
* it must be readable from a fault handler and from ``atexit``, where importing anything is unsafe;
* the cardinality is fixed and small — counter names are literals in this codebase, never
  user-supplied, which is also what keeps case 3.5 (cardinality explosion) from applying to us.

Counters reset in a forked child (``reset_for_fork``). The alternative — inheriting the parent's
totals — makes N workers each report the parent's pre-fork drops, so a single dropped event before
``fork()`` is reported N+1 times. Under-counting the pre-fork window is the lesser lie, and the
pre-fork window is where we deliberately do the least work anyway.
"""
from __future__ import annotations

import threading

# Counter names. Literals, so a typo is a NameError at import rather than a metric that never
# appears. Grouped by the failure they describe.
QUEUE_DROPPED = "queue_dropped"            # bounded queue full, oldest evicted (4.2, 4.3)
QUEUE_DEPTH_PEAK = "queue_depth_peak"      # high-water mark, so "never dropped" can be believed
SEND_FAILED = "send_failed"                # transport error, will retry (4.1)
SEND_ABANDONED = "send_abandoned"          # gave up: auth failure or retries exhausted (4.4)
SEND_OK = "send_ok"
EVENTS_ENQUEUED = "events_enqueued"
EVENTS_SENT = "events_sent"
FLUSH_TIMEOUT = "flush_timeout"            # shutdown/flush deadline hit with work outstanding (4.8)
HOOK_ERROR = "hook_error"                  # an SDK entry point raised and was contained (4.7)
PATCH_FAILED = "patch_failed"              # an integration failed to install (2.5)
BUILD_FAILED = "build_failed"              # event construction raised; nothing was enqueued
DISK_ERROR = "disk_error"                  # spill-to-disk failed (disk full, read-only fs)

_lock = threading.Lock()
_counts: dict[str, int] = {}


def incr(name: str, n: int = 1) -> None:
    with _lock:
        _counts[name] = _counts.get(name, 0) + n


def observe_max(name: str, value: int) -> None:
    """High-water mark. Separate from ``incr`` because a peak is not a sum."""
    with _lock:
        if value > _counts.get(name, 0):
            _counts[name] = value


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counts)


def get(name: str) -> int:
    with _lock:
        return _counts.get(name, 0)


def reset() -> None:
    """Test-only. Production code never zeroes counters: a counter that can go backwards cannot be
    rate-computed by anything downstream."""
    with _lock:
        _counts.clear()


def reset_for_fork() -> None:
    """Called from ``os.register_at_fork(after_in_child=...)``. See the module docstring for why
    the child starts from zero rather than inheriting."""
    global _lock
    # The lock may have been held by a thread that does not exist in the child. Replace it rather
    # than try to acquire it — this is the classic post-fork lock-corruption failure, and it
    # presents as a worker that hangs on its first event.
    _lock = threading.Lock()
    _counts.clear()
