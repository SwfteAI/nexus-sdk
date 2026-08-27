"""Process-model detection and lifecycle hooks — "worked on my laptop, silent in prod", solved.

This module exists because an in-process SDK does not get to choose its host. The same wheel is
imported into a gunicorn pre-fork master, a uWSGI worker with threads compiled out, a Lambda
sandbox that freezes between invocations, a Cloud Run container that gets ten seconds' notice
before ``SIGKILL``, and a Jupyter kernel where ``init()`` runs eleven times. Each of those breaks a
background-thread-plus-queue design in a *different* way, and every one of the breaks is silent:
the SDK keeps running, the events stop arriving, and nobody notices for a month.

``F3-SDK-RUNTIME-CASES.md`` §1 enumerates them. The mapping to code here:

===== ============================== =======================================================
Case  Shape                          Mechanism
===== ============================== =======================================================
1.2   gunicorn pre-fork              ``register_fork_hooks`` → ``os.register_at_fork``
1.3   gunicorn ``--preload``         ``_pre_fork_quiet``: no sockets, no threads before fork
1.4   uWSGI                          ``threads_available`` → transport falls back to sync
1.5   uvicorn/hypercorn workers      per-worker init is just 1.2 with a different parent
1.6   celery / billiard              billiard forks; ``os.register_at_fork`` still fires
1.7   multiprocessing spawn vs fork  spawn re-imports → ``init()`` is idempotent
1.8   threads                        context is thread-local via contextvars (``context.py``)
1.9   asyncio                        same contextvars, copied per Task by the event loop
1.10  gevent / eventlet              ``gevent_patched``; never hold a lock across a yield
1.11  AWS Lambda                     ``flush_before_return`` — no background flush at all
1.12  Cloud Run / ECS                ``install_sigterm_handler`` with a hard deadline
1.13  Kubernetes                     ``_k8s_identity`` via downward API env + ``/etc/podinfo``
1.14  Jupyter / REPL                 re-``init()`` is idempotent; hooks registered once
1.15  ``python -m app``              ``runpy._run_code`` patch, in the vendored watchdog
===== ============================== =======================================================

The single most important line in the file is in ``_after_in_child``: **the child starts with an
empty queue.** Everything buffered before ``fork()`` belongs to the parent. If the child inherits
it, every one of N workers flushes the same events and the ledger gets N copies of the pre-fork
window — which looks exactly like a traffic spike and corrupts every cost figure derived from it.
"""
from __future__ import annotations

import atexit
import os
import select
import signal
import sys
import threading
import time
import typing as t
from dataclasses import asdict, dataclass, field

_HAS_REGISTER_AT_FORK = hasattr(os, "register_at_fork")


@dataclass(frozen=True)
class RuntimeProfile:
    """What kind of process are we, and what is therefore safe to do in it."""

    #: False under uWSGI without ``--enable-threads``. Spinning a flush thread that the runtime
    #: will never schedule is worse than not having one: it looks healthy and delivers nothing.
    threads_available: bool = True
    fork_hooks_available: bool = _HAS_REGISTER_AT_FORK
    start_method: str = "fork"
    gevent_patched: bool = False
    uwsgi: bool = False
    is_lambda: bool = False
    is_cloud_run: bool = False
    is_k8s: bool = False
    is_frozen: bool = False
    is_interactive: bool = False
    #: Grace period the platform gives us between SIGTERM and SIGKILL, in seconds. The flush
    #: deadline is clamped below this — a flush that outlives the grace period is not a flush,
    #: it is a hang followed by data loss (case 1.12).
    grace_period_s: float = 10.0
    pod: dict = field(default_factory=dict)
    container_id: t.Optional[str] = None

    def as_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, {}, "")}


def _threads_available() -> t.Tuple[bool, bool]:
    """``(threads_available, running_under_uwsgi)``.

    uWSGI does not run the Python threading machinery unless started with ``--enable-threads``
    (or ``--python-worker-override``). The check is the presence of the ``uwsgi`` module — it only
    exists inside the uWSGI process — and then its own opt table, which is the authoritative
    answer rather than a guess.
    """
    uwsgi = sys.modules.get("uwsgi")
    if uwsgi is None:
        return True, False
    opt = getattr(uwsgi, "opt", {}) or {}
    for key in (b"enable-threads", "enable-threads", b"enable_threads", "enable_threads"):
        if key in opt:
            v = opt[key]
            if isinstance(v, bytes):
                v = v.decode("utf-8", "replace")
            return str(v).lower() not in ("0", "false", "off", "no"), True
    # Some builds expose it as a boolean attribute instead of an opt entry.
    if getattr(uwsgi, "has_threads", None) is not None:
        return bool(uwsgi.has_threads), True
    return False, True


def _gevent_patched() -> bool:
    """True if gevent/eventlet has monkeypatched the stdlib.

    We must tolerate being imported before *or* after ``monkey.patch_all()`` (case 1.10). Detection
    is only used to record the fact and to avoid assumptions about native locks — the code path is
    the same either way, because ``threading.Lock`` is itself patched and a greenlet-aware lock is
    the correct primitive once it is. What we must never do is hold a lock across a call that can
    yield, which is why every critical section in ``transport.py`` is a few statements long and
    does no I/O.
    """
    mky = sys.modules.get("gevent.monkey")
    if mky is not None:
        try:
            return bool(mky.is_module_patched("threading") or mky.is_module_patched("socket"))
        except Exception:  # noqa: BLE001
            return True
    ep = sys.modules.get("eventlet.patcher")
    if ep is not None:
        try:
            return bool(ep.is_monkey_patched("thread") or ep.is_monkey_patched("socket"))
        except Exception:  # noqa: BLE001
            return True
    return False


def _k8s_identity() -> t.Tuple[bool, dict]:
    """Pod identity from the downward API (case 1.13).

    Kubernetes does not hand a process its own identity; the operator has to project it, either as
    env vars (``fieldRef: metadata.name``) or as files under ``/etc/podinfo``. We read both, and we
    read the *conventional* env names as well as our own prefixed ones — asking a customer to add
    ``NEXUS_POD_NAME`` alongside the ``POD_NAME`` they already project is a needless install step,
    and install steps are where adoption dies.
    """
    pod: dict = {}
    for key, names in (
        ("pod_name", ("NEXUS_POD_NAME", "POD_NAME", "HOSTNAME")),
        ("namespace", ("NEXUS_POD_NAMESPACE", "POD_NAMESPACE", "NAMESPACE")),
        ("node_name", ("NEXUS_NODE_NAME", "NODE_NAME")),
        ("pod_ip", ("NEXUS_POD_IP", "POD_IP")),
    ):
        for n in names:
            v = os.environ.get(n)
            if v and v.strip():
                pod[key] = v.strip()[:128]
                break
    podinfo = os.environ.get("NEXUS_PODINFO_DIR", "/etc/podinfo")
    try:
        if os.path.isdir(podinfo):
            for fname, key in (("name", "pod_name"), ("namespace", "namespace"),
                               ("uid", "pod_uid")):
                p = os.path.join(podinfo, fname)
                if os.path.isfile(p):
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        pod[key] = fh.read().strip()[:128]
    except OSError:
        pass  # a projected volume that is not mounted is not an error worth surfacing
    in_k8s = bool(os.environ.get("KUBERNETES_SERVICE_HOST")) or bool(pod.get("namespace"))
    return in_k8s, pod


def _container_id() -> t.Optional[str]:
    """Best-effort container id from cgroup. Absent outside Linux containers; never raises."""
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for part in line.strip().split("/"):
                    if len(part) == 64 and all(c in "0123456789abcdef" for c in part):
                        return part
    except OSError:
        pass
    return None


def _grace_period() -> float:
    """How long we have after ``SIGTERM``.

    Cloud Run gives 10s by default and does not tell the process. Kubernetes defaults to 30s and
    also does not tell the process, so an operator who has changed it must say so. Guessing high is
    the dangerous direction: a flush that assumes 30s inside a 10s window gets ``SIGKILL``\\ ed
    mid-send and loses the batch it was already committed to.
    """
    from .config import _env_float
    if os.environ.get("K_SERVICE"):
        return _env_float("NEXUS_GRACE_PERIOD_S", 10.0)
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return _env_float("NEXUS_GRACE_PERIOD_S", 30.0)
    return _env_float("NEXUS_GRACE_PERIOD_S", 10.0)


def detect() -> RuntimeProfile:
    """One pass over the environment. Cheap, and deliberately called once per process."""
    threads_ok, uwsgi = _threads_available()
    in_k8s, pod = _k8s_identity()
    try:
        import multiprocessing
        start_method = multiprocessing.get_start_method(allow_none=True) or "fork"
    except Exception:  # noqa: BLE001
        start_method = "fork"
    return RuntimeProfile(
        threads_available=threads_ok,
        fork_hooks_available=_HAS_REGISTER_AT_FORK,
        start_method=start_method,
        gevent_patched=_gevent_patched(),
        uwsgi=uwsgi,
        is_lambda=bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME")),
        is_cloud_run=bool(os.environ.get("K_SERVICE")),
        is_k8s=in_k8s,
        is_frozen=bool(getattr(sys, "frozen", False)),
        is_interactive=bool(hasattr(sys, "ps1") or "ipykernel" in sys.modules),
        grace_period_s=_grace_period(),
        pod=pod,
        container_id=_container_id(),
    )


# --------------------------------------------------------------------------------------------
# fork
# --------------------------------------------------------------------------------------------

_fork_lock = threading.Lock()
_child_callbacks: list[t.Callable[[], None]] = []
_parent_callbacks: list[t.Callable[[], None]] = []
_fork_hooks_installed = False


def register_fork_hooks(*, after_in_child: t.Callable[[], None],
                        after_in_parent: t.Optional[t.Callable[[], None]] = None) -> bool:
    """Rebuild SDK state in a forked child.

    Threads and their queues **do not survive ``fork()``** — the child gets the memory and none of
    the threads, so a flush worker that existed in the parent is a dead reference in the child, and
    any lock it held is frozen held, forever. That is the classic pre-fork hang: the first event a
    gunicorn worker tries to enqueue blocks on a mutex owned by a thread that does not exist.

    Registration is process-global and idempotent; the callbacks are a list because the transport,
    the counters and the session identity each need to rebuild. ``os.register_at_fork`` is missing
    on Windows, where there is no ``fork`` to survive — we return False and the caller relies on
    ``init()`` being idempotent under the spawn start method instead (case 1.7).
    """
    global _fork_hooks_installed
    if not _HAS_REGISTER_AT_FORK:
        return False
    with _fork_lock:
        _child_callbacks.append(after_in_child)
        if after_in_parent is not None:
            _parent_callbacks.append(after_in_parent)
        if not _fork_hooks_installed:
            os.register_at_fork(after_in_child=_after_in_child,
                                after_in_parent=_after_in_parent)
            _fork_hooks_installed = True
    return True


def _after_in_child() -> None:
    # No lock here on purpose: we may have inherited it held by a thread that no longer exists.
    # This callback runs single-threaded in a brand-new address space, so there is nothing to race.
    for cb in list(_child_callbacks):
        try:
            cb()
        except Exception:  # noqa: BLE001 — a broken rebuild must not break the worker
            pass


def _after_in_parent() -> None:
    for cb in list(_parent_callbacks):
        try:
            cb()
        except Exception:  # noqa: BLE001
            pass


def _reset_fork_hooks_for_tests() -> None:
    _child_callbacks.clear()
    _parent_callbacks.clear()


# --------------------------------------------------------------------------------------------
# shutdown
# --------------------------------------------------------------------------------------------

_sigterm_installed = False
_atexit_installed = False
#: The one drainer this process owns, kept only so tests can tear its thread and fds down.
_drainer: t.Optional["_ShutdownDrainer"] = None

#: Share of the platform grace window the SDK may spend on telemetry. The rest belongs to the
#: application's own drain. 80% was the old value and it was the wrong way round: an SDK that eats
#: four fifths of a 30 s Kubernetes window before the app has closed a single connection is not a
#: guest. See ``_ShutdownDrainer`` for why the app no longer *waits* for this at all in the common
#: case; this number now only bounds how long we keep retrying a wedged collector.
_TELEMETRY_GRACE_SHARE = 0.2

#: How often the (rare) blocking branch re-reads the drainer's progress counter. A plain int read
#: plus ``time.sleep`` — deliberately not a ``threading.Event``, see ``wait_for``.
_DRAIN_POLL_S = 0.005

#: How long the drain thread parks in ``select`` between checks for shutdown. It exists so the
#: wait is *interruptible*; the value is not latency-critical, because a real request arrives as
#: readability on the pipe and wakes the select immediately.
_DRAIN_SELECT_S = 1.0


class _ShutdownDrainer:
    """Runs the ``SIGTERM`` flush on a worker thread, woken through a self-pipe.

    **This class exists because a signal handler may not take a lock that ordinary code takes.**
    CPython delivers signals on the main thread at a bytecode boundary, *inside whatever frame was
    executing*. The old handler called the flush directly, and the flush re-enters ``client.emit``
    → ``transport.enqueue``, which touches three different non-reentrant locks:

    * ``Transport._wake``'s internal condition lock (``Event.set`` → ``notify_all``),
    * ``Transport._lock`` (the queue, also read by ``transport.depth()``),
    * ``_counters._lock`` (every ``incr``/``observe_max``, and ``snapshot()`` in the health event).

    If the interrupted frame already held any one of them — on the *same* thread — the handler
    blocked on a lock that nothing would ever release. Measured at 33 hangs in 80 trials of an
    ordinary high-rate ``emit()`` loop against an unreachable collector, which is exactly the state
    a service is in during the rolling restart that sends the SIGTERM. Only ``SIGKILL`` cleared it,
    and because the handler never returned, neither the application's own SIGTERM handler nor
    ``atexit`` ever ran: a wedged pod that looks like a clean shutdown in the logs.

    Making those locks reentrant would be worse, not better. An ``RLock`` lets the handler walk
    *into* a half-updated deque or waiter list and mutate it; that trades a hang, which announces
    itself, for corruption, which does not.

    So the handler does the one thing a handler is allowed to do — record intent and return. One
    ``write(2)`` on a pipe takes no Python-level lock and cannot block on anything the interrupted
    frame holds. This thread does the actual draining, where locks are ordinary again.

    The pipe is not shared with a forked child: ``reinit_after_fork`` rebuilds it, because a child
    writing into the parent's pipe would have the parent flush the child's intent.
    """

    def __init__(self, flush: t.Callable[[float], bool], budget_s: float) -> None:
        self._flush = flush
        self._budget_s = budget_s
        self._r = -1
        self._w = -1
        self._thread: t.Optional[threading.Thread] = None
        # A plain one-element list, mutated only by the drain thread and only ever *read* by the
        # signal handler. ``STORE_SUBSCR``/``BINARY_SUBSCR`` are single bytecodes, so neither side
        # needs a lock — which is the entire point.
        self._served = [0]
        self._closing = False

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self) -> bool:
        try:
            self._r, self._w = os.pipe()
            os.set_inheritable(self._r, False)
            os.set_inheritable(self._w, False)
        except OSError:
            self._close_fds()
            return False
        try:
            th = threading.Thread(target=self._run, name="nexus-sigterm-drain", daemon=True)
            th.start()
        except (RuntimeError, OSError):
            self._close_fds()
            return False
        self._thread = th
        return True

    def stop(self) -> None:
        """Close the write end so ``os.read`` returns EOF and the thread exits. Test-only path;
        production processes are on their way out anyway."""
        self._closing = True
        self._close_fds()
        th = self._thread
        self._thread = None
        if th is not None and th.is_alive() and th is not threading.current_thread():
            th.join(timeout=0.5)

    def _close_fds(self) -> None:
        for attr in ("_w", "_r"):
            fd = getattr(self, attr)
            setattr(self, attr, -1)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def reinit_after_fork(self) -> None:
        """A forked child inherits the fds but not the thread. Rebuild both.

        Closing the inherited ends first matters: the parent holds its own copies, so the child's
        close is local, and without it the child's ``request()`` would be read by the *parent's*
        drain thread — the child's shutdown intent flushing the parent's queue.
        """
        self._closing = False
        self._close_fds()
        self._thread = None
        self._served = [0]
        self.start()

    # -- the signal-handler side: nothing here may take a Python lock -------------------------

    def served(self) -> int:
        """Drains completed so far. One list read; no lock."""
        return self._served[0]

    def request(self) -> bool:
        """Record intent. A single ``write(2)`` of one byte into a pipe with a 64 KiB buffer.

        This is the only SDK code the signal handler runs, and it is async-signal-safe: no Python
        lock, no allocation that could block, no re-entry into the transport.
        """
        w = self._w
        if w < 0:
            return False
        try:
            os.write(w, b"\x01")
            return True
        except OSError:
            return False

    def wait_for(self, served_before: int, deadline_s: float) -> bool:
        """Block until one more drain has completed, or the budget runs out.

        Only reached when the application installed **no** SIGTERM handler, where the next thing
        that happens is the process dying by default disposition — so if we do not wait here, the
        last events are lost and the deadlock would have been "fixed" by dropping telemetry.

        Polling an ``int`` with ``time.sleep`` rather than waiting on a ``threading.Event`` is
        deliberate: ``Event.wait`` acquires a condition lock, and re-introducing *any* lock into
        the handler re-introduces the class of bug this file just removed.
        """
        end = time.monotonic() + max(0.0, deadline_s)
        while self._served[0] <= served_before:
            if time.monotonic() >= end:
                return False
            time.sleep(_DRAIN_POLL_S)
        return True

    # -- the worker side: ordinary code, ordinary locks ---------------------------------------

    def _run(self) -> None:
        """Wait for intent, drain, repeat.

        **The wait is a ``select``, not a bare blocking ``os.read``, because of gevent** (case
        1.10). Under ``monkey.patch_all()`` a ``threading.Thread`` is a greenlet, and a greenlet
        that blocks in a raw ``os.read`` does not yield — it parks the whole hub, so every
        greenlet in the process stops, including the application's. A fix for a hang that
        introduces a different hang is not a fix; this was caught by
        ``test_1_10_gevent_monkeypatch_before_init`` hanging for 60s against an otherwise
        correct-looking drainer.

        ``select`` is cooperative under gevent (it patches the module in place) and is an ordinary
        efficient wait natively, so one shape is right in both runtimes. The timeout makes the
        wait interruptible rather than adding latency: a real request shows up as readability and
        returns from ``select`` at once.
        """
        while True:
            r = self._r
            if r < 0 or self._closing:
                return
            try:
                ready, _, _ = select.select([r], [], [], _DRAIN_SELECT_S)
            except (OSError, ValueError):
                return          # fd closed under us by stop()/reinit_after_fork
            if self._closing:
                return
            if not ready:
                continue
            try:
                data = os.read(r, 64)
            except (OSError, ValueError):
                return
            if not data or self._closing:
                return          # write end closed: nothing will ever ask again
            try:
                self._flush(self._budget_s)
            except Exception:   # noqa: BLE001 — a drain that can raise is a drain that stops
                pass
            # Published last, so a waiter that sees the increment knows the flush is finished.
            self._served[0] += 1


def install_sigterm_handler(flush: t.Callable[[float], bool], grace_s: float,
                            *, threads_available: bool = True) -> bool:
    """Flush on ``SIGTERM``, inside the platform's grace period — case 1.12.

    Four properties, each learned from someone else's outage:

    * **The handler only records intent.** It writes one byte to a pipe and returns. It does not
      flush, does not emit, does not touch the queue or the counters. A handler runs on the main
      thread inside an arbitrary frame, so anything it locks may already be locked by the frame it
      interrupted — a self-deadlock no ``try/except`` can contain, because a deadlock is not an
      exception. ``_ShutdownDrainer`` carries the full account; the short version is that the old
      shape hung 33 times in 80 trials of ordinary high-rate telemetry.
    * **The previous handler is chained, not replaced, and chained *first*.** Applications install
      their own ``SIGTERM`` handlers to drain connections. An SDK that clobbers one has turned
      graceful shutdown into a dropped-request incident, which is a far worse bug than losing
      telemetry — and an SDK that merely *delays* one has taken a slice of a budget it does not
      own. The application's handler now runs within microseconds of the signal.
    * **The deadline is derived from the grace period, not from our config**, and it is a minority
      share of it (``_TELEMETRY_GRACE_SHARE``). It no longer bounds anything the application waits
      for; it bounds how long we keep retrying a collector that is not answering.
    * **We do not exit.** Deciding the process should die is the application's call. We record, we
      hand the signal on, and the drain happens beside them.

    Signal handlers can only be installed from the main thread; under gunicorn's worker model that
    is where init runs, but under a thread-pool executor it is not, so the ``ValueError`` is caught
    rather than propagated.

    ``threads_available=False`` is the uWSGI-without-``--enable-threads`` runtime (case 1.4), where
    no worker of ours will ever be scheduled. There the flush stays inline, because a delegated
    drain that never runs is silence — and it is also the runtime where the proven hazard does not
    arise, since ``Transport`` is in ``"sync"`` mode and ``enqueue`` never calls ``_wake.set()``.
    That branch is narrower but not spotless: ``_counters._lock`` is still shared with the
    interrupted frame. It is the least-bad option available in a runtime with no threads.
    """
    global _sigterm_installed, _drainer
    if _sigterm_installed:
        return True
    try:
        previous = signal.getsignal(signal.SIGTERM)
    except (ValueError, AttributeError, OSError):
        return False

    budget_s = max(0.1, grace_s * _TELEMETRY_GRACE_SHARE)
    drainer: t.Optional[_ShutdownDrainer] = None
    if threads_available:
        d = _ShutdownDrainer(flush, budget_s)
        if d.start():
            drainer = d
            register_fork_hooks(after_in_child=d.reinit_after_fork)

    def _inline_flush() -> None:
        try:
            flush(budget_s)
        except Exception:  # noqa: BLE001
            pass

    def _handler(signum, frame):  # noqa: ANN001
        # --- async-signal-safe region: no Python-level lock may be acquired below -------------
        served = drainer.served() if drainer is not None else 0
        if drainer is not None:
            drainer.request()

        if callable(previous) and previous not in (signal.SIG_DFL, signal.SIG_IGN):
            previous(signum, frame)         # their drain starts now, not after ours
            if drainer is None:
                _inline_flush()
            return

        if previous == signal.SIG_DFL:
            # Nobody else is going to keep this process alive, so this is the one branch that has
            # to wait for the drain — otherwise the fix for the hang would just be "lose the last
            # events". The wait polls an int; it takes no lock (see ``wait_for``).
            if drainer is not None:
                drainer.wait_for(served, budget_s)
            else:
                _inline_flush()
            # Restore and re-raise so the default disposition (terminate) still applies. Anything
            # else silently converts a SIGTERM into "the container ignores shutdown", and the
            # orchestrator SIGKILLs it 30 seconds later.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)
            return

        # SIG_IGN: the application asked for SIGTERM to do nothing. We honour that and let the
        # background drain finish on its own time.

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError, RuntimeError):
        if drainer is not None:
            drainer.stop()
        return False       # not the main thread; atexit still covers the normal path
    _drainer = drainer
    _sigterm_installed = True
    return True


def install_atexit(flush: t.Callable[[float], bool], deadline_s: float) -> None:
    """Flush at interpreter exit, with a deadline (case 4.8).

    The deadline is the point. ``atexit`` handlers run before the interpreter tears down, and a
    flush that blocks on an unreachable collector there turns "the container stopped" into "the
    container hung until the orchestrator killed it" — a telemetry SDK visibly extending every
    deploy's rollout time is a telemetry SDK with a short life expectancy.
    """
    global _atexit_installed
    if _atexit_installed:
        return
    atexit.register(lambda: flush(deadline_s))
    _atexit_installed = True


def _reset_shutdown_hooks_for_tests() -> None:
    """Undo ``install_sigterm_handler``'s process-global state, **including the drain thread**.

    Clearing only the two booleans is what this used to do, and it leaked: every call to
    ``install_sigterm_handler`` builds a ``_ShutdownDrainer``, which owns an OS thread and a pipe
    (two fds). Resetting ``_sigterm_installed`` lets the next install build another one while the
    previous thread is still parked in ``select`` on fds nobody will ever close. Across a suite
    that installs the handler repeatedly, that is an unbounded thread and fd leak in the test
    process — and the leak is invisible until it exhausts the fd table, at which point the failure
    lands in whichever unrelated test happens to open a file next.

    ``_drainer`` exists for exactly this. It is documented at its definition as being kept "only so
    tests can tear its thread and fds down", and this is the only function that can do it.
    """
    global _sigterm_installed, _atexit_installed, _drainer
    d, _drainer = _drainer, None
    if d is not None:
        d.stop()
    _sigterm_installed = False
    _atexit_installed = False


# --------------------------------------------------------------------------------------------
# AWS Lambda
# --------------------------------------------------------------------------------------------

def wrap_lambda_handler(handler: t.Callable[..., t.Any],
                        flush: t.Callable[[float], bool],
                        budget_s: float = 1.0) -> t.Callable[..., t.Any]:
    """Flush **before the handler returns** — case 1.11.

    Lambda freezes the sandbox the instant the handler returns. A background flush thread is not
    slow in that world, it is *stopped*: it resumes minutes later inside the next invocation, or
    never, if the environment is reaped. Timer-based flushing is therefore not merely suboptimal
    on Lambda, it is a silent, total loss of the tail of every invocation.

    So the flush is synchronous and on the return path, with a budget, because the customer's
    invoice and their p99 are both measured in the milliseconds this takes. On error we flush too,
    then re-raise: a failing invocation is the one whose telemetry matters most, and it is exactly
    the one a ``finally``-less implementation loses.

    Anything still queued after the budget survives the freeze in memory and goes out on the next
    invocation — which is why the queue is not cleared here.
    """
    import functools

    @functools.wraps(handler)
    def wrapper(event, context=None, *args, **kwargs):  # noqa: ANN001
        try:
            return handler(event, context, *args, **kwargs)
        finally:
            try:
                flush(budget_s)
            except Exception:  # noqa: BLE001
                pass
    wrapper.__nexus_lambda_wrapped__ = True  # type: ignore[attr-defined]
    return wrapper
