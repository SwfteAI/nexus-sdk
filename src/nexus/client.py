"""The process-wide client: one queue, one identity, one lifecycle.

Everything the three API levels do funnels through here, which is what keeps "never raises, never
blocks" a property of five functions rather than of the whole codebase.

Three behaviours are worth reading the code for, because each is a named case rather than a taste:

**``init()`` is idempotent** (case 4.10). Called twice — and it *will* be, by a Jupyter cell
re-executed (1.14), by a spawn-start-method child re-importing the module (1.7), by an app that
calls it in both ``main()`` and a framework hook — the second call updates identity and returns the
same client. It never starts a second flush thread, never re-registers the fork hook, never opens a
second socket.

**No ``init()`` at all is a supported state** (case 4.11). Auto-instrumentation may be on with the
application never touching our API. Capturing under service identity ``unknown`` is right;
discarding the data because nobody introduced themselves is not, and crashing is unthinkable.

**A forked child is a new process, not a continuation** (case 1.2). It gets a fresh session id and
an empty queue. Reusing the parent's session id would merge N workers' work into one session in the
rollup, and inheriting the queue would ship the pre-fork window N times.
"""
from __future__ import annotations

import os
import threading
import typing as t
import uuid

from . import _counters, contract, runtime
from ._safety import guard
from .config import Config, resolve
from .health import HealthRollup
from .transport import Transport

_lock = threading.RLock()
_client: t.Optional["Client"] = None


class Client:
    def __init__(self, cfg: Config, *, transport: t.Optional[Transport] = None,
                 profile: t.Optional[runtime.RuntimeProfile] = None) -> None:
        self.cfg = cfg
        self.profile = profile or runtime.detect()
        self.session_id = uuid.uuid4().hex
        self.instance_id = f"{os.uname().nodename[:32] if hasattr(os, 'uname') else 'host'}-{os.getpid()}"
        self.transport = transport if transport is not None else Transport(cfg, profile=self.profile)
        self._started = False
        # §6.3. Constructed here, armed in ``start()``: the rollup must not be observing batches
        # in a ``--preload`` master whose spans belong to nobody.
        self.health = HealthRollup()

    # -- lifecycle ----------------------------------------------------------------------------

    @guard("client.start")
    def start(self) -> None:
        """Arm the process-level machinery. Separate from construction so that ``gunicorn
        --preload`` (case 1.3) can import and configure the SDK in the master without a thread or a
        socket existing before ``fork()``."""
        if self._started:
            return
        self._started = True
        self.transport.on_batch = self.health.observe
        self.transport.on_tick = self._roll_health
        self.transport.start()
        runtime.register_fork_hooks(after_in_child=self._after_fork_in_child)
        runtime.install_atexit(self._flush_and_report, self.cfg.flush_deadline_s)
        runtime.install_sigterm_handler(self._flush_and_report, self.profile.grace_period_s)
        if self.profile.is_lambda:
            # Nothing to arm: on Lambda the flush is on the handler's return path, which the
            # customer installs with `nexus.instrument_lambda_handler`. Recording the fact means
            # `pipeline_health` shows *why* there is no background flusher, rather than looking
            # like a bug to whoever debugs it next.
            pass
        self.emit(contract.session(self.session_id, self.cfg,
                                   instance_id=self.instance_id,
                                   runtime=self.profile.as_dict()))
        self.emit_health("session_start")

    def _after_fork_in_child(self) -> None:
        from . import context
        _counters.reset_for_fork()
        context.clear_for_fork()
        # A new process is a new session. See the module docstring.
        self.session_id = uuid.uuid4().hex
        self.instance_id = f"{self.instance_id.rsplit('-', 1)[0]}-{os.getpid()}"
        self.transport.reinit_after_fork()
        # The child inherits the parent's half-accumulated window. Keeping it would attribute the
        # parent's pre-fork spans to every one of N workers — the same N-way duplication the queue
        # reset above exists to prevent, spelled as latency instead of events.
        self.health = HealthRollup()
        self.transport.on_batch = self.health.observe
        self.transport.on_tick = self._roll_health
        # atexit/signal state does *not* survive as a registration we can reuse: atexit handlers
        # are inherited (so ours is still registered and still points at this object, which is
        # correct), but the SIGTERM disposition is inherited too and may now chain a handler the
        # parent installed. Re-installing is a no-op guarded by the module-level latch.
        self.emit(contract.session(self.session_id, self.cfg,
                                   instance_id=self.instance_id,
                                   runtime=self.profile.as_dict()))

    def _flush_and_report(self, deadline_s: float) -> bool:
        """Final flush. Emits the closing health event *first* so the drop counters describing the
        session are inside the batch being flushed rather than behind it."""
        try:
            # Close the open §6.3 window too. Not forced: an empty window at shutdown would be an
            # invented record of a process that measured nothing, which is `heartbeat()`'s job to
            # state deliberately and not something a stop hook should assert on its behalf.
            self.emit(self.health.roll(self.session_id, self.cfg))
            self.emit_health("stop")
        except Exception:  # noqa: BLE001
            pass
        return self.transport.flush(deadline_s)

    # -- emission -----------------------------------------------------------------------------

    @guard("client.emit", default=False)
    def emit(self, event: t.Optional[dict]) -> bool:
        if not event:
            return False
        return self.transport.enqueue(event)

    @guard("client.roll_health")
    def _roll_health(self) -> None:
        """One tick of the §6.3 rollup. Called by the flush worker and by nothing else.

        The window is a config knob rather than the flush interval: the flush interval is a latency
        budget for egress (2 s by default) and this is a statistical window, and equating them would
        publish a p99 computed over two seconds — a number that swings wildly and means nothing.
        """
        if not self.cfg.health_interval_s or not self.health.due(self.cfg.health_interval_s):
            return
        self.emit(self.health.roll(self.session_id, self.cfg))

    @guard("client.heartbeat", default=False)
    def heartbeat(self) -> bool:
        """Emit the current window immediately, even if empty. ``nexus.heartbeat()``'s body.

        The empty case is the point: a worker or a cron job has no request loop, so its honest
        health record is a window with a timestamp and no quantities — *alive, nothing measured* —
        which the console draws hollow rather than as a zero.
        """
        return self.emit(self.health.roll(self.session_id, self.cfg, empty_window=True))

    @guard("client.emit_health")
    def emit_health(self, checkpoint: str) -> None:
        self.emit(contract.pipeline_health(
            self.session_id, self.cfg, instance_id=self.instance_id,
            counters=_counters.snapshot(), queue_depth=self.transport.depth(),
            collector_up=bool(self.transport.last_send_ok is not False),
            checkpoint=checkpoint, runtime={"transport_mode": self.transport.mode}))

    @guard("client.flush", default=False)
    def flush(self, deadline_s: t.Optional[float] = None) -> bool:
        return self.transport.flush(deadline_s)

    @guard("client.shutdown", default=False)
    def shutdown(self, deadline_s: t.Optional[float] = None) -> bool:
        try:
            self.emit_health("stop")
        except Exception:  # noqa: BLE001
            pass
        return self.transport.shutdown(deadline_s)


# --------------------------------------------------------------------------------------------
# module-level accessors
# --------------------------------------------------------------------------------------------

def get_client() -> t.Optional["Client"]:
    return _client


def ensure_client() -> "Client":
    """The client, initialising a default one if the application never called ``init()``.

    Case 4.11 in one function. Double-checked under a re-entrant lock because the first agent call
    in an async service can easily be concurrent across threads, and two clients would mean two
    queues, two flush threads, and two session ids for one process.
    """
    global _client
    c = _client
    if c is not None:
        return c
    with _lock:
        if _client is None:
            _client = Client(resolve())
            _client.start()
        return _client


@guard("client.init")
def init(**kw: t.Any) -> t.Optional["Client"]:
    """Declare identity and arm the SDK. Idempotent — case 4.10."""
    global _client
    with _lock:
        cfg = resolve(**kw)
        if not cfg.enabled:
            # Reachable only when someone passes enabled=False explicitly; NEXUS_ENABLED=0 is
            # handled far earlier, in ``nexus/__init__.py``, before this module is even imported.
            return None
        if _client is None:
            _client = Client(cfg)
            _client.start()
        else:
            # Re-init: adopt the new identity, keep the queue, the thread and the session. Tearing
            # them down would drop whatever is buffered and orphan any in-flight run.
            _client.cfg = cfg
            _client.transport.cfg = cfg
        return _client


def _reset_for_tests() -> None:
    global _client
    with _lock:
        if _client is not None:
            try:
                _client.transport.shutdown(0.2)
            except Exception:  # noqa: BLE001
                pass
        _client = None
