"""Where "the current run" lives — cases 1.8 and 1.9.

``contextvars`` rather than thread-locals, because the two are not interchangeable in an async
service. A thread-local is shared by every coroutine on the event loop, so ten concurrent requests
in one worker thread would all see whichever run started last: telemetry attributed to the wrong
tenant, in a governance ledger. ``contextvars`` are copied per ``Task`` by the event loop, so
``await``, ``gather`` and ``TaskGroup`` all behave, and they are also per-thread, so the
synchronous case is covered by the same mechanism.

The one place the runtime does *not* propagate for us is ``run_in_executor`` and bare
``ThreadPoolExecutor.submit`` — a new thread starts from an empty context, not a copy of its
parent's. That is the correct default (case 1.8: never leak one request's context into another's),
so we do not fight it; we expose ``capture()`` / ``activate()`` for the caller who genuinely wants
the handoff, and let the silent default be the safe one.

Nothing here touches the transport, and nothing here can raise into user code: a missing context is
``None``, never a ``LookupError``.
"""
from __future__ import annotations

import contextvars
import typing as t
from dataclasses import dataclass

if t.TYPE_CHECKING:  # pragma: no cover
    from .api import Run


@dataclass(frozen=True)
class RunRef:
    """The identity of an in-flight run, small enough to copy across a thread boundary."""
    run_id: str
    name: str
    session_id: str


_current_run: contextvars.ContextVar[t.Optional[RunRef]] = contextvars.ContextVar(
    "nexus_current_run", default=None)


def current() -> t.Optional[RunRef]:
    return _current_run.get()


def push(ref: RunRef) -> contextvars.Token:
    """Enter a run. Returns the token the matching ``pop`` needs.

    Token-based restore rather than "set back to None": runs nest (an agent calls a sub-agent), and
    clearing on exit would delete the parent's context rather than restore it.
    """
    return _current_run.set(ref)


def pop(token: contextvars.Token) -> None:
    try:
        _current_run.reset(token)
    except (ValueError, RuntimeError):
        # Reset from a different context than the set — happens when a caller opens a run in one
        # task and closes it in another. Their bookkeeping is wrong, but that is not a reason to
        # raise into their code; the context var simply stays as it is in this context.
        pass


def capture() -> contextvars.Context:
    """Snapshot for an explicit hand-off to a worker thread. See the module docstring."""
    return contextvars.copy_context()


def activate(ref: t.Optional[RunRef]) -> contextvars.Token:
    return _current_run.set(ref)


def clear_for_fork() -> None:
    """A forked child inherits the parent's context. Whatever run was in flight belonged to the
    parent's request; continuing to attribute the child's work to it would produce a run with two
    unrelated halves in two processes."""
    _current_run.set(None)
