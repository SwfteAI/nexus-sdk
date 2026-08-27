"""The containment boundary: nothing in this SDK may raise into the host application.

Case 4.7, and the governing rule of §4: *a telemetry SDK must never be the reason a request
fails.* `nexus wrap` crashing annoys a developer at a terminal. This crashing takes down a payment
service, and the post-incident write-up ends with "we removed the vendor's SDK".

Two things make that testable rather than aspirational:

1. **Every entry point is decorated with ``@guard(name)``**, and ``guard`` registers ``name`` in
   ``HOOKS`` as a side effect of decoration. The chaos test iterates ``HOOKS`` — so the test is
   exhaustive *by construction*. Adding a new entry point without a guard means it is simply not in
   the set the test protects, which is why ``tests/test_fault_injection.py`` also asserts that every
   public callable on the ``nexus`` namespace resolves to a guarded function.
2. **Fault injection is a first-class feature, not a monkeypatch.** ``inject(name)`` makes the named
   hook raise on entry. Tests use it; so can a customer's staging environment, which is the only
   honest way to answer "what happens to my service when your SDK breaks?".

Deliberate non-goals:

* We do not swallow ``BaseException``. ``KeyboardInterrupt``, ``SystemExit`` and
  ``GeneratorExit`` belong to the host program; eating them turns a Ctrl-C into a hang.
* We do not log by default. A broken hook called once per request would emit one log line per
  request — the SDK's own failure mode becoming a second outage. Failures increment a counter and,
  at most once per hook name, emit a single ``logging`` warning.
"""
from __future__ import annotations

import functools
import logging
import os
import threading
import typing as t

from . import _counters

log = logging.getLogger("nexus")

#: Every guarded entry point, populated at decoration time. The chaos test iterates this.
HOOKS: set[str] = set()

#: Cap on a host exception's message. A `__str__` returning megabytes reaches the SDK through the
#: same unguarded line as one that raises; see `describe_exception`.
_ERROR_MESSAGE_LIMIT = 2048
#: Hook names currently forced to raise. Empty in production unless someone sets NEXUS_FAULT.
_faults: set[str] = set()
_warned: set[str] = set()
_warn_lock = threading.Lock()

_F = t.TypeVar("_F", bound=t.Callable[..., t.Any])


def _env_faults() -> set[str]:
    raw = os.environ.get("NEXUS_FAULT", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


_faults |= _env_faults()


class InjectedFault(RuntimeError):
    """Raised by an injected fault. Never escapes a guard — if you see this in an application
    traceback, a guard is missing."""


def inject(*names: str) -> None:
    _faults.update(names)


def clear_faults() -> None:
    _faults.clear()


def _fire(name: str) -> None:
    if name in _faults:
        raise InjectedFault(f"injected fault at hook {name!r}")


def _contain(name: str, exc: BaseException) -> None:
    _counters.incr(_counters.HOOK_ERROR)
    with _warn_lock:
        first = name not in _warned
        _warned.add(name)
    if first:
        # once per hook name per process — see the module docstring on log amplification
        log.warning("nexus: hook %s failed (%s: %s); telemetry degraded, application unaffected",
                    name, type(exc).__name__, exc)


def guard(name: str, default: t.Any = None) -> t.Callable[[_F], _F]:
    """Wrap an entry point so it can fail without the caller noticing.

    ``default`` is what the caller gets when the hook fails. It must be a value the caller can use
    without checking — ``None`` for fire-and-forget emitters, a null object for anything used as a
    context manager. Returning a sentinel the caller has to test would push the SDK's failure back
    into the application, which is the thing this module exists to prevent.
    """
    HOOKS.add(name)

    def deco(fn: _F) -> _F:
        @functools.wraps(fn)
        def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            try:
                _fire(name)
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — the entire point of this module
                _contain(name, exc)
                return default() if callable(default) else default
        wrapper.__nexus_guard__ = name  # type: ignore[attr-defined]
        return t.cast("_F", wrapper)

    return deco


def guard_async(name: str, default: t.Any = None) -> t.Callable[[_F], _F]:
    """``guard`` for coroutine functions. Separate decorator rather than runtime detection: an
    ``async def`` wrapped by the sync guard returns a coroutine that raises when awaited, i.e. the
    exception escapes anyway, one frame later, somewhere much harder to attribute."""
    HOOKS.add(name)

    def deco(fn: _F) -> _F:
        @functools.wraps(fn)
        async def wrapper(*args: t.Any, **kwargs: t.Any) -> t.Any:
            try:
                _fire(name)
                return await fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                _contain(name, exc)
                return default() if callable(default) else default
        wrapper.__nexus_guard__ = name  # type: ignore[attr-defined]
        return t.cast("_F", wrapper)

    return deco


def describe_exception(exc_type: t.Any, exc: BaseException) -> t.Optional[str]:
    """Render the host application's exception for telemetry **without touching the host's code**.

    The four ``__exit__``/``__aexit__`` methods used to build this string inline::

        self._close(error=None if exc is None else f"{exc_type.__name__}: {exc}")

    ``_close`` is ``@guard``ed; that f-string is not. It is evaluated in ``__exit__``, one frame
    *outside* the guard, and ``{exc}`` calls ``str()`` on an object the customer wrote. When that
    raised, the SDK's ``RuntimeError`` left the ``with`` block and the application's own exception
    was destroyed — measured on all four call sites. The type changes too, so the customer's
    ``except MyPaymentError:`` handler stops running and their error path silently takes the wrong
    branch. That is a worse outcome than a crash, because it is silent.

    Realistic sources of a ``__str__`` that raises are not exotic: SQLAlchemy exceptions holding
    detached instances, Django lazy translation proxies, exceptions carrying objects whose repr
    needs a live DB session, anything doing lazy formatting.

    So the rule here is: **the type name is free, the message is not.** ``exc_type.__name__`` is a
    class attribute read; ``str(exc)`` is an arbitrary call into foreign code. Degrade to the free
    half rather than lose the exception. A truncated message is telemetry with a gap in it; a
    replaced exception is an outage in someone else's service.

    The length cap is part of the containment, not tidiness: a ``__str__`` returning megabytes is
    the same defect wearing a different hat, and it arrives through the same unguarded line.
    """
    if exc is None and exc_type is None:
        return None
    try:
        name = exc_type.__name__
    except Exception:  # noqa: BLE001
        try:
            name = type(exc).__name__
        except Exception:  # noqa: BLE001
            return "Exception"
    try:
        message = str(exc)[:_ERROR_MESSAGE_LIMIT]
    except Exception:  # noqa: BLE001
        # The half we could get is the more useful half anyway.
        return name
    return f"{name}: {message}"
