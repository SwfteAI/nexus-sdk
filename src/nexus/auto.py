"""Level 0 — arming the SDK without touching the application's source.

Two entry points lead here and they are not interchangeable:

* ``nexus-run <cmd>`` (``cli.py``) prepends ``nexus/bootstrap`` to ``PYTHONPATH`` and execs the
  command, so CPython imports our ``sitecustomize`` during interpreter startup — *before* the
  application, before its dependencies, and early enough to patch ``runpy`` for ``python -m``.
* An operator can set ``PYTHONPATH`` themselves in a Dockerfile and skip the launcher entirely.
  This is the form that survives an entrypoint someone else owns (an init system, a framework's
  own runner, a base image's CMD), which is most production images.

An ``[project.entry-points]``-based path is deliberately *not* the primary mechanism: entry points
are only discovered when something enumerates them, which happens after the application has
already imported its libraries — too late for case 2.1 to be handled by hooks alone (we patch
already-imported modules directly, but the ordering guarantee is worth having).

**Everything here must be survivable.** A crash in ``sitecustomize`` is a crash of the interpreter
before the customer's ``main()`` — the single worst failure this SDK could have, and worse than any
amount of missing telemetry. Hence: one guarded call, no arguments, no I/O, and a
``NEXUS_AUTO_INSTRUMENT=0`` escape hatch for the operator who wants identity and manual capture
without import patching.
"""
from __future__ import annotations

import logging

from ._safety import guard
from .config import env_flag

log = logging.getLogger("nexus.auto")

_armed = False


@guard("auto.install", default=False)
def install() -> bool:
    """Arm the SDK with environment-derived identity. Called from ``sitecustomize``.

    Identity comes entirely from the environment here (``NEXUS_SERVICE`` and friends, falling back
    to ``unknown``). That is case 4.11's contract: capture with defaults, never crash and never
    silently discard. An application that later calls ``nexus.init(service=…)`` upgrades the
    identity in place without restarting the queue.
    """
    global _armed
    if _armed:
        return True
    import nexus
    if not nexus.enabled():
        return False
    _armed = True
    nexus.init()
    if env_flag("NEXUS_AUTO_INSTRUMENT", True):
        from . import hooks, integrations
        if hooks.install():
            integrations.install_all()
        hooks.on_main_module(_after_main)
    return True


def _after_main(_module) -> None:  # noqa: ANN001
    """``python -m yourapp`` finished. Flush on the way out.

    ``atexit`` would also fire, but not before ``runpy`` unwinds, and on a ``SystemExit`` raised
    from ``__main__`` the ordering of interpreter teardown against a daemon flush thread is not
    something to rely on. Flushing here is cheap and makes the common CLI/job shape deterministic.
    """
    try:
        import nexus
        nexus.flush()
    except Exception:  # noqa: BLE001
        pass
