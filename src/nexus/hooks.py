"""Import-hook wiring: the thin layer between the vendored watchdog and our integration registry.

The hard part is vendored (``vendor/ddtrace_module/module.py`` — read its docstring; every strange
line in it is a deadlock or a double-wrap someone else already debugged). What lives here is the
policy that machinery serves:

* **A library imported before ``init()`` is patched immediately; one imported after is patched by
  the hook** (cases 2.1/2.2). ``ModuleWatchdog.register_module_hook`` already does both — it calls
  the hook straight away if the module is in ``sys.modules``. Registering only the future hook is
  the classic bug: it works in every test, because tests import the SDK first, and fails for every
  real application, because applications import their dependencies at the top of the file.

* **``python -m yourapp`` needs ``runpy._run_code`` patched** (case 1.15). ``__main__`` under
  ``-m`` does not travel the normal import path, so a watchdog that only hooks imports is silently
  absent for the single most common production entrypoint. ``register_post_run_module_hook``
  exists for exactly this and must be registered during interpreter initialisation — which is why
  ``bootstrap/sitecustomize.py`` exists and why ``nexus-run`` puts it on ``PYTHONPATH``.

* **Frozen applications degrade rather than fail** (case 1.16, still an open decision upstream).
  PyInstaller and Nuitka replace the import system; hooks may never fire. We detect
  ``sys.frozen``, skip installation, and record it — loudly in diagnostics, silently at runtime.
  The explicit API keeps working, which is the honest fallback.

Installing the watchdog imports the vendored tree. That is deliberately *not* done at
``import nexus`` time: the kill switch and the published import-cost number both depend on the
vendored code staying unloaded until someone actually asks for auto-instrumentation.
"""
from __future__ import annotations

import logging
import sys
import typing as t

from ._safety import guard

log = logging.getLogger("nexus.hooks")

_installed = False


def _watchdog_class():
    from .vendor.ddtrace_module.module import ModuleWatchdog

    class NexusModuleWatchdog(ModuleWatchdog):
        """Our meta-path finder. Named distinctly from ddtrace's so that a process running both
        keeps two separate finders rather than one class shadowing the other in ``sys.meta_path``
        (the ``_find_in_meta_path`` lookup matches on exact type)."""

    return NexusModuleWatchdog


@guard("hooks.install", default=False)
def install() -> bool:
    """Install the import watchdog. Idempotent — case 1.14 re-runs this from a Jupyter cell."""
    global _installed
    if _installed:
        return True
    if getattr(sys, "frozen", False):
        log.debug("nexus: frozen application detected; import hooks skipped, explicit API only")
        return False
    cls = _watchdog_class()
    cls.install()
    _installed = True
    _register_pending()
    return True


@guard("hooks.uninstall")
def uninstall() -> None:
    global _installed
    if not _installed:
        return
    _watchdog_class().uninstall()
    _installed = False


def is_installed() -> bool:
    return _installed


@guard("hooks.on_import")
def on_import(module_name: str, hook: t.Callable[[t.Any], None]) -> None:
    """Run ``hook(module)`` when ``module_name`` is imported — or right now if it already is.

    Failures inside ``hook`` are the integration's problem, not the application's: a library whose
    API moved under us must degrade to pass-through with one structured warning (case 2.5), never a
    raise at the customer's import statement.
    """
    def _safe(module):  # noqa: ANN001
        try:
            hook(module)
        except Exception as exc:  # noqa: BLE001
            from . import _counters
            _counters.incr(_counters.PATCH_FAILED)
            log.warning("nexus: integration for %s failed to patch (%s); left unpatched",
                        module_name, type(exc).__name__)

    if not _installed:
        _pending.append((module_name, _safe))
        return
    _watchdog_class().register_module_hook(module_name, _safe)


_pending: list[tuple] = []


def _register_pending() -> None:
    cls = _watchdog_class()
    while _pending:
        name, hook = _pending.pop()
        cls.register_module_hook(name, hook)


@guard("hooks.post_run_module")
def on_main_module(hook: t.Callable[[t.Any], None]) -> None:
    """Fire after ``python -m yourapp`` finishes executing ``__main__`` — case 1.15.

    Only effective if this runs during interpreter initialisation (``sitecustomize``), because it
    patches ``runpy._run_code`` and ``runpy`` has already run by the time an application's own
    import of ``nexus`` executes.
    """
    from .vendor.ddtrace_module.module import register_post_run_module_hook
    register_post_run_module_hook(hook)
