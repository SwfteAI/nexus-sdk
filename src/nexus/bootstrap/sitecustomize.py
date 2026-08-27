"""Imported by CPython during interpreter startup when this directory is on ``PYTHONPATH``.

This module runs before the application, before its dependencies, and before ``runpy`` — which is
the only window in which zero-code instrumentation and the ``python -m`` hook are both possible.

It is also the most dangerous file in the package. An exception here aborts interpreter startup:
the customer's process does not fail to report, it fails to *start*, and it does so with a
traceback pointing at a module they never chose to import. So:

* everything is inside one ``try``/``except Exception``;
* we chain to any pre-existing ``sitecustomize`` on the path rather than shadowing it — another
  vendor's agent, or the customer's own, may already own that name, and silently disabling it
  would be a serious and very hard-to-diagnose regression;
* ``NEXUS_ENABLED=0`` short-circuits before ``nexus`` is imported at all, so the kill switch costs
  an environment lookup and nothing else (case 4.12).
"""
from __future__ import annotations

import os
import sys


def _chain_previous() -> None:
    """Import any other ``sitecustomize`` that was shadowed by ours.

    Ours is first on ``sys.path`` by construction (``nexus-run`` prepends), so a real one further
    along would never be imported. Removing our own directory and retrying is the standard trick;
    ``ddtrace`` and several APM agents do the same, which is also why it has to be robust to
    *their* copy being the one we find.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    saved = list(sys.path)
    try:
        sys.path = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != here]
        sys.modules.pop("sitecustomize", None)
        try:
            import sitecustomize  # noqa: F401
        except ImportError:
            pass
    finally:
        sys.path = saved


try:
    if os.environ.get("NEXUS_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off"):
        from nexus import auto as _auto
        _auto.install()
except Exception:  # noqa: BLE001 — never break interpreter startup
    pass
finally:
    try:
        _chain_previous()
    except Exception:  # noqa: BLE001
        pass
