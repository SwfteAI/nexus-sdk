"""Provider and framework adapters — **the registry, not the adapters.** (WP-5.)

M0–M1 deliberately ships zero integrations. What ships is the shape they must fit, because the
shape is what stops the next milestone from becoming a monolith:

* **Each library is an independently versioned adapter with its own patch/unpatch and its own
  tests.** Adding CrewAI must not be a core change. This is the single structural thing worth
  copying from ``ddtrace``, and it is the thing that decays first if the first two adapters are
  written directly into the core.
* **A version outside the supported range is skipped, recorded as unsupported, and never raises**
  (case 2.4). The failure a customer will actually hit is not "unsupported", it is "we patched a
  method that moved" — so an adapter that cannot find what it expects degrades to pass-through
  with one structured warning, not a loop of them (case 2.5).
* **Foreign wrappers must be detected, not fought** (cases 2.6/2.8). A customer running ``ddtrace``
  and/or OpenLLMetry has three SDKs wrapping the same ``Messages.create``. ``wrapt`` nests safely,
  so nothing crashes — which is precisely why this is dangerous: tokens get counted twice, span
  parentage breaks, and the exact-cost claim quietly becomes false. ``foreign_wrappers()`` below
  is the detection primitive; the WP-0 decision it serves is *detect, emit one billable record,
  attribute the rest as structure*. It lives here now so that WP-5 cannot be written without it.

The exclusion list is not a nicety either — see ``EXCLUDED_MODULES``.

**WP-5 update — what "adapter" turned out to mean.** The registry below is still the shape any
future library-specific patch must fit, but almost nothing needs to fit it. ``REPLICATION-EFFORT``
measured one OpenLLMetry provider adapter at 931 lines across 8 files; there are ~30 of them,
maintained by three funded projects under permissive licences. So the coverage strategy is to
*consume* those spans rather than re-derive them: :mod:`nexus.otel.bridge` turns OpenInference /
OpenLLMetry / GenAI-semconv spans into nexus events, adding the four things no upstream vocabulary
has — an epistemic class, our privacy tier re-applied on ingest, exact cost with the cache split,
and one billable record per logical call. Sibling modules here support that:

* :mod:`nexus.integrations.pricing` — the rate card, mirrored from ``nexus_devtools/pricing.py``
  and pinned by a parity test.
* :mod:`nexus.integrations.billing` — the logical-call ledger implementing D-4.
* :mod:`nexus.integrations.selfexclude` — case 2.19, in three independent layers.
* :mod:`nexus.integrations.streams` — case 2.12 for generators, where there is no span to watch.
"""
from __future__ import annotations

import logging
import types
import typing as t

from .selfexclude import is_self_module

log = logging.getLogger("nexus.integrations")

#: Modules that must never be instrumented, whatever a future adapter says.
#:
#: Case 2.19: our own egress client, wrapped by our own HTTP instrumentation, means every flush
#: produces events, which trigger a flush. That is not a slowdown, it is unbounded recursion that
#: consumes the process. The rule has to live at the registry level rather than inside each
#: adapter, because the adapter that breaks it will be the one written last, by someone who has not
#: read this comment.
EXCLUDED_MODULES: frozenset = frozenset({
    "nexus", "nexus.transport", "nexus.client", "nexus.contract",
    "nexus.otel", "nexus.otel.bridge", "nexus.integrations",
})

#: name -> factory. Populated by WP-5; empty on purpose today.
REGISTRY: dict = {}


def is_excluded(module_name: str) -> bool:
    """Never-instrument test, by prefix rather than by exact name.

    The exact-match version was a latent hole: ``nexus.transport`` was listed but a future
    ``nexus.transport.http`` would not have matched, and the adapter that reached it would have
    been written by someone who never read the comment above. ``selfexclude.is_self_module`` is the
    single predicate; this is here so the registry has one name for it.
    """
    return module_name in EXCLUDED_MODULES or is_self_module(module_name)


def register(module_name: str, installer: t.Callable[[t.Any], None]) -> None:
    """Declare that ``installer(module)`` patches ``module_name`` when it is imported."""
    if is_excluded(module_name):
        raise ValueError(f"{module_name} is on the never-instrument list")
    REGISTRY[module_name] = installer


def install_all() -> int:
    """Wire every registered adapter to the import watchdog. Returns how many were wired.

    Zero today. It is called by ``auto.install`` regardless, so that the day the first adapter
    lands there is no second code path to discover.
    """
    from .. import hooks
    n = 0
    for name, installer in REGISTRY.items():
        hooks.on_import(name, installer)
        n += 1
    return n


def foreign_wrappers(fn: t.Any) -> list[str]:
    """Walk the ``__wrapped__`` chain and name the other instrumentation on this callable.

    The detection primitive for double instrumentation (case 2.6). A customer running Datadog or
    OpenLLMetry alongside us gets double-counted tokens unless somebody notices the callable is
    already wrapped — and nobody notices, because everything keeps working.

    Attribution is by defining module of each layer, which is crude but sufficient: we only need to
    answer *"is there another instrumentation layer between us and the real method?"*, not to
    identify the vendor precisely.
    """
    seen: list[str] = []
    cur = fn
    for _ in range(16):     # bounded: a cyclic __wrapped__ chain is possible and must not hang
        nxt = getattr(cur, "__wrapped__", None)
        if nxt is None or nxt is cur:
            break
        mod = _wrapper_module(cur)
        if mod and mod != "builtins" and not is_self_module(mod):
            seen.append(mod)
        cur = nxt
    return seen


def _wrapper_module(obj: t.Any) -> str:
    """Which package defined *this layer* of a ``__wrapped__`` chain.

    Two wrapper shapes need opposite answers, and getting it backwards names the wrong vendor:

    * a **closure wrapper** — what ``ddtrace``'s patchers and most hand-written decorators produce —
      carries its defining module on the function object, while ``type(obj).__module__`` is just
      ``builtins``;
    * a **``wrapt.ObjectProxy``** forwards ``__module__`` to the object it wraps, so asking the
      instance returns the module of the layer *below* it. For those the proxy class is the only
      honest source.
    """
    if isinstance(obj, (types.FunctionType, types.MethodType)):
        return str(getattr(obj, "__module__", "") or "")
    type_module = str(getattr(type(obj), "__module__", "") or "")
    if type_module and type_module != "builtins":
        return type_module
    return str(getattr(obj, "__module__", "") or "")


#: Instrumentation we recognise by module prefix when walking a ``__wrapped__`` chain. Used only to
#: *name* what else is watching; precedence never depends on which vendor it is.
KNOWN_FOREIGN_PREFIXES: tuple[str, ...] = (
    "ddtrace", "opentelemetry", "openinference", "openllmetry", "traceloop", "openlit",
    "langsmith", "langfuse", "wrapt", "newrelic", "elasticapm", "sentry_sdk",
)


def wrap_depth(fn: t.Any) -> int:
    """How many wrappers sit between ``fn`` and the real callable. Bounded, cycle-safe."""
    depth, cur = 0, fn
    for _ in range(16):
        nxt = getattr(cur, "__wrapped__", None)
        if nxt is None or nxt is cur:
            break
        depth += 1
        cur = nxt
    return depth


def coexistence(fn: t.Any) -> dict:
    """What else is instrumenting this callable, as structure — the D-4 step-1 primitive.

    Answers three questions the billing decision needs and nothing more: is anybody else here, who,
    and how deep are we. It deliberately does **not** decide precedence. Precedence is a runtime
    property of the *call*, not of the patch: the innermost observer wins because it is the only one
    that sees the vendor's internal retries, and which layer is innermost is only knowable from span
    nesting at call time (:mod:`nexus.otel.billing`). Deciding it at patch time from wrapper order
    would get 2.14 wrong in the direction that over-bills.
    """
    others = foreign_wrappers(fn)
    named = sorted({p for p in KNOWN_FOREIGN_PREFIXES
                    for m in others if m == p or m.startswith(p + ".")})
    return {"foreign_wrappers": others, "recognised": named,
            "depth": wrap_depth(fn), "double_instrumented": bool(others)}
