"""nexus — agent governance as an application dependency.

    import nexus
    nexus.init(service="support-triage", env="prod")

    with nexus.agent("triage", goal_class="classify") as run:
        with run.action("db.write", target="tickets") as act:
            act.effect(rows=n)
        run.outcome("resolved", verified_by="test")

Three levels, mirroring ``ddtrace``'s zero-code → decorator → manual ladder:

* **Level 0, zero code** — ``nexus-run python -m myservice``, or drop ``nexus.bootstrap`` on
  ``PYTHONPATH`` and the ``sitecustomize`` hook arms the SDK before the application imports.
* **Level 1, one import** — ``nexus.init(service=…, env=…, version=…)`` declares identity.
* **Level 2, explicit** — ``nexus.agent`` / ``run.action`` for the things auto-instrumentation
  cannot infer: what the unit of work *was* and whether it *worked*.

----

**Why this file is written the way it is.** ``NEXUS_ENABLED=0`` must be a *true* kill switch — no
patching, no threads, no import hooks, and an import cost indistinguishable from zero (case 4.12).
"Initialise, then no-op" does not pass a security review, because the reviewer's question is not
"does it emit?" but "what code of yours runs inside my process?", and the honest answer has to be
"almost none".

So this module imports ``os`` and nothing else at module scope — **not even ``typing``**. That
looks like pedantry and is not: on a cold interpreter ``import typing`` pulls in ``re``, which
measures at tens of milliseconds (see ``docs/OVERHEAD.md``), and it would land in the cold-start
budget of every Lambda that has the SDK installed and switched off. ``from __future__ import
annotations`` makes the annotations below strings, so none of it is needed at runtime.

Every public function is a thin
shim that checks one boolean and, only if the SDK is live, imports the module that does the work.
When disabled, ``nexus.agent(...)`` returns an inert object that absorbs the whole ``with`` block —
so the application's code path is identical either way and there is no ``if telemetry_enabled:``
for the customer to write.

The corollary is that nothing heavy may be imported at the top of this file. If you find yourself
adding ``from .transport import …`` here, you have removed the kill switch.
"""
from __future__ import annotations

import os as _os

__all__ = ["init", "agent", "action", "flush", "shutdown", "enabled", "current_run",
           "instrument_lambda_handler", "counters", "integration", "expects_data",
           "deployment", "heartbeat", "__version__"]

__version__ = "0.1.0"      # duplicated from _version.py so `import nexus` costs one module, not two
                           # (tests/test_overhead.py::test_version_matches keeps them in step)


def _enabled_now() -> bool:
    v = _os.environ.get("NEXUS_ENABLED")
    if v is None:
        return True
    return v.strip().lower() not in ("0", "false", "no", "off")


#: Read once at import. A kill switch that can be flipped mid-process would mean every entry point
#: re-reads the environment on every call — a syscall-free dict lookup, but also a promise that the
#: SDK can be armed *later*, which is exactly what "no threads, no hooks" cannot deliver.
_ENABLED = _enabled_now()


class _Inert:
    """Absorbs everything, when the SDK is off. Deliberately defined here rather than imported:
    importing ``api`` to get the disabled-path null object would defeat the point of the switch."""

    __slots__ = ()

    def __call__(self, *a: object, **k: object) -> "_Inert":
        return self

    def __getattr__(self, _name: str) -> "_Inert":
        return self

    def __enter__(self) -> "_Inert":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    async def __aenter__(self) -> "_Inert":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


_INERT = _Inert()


def enabled() -> bool:
    """Whether this process is reporting. Cheap; safe to call per request."""
    return _ENABLED


def init(service: str | None = None, env: str | None = None,
         version: str | None = None, *, application: str | None = None,
         repo: str | None = None, commit: str | None = None, **kw: object):
    """Declare service identity and arm the SDK. Idempotent (case 4.10); safe before ``fork()``.

    ``service`` / ``env`` / ``version`` are Datadog's unified tags — the join keys that let one
    ledger correlate a model call with the deploy that introduced it. Explicit arguments beat the
    environment, with the single documented exception of ``NEXUS_ENABLED`` (see ``config``).
    """
    if not _ENABLED:
        return None
    from . import client, policy
    result = client.init(service=service, env=env, version=version,
                         application=application, repo=repo, commit=commit, **kw)
    # Arm enforcement at startup, not lazily: signature verification is ~10 ms of pure-Python curve
    # arithmetic, and deferring it lands that cost inside whichever request happens to be first —
    # which is how an SDK acquires a mysterious startup p99 spike. `client.init` runs first so that
    # a malformed envelope's integrity alert has a live client to emit through. Never raises.
    policy.init()
    return result


def agent(name: str, *, goal_class: str | None = None):
    """Open a run: a unit of agent work with an outcome."""
    if not _ENABLED:
        return _INERT
    from . import api
    return api.agent(name, goal_class=goal_class)


def action(name: str, target: str | None = None):
    """Open an action against the run currently in context."""
    if not _ENABLED:
        return _INERT
    from . import api
    return api.action(name, target)


def integration(name: str, *, kind: str | None = None):
    """Probe one outbound dependency — the silent-failure primitive (ANCHOR §6.2)::

        with nexus.integration("salesforce", kind="crm") as io:
            rows = client.fetch_accounts()
            io.data(rows=len(rows), watermark=rows[-1].updated_at)

    Liveness (*the call completed*) and freshness (*the newest business timestamp we saw*) are
    recorded as two separate fields and are never merged into one. "Succeeded and returned zero
    rows" is a different fact from "succeeded", and it is the fact that catches a sync which has
    been running happily and moving nothing for three days.
    """
    if not _ENABLED:
        return _INERT
    from . import api
    return api.integration(name, kind=kind)


def expects_data(name: str, *, within: str, kind: str | None = None):
    """Declare that scheduled work must produce data inside a window (ANCHOR §6.2)::

        @nexus.expects_data("crm_sync", within="24h")
        def sync(): ...

    Disabled, this is the identity decorator and imports nothing — a decorator is evaluated at the
    customer's *import* time, so a kill switch that still pulled in the SDK here would defeat
    itself before anything ran.
    """
    if not _ENABLED:
        return lambda fn: fn
    from . import api
    return api.expects_data(name, within=within, kind=kind)


def deployment(*, version: str | None = None, commit: str | None = None,
               env: str | None = None, **kw: object) -> bool:
    """Self-report a deployment at boot when no CI or cloud connector is wired (ANCHOR §6.4).

    Stamped ``detected_by="self"``, which is the weakest claim the plane accepts and is not
    something the caller can raise. Emits nothing — and returns ``False`` — when neither a version
    nor a commit is known, because a contentless deployment record would still satisfy the join the
    shadow-deploy alarm tests and would silence it while knowing less.
    """
    if not _ENABLED:
        return False
    from . import api
    return api.deployment(version=version, commit=commit, env=env, **kw)


def heartbeat() -> bool:
    """Say "alive" from a process with no request loop — a worker, a cron job (ANCHOR §6.3).

    Services with a request loop need nothing: ``service_health`` is rolled up from the action
    spans already collected, in the flush worker, on the existing interval.
    """
    if not _ENABLED:
        return False
    from . import api
    return api.heartbeat()


def current_run():
    """The run in context, or ``None``. Uses ``contextvars``, so it is correct across ``await``."""
    if not _ENABLED:
        return None
    from . import context
    return context.current()


def flush(deadline_s: float | None = None) -> bool:
    """Drain the queue within a hard deadline. Returns True if it emptied.

    Call this before a Lambda handler returns (or use ``instrument_lambda_handler``) and anywhere
    else the process is about to stop being scheduled. It is bounded on purpose: an unbounded
    flush turns container shutdown into a hang (case 4.8).
    """
    if not _ENABLED:
        return True
    from . import client
    c = client.get_client()
    return True if c is None else c.flush(deadline_s)


def shutdown(deadline_s: float | None = None) -> bool:
    """Final flush and stop. ``atexit`` already does this; call it explicitly when you control
    the lifecycle and want the deadline to be yours."""
    if not _ENABLED:
        return True
    from . import client
    c = client.get_client()
    return True if c is None else c.shutdown(deadline_s)


def instrument_lambda_handler(handler=None, *, budget_s: float = 1.0):
    """Flush before the handler returns — case 1.11.

    Lambda freezes the sandbox the moment the handler returns, so a background flush thread does
    not run late, it does not run at all. Usable as a decorator or a wrapper::

        @nexus.instrument_lambda_handler
        def handler(event, context): ...
    """
    if not _ENABLED:
        return handler if handler is not None else (lambda f: f)
    from . import client, runtime

    def wrap(fn):
        c = client.ensure_client()
        return runtime.wrap_lambda_handler(fn, c.flush, budget_s=budget_s)

    return wrap(handler) if handler is not None else wrap


def counters() -> dict:
    """The SDK's account of itself: drops, send failures, contained hook errors, queue peak.

    Exposed publicly because case 4.3's rule — *silence about dropped data is a bug* — has to be
    checkable by the customer, not only by us. If this dict shows drops, our coverage numbers are
    wrong and both sides should be able to see that.
    """
    if not _ENABLED:
        return {}
    from . import _counters
    return _counters.snapshot()
