"""Level 2 — the explicit run/action API.

Auto-instrumentation can see a model call. It cannot see the two things that make agent telemetry
worth governing:

* **a run** — a unit of work with an *outcome*. "Four model calls and nine tool calls happened" is
  observability; "the triage agent resolved ticket 91, verified by a passing test" is a governance
  record.
* **an action** — an effect on the world, with a target. This is also the natural enforcement
  point: a gate that runs *before* the effect is the only kind that can stop anything, which is why
  ``Action`` exists as an object with a body rather than as a post-hoc annotation. The gate is
  wired: ``Action.__enter__``/``__aenter__`` call :meth:`Action._gate`, which consults
  ``policy.decide`` and raises ``policy.Denied`` before the body runs. With no signed policy
  installed it decides *allow*, so the default posture is observation — but the seam is real
  code on the call path, not a placeholder.

``run.outcome()`` takes ``verified_by`` for a reason that is not ceremony. The event it produces is
tagged ``behavior_trace``, the epistemic class reserved for verifiable fact. A model asserting
success is ``interaction_narrative``. If nobody can name the thing that checked — an exit code, a
row count, a passing test — then ``verified`` stays ``None``, which honestly says *"nothing was
verified"* rather than quietly recording a claim as a fact.

Everything here is wrapped in ``@guard``: an SDK bug inside a ``with`` block must not become an
exception in the customer's request handler. Note the consequence, which is deliberate: a broken
``Run`` degrades to a no-op object the ``with`` statement still accepts, rather than to a raise.
"""
from __future__ import annotations

import functools
import hashlib
import time
import typing as t
import uuid
import weakref

from . import _counters, contract, context
from ._safety import describe_exception, guard
from .client import Client, ensure_client


class _Inert:
    """What a guarded failure returns. Absorbs any use — attribute access, call, ``with``,
    ``async with`` — so that a customer's code inside a broken run still runs to completion.

    The alternative (returning ``None``) would put the SDK's failure in the application's
    traceback as an ``AttributeError`` two lines later, which is precisely the outcome ``_safety``
    exists to prevent."""

    __slots__ = ()

    def __call__(self, *a: t.Any, **k: t.Any) -> "_Inert":
        return self

    def __getattr__(self, _name: str) -> "_Inert":
        return self

    def __enter__(self) -> "_Inert":
        return self

    def __exit__(self, *exc: t.Any) -> bool:
        return False

    async def __aenter__(self) -> "_Inert":
        return self

    async def __aexit__(self, *exc: t.Any) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


INERT = _Inert()


class Action:
    """One effect, bracketed. Emits a ``tool_action`` when it closes."""

    __slots__ = ("_run", "name", "target", "_t0", "_effect", "_blocked", "_reason", "_closed",
                 "_decision")

    def __init__(self, run: "Run", name: str, target: t.Optional[str] = None) -> None:
        self._run = run
        self.name = name
        self.target = target
        self._t0 = time.monotonic()
        self._effect: dict = {}
        self._blocked = False
        self._reason: t.Optional[str] = None
        self._closed = False
        self._decision = None

    @guard("action.effect", default=INERT)
    def effect(self, **fields: t.Any) -> "Action":
        """What actually happened: rows written, bytes sent, exit code, files touched.

        Structured, and therefore redacted structurally (case 5.5) — the common miss is a redactor
        that walks prompt strings and passes ``{"headers": {"Authorization": "Bearer …"}}``
        straight through.
        """
        self._effect.update(fields)
        return self

    @guard("action.block")
    def block(self, reason: str) -> None:
        """Mark this action as denied *by the caller*. Records; does not raise.

        This is the manual marker, not the policy gate. :meth:`_gate` is what enforces — it
        raises ``policy.Denied`` before the body runs. ``block`` exists for the case where the
        application made the decision itself and wants it recorded in the same shape.
        """
        self._blocked = True
        self._reason = reason

    def _gate(self) -> None:
        """WP-6. Decide before the body runs; raise ``policy.Denied`` if an enforcing rule refuses.

        Deliberately **not** wrapped in ``@guard``. ``guard`` catches every exception and returns a
        default, which is right for telemetry and precisely wrong here: it would swallow
        ``policy.Denied`` and the deny would silently not happen — the failure mode that turns
        enforcement back into observation. The containment that keeps this safe lives one level
        down instead: ``policy.decide`` never raises, so the only thing that can come out of it is
        the deliberate ``Denied``. The bare ``except`` below is belt and braces for an import
        failure, and it fails *open*.
        """
        from . import policy
        try:
            d = policy.decide("tool_action", {
                "tool": self.name,
                "target": self.target,
                "run": self._run.name,
                "session": self._run.session_id,
            })
        except Exception:  # noqa: BLE001
            return
        self._decision = d
        if d.denied:
            self._blocked = True
            self._reason = d.reason or "denied by policy"
            # Emit the record before the exception propagates. ``__exit__`` will not run — the
            # ``with`` block was never entered — so this is the only chance to record that the
            # deny happened, and an unrecorded deny is indistinguishable from a call that was
            # never attempted.
            self._close()
            raise policy.Denied(d)

    def __enter__(self) -> "Action":
        self._gate()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        self._close(error=describe_exception(exc_type, exc) if exc is not None else None)
        return False        # never suppress the application's exception

    async def __aenter__(self) -> "Action":
        self._gate()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        self._close(error=describe_exception(exc_type, exc) if exc is not None else None)
        return False

    @guard("action.close")
    def _close(self, error: t.Optional[str] = None) -> None:
        if self._closed:
            return
        self._closed = True
        from .redact import scrub_mapping
        cfg = self._run._client.cfg
        self._run._actions += 1
        if self._blocked:
            self._run._blocked += 1
        self._run._client.emit(contract.tool_action(
            self._run.session_id, cfg,
            tool_name=self.name, action="invoke", target=self.target,
            blocked=self._blocked, reason=self._reason,
            duration_ms=int((time.monotonic() - self._t0) * 1000),
            run_id=self._run.run_id,
            effect=scrub_mapping(self._effect, cfg.tier) or None,
            error=error))


class Run:
    """A unit of agent work. Use as a context manager, sync or async."""

    def __init__(self, client: Client, name: str, goal_class: t.Optional[str] = None) -> None:
        self._client = client
        self.name = name
        self.run_id = uuid.uuid4().hex
        self.session_id = client.session_id
        self.goal_class = goal_class
        self._t0 = time.monotonic()
        self._token = None
        self._actions = 0
        self._blocked = 0
        self._closed = False
        self._outcome: t.Optional[tuple] = None
        # Case 2.12's rule, applied to runs: a boundary we never observed must still produce a
        # record marked incomplete, because "no event" is indistinguishable from "the service was
        # idle" and that is how abandoned-work bugs stay invisible for months. A finalizer is the
        # only hook that fires for a run whose `with` block was never exited — an abandoned
        # generator, a task cancelled mid-flight, an interpreter tearing down.
        self._finalizer = weakref.finalize(self, _abandoned, client, name, self.run_id,
                                           client.session_id)

    # -- lifecycle ----------------------------------------------------------------------------

    @guard("run.start")
    def _start(self) -> None:
        self._token = context.push(context.RunRef(self.run_id, self.name, self.session_id))
        self._client.emit(contract.agent_run(
            self.session_id, self._client.cfg, run_id=self.run_id, name=self.name,
            phase="start", goal_class=self.goal_class))

    def __enter__(self) -> "Run":
        self._start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        try:
            self._close(error=describe_exception(exc_type, exc) if exc is not None else None)
        finally:
            self._detach_context()
        return False

    async def __aenter__(self) -> "Run":
        self._start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        try:
            self._close(error=describe_exception(exc_type, exc) if exc is not None else None)
        finally:
            self._detach_context()
        return False

    def _detach_context(self) -> None:
        """Leave the context on the way out **whatever happened inside ``_close``**.

        ``_close`` is guarded, so a bug in it degrades telemetry rather than raising — but if the
        context pop lived only inside it, that same bug would leave the run active in this
        thread/task forever. Everything the host did afterwards would then be attributed to a run
        that had already ended, which is worse than losing the run entirely: it is confidently
        wrong data that somebody will act on. So the pop is unconditional and idempotent.
        """
        token, self._token = self._token, None
        if token is not None:
            try:
                context.pop(token)
            except Exception:  # noqa: BLE001
                pass

    @guard("run.close")
    def _close(self, error: t.Optional[str] = None) -> None:
        if self._closed:
            return
        self._closed = True
        self._finalizer.detach()
        self._detach_context()
        cfg = self._client.cfg
        self._client.emit(contract.agent_run(
            self.session_id, cfg, run_id=self.run_id, name=self.name, phase="end",
            goal_class=self.goal_class,
            duration_ms=int((time.monotonic() - self._t0) * 1000),
            actions=self._actions, error=error))
        if self._outcome is None and error is not None:
            # An exception is an outcome, and a factual one: it is behaviour, not a claim.
            self.outcome("error", verified=False, verified_by="exception")

    # -- surface ------------------------------------------------------------------------------

    @guard("run.action", default=INERT)
    def action(self, name: str, target: t.Optional[str] = None) -> Action:
        return Action(self, name, target)

    @guard("run.usage")
    def usage(self, *, model: str, input_tokens: int, output_tokens: int,
              provider: t.Optional[str] = None,
              cache_read_tokens: t.Optional[int] = None,
              cache_write_tokens: t.Optional[int] = None,
              cost_usd: t.Optional[float] = None, cost_source: t.Optional[str] = None,
              attempts: int = 1, incomplete: bool = False) -> None:
        """Record one **logical** model call.

        Explicit today; WP-5's provider integrations will call this from the wrapped client, which
        is why ``attempts`` and ``incomplete`` are in the signature now — one logical call can be N
        HTTP attempts (case 2.14) and a stream can end without totals (case 2.12), and a signature
        that cannot express either would have to change under customers later.
        """
        self._client.emit(contract.token_usage(
            self.session_id, self._client.cfg, model=model, provider=provider,
            input_tokens=input_tokens, output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens,
            cost_usd=cost_usd, cost_source=cost_source, run_id=self.run_id,
            attempts=attempts, incomplete=incomplete))

    @guard("run.outcome")
    def outcome(self, outcome: str, *, verified: t.Optional[bool] = None,
                verified_by: t.Optional[str] = None) -> None:
        self._outcome = (outcome, verified, verified_by)
        self._client.emit(contract.turn_outcome(
            self.session_id, self._client.cfg, run_id=self.run_id, outcome=outcome,
            verified=verified, verified_by=verified_by,
            actions=self._actions, blocked=self._blocked))


def _abandoned(client: Client, name: str, run_id: str, session_id: str) -> None:
    """Finalizer for a run nobody closed. Emits a partial rather than nothing.

    Runs at GC time, possibly during interpreter shutdown, where importing a module or touching a
    half-torn-down thread raises. Hence the blanket catch: an exception here is reported by the
    garbage collector as an unraisable and pollutes the customer's logs with a stack trace from our
    finalizer, which is a bad look for a failure that costs one telemetry record.
    """
    try:
        _counters.incr("runs_abandoned")
        client.emit(contract.agent_run(session_id, client.cfg, run_id=run_id, name=name,
                                       phase="end", incomplete=True))
    except Exception:  # noqa: BLE001
        pass


@guard("agent", default=INERT)
def agent(name: str, *, goal_class: t.Optional[str] = None) -> Run:
    """Open a run. ``with nexus.agent("triage") as run: …``"""
    return Run(ensure_client(), name, goal_class=goal_class)


@guard("action", default=INERT)
def action(name: str, target: t.Optional[str] = None) -> Action:
    """Open an action against the run currently in context.

    Convenience for code that is several frames below the ``with nexus.agent(...)`` that opened the
    run — passing the ``Run`` object down through an application's call stack is exactly the sort of
    invasive change that makes teams decline an SDK. Outside any run it opens an implicit one, so
    the action is still captured rather than dropped for lack of a parent.
    """
    client = ensure_client()
    ref = context.current()
    run = Run(client, ref.name if ref else "unattributed")
    if ref is not None:
        run.run_id = ref.run_id
        run.session_id = ref.session_id
    run._finalizer.detach()      # a synthetic parent must not emit an abandoned-run record
    run._closed = True
    return Action(run, name, target)


# ============================================================ the operate plane (§6.2, §6.4)
# Two calls the agent API does not cover, because they are about the *service* rather than about
# the agent: is the data this process depends on still arriving, and what is this process actually
# running. Both obey the same rules as everything above — guarded, inert under the kill switch, no
# I/O on the calling thread.


def _watermark(value: t.Any) -> t.Optional[str]:
    """Normalise a business timestamp to RFC-3339, or return ``None``.

    Three accepted shapes and one deliberate refusal:

    * anything with ``.isoformat()`` (``datetime``, ``date``, most ORM columns) — used as given;
    * a string — used as given, bounded, because the caller read it off their own record and we are
      not in the business of reinterpreting somebody's timestamp format;
    * an ``int``/``float`` — POSIX epoch **seconds**, the convention ``time.time()`` returns.

    A number above ``1e11`` is rejected rather than converted. It is almost certainly milliseconds,
    and interpreting it as seconds would place the watermark in the year 5138 — which does not read
    as an error on a freshness cell, it reads as *perfectly fresh*, permanently. A dropped watermark
    leaves ``last_data_ts`` absent, which the console draws as a break; a wrong one silences the
    silent-failure alarm this whole call exists to raise.
    """
    if value is None:
        return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return str(iso())[:64]
        except Exception:  # noqa: BLE001
            return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value <= 0 or value > 1e11:
            return None
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))
    text = str(value).strip()
    return text[:64] or None


class Integration:
    """One observation of an outbound dependency, bracketed. Emits an ``integration_probe``.

    ::

        with nexus.integration("salesforce", kind="crm") as io:
            rows = client.fetch_accounts()
            io.data(rows=len(rows), watermark=rows[-1].updated_at)

    **The two registers this object keeps apart, and must never merge.**

    * ``integration_up`` — LIVENESS. Did the call complete? Set by the ``with`` block's exit, from
      whether an exception came out. Nothing else sets it.
    * ``last_data_ts`` — FRESHNESS. The newest *business* timestamp actually seen in the response.
      Set only by ``io.data(watermark=…)``, and never derived from the probe time.

    The second is the one no uptime monitor has. *Succeeded and returned zero rows* is a different
    fact from *succeeded*, and a sync that has returned the same three-day-old rows every minute
    since Tuesday is up, authorised, fast, and broken. If the body never calls ``io.data``, the
    probe carries liveness alone and the console draws the freshness half as absent — which is
    exactly right, because nobody told us.

    ``auth_ok`` is likewise only ever what ``io.auth()`` was told. It is not inferred from an
    exception's shape: a 403 from a rate limiter and a 403 from an expired credential are different
    incidents with different fixes, and guessing between them from a string would put the wrong one
    on the board.
    """

    __slots__ = ("_client", "name", "kind", "_t0", "_rows", "_watermark", "_schema",
                 "_auth_ok", "_error", "_error_class", "_up", "_closed")

    def __init__(self, client: Client, name: str, *, kind: t.Optional[str] = None) -> None:
        self._client = client
        self.name = str(name)[:128]
        self.kind = kind
        self._t0 = time.monotonic()
        self._rows: t.Optional[int] = None
        self._watermark: t.Optional[str] = None
        self._schema: t.Optional[str] = None
        self._auth_ok: t.Optional[bool] = None
        self._error: t.Optional[str] = None
        self._error_class: t.Optional[str] = None
        self._up: t.Optional[bool] = None
        self._closed = False

    @guard("integration.data", default=INERT)
    def data(self, *, rows: t.Optional[int] = None, watermark: t.Any = None,
             schema_fingerprint: t.Optional[str] = None) -> "Integration":
        """What came back. ``rows=0`` is a real answer and is recorded as one."""
        if rows is not None:
            self._rows = int(rows)
        wm = _watermark(watermark)
        if wm is not None:
            self._watermark = wm
        if schema_fingerprint is not None:
            self._schema = str(schema_fingerprint)[:64]
        return self

    @guard("integration.auth", default=INERT)
    def auth(self, ok: bool) -> "Integration":
        """Say whether the credential was accepted. Only the caller knows; we never guess."""
        self._auth_ok = bool(ok)
        return self

    @guard("integration.fail", default=INERT)
    def fail(self, error: t.Any, *, error_class: t.Optional[str] = None) -> "Integration":
        """Record a failure the caller handled, so it never became an exception we could see.

        The common shape this exists for is a client that returns an error object rather than
        raising. Without it the probe would report ``integration_up=True`` for a call that
        failed — the SDK confidently reporting the opposite of what happened.
        """
        self._up = False
        self._error = None if error is None else str(error)
        if error_class is not None:
            self._error_class = str(error_class)[:64]
        return self

    @guard("integration.schema", default=INERT)
    def schema(self, sample: t.Any) -> "Integration":
        """Fingerprint the response's *shape* so a silent schema break is visible before the rows
        stop matching. Keys only for a mapping; never values, at any tier."""
        if isinstance(sample, dict):
            shape = ",".join(sorted(str(k)[:64] for k in list(sample.keys())[:128]))
        else:
            shape = type(sample).__name__
        self._schema = contract.fingerprint(shape)
        return self

    # -- lifecycle ----------------------------------------------------------------------------

    def __enter__(self) -> "Integration":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        self._close(exc_type, exc)
        return False        # never suppress the application's exception

    async def __aenter__(self) -> "Integration":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        self._close(exc_type, exc)
        return False

    @guard("integration.close")
    def _close(self, exc_type=None, exc=None) -> None:  # noqa: ANN001
        if self._closed:
            return
        self._closed = True
        if exc is not None:
            self._up = False
            if self._error is None:
                self._error = describe_exception(exc_type, exc)
        elif self._up is None:
            self._up = True
        cfg = self._client.cfg
        self._client.emit(contract.integration_probe(
            self._client.session_id, cfg,
            integration=self.name,
            observed_ts=contract.now(),
            app_id=cfg.application,
            service=cfg.service if cfg.service != "unknown" else None,
            kind=self.kind,
            integration_up=self._up,
            auth_ok=self._auth_ok,
            latency_ms=int((time.monotonic() - self._t0) * 1000),
            last_data_ts=self._watermark,
            rows=self._rows,
            schema_fingerprint=self._schema,
            error=self._error,
            error_class=self._error_class,
            detected_by=contract.DETECTED_BY_SDK))


@guard("integration", default=INERT)
def integration(name: str, *, kind: t.Optional[str] = None) -> Integration:
    """Open a probe against one outbound dependency."""
    return Integration(ensure_client(), name, kind=kind)


# -- declared expectations (§6.2) ---------------------------------------------------------------
# The declaration half of the silent-failure alarm. The asymmetry that makes the alarm honest: it
# fires on *absence of evidence against a declared expectation*, never on absence alone, because
# absence alone is indistinguishable from "nobody ever declared this integration existed".
#
# TODO(contract): the declaration has no wire representation. `nexus_devtools/events.py` has no
# `data_expectation` builder and this module's own warning forbids inventing an event type here
# ahead of the artifact, so the window below stays in-process and the console's `DataExpectation`
# can only be populated by a human declaring it there. Until event 34 exists, this decorator
# delivers the *probe* half automatically and the alarm cannot fire from code alone.
DECLARED: dict = {}

_UNITS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def _within_ms(within: str) -> t.Optional[int]:
    """``"24h"`` → ``86400000``. ``None`` for anything unparseable — never a default window.

    A default here would be the whole feature failing quietly: an expectation that silently became
    "within 24h" because the caller typed ``"1 day"`` is an alarm whose threshold nobody chose.
    """
    text = str(within or "").strip().lower()
    if len(text) < 2 or text[-1] not in _UNITS:
        return None
    try:
        n = float(text[:-1])
    except ValueError:
        return None
    if n <= 0:
        return None
    return int(n * _UNITS[text[-1]])


def expects_data(integration_name: str, *, within: str, kind: t.Optional[str] = None):
    """Declare that a scheduled unit of work must produce data inside a window.

    ::

        @nexus.expects_data("crm_sync", within="24h")
        def sync(): ...

    Every call emits an ``integration_probe`` for ``integration_name``, so the liveness half needs
    no code at all. The freshness half still needs a watermark, which only the body can supply —
    open a ``nexus.integration()`` inside for that, or call the sync's own probe explicitly. A
    decorator cannot read a business timestamp out of an arbitrary return value without guessing at
    its meaning, and a guessed watermark is the one thing this feature must never produce.

    Decoration itself never raises. An unparseable ``within`` is recorded as an unparsed
    declaration rather than rejected at import time — the SDK refusing to load a customer's module
    because of a typo in a telemetry string is exactly the failure mode ``_safety`` exists for.
    """
    parsed = _within_ms(within)
    DECLARED[str(integration_name)] = {"integration": str(integration_name),
                                       "within": str(within), "within_ms": parsed,
                                       "kind": kind}

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a: t.Any, **kw: t.Any) -> t.Any:
            with integration(integration_name, kind=kind):
                return fn(*a, **kw)
        wrapper.__nexus_expects_data__ = DECLARED[str(integration_name)]  # type: ignore[attr-defined]
        return wrapper

    return deco


# -- self-reported deployment (§6.4) ------------------------------------------------------------

@guard("deployment", default=False)
def deployment(*, version: t.Optional[str] = None, commit: t.Optional[str] = None,
               env: t.Optional[str] = None, app_id: t.Optional[str] = None,
               repo: t.Optional[str] = None, deployment_id: t.Optional[str] = None,
               actor: t.Optional[str] = None, outcome: str = contract.DEPLOY_SUCCEEDED,
               started_ts: t.Optional[str] = None, finished_ts: t.Optional[str] = None,
               rollback_of: t.Optional[str] = None) -> bool:
    """Self-report a deployment at boot, when no CI or cloud connector is wired.

    ``detected_by`` is stamped ``"self"`` and is **not a parameter**. A process asserting its own
    deployment is the weakest claim on the plane — it has every incentive to believe it was
    deployed and no way to check — and the console ranks it below a forge, cloud or CI record
    everywhere it appears. Letting a caller pass ``detected_by="cloud"`` would let a self-report
    impersonate a connector, which is the one thing that would make the ranking worthless.

    **This returns ``False`` and emits nothing when neither a version nor a commit is known.** That
    is the most important line in the function. A deployment record with no version and no commit
    still *counts as a deployment record*, so it would satisfy the join that the shadow-deploy alarm
    tests — and the alarm ("production contains software that no release accounts for") would go
    quiet while knowing strictly less than before. Emitting nothing leaves the break drawn.

    ``deployment_id`` defaults to a digest of ``service:env:version:commit`` rather than a fresh
    uuid, so twelve replicas booting the same release report one deployment instead of twelve, and
    a restart does not read as a redeploy. It is derived from values we were given, never invented.
    """
    client = ensure_client()
    cfg = client.cfg
    version = version or (cfg.version if cfg.version != "unknown" else None)
    commit = commit or cfg.commit
    if not version and not commit:
        _counters.incr(_counters.BUILD_FAILED)
        return False
    env = env or (cfg.env if cfg.env != "unknown" else None)
    if not env:
        # Same rule as above: a deployment with no environment cannot be placed in the estate grid,
        # and placing it in a guessed one would put staging's version in the prod column.
        _counters.incr(_counters.BUILD_FAILED)
        return False
    if not deployment_id:
        seed = f"self:{cfg.service}:{env}:{version or ''}:{commit or ''}"
        deployment_id = "self-" + hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:16]
    return bool(client.emit(contract.deployment(
        client.session_id, cfg,
        deployment_id=deployment_id, env=env,
        app_id=app_id or cfg.application,
        version=version, commit=commit, repo=repo or cfg.repo,
        actor=actor, started_ts=started_ts, finished_ts=finished_ts,
        outcome=outcome, rollback_of=rollback_of,
        detected_by=contract.DETECTED_BY_SELF)))


@guard("heartbeat", default=False)
def heartbeat() -> bool:
    """Say "this process is alive" for a runtime with no request loop — a worker, a cron job.

    Emits the current ``service_health`` window immediately. When nothing was measured the window
    carries a timestamp and **no quantities**, which the console draws hollow. It does not carry
    ``requests: 0``, because a worker that served no HTTP requests is not a fact about the worker's
    health; it is a fact about what the SDK was asked to instrument.
    """
    return bool(ensure_client().heartbeat())
