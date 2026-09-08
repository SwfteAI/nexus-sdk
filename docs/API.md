# API reference

Every public name in `swfte-nexus-sdk`, what it does, and what it returns. The import name is
`nexus`; the distribution is `swfte-nexus-sdk`.

Two rules hold across the entire surface and are worth reading before the tables:

1. **Nothing here raises**, with exactly one exception: `policy.Denied`, which requires the rule to
   carry `enforce: true` *and* the call site not to decline it. Every other entry point is wrapped
   in a guard that contains the exception and returns a safe default. A telemetry SDK must never be
   the reason a request fails.
2. **When `NEXUS_ENABLED=0`, every call below is inert.** Not initialised-then-no-op'd — there are
   no threads, no import hooks and no sockets. A disabled `with nexus.agent(...)` block costs
   0.5 µs, and the objects returned absorb any attribute access or call you make on them.

- [Lifecycle](#lifecycle)
- [Capture](#capture) — runs, actions, usage, outcomes
- [Integrations](#integrations) — external systems you read from
- [Operations](#operations) — deployments, heartbeats, self-telemetry
- [Enforcement](#enforcement) — `nexus.policy`
- [Command line](#command-line)
- [Types](#types)

---

## Lifecycle

### `nexus.init(...)`

```python
nexus.init(service=None, env=None, version=None, *,
           application=None, repo=None, commit=None, **kw) -> Client | None
```

Declares service identity and arms the SDK. **Idempotent** and safe to call before `fork()`.
Calling it again — ten times from a notebook cell, or once at import and once in a factory —
upgrades identity in place rather than erroring.

`service` / `env` / `version` are Datadog's unified tags: the join keys that let one ledger
correlate a model call with the deploy that introduced it. Explicit arguments beat environment
variables, with the single documented exception of `NEXUS_ENABLED`.

There is **no user identity anywhere in this SDK**. A service does not have a user, and inventing
one is how a telemetry pipeline becomes a compliance problem.

Returns the client, or `None` when disabled.

```python
import nexus
nexus.init(service="checkout", env="prod", version="2026.8.1")
```

### `nexus.enabled()`

```python
nexus.enabled() -> bool
```

Whether this process is reporting. Cheap — a module-level boolean read, no syscall. Safe per
request.

The value is read **once at import**. A kill switch that could be flipped mid-process would mean
every entry point re-reading the environment, and would promise that the SDK can be armed *later*,
which is exactly what "no threads, no import hooks" cannot deliver.

### `nexus.flush(deadline_s=None)`

```python
nexus.flush(deadline_s: float | None = None) -> bool
```

Drains the queue within a hard deadline. Returns `True` if it emptied.

Bounded on purpose. Call it wherever the process is about to stop being scheduled — before a Lambda
handler returns, before a batch job exits.

### `nexus.shutdown(deadline_s=None)`

```python
nexus.shutdown(deadline_s: float | None = None) -> bool
```

Final flush, then stop. `atexit` already does this; call it explicitly when you control the
lifecycle and want the deadline to be yours. **A hung collector must not hang your container.**

### `nexus.instrument_lambda_handler(handler=None, *, budget_s=1.0)`

Flushes before the handler returns. Usable as a decorator or a wrapper.

AWS Lambda freezes the sandbox the moment the handler returns, so a background flush thread does
not run late — it does not run at all. This is the one deployment shape that needs a code change.

```python
@nexus.instrument_lambda_handler(budget_s=1.0)
def handler(event, context):
    ...
```

---

## Capture

A **run** is a unit of agent work with an outcome. An **action** is something with an effect on the
world — the thing enforcement gates. The distinction is not stylistic: what the agent *did*
(`behavior_trace`) and what the model *said it did* (`rationalisation`) are different epistemic
classes and are stamped as such, because only one is admissible as evidence.

### `nexus.agent(name, *, goal_class=None)`

```python
nexus.agent(name: str, *, goal_class: str | None = None) -> Run
```

Opens a run. Use as a context manager; the run closes with an outcome on exit, and an escaping
exception is recorded as the error.

### `nexus.current_run()`

```python
nexus.current_run() -> Run | None
```

The run in context, or `None`. Uses `contextvars`, so it is correct across `await`.

### `nexus.action(name, target=None)`

```python
nexus.action(name: str, target: str | None = None) -> Action
```

Opens an action against the run currently in context — convenience for code several frames below
the `with nexus.agent(...)` that opened the run. Threading a `Run` object down through an
application's call stack is exactly the sort of invasive change that makes teams decline an SDK.

Outside any run it opens an implicit one, so the action is still captured rather than dropped for
lack of a parent.

### `Run.action(name, target=None)`

```python
run.action(name: str, target: str | None = None) -> Action
```

Opens an action inside this run. Context manager.

### `Run.usage(...)`

```python
run.usage(*, model: str, input_tokens: int, output_tokens: int,
          provider: str | None = None,
          cache_read_tokens: int | None = None,
          cache_write_tokens: int | None = None,
          cost_usd: float | None = None, cost_source: str | None = None,
          attempts: int = 1, incomplete: bool = False) -> None
```

Records one **logical** model call.

`attempts` and `incomplete` are in the signature from the start deliberately: one logical call can
be N HTTP attempts, and a stream can end without totals. A signature unable to express either would
have had to change under customers later.

### `Run.outcome(outcome, *, verified=None, verified_by=None)`

```python
run.outcome(outcome: str, *, verified: bool | None = None,
            verified_by: str | None = None) -> None
```

How the run ended. `verified` / `verified_by` are what separate a claimed success from a checked
one — `verified_by="ledger_balance"` says something an agent's own assertion cannot.

### `Action.effect(**fields)`

```python
act.effect(**fields) -> Action
```

What the action did to the world. Chainable.

### `Action.block(reason)`

```python
act.block(reason: str) -> None
```

Records that this action was blocked, and why.

```python
with nexus.agent("refund-request", goal_class="transaction") as run:
    with run.action("db_write", target="refunds") as act:
        act.effect(rows=1, amount_cents=4200)

    run.usage(model="claude-opus-4", input_tokens=1_800, output_tokens=240)
    run.outcome("success", verified=True, verified_by="ledger_balance")
```

---

## Integrations

For external systems your service *reads from*, where the question is usually "did anything come
back, and was it fresh?".

### `nexus.integration(name, *, kind=None)`

```python
nexus.integration(name: str, *, kind: str | None = None) -> Integration
```

Context manager. Methods are chainable:

| Method | |
|---|---|
| `.data(*, rows=None, watermark=None, schema_fingerprint=None)` | what came back. **`rows=0` is a real answer** and is recorded as one, not treated as missing |
| `.auth(ok: bool)` | whether authentication succeeded |
| `.fail(error, *, error_class=None)` | it did not work |
| `.schema(sample)` | fingerprints the shape of a sample without sending it |

A bare-number `watermark` is interpreted as **epoch seconds** here (`time.time()`). The Node SDK
reads it as epoch milliseconds (`Date.now()`) — a deliberate difference, because picking one would
make the other language's idiomatic call wrong.

### `nexus.expects_data(integration_name, *, within, kind=None)`

Decorator. Declares that an integration is expected to produce data within a window, so that
*silence* becomes reportable rather than invisible. `within` is a duration string, e.g. `"15m"`.

---

## Operations

### `nexus.deployment(...)`

```python
nexus.deployment(*, version=None, commit=None, env=None, app_id=None, repo=None,
                 deployment_id=None, actor=None, outcome="succeeded",
                 started_ts=None, finished_ts=None, rollback_of=None) -> bool
```

Self-reports a deployment at boot, for when no CI or cloud connector is wired.

`detected_by` is stamped `"self"` and is **not a parameter**. A process asserting its own deployment
is the weakest claim on the plane, and the data model records that rather than letting it pass as
an observation.

### `nexus.heartbeat()`

```python
nexus.heartbeat() -> bool
```

Liveness for this service instance.

### `nexus.counters()`

```python
nexus.counters() -> dict
```

The SDK's account of itself: drops, send failures, contained hook errors, queue peak.

Public on purpose. The rule is *silence about dropped data is a bug*, and that has to be checkable
by you, not only by us. **If this dict shows drops, coverage numbers are wrong and both sides
should be able to see it.**

---

## Enforcement

```python
from nexus import policy
```

| Name | |
|---|---|
| `policy.decide(kind, subject, *, enforce=None, approval_max_s=None) -> Decision` | evaluate. **Never raises** |
| `policy.gate(kind, subject, ...)` | context manager. Decides *before* yielding; raises `Denied` on an enforcing deny |
| `policy.check(kind, subject, ...) -> Decision` | the raising counterpart to `decide`, for where the effect is the next statement and there is no block to wrap |
| `policy.install(envelope)` | install a signed, verified policy envelope |
| `policy.refresh()` / `policy.snapshot()` | refresh from the control plane / inspect what is active |
| `policy.configure(...)` / `policy.settings` | local settings |
| `policy.ALLOW` / `policy.DENY` | decision constants |
| `policy.Decision` / `policy.Denied` / `policy.Snapshot` / `policy.Settings` | types |
| `policy.alerts` / `policy.approval` / `policy.deputy` / `policy.envelope` / `policy.rules` | submodules |

Failure semantics are specified in the [README](../README.md#enforcement) and are worth reading
before you rely on this in production. The short version: missing or unverifiable policy **allows**
and alerts; verified-but-stale policy keeps enforcing its `enforce`-marked rules and degrades the
rest to advice; exceeding the latency budget **allows** and records the timeout. Denying because
something was unreachable is never a default.

---

## Command line

### `nexus-run`

```bash
nexus-run python -m yourapp
```

Level 1 — no code changes. **`exec`s** your program rather than spawning it as a child, so signals,
exit codes and process identity are yours, unchanged.

For containers, with no wrapper process at all:

```bash
PYTHONPATH=$(python -c "import nexus.bootstrap,os;print(os.path.dirname(nexus.bootstrap.__file__))")
```

---

## Types

| Name | |
|---|---|
| `nexus.__version__` | the package version, also stamped on every event as `sdk_version` |
| `Run`, `Action`, `Integration` | returned by the capture calls above; all are context managers |
| `policy.Decision`, `policy.Denied`, `policy.Snapshot`, `policy.Settings` | see [Enforcement](#enforcement) |

`nexus._version.CONTRACT_VERSION` is the **event-contract** version and moves independently of the
package version. A customer's production image does not upgrade on our schedule, so ingest must keep
accepting an eighteen-month-old SDK.

---

[Configuration and privacy tiers](../README.md#configuration) ·
[Overhead](OVERHEAD.md) · [Deployment coverage](RUNTIME-CASES-CHECKLIST.md) ·
[www.swfte.com](https://www.swfte.com)
