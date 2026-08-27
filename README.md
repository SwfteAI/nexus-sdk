# swfte-nexus-sdk

Agent observability for services you run yourself.

`nexus wrap` captures what an agent does inside a developer's terminal. This package captures the
same thing inside your own application — the third attach point on one event ledger, stamped
`producer="sdk"` so a run in production and a run on a laptop are the same shape in the same
tables.

```
pip install swfte-nexus-sdk        # import name is `nexus`
```

Python 3.10+. **Zero required dependencies** — see [Why no dependencies](#why-no-dependencies).

---

## Three levels, pick one

**Level 1 — no code changes.** Prefix the command:

```
nexus-run python -m yourapp
```

Or set it once for a container, with no wrapper process at all:

```
PYTHONPATH=$(python -c "import nexus.bootstrap,os;print(os.path.dirname(nexus.bootstrap.__file__))")
```

`nexus-run` execs your program rather than spawning it as a child, so signals, exit codes and
process identity are yours, unchanged.

**Level 2 — declare who you are.** One call, at startup:

```python
import nexus
nexus.init(service="checkout", env="prod", version="2026.8.1")
```

Datadog's unified tagging. `service` / `env` / `version` land on every event as join keys. There is
no user identity anywhere in this SDK: a service does not have a user, and inventing one is how a
telemetry pipeline becomes a compliance problem.

**Level 3 — say what the agent did.**

```python
with nexus.agent("refund-request", goal_class="transaction") as run:
    with run.action("db_write", target="refunds") as act:
        act.effect(rows=1, amount_cents=4200)

    run.usage(model="claude-opus-4", input_tokens=1_800, output_tokens=240)
    run.outcome("success", verified=True, verified_by="ledger_balance")
```

A **run** is a unit of agent work with an outcome. An **action** is something with an effect on the
world — the thing enforcement will eventually gate. The distinction is not stylistic: what the
agent *did* (`behavior_trace`) and what the model *said it did* (`rationalisation`) are different
epistemic classes and are stamped as such, because only one of them is admissible as evidence.

All three levels compose. Auto-init plus explicit `init()` plus manual spans is a supported
combination; `init()` called twice, or ten times from a notebook cell, upgrades identity in place.

---

## Guarantees

**A telemetry SDK must never be the reason a request fails.** Concretely, and each one is a test:

- Every public entry point is wrapped in a guard that contains exceptions and returns a safe
  default. Coverage is exhaustive by construction — guards register themselves, and the chaos suite
  iterates the registry, so a new entry point without a guard fails the build.
- The calling thread never performs I/O. Asserted by spying on `socket.socket.connect` across a
  realistic workload, not inferred from timings.
- The queue is bounded and drops **oldest**, because the newest events describe the incident. Every
  drop is counted and reported in `nexus.counters()`. Silence about dropped data is a bug.
- `fork()` is handled: the child replaces its locks rather than acquiring them (an inherited held
  lock is a deadlock in a pre-fork server), empties the inherited queue, takes a fresh session, and
  rebuilds its worker. Parent-buffered events are not replayed once per worker.
- Shutdown flushes with a **deadline**. A hung collector must not hang your container.
- `SIGKILL` loses the in-flight buffer. That is not fixable and we do not pretend otherwise —
  `test_4_9_sigkill_loses_the_buffer_and_we_say_so` asserts the loss.

Measured cost: **~19 µs** per action span, **~35 ms** to arm the SDK at startup, **~0 ms** for
`import nexus` itself. Full numbers, method, and the budgets enforced in CI:
[`docs/OVERHEAD.md`](docs/OVERHEAD.md).

### The kill switch is real

```
NEXUS_ENABLED=0
```

No threads, no import hooks, no sockets, and nothing initialised-then-no-op'd. `nexus/__init__.py`
imports only `os` at module scope — not even `typing`, because on a cold interpreter `import
typing` pulls in `re` and lands tens of milliseconds in the cold-start budget of every Lambda that
has this installed and switched off. A disabled `with nexus.agent(...)` block costs 0.5 µs.

---

## Configuration

Explicit arguments win over environment variables, which win over a config file, which wins over
defaults. The one exception is `NEXUS_ENABLED=0`, which wins over everything — an operator
disabling telemetry from outside the process has to beat application code that says otherwise, or
it is not a kill switch.

There is no `~/.nexus`. A file is read only when `NEXUS_CONFIG_FILE` names one, and failing to read
it is a warning, never an exception.

| Variable | Default | |
|---|---|---|
| `NEXUS_ENABLED` | `1` | `0` disables entirely |
| `NEXUS_SERVICE` / `NEXUS_ENV` / `NEXUS_VERSION` | `unknown` | unified tagging |
| `NEXUS_COLLECTOR_URL` | `http://127.0.0.1:8791` | full URL |
| `NEXUS_COLLECTOR_HOST` / `NEXUS_COLLECTOR_PORT` | — | **sidecar mode**: not hardcoded to loopback, IPv6 hosts are bracketed |
| `NEXUS_TIER` | `metadata_only` | `metadata_only` / `redacted_preview` / `full` |
| `NEXUS_QUEUE_CAPACITY` | `10000` | events, then drop-oldest |
| `NEXUS_FLUSH_INTERVAL_S` / `NEXUS_FLUSH_DEADLINE_S` | `2.0` / `5.0` | |
| `NEXUS_TRANSPORT_MODE` | auto | `thread` / `sync`; auto-detects uWSGI without `--enable-threads` |

| Tier | What goes on the wire |
|---|---|
| `metadata_only` | Shape, counts, durations, and `*_fingerprint` digests. No content. |
| `redacted_preview` | The above, plus a redacted, **truncated plaintext** preview of message text. |
| `full` | The above, with the text at its configured length limit rather than the preview limit. |

**No field is hashed except `*_fingerprint`.** The middle tier was originally spelled `hashed`,
which was wrong in the way that matters — it reads as "one-way digest" to exactly the person most
likely to choose it on the strength of the word, and what it emits is a sentence with the
recognisable parts struck out. `[REDACTED]` is applied by pattern matching, and a pattern
matches a shape, not a meaning. At this tier *"Patient Jane Doe, SSN 123-45-6789, said: my password
is hunter2"* leaves as *"Patient Jane Doe, SSN [REDACTED], said: my password is hunter2"* — the
national ID goes, because it has a shape; the name stays, because it does not; and so does the
password, because the credential patterns are anchored to an assignment (`password = "hunter2"` is
caught, "my password is hunter2" is prose). Read that example as the specification, not as a
worst case. If your requirement is that identifiable content never leaves the process, the tier
that meets it is `metadata_only`, and that is why it is the default. `hashed` is still accepted in configuration as an alias and still what travels on the
wire, so existing deployments and collectors need no change.

Nothing leaves the process above the configured tier. `metadata_only` is the default because the
first time an SDK ships prompt text to a collector by accident is the last time it is allowed in
that company.

## Deployment shapes

Gunicorn (pre-fork and `--preload`), uWSGI, uvicorn/hypercorn, celery, `multiprocessing` (fork and
spawn), threads, asyncio, gevent (before *or* after `monkey.patch_all()`), AWS Lambda, Cloud Run /
Fargate, Kubernetes with a sidecar collector, `python -m`, Jupyter, and frozen builds.

Each has a test, and where the runtime cannot be installed in CI the test drives the mechanism the
SDK actually depends on and says so in its name.
[`docs/RUNTIME-CASES-CHECKLIST.md`](docs/RUNTIME-CASES-CHECKLIST.md) records the status of every
case, including the ones not covered.

Comments in the source cite a few internal design documents (`DEPUTY.md`,
`F3-SDK-RUNTIME-CASES.md`, `REPLICATION-EFFORT.md`) and a `WP-N` phase shorthand.
[`docs/SPECS.md`](docs/SPECS.md) explains what each one is and which tests carry the
parts that govern behaviour here.

AWS Lambda needs one decorator, because the sandbox freezes between invocations and a background
flusher never runs:

```python
@nexus.instrument_lambda_handler(budget_s=1.0)
def handler(event, context):
    ...
```

---

## Why no dependencies

The core ring declares nothing. Not `requests`, not `urllib3`, not `wrapt`.

This is a product decision, not asceticism. An observability SDK is adopted by a team that already
has a resolver graph they are afraid of, and a version conflict at `pip install` time is where the
adoption conversation ends. `wrapt` and dd-trace-py's import-hook machinery are **vendored** under
`src/nexus/vendor/` with their licences and notices carried alongside — see [`NOTICE`](NOTICE).
A CI job asserts the installed distribution has no required dependencies, so this cannot regress
quietly.

Optional extras: `swfte-nexus-sdk[otel]` (an OTLP bridge — HTTP/protobuf only, never gRPC, because
`grpcio` is a C extension with fork-safety problems in exactly the pre-fork servers this SDK has to
survive) and `swfte-nexus-sdk[integrations]`. Neither is implemented yet.

## Not here yet

Provider auto-instrumentation (WP-5), policy enforcement (WP-6), and the Node SDK (WP-7). Seams
exist for all three — `nexus/integrations/`, `nexus/policy/`, `nexus/otel/` — and are documented
where they sit. None is implemented, and none is stubbed in a way that pretends otherwise.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
