# swfte-nexus-sdk

**Agent observability and enforcement for Python services you run yourself.**

[![PyPI](https://img.shields.io/pypi/v/swfte-nexus-sdk.svg)](https://pypi.org/project/swfte-nexus-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/swfte-nexus-sdk.svg)](https://pypi.org/project/swfte-nexus-sdk/)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](https://github.com/SwfteAI/nexus-sdk/blob/master/LICENSE)
[![Required dependencies](https://img.shields.io/badge/required%20dependencies-0-brightgreen.svg)](#why-no-dependencies)

`nexus wrap` captures what an agent does inside a developer's terminal. This package captures the
same thing inside your own application — the third attach point on one event ledger, stamped
`producer="sdk"` so a run in production and a run on a laptop are the same shape in the same
tables.

```
pip install swfte-nexus-sdk        # import name is `nexus`
```

Python 3.10+. **Zero required dependencies** — see [Why no dependencies](#why-no-dependencies).

Part of **[Nexus by Swfte](https://www.swfte.com)** — savings, governance and a real audit trail
for AI agents. See also the **[Node SDK](https://github.com/SwfteAI/nexus-sdk-node)**
(`@swfte/nexus-sdk`), which emits the same events, and the
**[terminal wrapper](https://www.npmjs.com/package/@swfte/nexus)** (`npm i -g @swfte/nexus`).

---

## Contents

| Section | |
|---|---|
| [Three levels, pick one](#three-levels-pick-one) | the whole API, in increasing detail |
| [Guarantees](#guarantees) | what this SDK promises never to do to your process |
| [Configuration](#configuration) | every variable, the precedence rule, and the privacy tiers |
| [Deployment shapes](#deployment-shapes) | gunicorn, uWSGI, Lambda, gevent, Kubernetes, and the rest |
| [Why no dependencies](#why-no-dependencies) | and what is vendored instead |
| [Status](#status) | what is implemented and what is not |

**Reference documentation**

| Document | For |
|---|---|
| [`docs/API.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/API.md) | every public name, its signature, and what it returns |
| [`docs/OVERHEAD.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/OVERHEAD.md) | measured cost, the method, and the budgets CI enforces |
| [`docs/RUNTIME-CASES-CHECKLIST.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/RUNTIME-CASES-CHECKLIST.md) | every deployment shape and its coverage status |
| [`docs/SPECS.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/SPECS.md) | the internal design documents the source comments cite |
| [`AGENTS.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/AGENTS.md) | orientation for coding agents working in this repository |
| [`CONTRIBUTING.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/CONTRIBUTING.md) | how to run the suite, and what review will ask of a change |
| [`SECURITY.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/SECURITY.md) | reporting a vulnerability |
| [`CHANGELOG.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/CHANGELOG.md) | what changed in each release, and why |

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
[`docs/OVERHEAD.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/OVERHEAD.md).

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

## Enforcement

Every agent-observability product observes. This one can **refuse**.

```python
from nexus import policy

# Decide, and branch yourself. Never raises.
d = policy.decide("tool_action", {"tool": "db.write", "target": "prod-orders"})
if d.denied:
    return "not allowed"

# Or let the gate do it. The body never runs if an enforcing rule denies.
with policy.gate("tool_action", {"tool": "db.write", "target": "prod-orders"}):
    write_the_rows()

policy.install(signed_envelope)      # signed, verified, versioned
```

**The decision happens before the body, not around it.** A denial raised after the write already
went out is not enforcement, it is journalism. `gate` decides and only then yields;
`test_enforcement.py::test_deny_lands_before_the_effect` asserts on a side-effect list that stays
empty, and inverting the order is exactly what makes it fail.

**What raises.** `Denied` is the only exception this SDK will ever put in your traceback, and you
opted into it twice — the rule carried `enforce: true` *and* the call site did not decline.
Everything else is contained: a bug in policy evaluation degrades to allow plus an integrity
alert, never to a 500 in your service. `decide()` never raises at all.

**Failure semantics**, which is the part that has to be exactly right:

| Situation | Behaviour |
|---|---|
| Policy missing, unverifiable or unparseable | **allow**, and raise an integrity alert — the gap is visible, not merely survived |
| Policy verified but stale | `enforce`-marked rules **keep denying**; unmarked rules degrade to advice |
| Evaluation exceeds its latency budget | **allow**, and record the timeout |
| A rule requires human approval and times out | **deny** if enforce-marked, **allow** if not |

Denying because we could not reach something is never a default anywhere in this package. A cached
deny never decays, though — otherwise disconnecting from the control plane would be the documented
bypass.

---

## Deployment shapes

Gunicorn (pre-fork and `--preload`), uWSGI, uvicorn/hypercorn, celery, `multiprocessing` (fork and
spawn), threads, asyncio, gevent (before *or* after `monkey.patch_all()`), AWS Lambda, Cloud Run /
Fargate, Kubernetes with a sidecar collector, `python -m`, Jupyter, and frozen builds.

Each has a test, and where the runtime cannot be installed in CI the test drives the mechanism the
SDK actually depends on and says so in its name.
[`docs/RUNTIME-CASES-CHECKLIST.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/RUNTIME-CASES-CHECKLIST.md) records the status of every
case, including the ones not covered.

Comments in the source cite a few internal design documents (`DEPUTY.md`,
`F3-SDK-RUNTIME-CASES.md`, `REPLICATION-EFFORT.md`) and a `WP-N` phase shorthand.
[`docs/SPECS.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/docs/SPECS.md) explains what each one is and which tests carry the
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
`src/nexus/vendor/` with their licences and notices carried alongside — see [`NOTICE`](https://github.com/SwfteAI/nexus-sdk/blob/master/NOTICE).
A CI job asserts the installed distribution has no required dependencies, so this cannot regress
quietly.

Optional extras: `swfte-nexus-sdk[otel]` (an OTLP bridge — HTTP/protobuf only, never gRPC, because
`grpcio` is a C extension with fork-safety problems in exactly the pre-fork servers this SDK has to
survive) and `swfte-nexus-sdk[integrations]`.

## Status

Honest about the difference between *implemented*, *a seam*, and *not here*. Nothing in this
package is stubbed in a way that pretends to work.

| Capability | Status | Where |
|---|---|---|
| Capture — runs, actions, usage, outcomes | **implemented** | `nexus/api.py` |
| Auto-attach — `nexus-run`, `sitecustomize` | **implemented** | `nexus/bootstrap/`, `nexus/auto.py` |
| Redaction ladder and privacy tiers | **implemented** | `nexus/redact.py` |
| Policy enforcement — a gate that can refuse | **implemented** | `nexus/policy/` |
| Signed policy envelopes, kill switch, approvals | **implemented** | `nexus/policy/envelope.py`, `ed25519.py`, `approval.py` |
| OTLP bridge (`[otel]` extra) | **implemented** | `nexus/otel/` |
| Node SDK, and conformance between the two | **implemented** | [nexus-sdk-node](https://github.com/SwfteAI/nexus-sdk-node) |
| Provider auto-instrumentation (WP-5) | **the registry, not the adapters** | `nexus/integrations/` |

`nexus/integrations/` deliberately ships zero adapters. What ships is the shape an adapter must
fit — independently versioned, its own patch/unpatch, its own tests — because that shape is what
stops the next milestone from becoming a monolith. Adding a library must not be a core change.

## The Node SDK, and staying identical to it

`@swfte/nexus-sdk` (Node) instruments the same ledger, and a service written in either language has
to be indistinguishable on the dashboard except for the language — any difference a customer can see
is a defect, not a language quirk.

That is checked rather than asserted. `nexus-sdk-node/conformance/` runs **one scripted scenario
through both SDKs** — two interpreters of a single `scenario.json`, both posting to a stub collector
that speaks the real ingest contract — and diffs the emitted event streams field by field, at every
privacy tier, against each other and against the 51 `$defs` of `contract/events.v1.json`. It is
wired into a `cross-sdk` job in **this** repository's CI as well as that one, because an instrument
that guards one direction guards nothing: the drift simply lands in whichever repository has no job
for it. `nexus-sdk-node/PARITY.md` §9 describes what it covers, and §3b lists every difference that
deliberately remains, with the reason for each.

Where the two are allowed to differ, they differ in *interpretation of a caller's argument* rather
than on the wire — a bare-number watermark is epoch seconds here (`time.time()`) and epoch
milliseconds there (`Date.now()`), because picking one would make the other language's idiomatic
call wrong.

## Nexus, beyond this package

This SDK is one attach point of three. All three write the same events to the same ledger, so a
run in production and a run on a laptop are the same shape in the same tables.

| | Install | What it attaches to |
|---|---|---|
| **Terminal wrapper** | `npm i -g @swfte/nexus` · `pip install swfte-nexus` | coding agents in a developer's terminal — Claude Code, Codex |
| **Python SDK** — this package | `pip install swfte-nexus-sdk` | your own Python services |
| **[Node SDK](https://github.com/SwfteAI/nexus-sdk-node)** | `npm i @swfte/nexus-sdk` | your own Node services |

- **Product, pricing and docs:** [www.swfte.com](https://www.swfte.com)
- **Self-hosting, procurement, security review, pilots:** [sales@swfte.com](mailto:sales@swfte.com)
- **Report a vulnerability:** [`SECURITY.md`](https://github.com/SwfteAI/nexus-sdk/blob/master/SECURITY.md)

## Licence

Apache-2.0. See [`LICENSE`](https://github.com/SwfteAI/nexus-sdk/blob/master/LICENSE) and [`NOTICE`](https://github.com/SwfteAI/nexus-sdk/blob/master/NOTICE) — the latter carries the attribution
for the vendored `wrapt` and dd-trace-py import-hook machinery.

Built by **[Swfte AI](https://www.swfte.com)**.
