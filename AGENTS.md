# AGENTS.md — orientation for coding agents

Read this before changing anything here. It is written for an agent with no prior context on this
repository, and it states the invariants that are easy to break and expensive to break.

Human contributors: [`CONTRIBUTING.md`](CONTRIBUTING.md) covers the same ground with more prose.

---

## What this package is

`swfte-nexus-sdk` (import name `nexus`) is an **embedded agent-observability and enforcement SDK
for Python services**. It is installed into somebody else's production application. That single
fact drives every invariant below: this code runs in a process it does not own, on a request path
it must not slow, in a company that did not choose its dependencies.

- **Distribution name** `swfte-nexus-sdk`, **import name** `nexus`. They differ on purpose —
  `nexus-sdk` on PyPI belongs to Blue Brain and PyPI names are never transferred.
- Part of [Nexus by Swfte](https://www.swfte.com). Sibling repositories:
  [nexus-sdk-node](https://github.com/SwfteAI/nexus-sdk-node) (the Node SDK, must stay conformant
  with this one) and the terminal wrapper published as `@swfte/nexus`.

## Orientation

| Path | What lives there |
|---|---|
| `src/nexus/__init__.py` | the public surface and the kill switch. Imports **only `os`** at module scope |
| `src/nexus/api.py` | `agent()`, `action()`, `integration()`, the `Run` / `Action` objects |
| `src/nexus/client.py` | `init()`, identity, the client singleton |
| `src/nexus/config.py` | resolution order: explicit args → env → file → defaults |
| `src/nexus/transport.py` | the background worker. The **only** place that opens a socket |
| `src/nexus/redact.py` | the redaction ladder and the privacy tiers |
| `src/nexus/policy/` | enforcement — the part that can say *no* |
| `src/nexus/otel/` | the OTLP bridge, behind the `[otel]` extra |
| `src/nexus/integrations/` | the adapter **registry**. Deliberately ships zero adapters |
| `src/nexus/vendor/` | vendored `wrapt` and dd-trace-py import hooks. **Do not edit** |
| `src/nexus/_safety.py` | the guard decorator that contains exceptions at every entry point |
| `tests/` | 788 tests. Named for the case they prove, not the function they call |

## Invariants — breaking any of these should fail the build

1. **Zero required dependencies.** The core ring declares nothing. `wrapt` and the dd-trace-py
   import-hook machinery are vendored under `src/nexus/vendor/`. A CI job
   (`.github/scripts/assert_no_deps.py`) asserts the built distribution has no requirements, so
   this cannot regress quietly. Adding a runtime dependency is a product decision, not a
   refactor — a version conflict at `pip install` time is where adoption ends.

2. **A telemetry SDK must never be the reason a request fails.** Every public entry point is
   wrapped by a guard from `_safety.py` that contains exceptions and returns a safe default.
   Guards register themselves and the chaos suite iterates the registry, so **a new public entry
   point without a guard fails the build**. If you add one, guard it.

3. **The calling thread never performs I/O.** Asserted by spying on `socket.socket.connect` across
   a realistic workload — not inferred from timings. Never open a socket outside `transport.py`.

4. **`import nexus` stays cheap and `NEXUS_ENABLED=0` stays total.** `__init__.py` imports only
   `os` at module scope — not even `typing`, because on a cold interpreter that pulls in `re` and
   lands tens of milliseconds in the cold-start budget of every Lambda that has this installed and
   switched off. When disabled there are no threads, no import hooks and no sockets. Do not add a
   module-scope import to `__init__.py`.

5. **The queue is bounded and drops oldest.** The newest events describe the incident. Every drop
   is counted and surfaced by `nexus.counters()`. Silence about dropped data is a bug.

6. **Enforcement decides before the body, never around it.** `policy.gate()` evaluates, and only
   then yields. A denial raised after the effect already happened is not enforcement.

7. **Nothing leaves the process above the configured tier**, and `metadata_only` is the default.
   Read the privacy-tier table in the README as a specification, not as a worst case.

8. **Fail open, and say so.** Missing, unverifiable or unparseable policy allows and raises an
   integrity alert. Denying because something was unreachable is never a default here.

9. **Wire compatibility with the Node SDK.** The two SDKs are diffed field by field against one
   scripted scenario at every privacy tier. If you change an emitted field, the conformance job
   fails in both repositories — that is intentional. See `PARITY.md` in the Node repository.

## Running things

```bash
uv venv --seed .venv && .venv/bin/pip install -e . pytest pytest-timeout gevent
.venv/bin/python -m pytest -q --timeout=180        # 788 tests, ~2.5 min
uvx ruff@0.16.6 check src tests --exclude src/nexus/vendor
python .github/scripts/assert_no_deps.py           # the zero-dependency guard
```

CI additionally runs the suite **against the built wheel** rather than the source tree, so a file
left out of the build fails there rather than at a customer's `pip install`. It also runs an
overhead job with enforced budgets — see [`docs/OVERHEAD.md`](docs/OVERHEAD.md).

## Conventions that reviewers will hold you to

- **Comments explain *why*, not *what*.** The existing source is dense with rationale, much of it
  recording a decision that was expensive to learn. Match that. Do not delete a comment because it
  is long; it is usually load-bearing.
- **Tests are named for the claim they prove.** `test_4_9_sigkill_loses_the_buffer_and_we_say_so`
  is a better name than `test_sigkill`. A test that only ever passes is indistinguishable from no
  test — where a guard matters, add the inverted case that proves it can fail.
- **Do not weaken an assertion to make it pass.** If a budget or an exact count fails, either the
  change is wrong or the budget genuinely moved; establish which, and say which in the commit.
- **Never edit `src/nexus/vendor/`.** It is third-party code carried with its licences.

## Common traps

| Trap | What happens |
|---|---|
| Adding an import to `nexus/__init__.py` | blows the cold-start budget for every disabled install |
| Adding a public function without a `_safety` guard | the chaos suite fails on the guard registry |
| Doing I/O on the calling thread | the socket-spy test fails |
| Changing an emitted field name | the cross-SDK conformance diff fails in both repositories |
| Editing a version in one place | `scripts/check_versions.py` fails — the version is restated in `pyproject.toml`, `src/nexus/_version.py` and `src/nexus/__init__.py` |
| Cancelling a failing release run to save time | see the release notes in `CONTRIBUTING.md` |
