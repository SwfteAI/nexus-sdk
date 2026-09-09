# Changelog

All notable changes to `swfte-nexus-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

The **package version** and the **event-contract version** move independently, on purpose. A
customer's production image does not upgrade on our schedule, so ingest must keep accepting an
eighteen-month-old SDK. Bumping the package must never silently bump the contract; `CONTRACT_VERSION`
in `src/nexus/_version.py` is the one that matters to a collector.

## [Unreleased]

## [0.1.0]

First public release. Embedded agent observability and enforcement for Python services — the third
attach point on the same event ledger as `nexus wrap`, stamped `producer="sdk"` so a run in
production and a run on a laptop are the same shape in the same tables.

### Added

- **Three attach levels that compose.** `nexus-run python -m yourapp` needs no code change at all;
  `nexus.init(service=…, env=…, version=…)` declares identity for joins; `nexus.agent()` /
  `run.action()` say what the agent actually did. Auto-init plus explicit `init()` plus manual
  spans is a supported combination, and `init()` called ten times from a notebook cell upgrades
  identity in place rather than erroring.
- **A distinction the data model takes seriously.** What an agent *did* (`behavior_trace`) and what
  the model *said it did* (`rationalisation`) are different epistemic classes and are stamped as
  such, because only one of them is admissible as evidence.
- **Enforcement — a gate that can refuse.** `policy.decide()` to branch yourself, `policy.gate()`
  to have the decision made for you. The decision lands *before* the body, not around it: a denial
  raised after the write already went out is journalism, not enforcement. Policy arrives as a
  signed, verified envelope with a kill switch and human-approval rules.
- **Failure semantics that are written down and tested.** Missing, unverifiable or unparseable
  policy allows and raises an integrity alert. Verified-but-stale policy keeps enforcing its
  `enforce`-marked rules — a cached deny never decays, or disconnecting from the control plane
  would be the documented bypass — while unmarked rules degrade to advice. Denying because
  something was unreachable is never a default.
- **A redaction ladder with three tiers**, defaulting to the safe one. `metadata_only` emits shape,
  counts, durations and fingerprints, and no content at all.
- **An OTLP bridge** behind the `[otel]` extra. HTTP/protobuf only, never gRPC: `grpcio` is a C
  extension with fork-safety problems in exactly the pre-fork servers this SDK has to survive.
- **Deployment coverage as tests, not claims.** Gunicorn (pre-fork and `--preload`), uWSGI,
  uvicorn/hypercorn, celery, `multiprocessing` (fork and spawn), threads, asyncio, gevent before
  *or* after `monkey.patch_all()`, AWS Lambda, Cloud Run/Fargate, Kubernetes with a sidecar
  collector, `python -m`, Jupyter and frozen builds. Where a runtime cannot be installed in CI, the
  test drives the mechanism the SDK actually depends on and says so in its name.
- **Wire conformance with the Node SDK.** One scripted scenario is run through both SDKs and the
  emitted event streams are diffed field by field, at every privacy tier, against each other and
  against the event contract. The job runs in *both* repositories, because an instrument that
  guards one direction guards nothing — the drift simply lands wherever there is no job for it.

### Guarantees

Each of these is a test, not an aspiration:

- Every public entry point is wrapped in a guard that contains exceptions and returns a safe
  default. Guards register themselves and the chaos suite iterates the registry, so a new entry
  point without a guard fails the build.
- The calling thread never performs I/O — asserted by spying on `socket.socket.connect` across a
  realistic workload, not inferred from timings.
- The queue is bounded and drops **oldest**, because the newest events describe the incident. Every
  drop is counted and reported by `nexus.counters()`.
- `fork()` is handled: the child replaces its locks rather than acquiring them, empties the
  inherited queue, takes a fresh session and rebuilds its worker.
- Shutdown flushes with a deadline. A hung collector must not hang your container.
- `SIGKILL` loses the in-flight buffer. That is not fixable and the suite asserts the loss rather
  than pretending otherwise.

### Notes

- **Zero required dependencies.** `wrapt` and dd-trace-py's import-hook machinery are vendored with
  their licences and notices; a CI job asserts the built distribution declares no requirements.
- **`NEXUS_ENABLED=0` is total** — no threads, no import hooks, no sockets, nothing
  initialised-then-no-op'd. A disabled `with nexus.agent(...)` block costs 0.5 µs.
- Measured cost: ~19 µs per action span, ~35 ms to arm at startup, ~0 ms for `import nexus`.
- The distribution is `swfte-nexus-sdk` while the import is `nexus`. `nexus-sdk` on PyPI belongs to
  Blue Brain's `nexus-python-sdk`, and PyPI names are first-come and never transferred.
- Provider auto-instrumentation ships as the adapter **registry** only. No adapters yet, and none
  stubbed in a way that pretends otherwise.
