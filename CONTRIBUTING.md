# Contributing to swfte-nexus-sdk

Thanks for looking. This document is the human-readable companion to [`AGENTS.md`](AGENTS.md),
which states the same invariants more tersely for coding agents.

## The one thing to understand first

**This SDK is installed into somebody else's production application.** It runs in a process it does
not own, on a request path it must not slow, in a company that did not choose its dependencies.
Almost every rule below follows from that, and a change that is elegant but violates it will not be
merged.

## Getting set up

```bash
git clone https://github.com/SwfteAI/nexus-sdk.git && cd nexus-sdk
uv venv --seed .venv
.venv/bin/pip install -e . pytest pytest-timeout gevent
```

Then:

```bash
.venv/bin/python -m pytest -q --timeout=180        # 788 tests, ~2.5 minutes
uvx ruff@0.16.6 check src tests --exclude src/nexus/vendor
python .github/scripts/assert_no_deps.py           # the zero-dependency guard
```

CI runs the suite **against the built wheel**, not the source tree, so a module missing from the
build fails there rather than at a customer's `pip install`. It also enforces overhead budgets; see
[`docs/OVERHEAD.md`](docs/OVERHEAD.md) for the numbers and the method.

## What review will ask

**Does it keep the zero-dependency promise?** The core ring declares nothing. Adding a runtime
dependency is a product decision, not a refactor: a version conflict at `pip install` time is where
the adoption conversation ends. If you genuinely need a third-party module, vendor it under
`src/nexus/vendor/` with its licence and a `NOTICE` entry, or put it behind an extra.

**Is every new public entry point guarded?** `_safety.py` provides the guard that contains
exceptions and returns a safe default. Guards register themselves and the chaos suite iterates the
registry, so an unguarded entry point fails the build — but please add the guard rather than
discovering this from CI.

**Does it do I/O on the calling thread?** It must not. `transport.py` is the only module that opens
a socket, and a test spies on `socket.socket.connect` to prove it.

**Did you add an import to `nexus/__init__.py`?** Don't. It imports only `os` at module scope —
not even `typing`, because on a cold interpreter that pulls in `re` and lands tens of milliseconds
in the cold-start budget of every Lambda that has this installed and switched off.

**Does the test prove the claim, and can it fail?** A guard that only ever passes is
indistinguishable from no guard. Where you add one, add the inverted case that proves it bites.
Name tests for the claim rather than the function: `test_4_9_sigkill_loses_the_buffer_and_we_say_so`
tells a reader what is being asserted; `test_sigkill` does not.

**Do the comments explain *why*?** The source here is dense with rationale, much of it recording
something that was expensive to learn. Match that register. Don't delete a long comment for being
long — it is usually load-bearing.

**Did you change an emitted field?** Then the cross-SDK conformance job will fail here *and* in
[nexus-sdk-node](https://github.com/SwfteAI/nexus-sdk-node). That is intentional: the two SDKs must
stay indistinguishable on the dashboard except for the language. Update both, and record any
deliberate difference in the Node repository's `PARITY.md` §3b with its reason.

**Never edit `src/nexus/vendor/`.** It is third-party code carried with its licences.

## Things that are deliberately the way they are

Before "fixing" one of these, read the comment next to it — each cost somebody a debugging session:

- The distribution is `swfte-nexus-sdk` and the import is `nexus`. `nexus-sdk` on PyPI belongs to
  someone else and PyPI names are never transferred.
- The middle privacy tier is spelled `redacted_preview`, with `hashed` kept as a configuration
  alias and still what travels on the wire.
- The version is written out three times — `pyproject.toml`, `src/nexus/_version.py`,
  `src/nexus/__init__.py`. `scripts/check_versions.py` keeps them equal; the duplication in
  `__init__.py` is so `import nexus` costs one module rather than two.
- `CONTRACT_VERSION` is separate from `__version__`. Bumping the package must never silently bump
  the event contract — ingest has to keep accepting an eighteen-month-old SDK.

## Releasing

Releases run from `.github/workflows/release.yml`, publishing to PyPI via **Trusted Publishing**
(OIDC) — there is no long-lived PyPI token stored anywhere, which matters more here than usual.

1. Bump the version in all three places and update `CHANGELOG.md`.
2. Dispatch the workflow with `publish` **off** first. It builds, tests and stops at the gate.
3. Dispatch again with `publish` on, typing the version to confirm it.

Two operational rules learned the hard way on the sibling repository:

- **A publish is irreversible.** PyPI does not let you re-upload a version, and neither does npm.
  A failed publish is re-run at the *same* version only when nothing was uploaded and no source
  changed; any code change means the next number.
- **Never cancel a failing release run to save time.** Teardown jobs are `if: always()`, which
  cannot help a job that was never scheduled — cancelling can leave provisioned infrastructure
  billing until something else collects it.

## Reporting security issues

Not here — see [`SECURITY.md`](SECURITY.md).

---

Questions: [sales@swfte.com](mailto:sales@swfte.com) · [www.swfte.com](https://www.swfte.com)
