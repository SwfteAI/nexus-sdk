# Referenced specifications and internal vocabulary

Comments and docstrings in this repository cite a handful of documents that are **not shipped
here**, and use a work-package shorthand. Both are deliberate, and this file is what makes those
citations resolve rather than read as broken links.

## Cited documents

| Cited as | What it is | Why it is not in this repo |
| --- | --- | --- |
| `DEPUTY.md` | The normative specification for delegated approval authority — the rules-file grammar, the first-match-wins precedence, the escalation table, and the "there is no path from *I don't know* to *allow*" rule. | An internal Swfte design document covering more than this SDK. The parts that govern behaviour here are ported into `src/nexus/policy/` and pinned by `tests/test_enforcement.py` and `tests/test_policy.py`, which assert the spec's own worked examples row for row. |
| `F3-SDK-RUNTIME-CASES.md` | The case checklist this SDK is built against: the process and runtime models it must survive (§1), transport failure behaviour (§4), enforcement semantics (§6), and the configuration precedence rule (§7.6). Cases are cited by number — "case 4.12", "§6" — throughout the source and the suite. | An internal Swfte document that also covers surfaces outside this SDK. Every case that governs behaviour here is tracked in [`RUNTIME-CASES-CHECKLIST.md`](RUNTIME-CASES-CHECKLIST.md) beside this file, **including the ones not covered**, so a case number cited in a comment resolves to a status you can read. |
| `REPLICATION-EFFORT.md` | The measurement that decided provider coverage: writing per-provider adapters versus consuming the spans other instrumentations already emit. | Internal analysis. Its conclusion — *consume, do not replicate* — is the whole design of `src/nexus/otel/`, and the numbers it produced are quoted inline where they matter. |

Where a citation says "verbatim" or "row for row", the corresponding test is the enforceable
version of that claim. The spec is the source; the test is the part you can run.

## Work-package shorthand

`WP-0` … `WP-6` are the phases this SDK was built in. They survive in comments because they record
*why a decision was taken in the order it was*, which is often the only thing that explains a seam:

| Label | Phase |
| --- | --- |
| WP-0 | Foundational decisions — native events first, OTLP as a bridge |
| WP-4 | SDK scaffold: the client, transport, contract and redaction core |
| WP-5 | Provider coverage by consuming existing instrumentation |
| WP-6 | The enforcement seam — the policy gate on `Action` |

Nothing in the public API depends on this vocabulary; it is commentary only.
