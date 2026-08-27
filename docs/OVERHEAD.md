# Overhead

Case 7.4 of `F3-SDK-RUNTIME-CASES.md`: *published p99 added latency and import-time cost, asserted
in CI. Customers will ask; "negligible" is not an answer.*

Every number below is produced by `tests/test_overhead.py`, which also enforces the budgets. The
file writes `overhead-latest.json` on each run; CI uploads it as a build artefact. If a change
regresses these, the build goes red — the numbers cannot drift silently.

## Measured

Apple M3 Max, macOS 15.6.1, CPython 3.12.13. Reproduce with
`PYTHONPATH=src pytest tests/test_overhead.py -q -s`.

| Measurement | p50 | p95 | p99 | Budget |
|---|---|---|---|---|
| One action span (`with run.action(...)`) | 19.2 µs | 25.0 µs | 90 µs | p50 < 40 µs, p95 < 150 µs |
| One run (3 events: start, outcome, end) | 33.6 µs | 55.1 µs | 109 µs | p50 < 120 µs, p95 < 600 µs |
| `enqueue` on an empty queue | — | 1.1 µs | — | — |
| `enqueue` on a **full** queue (drop path) | — | 1.4 µs | — | must not exceed the empty case |

| Startup | Added | Budget |
|---|---|---|
| `import nexus`, SDK enabled | ~0.4 ms | < 40 ms |
| `import nexus`, `NEXUS_ENABLED=0` | ~0.5 ms | < 10 ms |
| `import nexus` + `init()` (fully armed) | 35 ms | < 150 ms |
| Interpreter exit with the collector unreachable | 823 ms | < 8 s |

| Disabled mode | Cost |
|---|---|
| `with nexus.agent(...) as run: run.outcome(...)` | 0.49 µs |

Both import figures are wall-clock deltas against `python -c pass` on the same interpreter,
minimum of seven runs. The absolute baseline on this hardware is ~46 ms, which is why a
~0.4 ms delta is reported as "≈ 0" — it is inside the interpreter's own start-up variance.

## Where the 35 ms of arming goes

`import nexus` is deliberately trivial in both modes; the cost appears only when `init()` pulls in
the machinery that actually sends. Measured with `-X importtime` (cumulative, in ms):

| Module | Cost | Why it is there |
|---|---|---|
| `nexus.config` | 8.2 | `dataclasses` → `inspect` → `dis`, `ast` |
| `logging` | 6.9 | the only channel for "we contained an internal error" |
| `json` | 5.9 | `json.decoder` → `re` |
| `collections` | 2.4 | `deque` — the bounded queue |
| `typing` | 2.2 | annotations in every module except `nexus/__init__.py` |
| `gzip` | 1.9 | request bodies over the compression threshold |
| `nexus.runtime` | 1.4 | our own |

Almost all of it is the standard library. Two decisions kept it from being three times larger:

**`urllib` is imported on first send, not at import time.** `import urllib.request` measures 31 ms
on a cold interpreter — more than everything else in this SDK combined. Charging that to every
Lambda cold start and every short-lived job, whether or not a single event is ever sent, is the
wrong place to spend it. It now lands on the flush worker instead. The reason it was originally
eager was fork safety: building an opener calls `getproxies()`, which on macOS calls into
`_scproxy` → SystemConfiguration → the Objective-C runtime, and doing that in a child forked from a
threaded parent aborts the process. That is solved more cheaply by resolving proxies from
`getproxies_environment()` only — `HTTPS_PROXY` / `NO_PROXY`, pure `os.environ`, safe post-fork and
free. See `transport._load_urllib` and `transport._proxies`.

**`nexus/__init__.py` imports only `os` at module scope — not even `typing`.** On a cold
interpreter `import typing` pulls in `re`, which measures at tens of milliseconds. The kill switch
(case 4.12) is only credible if a customer who sets `NEXUS_ENABLED=0` genuinely pays nothing, and
"nothing" has to include the type annotations.

## How these are measured, and what the numbers do not say

The hot-path timings run against a **null sink**, not the test collector. The fake collector runs
in the same interpreter as the benchmark, so its handler threads contend for the GIL with the code
being timed; including that would publish a number about pytest rather than about the SDK. In
production the collector is another process. The egress path has its own tests.

**p50 and p95 are asserted on wall clock; p99 is asserted on CPU time and only conditionally on
wall clock.** On a loaded machine a scheduler preemption lands in the 99th percentile of any loop,
including an empty one, and a fixed wall p99 bound makes the test a coin flip on shared CI — after
which it gets deleted, taking the real signal with it. So every sample is timed on two clocks and
the tail is charged to whoever caused it: CPU time the SDK burned is always asserted, wall time is
asserted only when the loop's own CPU/wall ratio shows the box was actually idle. When it was not,
the test prints the number with a note instead of failing.

A footnote worth keeping: this uses `time.process_time`, not the obviously correct
`time.thread_time`, because on macOS `CLOCK_THREAD_CPUTIME_ID` is wrong by more than an order of
magnitude — a 195 ms pure-CPU loop reports 4.7 ms of thread time while `process_time` reports
195.2 ms, and `time.get_clock_info` advertises 1 ns resolution for it regardless. Using it would
have made every machine look permanently contended and quietly disabled the wall assertion: a green
test asserting nothing.

The wall-clock bound is still the weakest assertion here, which is why
`test_the_hot_path_never_touches_the_network` exists. "The calling thread performs no I/O" is the
property the timings are a proxy for, and it can be asserted exactly — the test spies on
`socket.socket.connect` for the duration of a realistic workload. That one does not degrade on a
busy runner.

Not measured, and deliberately so: throughput, and the cost of provider instrumentation. The
former is a property of the collector, not of this package. The latter does not exist yet (WP-5).
