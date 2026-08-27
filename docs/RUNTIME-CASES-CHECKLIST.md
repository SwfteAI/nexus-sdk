# Runtime cases — coverage checklist

Maps every case in `nexus-devtools/docs/F3-SDK-RUNTIME-CASES.md` §1 (process and runtime models)
and §4 (failure modes) to the test that covers it, with an honest status. **No case is omitted.**
A case with no test says so.

Status vocabulary — the distinction is the point of this file:

| Status | Meaning |
|---|---|
| **e2e** | The real thing runs. Real `fork()`, real signals, real gevent, real subprocesses. |
| **mechanism** | The runtime cannot be installed in CI (uWSGI's threading model, the Lambda freeze/thaw sandbox, an evicting kubelet), so the test drives **the mechanism the SDK actually relies on** — the detection function, the hook, the deadline — and asserts its behaviour directly. The test name ends in `_MECHANISM`. |
| **deferred** | Out of scope for M0–M1 by the work-package brief. Named here so nobody has to rediscover the gap. |

Test files: `tests/test_process_models.py` (§1), `tests/test_concurrency.py` (§1.8–1.10),
`tests/test_failure_modes.py` (§4), `tests/test_fault_injection.py` (§4.7, exhaustive),
`tests/test_overhead.py` (§4.12, §7.4).

---

## §1 Process and runtime models

| # | Case | Status | Tests |
|---|---|---|---|
| 1.1 | Single sync process | **e2e** | `test_1_1_single_sync_process` — subprocess, real collector, asserts all five event types and `producer="sdk"` |
| 1.2 | Gunicorn pre-fork | **e2e** | `test_1_2_prefork_children_do_not_replay_the_parent_queue`, `test_1_2_no_duplicate_event_ids_across_the_fleet`, `test_1_2_each_child_has_exactly_one_flusher_and_its_own_session`, `test_1_2_transport_reinit_replaces_locks_rather_than_acquiring_them` |
| 1.3 | Gunicorn `--preload` | **e2e** (shape) | `test_1_3_preload_shape_does_not_open_sockets_before_the_fork`. Gunicorn itself is not installed; what `--preload` changes is *when* init runs relative to the fork, and that window is reproduced exactly. The fork contract underneath is 1.2's, tested for real. |
| 1.4 | uWSGI | **mechanism** | `test_1_4_uwsgi_without_enable_threads_is_detected_MECHANISM`, `test_1_4_uwsgi_with_enable_threads_is_detected_MECHANISM`, `test_1_4_no_thread_is_started_when_threads_cannot_run_MECHANISM`. uWSGI is a C server that must be built and run to reproduce its threading model. The SDK's dependence on it is one detection function and one branch (start a flusher, or fall back to synchronous flush); both are asserted. |
| 1.5 | uvicorn / hypercorn multi-worker | **e2e** (protocol) | `test_1_5_asgi_lifespan_arms_and_drains_per_worker` drives the real ASGI lifespan handshake and eight concurrent request scopes on one loop; `test_1_5_two_workers_have_independent_sessions`. The supervisor's fork/spawn behaviour is 1.2 and 1.7, tested for real. |
| 1.6 | Celery prefork (`billiard`) | **mechanism** | `test_1_6_billiard_style_fork_is_covered_by_the_same_hook_MECHANISM`. `billiard` forks through `os.fork` and therefore fires `os.register_at_fork`, which is the only thing the SDK relies on; the test asserts the hook fires for a billiard-shaped fork. A real celery worker is an integration test for M2. |
| 1.7 | `multiprocessing` / `ProcessPoolExecutor` | **e2e** | `test_1_7_multiprocessing_both_start_methods` — parametrised over `fork` and `spawn`, including the re-import path spawn forces |
| 1.8 | Threads / `ThreadPoolExecutor` | **e2e** | `test_1_8_interleaved_runs_in_threads_never_cross`, `test_1_8_context_does_not_leak_into_a_pooled_thread`, `test_1_8_context_can_be_carried_across_a_handoff_explicitly` |
| 1.9 | asyncio | **e2e** | `test_1_9_context_survives_await`, `test_1_9_gather_keeps_sibling_tasks_apart`, `test_1_9_taskgroup`, `test_1_9_run_in_executor_does_not_inherit_the_run`, `test_1_9_exception_inside_an_async_run_still_closes_it` |
| 1.10 | gevent / eventlet monkeypatching | **e2e** (gevent) | `test_1_10_gevent_monkeypatch_before_init`, `test_1_10_gevent_monkeypatch_after_init` — real gevent, real subprocesses, both orderings. `test_1_10_no_native_lock_is_held_across_io` asserts enqueue does not block while a send is in flight. `test_1_10_gevent_detection`. **eventlet is not tested** — it is a second greenlet library with the same contract and is not installed; the property that matters (no native lock across a yield point) is library-agnostic and asserted. |
| 1.11 | AWS Lambda | **mechanism** + e2e | `test_1_11_handler_flushes_before_returning_MECHANISM` (the decorator's flush-before-return, with budget), `test_1_11_handler_exception_still_flushes_and_still_propagates`, `test_1_11_a_frozen_queue_resumes_on_the_next_invocation` (simulated freeze/thaw over a real queue), `test_1_11_lambda_runtime_is_detected`. The sandbox freeze itself cannot be reproduced outside Lambda; what the SDK relies on — flush before return, a survivable queue across invocations — is asserted directly. Cold-start cost is `docs/OVERHEAD.md`. |
| 1.12 | Cloud Run / Fargate / ECS | **e2e** | `test_1_12_sigterm_flushes_within_the_grace_period`, `test_1_12_sigterm_still_terminates_the_process`, `test_1_12_a_short_grace_period_is_abandoned_cleanly`, `test_1_12_sigterm_handler_chains_to_the_application`. Real subprocesses, real `SIGTERM`, real deadlines. |
| 1.13 | Kubernetes | **e2e** + mechanism | `test_1_13_downward_api_identity_is_read`, `test_1_13_sidecar_collector_is_not_hardcoded_to_loopback`, `test_1_13_ipv6_host_is_bracketed`, `test_1_13_pod_eviction_looks_like_sigterm_then_sigkill_MECHANISM`. No cluster in CI; eviction is `SIGTERM` then `SIGKILL`, and both halves are tested as such (see also 4.9). |
| 1.14 | Jupyter / REPL | **e2e** | `test_1_14_reexecuting_init_does_not_rewrap` — four re-executions, asserts one flush thread, no accumulating `meta_path` finder, identity updated in place, and the run emitted exactly once |
| 1.15 | `python -m yourapp` | **e2e** | `test_1_15_python_dash_m_entrypoint` (real `python -m` against a real package), `test_1_15_post_run_module_hook_is_available`. This is why `ddtrace/internal/module.py` patches `runpy._run_code`, and why it was vendored. |
| 1.16 | Frozen apps (PyInstaller, Nuitka) | **mechanism** | `test_1_16_frozen_interpreter_degrades_to_explicit_api_MECHANISM`, `test_1_16_explicit_api_still_works_when_hooks_are_declined`. Building a PyInstaller bundle in CI is possible but tests the freezer, not us; the SDK's contract is "if the import hook cannot install, degrade to explicit-API-only, silently at runtime", and that branch is driven directly. F3 lists this case as `open`. |
| 1.17 | Node: ESM | **deferred** | WP-7. No Node in this repo. |
| 1.18 | Node: bundlers | **deferred** | WP-7. |
| 1.19 | Node: `cluster` / `worker_threads` | **deferred** | WP-7. |

---

## §4 Failure modes

Governing rule: **a telemetry SDK must never be the reason a request fails.**

| # | Case | Status | Tests |
|---|---|---|---|
| 4.1 | Collector unreachable | **e2e** | `test_4_1_collector_unreachable_never_blocks_and_never_raises`, `test_4_1_recovers_when_the_collector_comes_back` |
| 4.2 | Collector slow (backpressure) | **e2e** | `test_4_2_slow_collector_does_not_slow_the_caller` — the fake collector holds each request open; the caller's timing is asserted, not inspected |
| 4.3 | Queue full | **e2e** | `test_4_3_queue_full_drops_oldest_and_counts_every_drop` (asserts *which* events survive: drop-oldest, because the newest events describe the incident), `test_4_3_enqueue_reports_the_drop_to_its_caller`, `test_4_3_requeue_cannot_grow_the_queue_past_its_cap` |
| 4.4 | Gateway 401/403 | **e2e** | `test_4_4_401_latches_and_stops_generating_load`, `test_4_4_403_latches_too` |
| 4.5 | Gateway 429 | **e2e** | `test_4_5_429_is_honoured_and_clamped` (Retry-After clamped to 30 s — a hostile or broken header must not park the queue for an hour), `test_4_5_429_does_not_amplify` |
| 4.6 | Compression unsupported by peer | **e2e** | `test_4_6_gzip_is_used_for_large_bodies`, `test_4_6_415_latches_to_uncompressed` |
| 4.7 | SDK internal exception anywhere | **e2e, exhaustive** | `tests/test_fault_injection.py` — 50 tests. Every guarded entry point registers into `_safety.HOOKS`, and two parametrised chaos tests iterate that registry, so coverage is exhaustive **by construction**: a new guarded hook is automatically fault-tested, and `test_every_public_entry_point_is_guarded` fails if a public entry point is added without a guard. Plus `test_4_7_an_exploding_sink_does_not_reach_the_caller`, `test_4_7_unserialisable_event_does_not_wedge_the_queue`. |
| 4.8 | Graceful shutdown with a deadline | **e2e** | `test_4_8_flush_respects_its_deadline`, `test_4_8_shutdown_stops_the_worker_thread`, `test_4_8_atexit_flush_happens_in_a_real_process`. Bounded exit against a dead collector is also measured: `test_exit_is_bounded_when_the_collector_is_unreachable`. |
| 4.9 | `SIGKILL` / hard crash | **e2e** | `test_4_9_sigkill_loses_the_buffer_and_we_say_so` — asserts the loss rather than pretending otherwise, and asserts the process really was killed (`returncode in (-9, 137)`). Documented in `README.md`. |
| 4.10 | `init()` called twice | **e2e** | `test_4_10_init_twice_is_idempotent` (identity upgraded in place, no second client), `test_4_10_reload_of_the_package_does_not_double_wrap`. See also 1.14. |
| 4.11 | Auto-instrumentation on, `init()` never called | **e2e** | `test_4_11_capture_without_init_uses_unknown_identity`, `test_4_11_is_thread_safe` (twelve threads race on a barrier to create the client; exactly one may win) |
| 4.12 | Kill switch `NEXUS_ENABLED=0` | **e2e** | `test_4_12_disabled_means_no_threads_no_hooks`, `test_4_12_disabled_never_touches_the_network`, `test_4_12_import_of_a_disabled_sdk_pulls_in_nothing_heavy`, `test_the_disabled_sdk_imports_nothing_of_its_own`, `test_disabled_call_overhead`. A **true** kill switch: `nexus/__init__.py` imports only `os` at module scope, so nothing is initialised and then no-op'd. |

---

## Known divergences from the spec

Recorded rather than silently absorbed.

### The attach-point key is `producer`, not `source`

The WP-4 brief and `EMBEDDED-SDK-DESIGN.md` §9 both say `source="sdk"`. The wire key implemented
here is **`producer`**, per F3 §7.2 and `nexus_devtools/events.py:86-89, 202-206`. This is not
pedantry:

- Eight builders in the parent's `events.py` already take a `source` kwarg with an unrelated
  meaning (per-value provenance, `cost_source`), so `source="sdk"` collides inside one column
  family.
- `events.py` defaults a missing `producer` to `wrap`. An SDK that stamped only `source` would not
  fail loudly — it would attribute every customer's production service to a developer's terminal,
  in every rollup and on the bill.

`contract.PRODUCER` is the constant; `contract.SOURCE` is kept as an alias so a reader grepping for
the name in the brief finds the explanation instead of concluding it was forgotten. Pinned by
`test_7_2_the_attach_point_is_stamped_under_producer_not_source` and
`test_7_2_a_builder_cannot_shadow_the_attach_point`.

### Config precedence is args > env > file > defaults, not env > code

F3 §7.6 specifies `env > code > file > remote`. This SDK implements **explicit arguments > env >
file > defaults**, with exactly one env-authoritative key: `NEXUS_ENABLED=0`. The `file` and
`remote` tiers of the spec's ordering are preserved relative to each other; what is inverted is
`code` against `env`.

The reasoning: `init(service="checkout")` is a statement about what this process *is*, and an
ambient environment variable silently overriding it produces the worst failure mode this contract
has — events attributed to the wrong service, with nothing anywhere reporting a conflict. Datadog
resolves this the same way for `service`/`env`/`version`. The kill switch is the deliberate
exception, and must be: an operator disabling telemetry from outside the process has to win against
application code that says otherwise, or it is not a kill switch and does not survive a security
review.

A config *file* is read only when `NEXUS_CONFIG_FILE` explicitly names one — there is no
`~/.nexus`, because containers are ephemeral and frequently read-only, and an SDK that reads a home
directory behaves differently in dev and prod for reasons nobody can see. A failure to read the
named file is a warning, never an exception. **Remote** configuration is not implemented in M0–M1;
when it lands it slots below file.

### Not covered

- **eventlet** (part of 1.10). gevent is tested for real in both monkeypatch orderings; eventlet is
  a second library with the same contract, not installed, and the property that matters is
  library-agnostic.
- **A real celery worker, a real uWSGI process, a real Lambda, a real cluster.** All four are
  M2 integration-environment work. Every one has its mechanism tested here, and every one is
  flagged `_MECHANISM` in the test name so the gap is visible from a test run rather than from this
  file.
- **§2 (instrumentation correctness), §3 (data correctness), §5 (privacy), §6 (policy)** are not
  M1 acceptance and are not claimed. Seams exist: `nexus/integrations/` (WP-5, including the 2.19
  recursion guard and the 2.6 foreign-wrapper detection primitive), `nexus/policy/` (WP-6),
  `nexus/otel/` (the `[otel]` extra). None is implemented.
