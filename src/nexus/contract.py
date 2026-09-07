"""The event contract, as spoken by the SDK.

Every field name, tier string and epistemic-class string here is copied **verbatim** from
``nexus_devtools/events.py`` in the wrapper repo. They are wire values in a shared ledger: the same
rollups, the same knowledge graph and the same bill consume events from `nexus wrap`, from this
SDK, and from the connection ingesters. Two producers with drifting shapes destroys all three.

.. warning::

   **TODO(WP-2 contract artifact).** ``nexus-devtools`` is concurrently gaining a generated,
   versioned JSON Schema artifact (``contract/events.v1.json``, design §7) derived from
   ``events.py``'s builders, plus the ``producer`` discriminator this module already stamps. When
   that artifact lands, this module stops hand-writing field names: the builders below become
   generated from the pinned artifact, and a conformance suite validates every emitted event
   against it in CI. Until then these definitions are **hand-mirrored and therefore capable of
   drifting**, which is exactly the failure mode the artifact exists to prevent. Do not add a new
   event type here without opening the matching change against the artifact.

   **Operate plane, added 2026-08-23 (catalog §28–33).** ``deployment``, ``service_health``,
   ``integration_probe``, ``incident``, ``infra_cost`` and ``ownership`` are hand-mirrored from
   ``nexus_devtools/events.py:933-1242`` while both land. One divergence is known and is *not* on
   this side: the console's consumer types (``nexus-web-app``,
   ``lib/features/operate/types.ts:206``) spell the liveness register ``reachable``, and both
   producers spell it ``integration_up``. This module follows the producers, because the artifact
   is generated from them; the consumer needs the rename. Three of the six — ``incident``,
   ``infra_cost``, ``ownership`` — have **no SDK entry point** and exist here only so the two
   mirrors cannot drift apart in the interval: they are the console's and the connectors' to emit,
   and a running service cannot honestly observe any of them about itself.

   ``agent_run`` (below) is the one shape with no counterpart in ``events.py`` today. It is flagged
   as such rather than shoehorned into an existing type, because a *run* — a unit of agent work with
   an outcome — is the concept the SDK exists to model and the wrapper infers from session
   boundaries. It needs reconciling with WP-2 before M2.

Three properties that are not obvious from the field lists:

**``producer="sdk"`` on everything.** One ledger fed by three attach points is uninterpretable
without it. It is stamped in ``base()`` rather than per builder so it cannot be forgotten. The
brief for this work says ``source="sdk"``; the wire key is ``producer``, because ``source`` was
already taken — see the ``PRODUCER`` constant below for why that difference is load-bearing rather
than pedantic.

**``epistemic_class`` on everything.** ``behavior_trace`` / ``rationalisation`` /
``interaction_narrative`` (``events.py:32-34``) is the distinction that makes this data admissible
for governance: a model saying it succeeded is narrative, an exit code is behaviour. Losing it
downgrades the ledger to ordinary observability. ``base()`` requires it; there is no default.

**Client time is not authoritative.** ``ts`` is what this process believed the time was. Ingest
stamps its own arrival time and bills on that (case 3.2). A container with a skewed clock is
common; a container that can move a billing window by skewing its clock is a vulnerability.
"""
from __future__ import annotations

import hashlib
import os
import time
import typing as t
import uuid

from ._version import CONTRACT_VERSION
from .config import TIER_FULL, TIER_HASHED, TIER_METADATA_ONLY, Config
from .redact import MASK, scan_window

# Epistemic classes — verbatim from nexus_devtools/events.py:32-34.
EPISTEMIC_BEHAVIOR = "behavior_trace"
EPISTEMIC_RATIONALISATION = "rationalisation"
EPISTEMIC_NARRATIVE = "interaction_narrative"

#: The attach-point discriminator (design §9 / case 7.2). Ours is always this.
#:
#: The key on the wire is ``producer``, **not** ``source``, and the distinction is not cosmetic:
#: eight builders in ``nexus_devtools/events.py`` already take a ``source`` kwarg meaning something
#: else entirely (``cost_source``, and per-event provenance of a value). Stamping ``source="sdk"``
#: would collide with those in the same column family and, worse, would leave ``producer`` unset —
#: so every SDK event would be classified as ``wrap``, silently attributing a customer's service to
#: a developer's terminal. See ``events.py:196-206``, which writes ``producer`` *last* for exactly
#: this reason: process identity is never a per-call payload field.
PRODUCER = "sdk"

#: Retained as an alias because the design doc and WP-4 brief both say ``source="sdk"`` in prose.
#: The wire key is what matters; this is here so a reader who greps for the name in the brief finds
#: the answer rather than concluding it was forgotten.
SOURCE = PRODUCER

__all__ = [
    "PRODUCER", "SOURCE", "CONTRACT_VERSION", "EPISTEMIC_BEHAVIOR", "EPISTEMIC_RATIONALISATION",
    "EPISTEMIC_NARRATIVE", "base", "session", "agent_run", "tool_action", "token_usage",
    "turn_outcome", "pipeline_health", "fingerprint", "est_tokens", "now",
]


def now() -> str:
    """RFC-3339 UTC seconds via ``gmtime`` so ledgers are timezone-stable across hosts."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fingerprint(text: str) -> str:
    """Stable 12-char content fingerprint, never reversible to the source text.

    ``errors="replace"`` is load-bearing, not defensive: case 3.7 — captured content routinely
    contains lone surrogates and raw bytes decoded optimistically upstream, and an SDK that raises
    ``UnicodeEncodeError`` while building a telemetry event has become the reason a request failed.
    """
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:12]


def est_tokens(text: str) -> int:
    """~4 chars/token. Good enough for rollups; the provider's own count wins when present."""
    return (len(text or "") + 3) // 4


def label(v: t.Any, max_len: int = 64) -> t.Optional[str]:
    """A **dimension**: a low-cardinality string a consumer groups by. Bounded, never redacted.

    These are the fields a rollup does ``GROUP BY`` on — ``goal_class``, ``model``, ``provider``,
    ``kind``, ``error_class``, and the five provenance labels that ride the base envelope. They are
    not content, so the tier ladder is the wrong instrument for them; what they need is a *length
    bound*, and most of them had none.

    The failure mode is **cardinality, not disclosure**, and that is exactly why it survived so
    long: nothing errors, nothing leaks, no test goes red. The rollup and the cost report just
    quietly degrade on the collector's side, where the customer cannot see it and we are the ones
    paying for it. ``token_usage.model`` is the sharpest case — it is the primary group-by of every
    cost rollup, so a per-request value fragments spend into one row per call and no per-model total
    can be computed at all.

    **What this does and does not fix.** Truncating to a bound stops a megabyte of prose becoming a
    group-by key. It does *not* reduce the number of distinct values, which is the other half of
    cardinality; capping that in-process would mean remembering every value ever seen, which is
    itself unbounded memory, so it belongs to the collector. ``tests/test_dimensions.py`` asserts
    that limit explicitly so the bound is not mistaken for a fix it is not.

    Semantics are the Node SDK's ``label()`` in ``src/core.cjs``, character for character, and the
    cross-SDK conformance suite checks that they still are:

    * ``None`` stays ``None`` — ``base()`` then drops the key, so absent stays absent;
    * the value is stringified rather than dropped, because ``goal_class=42`` is a caller mistake
      and silently losing the label is a worse response to it than recording it;
    * surrounding whitespace is stripped, and a value that was *only* whitespace becomes ``None``,
      because ``"   "`` is not a cohort;
    * the bound is applied last, so an ordinary label survives untouched.
    """
    if v is None:
        return None
    s = str(v).strip()
    return s[:max_len] if s else None


def base(event_type: str, session_id: str, cfg: Config, *, epistemic_class: str,
         **extra: t.Any) -> dict:
    """Build the common envelope.

    ``event_id`` is the natural key: the idempotency key for publish and the dedup key the
    analytics store collapses repeats on. It matters more here than in the wrapper — delivery is
    at-least-once (case 3.1) and a retried batch after a timeout is the normal case, not the edge.

    Keys with ``None`` values are dropped, so a reader can distinguish *"not captured"* from
    *"captured as empty"*. That distinction is the difference between a coverage gap and a fact.
    """
    e = {
        "schema": CONTRACT_VERSION,
        "event_id": uuid.uuid4().hex,
        "type": event_type,
        "session_id": session_id,
        "ts": now(),
        # unified tagging (7.1) — the join keys, on every event rather than on the session only,
        # because events from one process can outlive the session record that introduced them.
        "service": cfg.service,
        "env": cfg.env,
        "service_version": cfg.version,
        "sdk_version": _sdk_version(),
        "epistemic_class": epistemic_class,

        # -- operate-plane join keys, on every event for the SAME reason the three above are ----
        #
        # These used to ride ``session`` alone, nested under ``provenance``, and this module's own
        # docstring argued for that: six more keys on every event restating a fact that cannot
        # change for the life of the process is bytes without information.
        #
        # That argument is wrong in the one way that matters, and it is wrong by this module's own
        # precedent — ``service`` and ``env`` are here for exactly the reason it rejects. Events
        # from one process outlive the session record that introduced them, and a consumer that has
        # to look up a session to learn which application a row belongs to will eventually be
        # handed a row whose session it never received. On a per-deploy cost view that is not a
        # degraded answer, it is no answer: the rows are there and cannot be attributed.
        #
        # It was also a difference a customer could see. The Node SDK put these on the base
        # envelope; this one did not, so identical instrumentation produced rows that could be
        # grouped by commit from one SDK and not from the other, on one dashboard. Found by the
        # cross-SDK conformance suite, which is the first thing that ever compared the two streams.
        #
        # Bounded at config resolution rather than here, so no builder can forget — ``config.py``.
        # ``session`` renames ``repo`` to ``repo_slug`` on the way out; see that builder.
        "application": cfg.application,
        "repo": cfg.repo,
        "commit": cfg.commit,
        # Which variable the commit was read from, e.g. ``env:VERCEL_GIT_COMMIT_SHA``. The full
        # per-field breakdown stays on ``session``; this is the one a reader needs beside every row.
        "provenance_source": cfg.provenance_source,
    }
    e.update({k: v for k, v in extra.items() if v is not None})
    # Written LAST, after **extra, exactly as ``events.py:206`` does: the attach point is process
    # identity and a builder must not be able to shadow it, deliberately or by a name collision.
    e["producer"] = PRODUCER
    if cfg.tags:
        e["tags"] = cfg.tags
    return e


def _sdk_version() -> str:
    from ._version import __version__
    return __version__


# --------------------------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------------------------

def session(session_id: str, cfg: Config, *, instance_id: str,
            runtime: t.Optional[dict] = None) -> dict:
    """A service process began reporting. The SDK's analogue of a wrapped terminal session.

    Note what is *not* here: no ``user``, no ``repo`` root, no home path. The wrapper stamps a
    human and an absolute path because a laptop has both and local features key on them. A
    production container has neither, and inventing them is how a governance ledger acquires PII it
    was never meant to hold.

    ``runtime`` is the detected process model (pre-fork, Lambda, k8s pod identity, …) — pure
    metadata, safe at every tier, and the first thing anyone debugging "why is this service silent"
    will want.

    **Provenance (§6.1) rides here, nested, and only here.** ``provenance`` is what the console's
    ``RunningVersion`` is built from — "what a process says it is" — and this is the process
    identity event, emitted once per session.

    Two deliberate shapes, both of which were wrong in the first draft:

    * **Not in ``base()``.** The three unified tags are short strings a consumer needs on a stray
      ``token_usage`` that arrives after its session record. Provenance is six more keys on every
      event in the ledger restating a fact that cannot change for the life of the process.
    * **Nested, not flattened.** ``events.py:218`` already has a ``session.repo``, and it is a
      **dict** (``{root, …}``) describing the wrapped repository. Writing a *string* into the same
      wire key from this producer would give one column two types in the shared ledger — the exact
      hand-mirror drift the module warning is about, and the kind that surfaces as a cast error in
      somebody's rollup weeks later. The nested object keeps this producer's addition unambiguous
      and moves cleanly into whatever slot the generated artifact ends up giving it.

    Each absent field is simply not written, and the whole key is omitted when nothing was read, so
    a session with no provenance is the *break* the ribbon draws rather than a claim it cannot check.
    """
    prov = {k: v for k, v in (
        ("application", cfg.application), ("repo", cfg.repo), ("commit", cfg.commit),
        ("branch", cfg.branch), ("deployment_id", cfg.deployment_id),
        ("source", cfg.provenance_source), ("sources", cfg.provenance_sources or None),
    ) if v is not None}
    e = base("session", session_id, cfg,
             epistemic_class=EPISTEMIC_BEHAVIOR,
             terminal_id=instance_id, tool="sdk",
             privacy_tier=cfg.tier, runtime=runtime,
             pid=os.getpid(),
             # Flattened beside the nested map, matching the Node SDK. Redundant with
             # ``provenance`` and deliberately so: they are the two provenance fields a reader most
             # often wants without walking into a sub-object, and the alternative was two SDKs
             # writing the same session record with different key sets.
             branch=cfg.branch,
             platform_deployment_id=cfg.deployment_id,
             provenance=prov or None)

    # ── a field-name collision between two producers, resolved by moving ours ────────────────
    #
    # ``base()`` now writes the provenance repo slug (``github.com/acme/portal``) onto every event
    # as a string. On ``session`` that lands on top of a key the OTHER producer already owns and
    # means something else by: ``nexus_devtools/events.py:session`` takes ``repo: Optional[dict]``
    # — a local repository descriptor holding an absolute ``root`` — and
    # ``contract/events.v1.json`` declares ``session.repo`` as ``{"type": "object"}`` accordingly.
    # Four other event types declare ``repo`` as a string; ``session`` is the only one that does
    # not.
    #
    # Nothing rejects a string there — the collector validates the schema major, not per-field
    # types — so the damage would be a reader doing ``session.repo["root"]`` and getting a
    # ``TypeError`` for exactly the rows that came from production. Renamed rather than dropped:
    # the slug is a real operate-plane join key and ``session`` is where a reader looks for it.
    # The Node SDK reached this conclusion first and spells it the same way.
    if "repo" in e:
        e["repo_slug"] = e.pop("repo")
    return e


def agent_run(session_id: str, cfg: Config, *, run_id: str, name: str, phase: str,
              goal_class: t.Optional[str] = None, duration_ms: t.Optional[int] = None,
              actions: t.Optional[int] = None, error: t.Optional[str] = None,
              incomplete: bool = False) -> dict:
    """A unit of agent work, opened and closed.

    ``phase`` is ``"start"`` or ``"end"``. Both are emitted rather than only the close, because the
    close is the event most likely to be lost — a ``SIGKILL`` mid-run leaves no trailing record at
    all (case 4.9), and a run that started and never ended is itself a finding.

    ``incomplete=True`` marks a run whose boundary we inferred rather than observed: the process
    exited, the context manager was abandoned, the generator was never exhausted. Emitting a
    partial with a flag beats emitting nothing — the missing-record case is indistinguishable from
    "the service was idle", which is how streaming bugs stay invisible for months (case 2.12).

    ``error`` is free text from an exception and therefore goes through the tier gate: exception
    messages carry connection strings and row contents at least as often as prompts do (case 5.6).
    At T0 that means ``error_chars`` and ``error_fingerprint`` and no ``error`` key — a run that
    failed is still visibly a run that failed, and two runs that failed the same way still group.
    """
    return base("agent_run", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                run_id=run_id, name=label(name, 128), phase=phase,
                goal_class=label(goal_class, 64), duration_ms=duration_ms,
                actions=actions,
                incomplete=incomplete or None,
                **tiered_text("error", error, cfg.tier, full_limit=256, preview_limit=256))


def tool_action(session_id: str, cfg: Config, *, tool_name: str, action: str,
                target: t.Optional[str] = None, blocked: bool = False,
                reason: t.Optional[str] = None, duration_ms: t.Optional[int] = None,
                run_id: t.Optional[str] = None, effect: t.Optional[dict] = None,
                error: t.Optional[str] = None) -> dict:
    """An action with an effect on the world — the thing enforcement will eventually gate.

    Field names match ``events.tool_action`` so SDK actions and wrapper tool calls land in one
    column family. ``run_id`` rides in ``caused_by_prompt_id``, which is the wrapper's causal
    linkage field: a run is the SDK's unit of causation exactly as a prompt is the wrapper's.

    ``effect`` is what actually happened — rows written, bytes sent, exit code. It is a
    *behaviour trace*, which is the whole point: the model's account of what it did is a different
    epistemic class and belongs on a different event.

    ``target``, ``reason`` and ``error`` are all free text and all three are tier-gated the same
    way. ``target`` matters most: under auto-instrumentation it is fed from ``tool.parameters`` and
    ``input.value``, which are a model's own arguments — arbitrary customer content arriving
    through a path the customer never wrote. ``target_fingerprint`` is emitted at every tier and
    was already being emitted *beside* the text rather than instead of it; at T0 it is now the
    whole story, which is what it was always for.
    """
    return base("tool_action", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                tool_name=label(tool_name, 64), action=label(action, 64),
                blocked=blocked,
                duration_ms=duration_ms, caused_by_prompt_id=run_id,
                effect=effect or None,
                **tiered_text("target", target, cfg.tier, full_limit=256, preview_limit=256),
                **tiered_text("reason", reason, cfg.tier, full_limit=256, preview_limit=256),
                **tiered_text("error", error, cfg.tier, full_limit=256, preview_limit=256))


def token_usage(session_id: str, cfg: Config, *, model: str,
                input_tokens: int, output_tokens: int,
                provider: t.Optional[str] = None,
                cache_read_tokens: t.Optional[int] = None,
                cache_write_tokens: t.Optional[int] = None,
                cost_usd: t.Optional[float] = None, cost_source: t.Optional[str] = None,
                run_id: t.Optional[str] = None, attempts: int = 1,
                incomplete: bool = False) -> dict:
    """Token and cost accounting for one **logical** model call.

    Two fields exist because of failure cases rather than features:

    ``cache_read_tokens`` / ``cache_write_tokens`` split the cached portion out of
    ``input_tokens``. Without the split the cost is not merely imprecise, it is materially wrong —
    cached input is an order of magnitude cheaper — and "exact cost" is one of the claims this
    product is sold on (case 2.16).

    ``attempts`` records HTTP attempts for one logical call. The vendor clients retry internally,
    so a naive wrapper bills a flaky network as N calls (case 2.14). One usage record, N attempts.
    """
    # -- cost, computed here when the caller did not supply one ---------------------------------
    #
    # It used to be a parameter and nothing else, so ``cost_usd`` was populated by the OTel bridge
    # and the streams integration and was simply absent from every ``run.usage()`` call — the one
    # path a customer instrumenting their own service actually uses. The Node SDK computes it at
    # this layer, so the same explicit instrumentation produced a priced row from one SDK and an
    # unpriced row from the other, into the same cost rollup. That is not a rounding difference;
    # it is a service whose spend reads as zero because of which SDK it installed.
    #
    # Same rate card, same function, one layer down. ``scripts/pricing-parity.mjs`` already checks
    # the arithmetic against the Node port differentially (264 assertions); this only changes
    # *where* it is called. A caller-supplied figure still wins and is stamped ``provider`` rather
    # than ``usage``, because a number the provider billed is evidence and a number we derived is
    # an inference, and a reconciliation against an invoice has to be able to tell them apart.
    if cost_usd is None:
        from .integrations import pricing
        cost_usd = pricing.cost_from_tokens(
            model, input_tokens=input_tokens, output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens,
        ) if model else None
        cost_source = pricing.SOURCE_USAGE if cost_usd is not None else None
    elif not cost_source:
        from .integrations import pricing
        cost_source = pricing.SOURCE_PROVIDER

    return base("token_usage", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                model=label(model, 128), provider=label(provider, 64),
                input_tokens=int(input_tokens or 0), output_tokens=int(output_tokens or 0),
                cache_read_tokens=cache_read_tokens, cache_write_tokens=cache_write_tokens,
                cost_usd=cost_usd, cost_source=label(cost_source, 32),
                caused_by_prompt_id=run_id,
                attempts=attempts if attempts != 1 else None,
                incomplete=incomplete or None)


def turn_outcome(session_id: str, cfg: Config, *, run_id: t.Optional[str], outcome: str,
                 verified: t.Optional[bool] = None, verified_by: t.Optional[str] = None,
                 actions: int = 0, blocked: int = 0, partial: bool = False) -> dict:
    """What the run actually achieved.

    ``verified_by`` is not decoration. A model reporting success is ``interaction_narrative``; an
    exit code, a row count or a passing test is ``behavior_trace``. This event is tagged as
    behaviour, so it is only honest to emit when the caller can name the thing that verified it —
    when ``verified_by`` is absent, ``verified`` stays ``None`` (*"nothing was verified"*) rather
    than defaulting to ``True``, and the consumer weights it accordingly.
    """
    if verified is None and verified_by:
        verified = True
    return base("turn_outcome", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                prompt_id=run_id, outcome=label(outcome, 64),
                verified=verified, verified_by=label(verified_by, 64),
                actions=actions, blocked=blocked, partial=partial or None)


def pipeline_health(session_id: str, cfg: Config, *, instance_id: str, counters: dict,
                    queue_depth: int, collector_up: bool, checkpoint: str,
                    runtime: t.Optional[dict] = None) -> dict:
    """The SDK's report on itself: drops, failures, queue depth, transport mode.

    Case 4.3 in one event. Pure counters and booleans, so it is safe at ``metadata_only`` and
    therefore always emitted — a health signal that is suppressed by the default privacy tier is a
    health signal that does not exist. This is the event that makes "we captured everything" a
    checkable claim rather than a marketing one.
    """
    return base("pipeline_health", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                terminal_id=instance_id, collector_up=collector_up,
                checkpoint=checkpoint, queue_depth=queue_depth,
                runtime=runtime,
                **{k: int(v) for k, v in (counters or {}).items()})


# ------------------------------------------------------------------ operate plane (catalog §28–33)
# The right half of the causal chain. Hand-mirrored from ``nexus_devtools/events.py:933-1242``,
# under the same warning as the rest of this module: these are wire shapes shared with the wrapper
# and the connection ingesters, and two producers drifting is the failure the generated artifact
# will eventually prevent. Field names, defaults and tier behaviour below are copied, not designed.
#
# ``detected_by`` is a THIRD provenance key, deliberately neither of the two already here:
#
#     producer      the ATTACH POINT that put the row on the wire      wrap | sdk | connection
#     source        content provenance on the older events             mechanical | llm_judged | …
#     detected_by   the INSTRUMENT that observed the fact              forge | cloud | ci | apm | …
#
# The value that earns the key its place is ``self``: a process asserting its own deployment is the
# weakest claim on this plane, and the console must be able to label it as such wherever it appears.
# Every default is the WEAKEST value the event could honestly carry, for the same reason ``tier``
# defaults to ``metadata_only`` — a call site that says nothing must not be able to overclaim.
DETECTED_BY_FORGE = "forge"        # read-only GitHub/GitLab/Bitbucket/ADO connector
DETECTED_BY_CLOUD = "cloud"        # Vercel, AWS, GCP, Cloudflare, Kubernetes
DETECTED_BY_CI = "ci"              # a build system reporting its own result
DETECTED_BY_APM = "apm"            # Sentry / Datadog / Grafana
DETECTED_BY_SDK = "sdk"            # nexus-sdk, observed at runtime
DETECTED_BY_SELF = "self"          # the process asserted it about itself — weakest claim here
DETECTED_BY_CONSOLE = "console"    # a human typed it into the console
DETECTED_BY = (DETECTED_BY_FORGE, DETECTED_BY_CLOUD, DETECTED_BY_CI, DETECTED_BY_APM,
               DETECTED_BY_SDK, DETECTED_BY_SELF, DETECTED_BY_CONSOLE)

# Closed vocabularies, named rather than spelled at call sites so a caller cannot invent
# `succeeded`/`success`/`ok` as three names for one outcome.
DEPLOY_SUCCEEDED = "succeeded"
DEPLOY_FAILED = "failed"
DEPLOY_CANCELLED = "cancelled"
DEPLOY_IN_PROGRESS = "in_progress"
DEPLOY_OUTCOMES = (DEPLOY_SUCCEEDED, DEPLOY_FAILED, DEPLOY_CANCELLED, DEPLOY_IN_PROGRESS)

COST_COMPUTE = "compute"
COST_DATABASE = "database"
COST_STORAGE = "storage"
COST_NETWORK = "network"
COST_THIRD_PARTY = "third_party"
COST_OTHER = "other"
COST_CLASSES = (COST_COMPUTE, COST_DATABASE, COST_STORAGE, COST_NETWORK, COST_THIRD_PARTY,
                COST_OTHER)

OWNER_ROLE_OWNER = "owner"
OWNER_ROLE_DEPUTY = "deputy"
OWNER_ROLE_MAINTAINER = "maintainer"
OWNER_ROLES = (OWNER_ROLE_OWNER, OWNER_ROLE_DEPUTY, OWNER_ROLE_MAINTAINER)


def deployment(session_id: str, cfg: Config, *, deployment_id: str, env: str,
               app_id: t.Optional[str] = None, version: t.Optional[str] = None,
               commit: t.Optional[str] = None, repo: t.Optional[str] = None,
               actor: t.Optional[str] = None, started_ts: t.Optional[str] = None,
               finished_ts: t.Optional[str] = None, outcome: t.Optional[str] = None,
               rollback_of: t.Optional[str] = None,
               detected_by: str = DETECTED_BY_SELF) -> dict:
    """A version reached an environment — the one record the operate plane is built on.

    ``rollback_of`` stays a field rather than becoming a sibling event type: a rollback is a
    deployment for every other purpose, and splitting it forces every consumer that wants "what
    reached prod" to union two types — a bug that fails silently toward *under*-counting production
    changes. Absent on a forward deploy means absent, not false, because "not a rollback" and
    "nobody recorded whether it was" are different facts and the drift lanes draw them differently.

    ``actor`` is tier-gated, and the gate it used to sit behind was the wrong one. It is
    identity, not prose, so it keeps its *shape* at every tier — a deployment ledger that cannot
    say a bot did it is not a ledger — but it very often arrives as a commit author's email
    address, which the T0 promise ("fingerprint the shape, never the content") does not cover. The
    previous docstring said that below ``full`` it went "through the same scrub as any other
    outward-facing free text", and that was true and useless in the same sentence: the scrub had no
    email pattern, so the stated mitigation was a no-op and the address shipped verbatim at the
    default tier.

    Two things now hold instead of one being asserted. ``actor_fingerprint`` is what the ledger
    groups and counts on, and it is content-free, so it goes out at every tier — deploys per actor,
    "the same person as last time", first-time-deployer: all still answerable at T0. The address
    itself appears only at ``hashed`` and above, and the redactor has an email rule now, so a
    ``full``-tier operator who set the tier for prompt text does not silently get personal data as
    a side effect.
    """
    return base("deployment", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                deployment_id=label(deployment_id, 128), env=label(env, 64),
                app_id=label(app_id, 128), version=label(version, 128),
                commit=label(commit, 128), repo=label(repo, 200),
                started_ts=started_ts, finished_ts=finished_ts,
                outcome=label(outcome, 32), rollback_of=label(rollback_of, 128),
                detected_by=detected_by,
                **tiered_text("actor", actor, cfg.tier, full_limit=128, preview_limit=128))


def service_health(session_id: str, cfg: Config, *, service: str,
                   app_id: t.Optional[str] = None, env: t.Optional[str] = None,
                   window_from: t.Optional[str] = None, window_to: t.Optional[str] = None,
                   requests: t.Optional[int] = None, errors: t.Optional[int] = None,
                   p50_ms: t.Optional[float] = None, p95_ms: t.Optional[float] = None,
                   p99_ms: t.Optional[float] = None, saturation: t.Optional[float] = None,
                   detected_by: str = DETECTED_BY_SDK) -> dict:
    """A window of observed service behaviour — *behavior trace*.

    Every quantity is independently optional, and that is the whole design of the event. A producer
    that measured latency but not saturation must not be made to look like one that measured
    neither, and a zero written where nothing was measured is the specific lie this plane exists to
    avoid: a service with ``errors`` absent is unmeasured, a service with ``errors: 0`` is healthy,
    and one number cannot be allowed to mean both. ``base()`` drops ``None``, so absent stays absent
    all the way to the wire.

    The window is two explicit timestamps rather than a duration, because the reader's question is
    "over which period" and a bare ``"5m"`` cannot answer it once the record arrives late.
    """
    return base("service_health", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                service=label(service, 128), app_id=label(app_id, 128),
                env=label(env, 64),
                window_from=window_from, window_to=window_to,
                requests=requests, errors=errors,
                p50_ms=p50_ms, p95_ms=p95_ms, p99_ms=p99_ms, saturation=saturation,
                detected_by=detected_by)


def integration_probe(session_id: str, cfg: Config, *, integration: str, observed_ts: str,
                      app_id: t.Optional[str] = None, service: t.Optional[str] = None,
                      kind: t.Optional[str] = None,
                      integration_up: t.Optional[bool] = None,
                      auth_ok: t.Optional[bool] = None,
                      latency_ms: t.Optional[int] = None,
                      last_data_ts: t.Optional[str] = None,
                      rows: t.Optional[int] = None,
                      schema_fingerprint: t.Optional[str] = None,
                      error: t.Optional[str] = None, error_class: t.Optional[str] = None,
                      detected_by: str = DETECTED_BY_SDK) -> dict:
    """One observation of an outbound dependency — the silent-failure primitive.

    ``integration_up`` and ``last_data_ts`` are two registers and must **never** be merged into one.
    ``integration_up`` is LIVENESS — the call completed. ``last_data_ts`` is FRESHNESS — the newest
    *business* timestamp actually observed in the response. The PRD's headline case is only
    expressible because they are separate: a sync that runs every minute and has returned the same
    stale rows for three days is up, authorised, fast, and broken.

    The naming follows ``pipeline_health``, which already splits the same idea for the client's own
    capture pipeline (``collector_up`` for liveness, backlog fields for freshness).
    ``integration_up`` is ``collector_up`` pointed outward and is spelled the same way on purpose.

    ``rows`` is the count returned, and zero is a real, reportable answer: *the call succeeded and
    returned nothing* is a different fact from *the call succeeded*, and it is the fact no uptime
    monitor records. ``schema_fingerprint`` changes when the response shape changes, which is how a
    silent schema break becomes visible before the rows stop matching.

    ``error`` is a vendor exception string lifted off a third-party client and is gated exactly like
    ``prompt``: T0 keeps only the shape (length + one-way fingerprint), T1 a redacted preview, T2 the
    text. Those messages carry request URLs with query strings, account identifiers and token
    fragments at least as often as prompts do. ``error_class`` is the content-free companion
    (``auth`` / ``timeout`` / ``http_5xx`` / ``schema`` / ``transport``): it survives every tier,
    because the alarm branches on it and an alarm that only works at T2 is not an alarm.
    """
    e = base("integration_probe", session_id, cfg,
             epistemic_class=EPISTEMIC_BEHAVIOR,
             integration=label(integration, 128), observed_ts=observed_ts,
             app_id=label(app_id, 128), service=label(service, 128),
             kind=label(kind, 64),
             integration_up=integration_up, auth_ok=auth_ok, latency_ms=latency_ms,
             last_data_ts=last_data_ts, rows=rows,
             schema_fingerprint=label(schema_fingerprint, 64),
             error_class=label(error_class, 64), detected_by=detected_by)
    # Shape at every tier — content-free, so repeated failures can be counted and "the same error
    # as yesterday" answered, without the text ever leaving the machine. Hand-rolled here until the
    # tier ladder landed; now the same ``tiered_text`` the other free-text fields use, with the
    # same key names it was already producing. Two copies of a tier ladder is how one of them ends
    # up with a rung missing.
    e.update(tiered_text("error", error, cfg.tier, full_limit=512, preview_limit=280))
    return e


def incident(session_id: str, cfg: Config, *, incident_id: str,
             app_id: t.Optional[str] = None, title: t.Optional[str] = None,
             severity: t.Optional[str] = None, suggested_severity: t.Optional[str] = None,
             detected_ts: t.Optional[str] = None, resolved_ts: t.Optional[str] = None,
             affected_services: t.Optional[list] = None,
             detected_by: str = DETECTED_BY_CONSOLE) -> dict:
    """An incident's lifecycle record. Mirror-only: the SDK has no entry point that emits this.

    ``severity`` is declared by a human; ``suggested_severity`` is what a system would have guessed.
    They are carried side by side and never coalesced — overwriting a declared severity with a
    derived one, or writing the derived one into the same field when no human has ruled, makes it
    impossible to ask afterwards whether the suggestion was any good, which is the only way a
    suggestion ever earns the right to be shown.

    **Not carried here: the investigation's conclusion.** An incident record with an embedded
    system-drawn probable cause would put two different epistemic classes under one row-level
    ``epistemic_class``, and the stronger one would launder the weaker. The hypothesis is a separate
    record stamped ``system_inference``.
    """
    e = base("incident", session_id, cfg,
             epistemic_class=EPISTEMIC_BEHAVIOR,
             incident_id=incident_id, app_id=app_id,
             severity=severity, suggested_severity=suggested_severity,
             detected_ts=detected_ts, resolved_ts=resolved_ts,
             affected_services=affected_services, detected_by=detected_by)
    e.update(tiered_text("title", title, cfg.tier, full_limit=200, preview_limit=200))
    return e


def infra_cost(session_id: str, cfg: Config, *, provider: str, resource_class: str,
               currency: str, app_id: t.Optional[str] = None,
               period_from: t.Optional[str] = None, period_to: t.Optional[str] = None,
               amount_minor: t.Optional[int] = None,
               detected_by: str = DETECTED_BY_CLOUD) -> dict:
    """Measured infrastructure spend. Mirror-only: no SDK entry point emits this.

    Its own event rather than a fold into the token stack. Token cost is DERIVED (measured tokens ×
    a price table that can be weeks stale); infrastructure cost read back from a provider's billing
    API is MEASURED. The two cannot share a typeface and cannot share an event.

    ``amount_minor`` is minor units as an integer — cents, not euros — because money in a float is a
    rounding bug with a delivery date. ``currency`` is required alongside it for the same reason: an
    amount without one is not a smaller fact, it is an unusable one.

    ``provider`` here is the CLOUD provider (``aws`` / ``vercel`` / ``gcp``), which is NOT the
    vocabulary the same wire key carries on ``token_usage`` and ``session``, where it is the model
    provider (``anthropic`` / ``openai``).
    """
    return base("infra_cost", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                provider=provider, resource_class=resource_class, currency=currency,
                app_id=app_id, period_from=period_from, period_to=period_to,
                amount_minor=amount_minor, detected_by=detected_by)


def ownership(session_id: str, cfg: Config, *, app_id: str, principal: str, role: str,
              asserted_by: t.Optional[str] = None, asserted_ts: t.Optional[str] = None,
              detected_by: str = DETECTED_BY_CONSOLE) -> dict:
    """A human claimed responsibility for an application — *behavior trace*. Mirror-only.

    Read the class twice; the first instinct is wrong and the design implements the corrected one.
    ``epistemic_class`` answers *how do we know this record exists*, not *is the proposition inside
    it true*. The assertion happening **is** observed — we have who claimed it and when. The nearest
    shipped precedent is ``human_feedback``, filed ``behavior_trace`` on exactly this reasoning.

    What carries the doubt instead is ``detected_by`` plus the surface: ``asserted_by`` and
    ``asserted_ts`` are printed wherever the claim appears, so the reader sees "recorded by X, 40
    days ago" rather than a fact.

    ``principal`` and ``asserted_by`` are the two fields in this package that are *always*
    a person — not text that might contain a person, but a name or a work email address by
    definition of what the field is for. They went straight into ``base()``, which does not consult
    ``cfg.tier`` at all, so both shipped verbatim at ``metadata_only``: the tier whose entire
    promise is that no content leaves the process. An operator reading the tier table would have
    had no way to expect it.

    They now go through the same ladder as every other free-text field. At T0 that is a length and
    a fingerprint, which is what a ledger actually needs from an identity — the fingerprint is
    stable, so "the same person asserted these forty records" still reads correctly, and "who"
    resolves only at a tier where the operator has said content may leave.

    ``role`` is deliberately left ungated: it is drawn from a small fixed vocabulary (owner,
    approver, …), which makes it a category rather than an identity, and hashing a five-value enum
    produces a digest anybody can reverse by trying all five.

    This function has no SDK entry point today — it is mirror-only — and that is exactly why it was
    worth fixing now rather than when it acquires one. ``contract`` is a public, importable module,
    and "one new call site away from shipping names at T0" is a state this file has been in before.
    """
    return base("ownership", session_id, cfg,
                epistemic_class=EPISTEMIC_BEHAVIOR,
                app_id=app_id, role=role,
                asserted_ts=asserted_ts, detected_by=detected_by,
                **tiered_text("principal", principal, cfg.tier, full_limit=128, preview_limit=128),
                **tiered_text("asserted_by", asserted_by or "", cfg.tier, full_limit=128, preview_limit=128))


def redact_preview(text: str, tier: str, limit: int = 280) -> t.Optional[dict]:
    """Tier-appropriate rendering of a free-text field, as a fragment to splat into a builder.

    T0 gives shape only (length + one-way fingerprint), T1 a redacted preview, T2 the redacted
    text. Below T2 the *content* key is absent rather than blanked — a reader must be able to tell
    "no content was captured" from "the content was empty".

    Unprefixed keys, for the model-text events that carry exactly one free-text field and rename
    the fragment on the way in (``bridge._emit_content``). Fields that live beside other fields use
    ``tiered_text``, which is the same ladder with the field's name in front of every key. Both
    share ``_rungs``, so a tier cannot mean one thing here and another there — that divergence
    *was* a live defect: five fields went through a helper with two branches while three went through
    this one, which has three.
    """
    if not text:
        return None
    frag: dict = {"chars": len(text), "fingerprint": fingerprint(text),
                  "tokens_est": est_tokens(text)}
    frag.update(_rungs(text, tier, full_limit=None, preview_limit=limit))
    return frag


def _rungs(text: str, tier: str, *, full_limit: t.Optional[int], preview_limit: int) -> dict:
    """The ladder itself, in one place: what content — if any — this tier may carry.

    Returns canonical keys (``text`` / ``preview`` and their flags); the two public wrappers rename
    them. **T0 returns an empty dict**: not a blank string, not a mask, nothing. That empty dict is
    the rung whose absence was that defect, and it is now impossible to have it in one caller and not
    the other, because there is only one caller of the ladder.

    ``full`` is redacted too. A tier is a decision about *content*; it is never a waiver on
    credentials, and the T2 branch that used to slice raw text is how ``integration_probe.error``
    would have shipped an unscrubbed vendor exception to anyone who set ``tier=full``.

    **Both rungs go through ``scan_window``, and that is the point of this change.** The
    ladder used to call ``redact()`` on the whole input and slice afterwards, which is the shape
    already called out on ``wire_text`` and fixed *there only*. Two consequences, both
    measured:

    * Latency. On one 21 MB string, ``contract.tiered_text`` took 13.5 s of CPU on the
      caller's thread where ``redact.wire_text`` took 0.003 s. Whether a caller can reach 21 MB
      depends on bounds upstream — ``otel/semconv._text`` caps its path at 20 000 characters —
      but ``contract`` is a public importable module and ``tiered_text`` takes whatever string it
      is handed. The bound belongs in the function, not in a survey of its callers.
    * Correctness. A secret longer than the scan window never matches its own terminator,
      so its opening bytes survive redaction. ``wire_text`` learned to refuse those; the ladder
      would still have emitted ``-----BEGIN RSA PRIVATE KEY-----`` at T1 and T2. Sharing the
      helper is what makes "a tier cannot mean one thing here and another there" true of the
      scanning rules too, and not just of the rungs.
    """
    if tier == TIER_FULL:
        scrubbed, was, unfinished = scan_window(text, full_limit)
        out = {"text": MASK if unfinished else scrubbed, "text_redacted": was or unfinished}
        if full_limit is not None:
            out["text_truncated"] = len(text) > full_limit
        return out
    if tier == TIER_HASHED:
        scrubbed, was, unfinished = scan_window(text, preview_limit)
        return {"preview": MASK if unfinished else scrubbed,
                "preview_redacted": was or unfinished,
                "preview_truncated": len(text) > preview_limit}
    if tier != TIER_METADATA_ONLY:  # unreachable; kept so a new tier fails loudly in tests
        raise ValueError(f"unknown tier {tier!r}")
    return {}


def tiered_text(name: str, text: t.Optional[str], tier: str, *,
                full_limit: int = 512, preview_limit: int = 280) -> dict:
    """A *named* free-text field, gated by tier, as a fragment to splat into ``base(**…)``.

    This is where the five fields that used to call ``redact.wire_text`` now go: ``agent_run
    .error``, ``tool_action.target`` / ``.reason`` / ``.error``, and ``deployment.actor``. They
    were the only content-bearing fields on the wire with no T0 rung, and they lacked one for a
    structural reason rather than through five separate oversights — they went through a helper
    that returns a string, and no string means "shape only".

    Shape survives every tier. ``<name>_chars`` and ``<name>_fingerprint`` are content-free, so at
    T0 "the same error as yesterday" stays answerable, deploy actors stay countable and a repeated
    target stays groupable, without the text leaving the process. The content key is ``<name>`` at
    T2 and ``<name>_preview`` at T1; at T0 it does not exist.

    Empty in, empty out — an absent field writes nothing, not a zero length.
    """
    txt = (text if isinstance(text, str) else str(text) if text else "").strip()
    if not txt:
        return {}
    out: dict = {f"{name}_chars": len(txt), f"{name}_fingerprint": fingerprint(txt)}
    for k, v in _rungs(txt, tier, full_limit=full_limit, preview_limit=preview_limit).items():
        # ``text`` is the field itself; ``text_redacted`` is a flag *about* the field and reads as
        # ``<name>_redacted``, matching ``<name>_preview_redacted`` one rung down. Leaving the
        # canonical name in would spell it ``actor_text_redacted``, which invents a second word for
        # the same thing in the same event.
        suffix = k[5:] if k.startswith("text_") else ("" if k == "text" else k)
        out[f"{name}_{suffix}" if suffix else name] = v
    return out
