"""Dimensions — the group-by keys, and the bound most of them did not have.

A *dimension* is a field a rollup does ``GROUP BY`` on: ``goal_class``, ``model``, ``provider``,
``kind``, ``error_class``, and the five provenance labels that ride the base envelope. They are not
content, so the tier ladder is the wrong instrument for them — what they need is a **length bound**,
and most of them had none.

This is the third instance of one class, and the class is worth naming because its members do not
look alike:

1. a caller object spread onto an event with no gate — a *disclosure* failure, and it looks alarming;
2. ``tags`` — a caller object spread onto every event with no bound;
3. these — caller strings landing in fields a consumer aggregates on.

The second and third are *cardinality* failures and they look like nothing at all: no error, no
leak, no red test. The rollup and the cost report just quietly degrade on the collector's side,
where the customer cannot see it and we are the ones paying for it. That asymmetry is why this was
found by sweeping for the shape rather than by noticing a symptom.

**Neither SDK bounded these.** The gap existed here first and was faithfully reproduced in the Node
port; Node closed it, and this file closes it here. Two of the previous sweep's claims about this
module turned out to be wrong and are corrected in the assertions below: ``integration_probe``'s
``error_class`` was *already* bounded, at the API layer in ``api.py`` rather than in the builder,
and ``service`` / ``env`` / ``service_version`` were already bounded here while the Node SDK left
all three unbounded — the reverse of the direction PARITY.md §7a described.

The cross-SDK conformance suite (``nexus-sdk-node/conformance/``) is what proves the two agree; this
file is the offline half, so ``pytest`` still fails on Python-side drift on a machine that has never
seen the Node SDK.
"""
from __future__ import annotations

import pytest

import nexus
from nexus import client, config, contract

HUGE = "x" * 5000


@pytest.fixture()
def cfg():
    return config.resolve(service="t", env="test", version="1.0.0",
                          collector_url="http://127.0.0.1:1/none")


# Every dimension, its bound, and **what an unbounded value costs there** — which is the part that
# makes this a product decision rather than a lint rule. Kept as data so the Node SDK's
# `test/dimensions.test.mjs` and `conformance/scenario.json` can carry the same evidence rather
# than a prose summary of it.
DIMENSIONS = [
    ("agent_run", "name", 128,
     "the run label, and the join key of every run view"),
    ("agent_run", "goal_class", 64,
     "the axis runs are compared on across services and over time; a per-request value makes "
     "every run its own cohort and the comparison silently meaningless"),
    ("tool_action", "tool_name", 64, "the group-by of every tool-usage view"),
    ("tool_action", "action", 64, "the second axis of the same view"),
    ("token_usage", "model", 128,
     "the primary group-by of every cost rollup; a per-request value fragments spend into one row "
     "per call and no per-model total can be computed at all"),
    ("token_usage", "provider", 64, "the second cost axis, the same failure one level up"),
    ("token_usage", "cost_source", 32,
     "a two-value enum (usage/provider) distinguishing an inference from evidence; a free string "
     "leaves a reconciliation against an invoice unable to tell them apart"),
    ("turn_outcome", "outcome", 64, "the outcome distribution"),
    ("turn_outcome", "verified_by", 64, "the axis 'verified' claims are weighed on"),
    ("integration_probe", "integration", 128, "the probe's own identity"),
    ("integration_probe", "kind", 64,
     "groups probes by dependency type; unbounded, a silent-failure alarm cannot be scoped to one "
     "class of dependency"),
    ("integration_probe", "error_class", 64,
     "the branch key an alarm fires on; a per-incident value means the alarm never sees two of "
     "anything and therefore never fires — a monitoring control that is present and inert"),
    ("integration_probe", "schema_fingerprint", 64, "silent schema-break detection"),
    ("deployment", "outcome", 32, "the deployment ledger's group-by"),
    ("deployment", "rollback_of", 128, "which deploy this one reverted"),
    ("deployment", "version", 128, "which version reached the environment"),
    ("deployment", "commit", 128, "the deploy ledger's join key back to the forge"),
    ("deployment", "repo", 200, "the same"),
    ("deployment", "app_id", 128, "the same"),
    ("service_health", "service", 128, "rollup identity"),
    ("service_health", "app_id", 128, "rollup identity"),
    ("service_health", "env", 64, "rollup identity"),
]


def _build(kind, cfg, **kw):
    """Build one event of each type with every dimension handed 5000 characters."""
    common = dict(session_id="s", cfg=cfg)
    if kind == "agent_run":
        return contract.agent_run(**common, run_id="r", name=HUGE, phase="end", goal_class=HUGE)
    if kind == "tool_action":
        return contract.tool_action(**common, tool_name=HUGE, action=HUGE)
    if kind == "token_usage":
        return contract.token_usage(**common, model=HUGE, provider=HUGE, input_tokens=1,
                                    output_tokens=1, cost_usd=0.5, cost_source=HUGE)
    if kind == "turn_outcome":
        return contract.turn_outcome(**common, run_id="r", outcome=HUGE, verified_by=HUGE)
    if kind == "integration_probe":
        return contract.integration_probe(**common, integration=HUGE, observed_ts="t", kind=HUGE,
                                          error_class=HUGE, schema_fingerprint=HUGE, app_id=HUGE,
                                          service=HUGE)
    if kind == "deployment":
        return contract.deployment(**common, deployment_id=HUGE, env=HUGE, outcome=HUGE,
                                   rollback_of=HUGE, version=HUGE, commit=HUGE, repo=HUGE,
                                   app_id=HUGE)
    if kind == "service_health":
        return contract.service_health(**common, service=HUGE, app_id=HUGE, env=HUGE)
    raise AssertionError(kind)


@pytest.mark.parametrize("kind,field,limit,why", DIMENSIONS,
                         ids=[f"{k}.{f}" for k, f, _, _ in DIMENSIONS])
def test_every_group_by_dimension_is_bounded(cfg, kind, field, limit, why):
    e = _build(kind, cfg)
    assert field in e, f"{kind}.{field} was never emitted, so nothing was checked"
    assert len(e[field]) <= limit, (
        f"{kind}.{field} is {len(e[field])} chars, bound {limit}. Unbounded here: {why}")


def test_the_base_envelope_dimensions_are_bounded_at_config_resolution():
    """The widest blast radius in the product, and the reason they are bounded in ``config``.

    These five ride the base envelope, so they appear on *every* event. An unbounded ``commit`` is
    not one oversized field, it is one oversized field multiplied by every row the process ever
    emits. Bounding at resolution also means no builder can forget, and there is one place to read
    the bound off.
    """
    c = config.resolve(service=HUGE, env=HUGE, version=HUGE, application=HUGE, repo=HUGE,
                       commit=HUGE, branch=HUGE, deployment_id=HUGE,
                       collector_url="http://127.0.0.1:1/none")
    assert (len(c.service), len(c.env), len(c.version)) == (128, 64, 64)
    assert (len(c.application), len(c.repo), len(c.commit)) == (128, 200, 128)
    assert (len(c.branch), len(c.deployment_id)) == (128, 128)

    # And they arrive bounded on an ordinary event, not only in the config object.
    e = contract.agent_run(session_id="s", cfg=c, run_id="r", name="n", phase="start")
    assert len(e["service"]) == 128 and len(e["env"]) == 64 and len(e["service_version"]) == 64
    assert len(e["application"]) == 128 and len(e["commit"]) == 128 and len(e["repo"]) == 200


def test_bounding_does_not_blank_an_ordinary_label(cfg):
    e = contract.agent_run(session_id="s", cfg=cfg, run_id="r", name="nightly", phase="end",
                           goal_class="reconciliation")
    assert e["name"] == "nightly"
    assert e["goal_class"] == "reconciliation"

    u = contract.token_usage(session_id="s", cfg=cfg, model="claude-opus-4-1",
                             provider="anthropic", input_tokens=10, output_tokens=2)
    # The model has to survive intact or the rate card cannot price it — a bound that broke pricing
    # would be a worse bug than the one it fixed.
    assert u["model"] == "claude-opus-4-1"
    assert u["cost_source"] == "usage"
    assert u["cost_usd"] > 0


def test_an_empty_or_whitespace_only_dimension_is_absent_rather_than_blank(cfg):
    e = contract.agent_run(session_id="s", cfg=cfg, run_id="r", name="n", phase="end",
                           goal_class="   ")
    # Absent and empty are different facts, and dropping None keys keeps them different all the
    # way to the wire. `"   "` is not a cohort.
    assert "goal_class" not in e


def test_a_non_string_dimension_is_coerced_rather_than_dropped_or_raised_on(cfg):
    e = contract.agent_run(session_id="s", cfg=cfg, run_id="r", name="n", phase="end",
                           goal_class=42)
    # Passing `goal_class=42` is a caller mistake, but silently losing the label is a worse response
    # to it than recording it — and raising on the application's own path is worse still.
    assert e["goal_class"] == "42"


def test_error_class_is_bounded_by_the_api_layer_too(monkeypatch):
    """``api.Integration.fail`` already bounded this before the builder did.

    Worth pinning both, because a previous sweep of ``contract.py`` alone reported ``error_class``
    as unbounded when it was not, and "the field is unbounded" and "the builder does not bound it"
    are different claims. The builder holds the invariant now; this asserts the API layer still
    does as well, so removing either does not silently un-bound the field.
    """
    io = nexus.integration("crm", kind="saas")
    io.fail(RuntimeError("boom"), error_class=HUGE)
    assert len(io._error_class) == 64


def test_a_length_bound_is_not_a_distinct_value_bound(cfg):
    """Stated as a test so the bound is not mistaken for a fix it is not.

    Truncating stops a megabyte of prose becoming a group-by key; it does not reduce the *number*
    of distinct values, which is the other half of cardinality. Capping that in-process would mean
    remembering every value ever seen — itself unbounded memory — so it belongs to the collector.
    """
    classes = {
        contract.agent_run(session_id="s", cfg=cfg, run_id="r", name="n", phase="end",
                           goal_class=f"per-request-{i}")["goal_class"]
        for i in range(50)
    }
    assert len(classes) == 50


def test_the_bounds_match_the_node_sdk_exactly(tmp_path):
    """The bounds are a cross-SDK contract, not a local style choice.

    A bound that differs by SDK is a cardinality difference a customer can see: the same value
    truncated at 64 by one service and 128 by another produces two group-by keys for one thing.
    This reads the Node SDK's own table when it is checked out beside this one and diffs it, so the
    two cannot drift silently. Skipped rather than failed when it is absent — this suite has to
    pass on a machine that has only ever seen Python.
    """
    import json
    import pathlib

    scenario = (pathlib.Path(__file__).resolve().parents[2]
                / "nexus-sdk-node" / "conformance" / "scenario.json")
    if not scenario.exists():
        pytest.skip("nexus-sdk-node is not checked out beside this repository")

    node_bounds = {(t, f): b for t, f, b, _ in json.loads(scenario.read_text())["dimensions"]}
    ours = {(t, f): b for t, f, b, _ in DIMENSIONS}
    shared = set(node_bounds) & set(ours)
    assert shared, "the two tables share no dimension, so nothing was compared"
    for key in sorted(shared):
        assert ours[key] == node_bounds[key], (
            f"{key[0]}.{key[1]}: python bounds at {ours[key]}, node at {node_bounds[key]}")
