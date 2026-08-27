"""Case 6.4 — the decision latency budget, asserted so CI enforces it.

This is the test that lets us publish a number. §7.4 says an overhead budget must be *published
and asserted in CI*, because customers will ask and "negligible" is not an answer; §6.4 makes the
policy path specifically a hard cap, because this is the one place the SDK sits between a
customer's request and its effect. An SDK that adds unbounded latency to a checkout does not
survive its first incident review, and the review will ask for exactly this measurement.

Three properties are asserted here, and they are different claims:

1. **p99 evaluation latency is under the published cap** — the contractual guarantee.
2. **Signature verification is not on the decision path** — the structural reason (1) holds. The
   verifier is ~10ms of pure-Python curve arithmetic; if it ran per decision, no budget would be
   holdable and the fix would be a redesign rather than a tune. A counting stub proves it runs
   zero times across thousands of decisions.
3. **Exceeding the budget allows** — the cap is a real abandonment, not an assertion in a comment,
   and it abandons in the permissive direction even when the rule that would have matched is
   ``enforce``-marked.

The p99 threshold is the published cap rather than a tight regression bound, deliberately: a
suite that fails on a busy CI runner teaches everyone to re-run it, and a flaky latency gate is
worth less than none. The tight bound is on the median, which is stable under load. The measured
numbers are printed so a regression shows up in the log even when it stays inside the cap.
"""
from __future__ import annotations

import time

import pytest

from nexus import policy
from nexus.policy import alerts, ed25519, engine
from nexus.policy import envelope as env_mod
from nexus.policy import settings

SEED = bytes(range(32))
PUB_HEX = ed25519.public_key(SEED).hex()

#: Enough rules to be realistic and then some. A control plane shipping more than this to a
#: request path is a control-plane bug, which is why ``settings.max_rules`` exists.
RULE_COUNT = 50
SAMPLES = 5000


def sign_envelope(payload: dict) -> dict:
    """``issued_at`` lives inside the signature — see ``test_policy.py``."""
    body = {"issued_at": time.time(), **payload}
    return {"policy": body, "signature": ed25519.sign(SEED, env_mod.canonical(body)).hex()}


def realistic_rules() -> list:
    """A rule set shaped like one a customer would actually write: mostly non-matching, mixed
    clause types, with the matching rule last so every decision walks the whole set. Putting the
    match first would measure the best case and publish it as the budget."""
    out = []
    for i in range(RULE_COUNT - 1):
        out.append({"id": f"rule-{i}", "action": "deny", "enforce": bool(i % 2),
                    "reason": f"rule {i}",
                    "match": {"tool": [f"tool-{i}", f"alt-{i}"],
                              "target_glob": [f"env-{i}-*", f"other-{i}-*"],
                              "target_contains": [f"seg{i}"]}})
    out.append({"id": "no-prod-writes", "action": "deny", "enforce": True,
                "reason": "writes to production orders require a change ticket",
                "match": {"tool": "db.write", "target_glob": "prod-*"}})
    return out


SUBJECT = {"tool": "db.write", "target": "prod-orders", "risk": "high", "repo": "checkout-api"}


@pytest.fixture(autouse=True)
def _policy_isolation():
    policy.reset_for_tests()
    settings.configure(pubkey_hex=PUB_HEX)
    yield
    policy.reset_for_tests()


def percentile(values: list, p: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(p / 100.0 * len(ordered))) - 1))
    return ordered[idx]


def test_p99_decision_latency_is_under_the_published_cap(capsys):
    """**Acceptance.** Case 6.4 / 7.4: the number we publish, asserted where CI runs it."""
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    cap_ms = settings.current().decision_budget_ms

    # Warm the lazy imports on the decision path (``_counters``) so the first call's import cost
    # is not reported as a policy decision. Paying it once at init is the design; measuring it as
    # a per-decision cost would be a lie in the flattering direction... and in the other one, it
    # would make the published p99 depend on how many tests ran first.
    for _ in range(50):
        policy.decide("tool_action", SUBJECT)

    samples = []
    for _ in range(SAMPLES):
        d = policy.decide("tool_action", SUBJECT)
        samples.append(d.eval_ms)
        assert d.denied is True          # the work being measured is a real full-set walk

    p50, p99, worst = (percentile(samples, 50), percentile(samples, 99), max(samples))
    with capsys.disabled():
        print(f"\n  policy decision latency over {SAMPLES} samples, {RULE_COUNT} rules:"
              f" p50={p50 * 1000:.1f}us p99={p99 * 1000:.1f}us max={worst * 1000:.1f}us"
              f" (cap {cap_ms:.0f}ms)")

    # Floor first. "p99 is under the cap" is satisfied trivially by a metric stuck at zero, and
    # during development it *was* — every non-approval branch stamped ``eval_ms=0``, so this
    # entire test passed while measuring nothing. A latency gate with a trivially-satisfying
    # failure mode is worse than no gate, because it reports success.
    assert min(samples) > 0.0, "eval_ms is not being stamped — this test is measuring nothing"

    assert p99 < cap_ms, f"p99 {p99:.3f}ms exceeds the published cap of {cap_ms}ms"
    # Stable under CI load in a way p99 is not; catches an order-of-magnitude regression that
    # still fits inside the cap.
    assert p50 < 1.0, f"median {p50:.3f}ms — something is doing real work per decision"


def test_signature_verification_never_runs_on_the_decision_path(monkeypatch):
    """The structural reason the budget is holdable. ~10ms of curve arithmetic per decision would
    make the cap unreachable by tuning."""
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)

    calls = []
    monkeypatch.setattr(ed25519, "verify", lambda *a, **k: calls.append(1) or True)
    for _ in range(1000):
        policy.decide("tool_action", SUBJECT)
    assert calls == []


def test_no_policy_decisions_are_cheap_too():
    """The common case for a customer who has not configured policy: it must cost nothing
    noticeable, or the seam is a tax on people who are not using the feature."""
    for _ in range(50):
        policy.decide("tool_action", SUBJECT)
    samples = [policy.decide("tool_action", SUBJECT).eval_ms for _ in range(SAMPLES)]
    assert min(samples) > 0.0
    assert percentile(samples, 99) < settings.current().decision_budget_ms
    assert percentile(samples, 50) < 0.5


def test_exceeding_the_budget_allows_and_records_the_timeout(slow_evaluation):
    """Case 6.4, stated exactly: *exceeding it = allow + record the timeout.*

    Note which rule is in play — an ``enforce``-marked deny that would otherwise block. The budget
    abandons in the permissive direction even then, because the alternative is that a slow rule
    set becomes an outage.

    This used to reach the timeout by passing ``budget_ms=0.0``, which was not an overrun but the
    real hole: a caller nominating a budget that could not be met, erasing the deny into a record
    shaped like infrastructure. The condition is now produced by a slow evaluation, which is what
    case 6.4 actually describes, so the test proves fail-open rather than the bypass that used to
    cause it.
    """
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    assert policy.decide("tool_action", SUBJECT).denied is True     # blocks with a normal budget

    slow_evaluation.engage()
    d = policy.decide("tool_action", SUBJECT)
    assert d.allowed is True
    assert d.timed_out is True
    assert d.source == "budget-exceeded"
    assert alerts.BUDGET_EXCEEDED in alerts.kinds()


def test_a_caller_cannot_nominate_a_budget_that_cannot_be_met(unhurried_evaluation):
    """``budget_ms`` is the caller's, and it used to have no floor.

    `settings._reload` has always written ``max(1.0, NEXUS_POLICY_BUDGET_MS)``, so an operator
    could not configure a zero budget. The caller path divided the number as given, so
    ``decide(..., budget_ms=0.0)`` expired on the first deadline check and returned
    ``budget-exceeded`` — an allow, with no rule named.

    What makes that worth fixing is not the allow. ``enforce=False`` is a documented per-call
    dry-run and anyone who can pass one can pass the other, so no authority is gained. It is the
    record: the dry-run route reports ``action=deny, rule='...', enforced=False`` — it says what
    the policy said and that this call site declined to apply it — while the budget route reports
    an infrastructure timeout with no rule at all, indistinguishable from a control plane having a
    bad day. An enforcing deny must not be erasable into something that looks like weather.

    Driven, not raced: the clock here holds at 0.5ms, inside the 1.0ms floor and outside the 0.0ms
    the caller asked for, so the two answers are distinguishable with no dependence on hardware.
    """
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)

    d = policy.decide("tool_action", SUBJECT, budget_ms=0.0)
    assert d.source == "policy", f"the deny was erased into {d.source!r}"
    assert d.denied is True
    assert d.timed_out is False
    assert alerts.BUDGET_EXCEEDED not in alerts.kinds()


def test_a_negative_budget_is_floored_too(unhurried_evaluation):
    """Zero is the value a test reaches for; negative is the one a bug reaches for.

    ``max()`` covers both, and this exists so that a future floor written as ``if budget == 0``
    fails here rather than shipping.
    """
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    assert policy.decide("tool_action", SUBJECT, budget_ms=-1000.0).denied is True


def test_the_floor_does_not_stop_a_caller_lowering_the_budget(driven_clock):
    """The over-correction. A floor that pinned every caller to the operator's 25ms would
    close the hole by deleting the feature — and the feature is the reason the parameter exists: a
    checkout handler and an overnight batch job do not owe each other the same patience.

    The clock sits at 15ms, deliberately between the caller's 10ms and the default 25ms: the
    caller's budget has lapsed and the operator's has not, so an implementation that quietly
    substituted the operator's number shows up here as a decision that did *not* time out.

    The first version of this test armed a 100-second clock instead, which breaches both budgets
    and therefore could not tell them apart — it passed against exactly the mutant it existed to
    catch. It is kept in this shape as the reason the fixture takes an elapsed at all.
    """
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    driven_clock(15.0)
    d = policy.decide("tool_action", SUBJECT, budget_ms=10.0)
    assert d.timed_out is True, "the caller's own budget was not honoured"
    assert d.source == "budget-exceeded"


def test_the_budget_is_configurable(monkeypatch):
    """A hard cap nobody can change is a cap somebody will work around by removing the SDK."""
    monkeypatch.setenv("NEXUS_POLICY_BUDGET_MS", "7.5")
    settings.resolve_from_env()
    assert settings.current().decision_budget_ms == 7.5

    settings.configure(decision_budget_ms=3.0)
    assert settings.current().decision_budget_ms == 3.0


def test_an_approval_wait_is_excluded_from_the_evaluation_budget():
    """A decision that spent twenty seconds waiting for a human has not breached a 25ms budget.
    Conflating the two would either make the budget meaningless or make approval impossible."""
    from nexus.policy import approval

    engine.install(sign_envelope({"rules": [
        {"id": "needs-human", "action": "require_approval", "enforce": True,
         "approval": {"timeout_s": 0.3}, "match": {"tool": "refund"}}]}), pubkey_hex=PUB_HEX)
    approval.register_approver("asleep", lambda: True)

    d = policy.decide("tool_action", {"tool": "refund", "target": "cust-1"})
    assert d.approval == approval.TIMEOUT
    assert d.latency_ms >= 300.0                                    # really waited
    assert d.eval_ms < settings.current().decision_budget_ms        # …but evaluation did not


def test_a_rule_set_larger_than_the_bound_is_truncated():
    """The control plane does not get to set our latency."""
    settings.configure(max_rules=25)
    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    assert len(engine.snapshot().ruleset.rules) == 25


def test_a_pathological_matcher_is_abandoned_between_rules(monkeypatch):
    """The honest form of the guarantee: the deadline is polled *between* rules, so the bound is
    one rule's matching time past the budget rather than zero. Python cannot pre-empt a running
    frame; this test pins the behaviour we do have rather than the one we do not."""
    from nexus.policy import rules as rules_mod

    engine.install(sign_envelope({"rules": realistic_rules()}), pubkey_hex=PUB_HEX)
    real = rules_mod.matches

    # *args/**kw rather than the real signature, and that is deliberate. This stub used to be
    # ``def slow(rule, subject)``; when ``matches`` grew a third parameter the stub started raising
    # TypeError, ``first_match``'s ``except Exception`` logged it as a malformed rule and skipped
    # EVERY rule, and the decision came back "no-match" in 0.6ms. The sleep never ran, so the thing
    # this test exists to measure was not measured — and it failed on the timed_out assertion, which
    # is luck: had the ruleset defaulted to allow-on-no-match with timed_out unset the same way, it
    # would have gone green while testing nothing. A stub that names its target's signature is a
    # second copy of that signature, and copies drift.
    def slow(*a, **kw):
        time.sleep(0.002)
        return real(*a, **kw)

    monkeypatch.setattr(rules_mod, "matches", slow)
    t0 = time.perf_counter()
    d = policy.decide("tool_action", SUBJECT, budget_ms=10.0)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Guard the seam itself: if a refactor stops routing through ``rules.matches`` again, say so
    # here rather than letting the timing assertion pass on a decision that never matched anything.
    assert d.source != "no-match", (
        "the slow matcher was never consulted — rules.matches is no longer the seam, so this "
        "test is measuring nothing")
    assert d.timed_out is True and d.allowed is True
    # Abandoned near the budget, not after all 50 rules (which would be ~100ms).
    assert elapsed_ms < 40.0, f"took {elapsed_ms:.1f}ms — the deadline is not being polled"
