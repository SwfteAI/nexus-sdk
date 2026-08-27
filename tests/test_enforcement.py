"""Enforcement semantics — ``F3-SDK-RUNTIME-CASES.md`` §6, case by case.

Each test names the case it covers in its docstring. The two that matter most, and that would be
the first things a customer's security reviewer reads:

* ``test_deny_lands_before_the_effect`` — a denial recorded after the API call already went out is
  not enforcement, it is journalism. The test asserts on a side-effect list that stays empty, so
  inverting the ordering in ``policy.gate`` is exactly what makes it fail.
* ``test_enforce_marking_is_required_and_sufficient`` and its stale/unavailable variants — the
  fail-open-for-capture / fail-closed-only-for-``enforce`` asymmetry, exercised in both
  directions, because an asymmetry only tested one way is a coin flip that happened to land right.
"""
from __future__ import annotations

import threading
import time

import pytest

from nexus import policy
from nexus.policy import alerts, approval, deputy, ed25519, engine
from nexus.policy import envelope as env_mod
from nexus.policy import rules, settings

SEED = bytes(range(32))
PUB_HEX = ed25519.public_key(SEED).hex()


def sign_envelope(payload: dict, *, seed: bytes = SEED) -> dict:
    """Sign a payload, defaulting the signed ``issued_at`` to now. See ``test_policy.py``."""
    body = {"issued_at": time.time(), **payload}
    return {"policy": body, "signature": ed25519.sign(seed, env_mod.canonical(body)).hex()}


def install_rules(*rule_dicts, issued_at=None, **payload_extra):
    """``issued_at`` is how a test makes an envelope old, and it is *signed*. There is no longer
    any way to age an envelope from outside the signature — that is the whole of the fix."""
    extra = dict(payload_extra)
    if issued_at is not None:
        extra["issued_at"] = issued_at
    raw = sign_envelope({"version": "1", "rules": list(rule_dicts), **extra})
    return engine.install(raw, pubkey_hex=PUB_HEX)


DENY_PROD_WRITES = {"id": "no-prod-writes", "action": "deny", "enforce": True,
                    "reason": "writes to production orders require a change ticket",
                    "match": {"tool": "db.write", "target_glob": "prod-*"}}
ADVISORY_PROD_WRITES = {**DENY_PROD_WRITES, "id": "advisory-prod-writes", "enforce": False}
SUBJECT = {"tool": "db.write", "target": "prod-orders"}


@pytest.fixture(autouse=True)
def _policy_isolation():
    policy.reset_for_tests()
    settings.configure(pubkey_hex=PUB_HEX)
    yield
    policy.reset_for_tests()


# ------------------------------------------------------------------------------------------
# 6.2 — deny works, and works BEFORE the effect
# ------------------------------------------------------------------------------------------

def test_deny_lands_before_the_effect():
    """**Acceptance.** Case 6.2: block *before* the effect.

    This test fails if the ordering inverts. If ``gate`` yielded first and checked afterwards,
    ``effects`` would contain the write and the assertion below would catch it — which is the only
    difference between enforcement and a very well-instrumented incident report.
    """
    install_rules(DENY_PROD_WRITES)
    effects: list[str] = []

    with pytest.raises(policy.Denied) as excinfo:
        with policy.gate("tool_action", SUBJECT):
            effects.append("wrote 4000 rows to prod-orders")

    assert effects == []
    assert excinfo.value.rule_id == "no-prod-writes"
    assert "change ticket" in str(excinfo.value)


def test_check_raises_before_the_next_statement():
    """Case 6.2 via the non-context-manager entry point."""
    install_rules(DENY_PROD_WRITES)
    effects: list[str] = []

    def handler():
        policy.check("tool_action", SUBJECT)
        effects.append("sent")

    with pytest.raises(policy.Denied):
        handler()
    assert effects == []


def test_allowed_gate_runs_the_body_and_yields_the_decision():
    install_rules(DENY_PROD_WRITES)
    effects = []
    with policy.gate("tool_action", {"tool": "db.read", "target": "prod-orders"}) as d:
        effects.append("read")
    assert effects == ["read"]
    assert d.allowed and d.source == "no-match"


# ------------------------------------------------------------------------------------------
# 6.1 — advise mode: evaluate, record the verdict, never block
# ------------------------------------------------------------------------------------------

def test_advise_mode_records_the_verdict_without_blocking():
    """Case 6.1. The shadow deployment: the customer can count what enforcement *would* block."""
    install_rules(ADVISORY_PROD_WRITES)
    effects = []
    with policy.gate("tool_action", SUBJECT) as d:
        effects.append("wrote")

    assert effects == ["wrote"]           # never blocked
    assert d.action == policy.DENY        # …but the verdict is recorded as a deny
    assert d.enforced is False
    assert d.allowed is True
    assert d.rule_id == "advisory-prod-writes"


def test_advise_is_the_default_for_the_legacy_seam():
    """``policy.evaluate`` is WP-5's seam. Installing a policy must not silently start blocking
    traffic at call sites written against a no-op."""
    install_rules(DENY_PROD_WRITES)
    d = policy.evaluate("tool_action", SUBJECT)
    assert d.action == policy.DENY and d.allowed is True


# ------------------------------------------------------------------------------------------
# the asymmetry, in both directions
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rule,should_block", [(DENY_PROD_WRITES, True),
                                               (ADVISORY_PROD_WRITES, False)])
def test_enforce_marking_is_required_and_sufficient(rule, should_block):
    """Case 6.2/6.3: identical rules, identical subject, one flag apart."""
    install_rules(rule)
    d = policy.decide("tool_action", SUBJECT)
    assert d.action == policy.DENY
    assert d.enforced is should_block
    assert d.denied is should_block


def test_a_call_site_can_decline_enforcement_but_cannot_promote_it():
    """The two flags must agree, and only one of them can create a block.

    A call site that could promote an unmarked rule would make ``enforce``-marked meaningless, and
    the fail-closed half of 6.3 would collapse with it.
    """
    install_rules(DENY_PROD_WRITES)
    assert policy.decide("tool_action", SUBJECT, enforce=False).denied is False   # declined

    install_rules(ADVISORY_PROD_WRITES)
    assert policy.decide("tool_action", SUBJECT, enforce=True).denied is False    # not promoted


def test_operator_kill_switch_downgrades_enforcement_to_advice(monkeypatch):
    """``NEXUS_POLICY_ENABLED=0``: stop denying, keep recording. An operator disarming
    enforcement mid-incident still wants to know what would have been blocked."""
    install_rules(DENY_PROD_WRITES)
    monkeypatch.setenv("NEXUS_POLICY_ENABLED", "0")
    d = policy.decide("tool_action", SUBJECT)
    assert d.action == policy.DENY and d.enforced is False


# ------------------------------------------------------------------------------------------
# 6.3 — policy unavailable
# ------------------------------------------------------------------------------------------

def test_no_policy_at_all_fails_open():
    """Case 6.3: a policy fetch failure must never silently start denying."""
    d = policy.decide("tool_action", SUBJECT)
    assert d.allowed and d.source == "no-policy"
    assert alerts.NO_POLICY in alerts.kinds()


def test_unreachable_control_plane_keeps_the_last_good_policy():
    """Case 6.3, fail-closed half: a blip must not disarm every enforcing rule in the fleet."""
    install_rules(DENY_PROD_WRITES)

    def broken_fetch():
        raise ConnectionError("control plane unreachable")

    assert engine.refresh(broken_fetch, pubkey_hex=PUB_HEX) is False
    assert alerts.UNREACHABLE in alerts.kinds()
    assert policy.decide("tool_action", SUBJECT).denied is True     # still enforcing


def test_a_fetch_returning_nothing_is_also_not_a_disarm():
    install_rules(DENY_PROD_WRITES)
    assert engine.refresh(lambda: None, pubkey_hex=PUB_HEX) is False
    assert policy.decide("tool_action", SUBJECT).denied is True


def test_cache_miss_allows():
    """Case 6.3: an empty snapshot — first start, envelope never delivered — allows."""
    engine.reset_for_tests()
    assert engine.snapshot().present is False
    assert policy.decide("tool_action", SUBJECT).allowed is True


# ------------------------------------------------------------------------------------------
# 6.5 — invalid signature
# ------------------------------------------------------------------------------------------

def test_invalid_signature_is_treated_as_no_policy_and_alerts():
    """Case 6.5. A key-rotation mistake must degrade to unenforced, not to a fleet-wide outage —
    and must be loud, or enforcement silently becomes advice and nobody finds out until the
    incident report."""
    good = sign_envelope({"rules": [DENY_PROD_WRITES]})
    engine.install({**good, "signature": "11" * 64}, pubkey_hex=PUB_HEX)

    d = policy.decide("tool_action", SUBJECT)
    assert d.allowed is True and d.source == "no-policy"
    assert alerts.BAD_SIGNATURE in alerts.kinds()


def test_a_tampered_envelope_cannot_strip_the_enforce_marking():
    """The attack the signature exists to stop: edit ``enforce`` to false in the file we hold."""
    payload = {"rules": [DENY_PROD_WRITES]}
    signed = sign_envelope(payload)
    tampered = {**signed, "policy": {"rules": [{**DENY_PROD_WRITES, "enforce": False}]}}
    engine.install(tampered, pubkey_hex=PUB_HEX)
    # Not honoured in either direction — the whole envelope is untrusted, not partially applied.
    assert engine.snapshot().present is False
    assert alerts.BAD_SIGNATURE in alerts.kinds()


# ------------------------------------------------------------------------------------------
# 6.6 — stale / expired envelope
# ------------------------------------------------------------------------------------------

def test_a_stale_enforcing_deny_never_decays():
    """Case 6.6. If it decayed, disconnecting the pod from the control plane would be the
    documented bypass for every control we sell."""
    old = time.time() - settings.current().hard_stale_s - 100
    install_rules(DENY_PROD_WRITES, issued_at=old)
    d = policy.decide("tool_action", SUBJECT)
    assert d.denied is True and d.stale is True


def test_a_stale_unmarked_rule_degrades_to_advice():
    """Case 6.6, the other half: an advisory rule from a year-old envelope is advice, not law."""
    old = time.time() - settings.current().hard_stale_s - 100
    install_rules(ADVISORY_PROD_WRITES, issued_at=old)
    d = policy.decide("tool_action", SUBJECT)
    assert d.allowed is True and d.stale is True and d.source == "stale-advisory"
    assert d.action == policy.DENY          # the verdict is still recorded


def test_an_expired_envelope_still_enforces_marked_rules():
    now = time.time()
    install_rules(DENY_PROD_WRITES, issued_at=now, expires_at=now - 1)
    assert policy.decide("tool_action", SUBJECT).denied is True
    assert alerts.EXPIRED in alerts.kinds()


# ------------------------------------------------------------------------------------------
# malformed rules
# ------------------------------------------------------------------------------------------

def test_a_malformed_rule_does_not_disarm_the_rules_around_it():
    install_rules({"id": "broken", "action": "explode"}, DENY_PROD_WRITES)
    assert policy.decide("tool_action", SUBJECT).denied is True
    assert engine.snapshot().ruleset.quarantined          # named, not merely counted
    assert alerts.MALFORMED_RULE in alerts.kinds()


def test_a_quarantined_enforcing_rule_is_an_enforcement_gap_that_is_reported():
    """The honest cost of quarantining rather than rejecting the envelope."""
    install_rules({"id": "no-prod-writes", "action": "deny", "enforce": True,
                   "match": {"targt_glob": "prod-*"}})       # typo'd clause
    assert policy.decide("tool_action", SUBJECT).allowed is True   # the gap is real
    assert alerts.MALFORMED_RULE in alerts.kinds()                 # …and it is visible


# ------------------------------------------------------------------------------------------
# 4.7 / never raise into the host
# ------------------------------------------------------------------------------------------

def test_a_bug_in_policy_degrades_to_allow_plus_alert(monkeypatch):
    """Case 4.7 applied to the one synchronous path. A policy bug must never be a 500."""
    install_rules(DENY_PROD_WRITES)
    monkeypatch.setattr(rules, "first_match",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    d = policy.decide("tool_action", SUBJECT)
    assert d.allowed is True and d.source == "error"
    assert alerts.INTERNAL_ERROR in alerts.kinds()


def test_decide_never_raises_on_hostile_subjects():
    install_rules(DENY_PROD_WRITES, {"id": "any", "action": "deny", "enforce": True,
                                     "match": {"target_contains": "x"}})
    for subject in [{}, {"tool": None}, {"target": object()}, {"tool": ["a", "b"]},
                    {"target": "\udcff lone surrogate"}, {"risk": 12}]:
        assert policy.decide("tool_action", subject) is not None


def test_denied_is_the_only_exception_that_escapes():
    install_rules(DENY_PROD_WRITES)
    with pytest.raises(policy.Denied):
        policy.check("tool_action", SUBJECT)
    # …and it is catchable as itself, with an explanation the developer can act on.
    try:
        policy.check("tool_action", SUBJECT)
    except policy.Denied as exc:
        assert exc.rule_id and exc.reason


# ------------------------------------------------------------------------------------------
# 6.8 — human approval in production
# ------------------------------------------------------------------------------------------

APPROVAL_RULE = {"id": "prod-refund", "action": "require_approval", "enforce": True,
                 "reason": "refunds over 1000 need a human",
                 "approval": {"timeout_s": 0.5},
                 "match": {"tool": "refund"}}
REFUND = {"tool": "refund", "target": "cust-9"}


def _approver(answer, *, delay=0.0):
    """A background approver that answers the first pending card."""
    approval.register_approver("test", lambda: True)

    def run():
        deadline = time.time() + 3.0
        while time.time() < deadline:
            cards = approval.pending()
            if cards:
                time.sleep(delay)
                approval.resolve(cards[0].id, answer, actor="reviewer@example.com")
                return
            time.sleep(0.005)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th


def test_approval_granted_allows():
    """Case 6.8, happy path."""
    install_rules(APPROVAL_RULE)
    _approver(approval.GRANTED)
    d = policy.decide("tool_action", REFUND)
    assert d.allowed is True and d.approval == approval.GRANTED
    assert d.approver == "reviewer@example.com"


def test_approval_declined_denies():
    install_rules(APPROVAL_RULE)
    _approver(approval.DENIED)
    d = policy.decide("tool_action", REFUND)
    assert d.denied is True and d.approval == approval.DENIED


def test_approval_times_out_and_an_enforcing_rule_denies():
    """Case 6.8: there is no such thing as an approval that waits forever in a request path."""
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 0.15}})
    approval.register_approver("asleep", lambda: True)      # live, but never answers

    t0 = time.perf_counter()
    d = policy.decide("tool_action", REFUND)
    waited = time.perf_counter() - t0

    assert d.denied is True and d.approval == approval.TIMEOUT
    assert 0.15 <= waited < 1.0                             # bounded, and actually waited
    assert "no answer within" in (d.reason or "")
    assert alerts.APPROVAL_TIMEOUT in alerts.kinds()


def test_approval_times_out_and_an_advisory_rule_allows():
    """A silent reviewer must not turn an advisory rule into an outage."""
    install_rules({**APPROVAL_RULE, "enforce": False, "approval": {"timeout_s": 0.1}})
    approval.register_approver("asleep", lambda: True)
    d = policy.decide("tool_action", REFUND)
    assert d.allowed is True and d.approval == approval.TIMEOUT


def test_no_live_approver_does_not_wait_at_all():
    """``DEPUTY.md``: a gate is only armed when someone can actually answer it. Arming it for an
    approver that does not exist makes every gated call sit out its full budget first."""
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 5.0}})
    t0 = time.perf_counter()
    d = policy.decide("tool_action", REFUND)
    assert time.perf_counter() - t0 < 0.5           # not five seconds
    assert d.denied is True and d.approval == approval.NO_APPROVER
    assert "no approver was available" in (d.reason or "")


def test_a_dead_approver_disarms_the_gate_within_one_decision():
    """"Live" means a recent heartbeat, not a config flag."""
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 5.0}})
    alive = {"v": True}
    approval.register_approver("deputy", lambda: alive["v"])
    alive["v"] = False
    t0 = time.perf_counter()
    assert policy.decide("tool_action", REFUND).approval == approval.NO_APPROVER
    assert time.perf_counter() - t0 < 0.5


def test_an_approval_timeout_is_mandatory_by_signature():
    """The mechanism for "mandatory", per ``DECISIONS.md``: not a check in the body that a future
    caller could route around, but the fact that there is no way to call this without a bound."""
    import inspect
    sig = inspect.signature(approval.request)
    assert sig.parameters["timeout_s"].default is inspect.Parameter.empty
    assert sig.parameters["timeout_s"].kind is inspect.Parameter.KEYWORD_ONLY


def test_a_rule_cannot_ask_for_an_unbounded_wait():
    """A rule asking for an hour in a checkout path is an outage with a JSON file in front of it."""
    settings.configure(approval_timeout_max_s=0.2)
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 3600}})
    approval.register_approver("asleep", lambda: True)
    t0 = time.perf_counter()
    d = policy.decide("tool_action", REFUND)
    assert time.perf_counter() - t0 < 1.0
    assert d.approval == approval.TIMEOUT
    assert alerts.TIMEOUT_CLAMPED in alerts.kinds()


def test_a_late_answer_loses():
    """Whoever answers first wins; past the timeout, the timeout has answered."""
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 0.1}})
    approval.register_approver("slow", lambda: True)
    d = policy.decide("tool_action", REFUND)
    assert d.approval == approval.TIMEOUT
    assert approval.pending() == []                 # the card is closed, not left dangling


def test_resolve_reports_but_cannot_originate():
    """``DEPUTY.md``: the resolve endpoint reports a decision the host already took. A stolen key
    can close cards it should not have, visibly — it cannot unblock a call nobody is holding."""
    assert approval.resolve("no-such-card", approval.GRANTED) is False
    assert approval.resolve("no-such-card", "allow-everything") is False


# ------------------------------------------------------------------------------------------
# 6.7 — deputy delegated approval
# ------------------------------------------------------------------------------------------

#: ``DEPUTY.md``'s worked example, with one deliberate change: the ``never-read-secrets`` deny is
#: moved to the front. First matching rule wins, so in the document's own ordering — deny last —
#: a ``Read`` of ``/app/.env`` is allowed by ``read-only-tools`` before the deny is ever reached.
#: See ``test_an_earlier_allow_shadows_a_later_deny``. The document's example is reported upstream
#: as a bug in the example rather than papered over here by changing the precedence rule.
DEPUTY_DOC = {
    "version": "1",
    "default": "escalate",
    "rules": [
        {"id": "never-read-secrets", "action": "deny", "reason": "no agent needs the raw env file",
         "match": {"target_contains": ".env"}},
        {"id": "read-only-tools", "action": "allow", "reason": "reading has no side effect",
         "match": {"tool": ["Read", "Grep", "Glob"]}},
        {"id": "test-suites", "action": "allow", "reason": "tests have no external effect",
         "match": {"command_glob": "pnpm test*", "repos": ["checkout-*"], "max_risk": "medium"}},
        {"id": "feature-branch-pushes", "action": "allow", "reason": "reversible",
         "match": {"command_glob": "git push*", "branch_not": ["main", "master"]}},
    ],
}


def _deputy(card, doc=DEPUTY_DOC, **kw):
    ruleset, default = deputy.parse_rules(doc)
    return deputy.decide(card, ruleset, default=default, **kw)


def test_deputy_allows_only_what_it_was_told_it_may_allow():
    v = _deputy({"tool": "Read", "target": "src/app.py"})
    assert v.action == deputy.ALLOW and v.rule_id == "read-only-tools"
    assert v.actor == "deputy:read-only-tools"      # never a bare actor


def test_deputy_denies_what_the_policy_denies():
    v = _deputy({"tool": "Read", "target": "/app/.env"})
    assert v.action == deputy.DENY and v.rule_id == "never-read-secrets"


#: The two rules of the shadowing pair, written once so the two tests below cannot drift into
#: testing different things — which is the failure mode that makes a matched pair worthless.
_SHADOW_ALLOW = {"id": "read-only-tools", "action": "allow", "match": {"tool": ["Read"]}}
_SHADOW_DENY = {"id": "never-read-secrets", "action": "deny",
                "match": {"target_contains": ".env"}}
_SHADOW_CARD = {"tool": "Read", "target": "/app/.env"}


def test_an_earlier_allow_shadows_a_later_deny():
    """First matching rule wins, so ordering is load-bearing and a deny placed after a broad
    allow never runs.

    Asserted rather than fixed: changing precedence so denies always win would diverge from
    ``DEPUTY.md``'s stated rule and from every rules file already written against it. Precedence
    is a published semantic, not something to change inside a security fix.

    Read with the two below it, not alone. On its own this says "denies lose", which is not the
    decision and would fight anyone who later tries to make denies win for good reasons. Together
    they say *ordering decides* — same card, same two rules, opposite order, opposite answer —
    which is the semantic that was actually chosen. If precedence is ever revisited, all three
    fail, and their docstrings explain what the choice was.

    The hazard is documented where the rules are authored rather than detected here:
    ``nexus-devtools/docs/DEPUTY.md`` puts ``never-read-secrets`` first in its worked example and
    says why ("behind ``read-only-tools`` it would never get a turn, and ``Read /app/.env`` would
    succeed"). That file ships from another repository, so this suite cannot assert on it. Making
    the parser *detect* an unreachable rule is the obvious follow-up and is deliberately not done
    here: soundly deciding that an earlier allow shadows a later deny means deciding overlap
    between two glob-and-list match clauses, and the conservative version — warn unless provably
    disjoint — fires on ordinary files that are not wrong. That is a design decision with its own
    review, not a line to slip into a fix.
    """
    shadowed = {"default": "escalate", "rules": [_SHADOW_ALLOW, _SHADOW_DENY]}
    assert _deputy(_SHADOW_CARD, doc=shadowed).action == deputy.ALLOW


def test_the_same_deny_placed_first_does_fire():
    """The other half. Ordering is the operator's lever, and this proves the lever works.

    Without it the suite pins only the permissive outcome, and a reader cannot tell a deliberate
    precedence rule from a hole nobody noticed. This is also the ordering the shipped example
    uses, so what is asserted here is what a customer copying the documentation actually gets.
    """
    correct = {"default": "escalate", "rules": [_SHADOW_DENY, _SHADOW_ALLOW]}
    v = _deputy(_SHADOW_CARD, doc=correct)
    assert v.action == deputy.DENY
    assert v.rule_id == "never-read-secrets"


def test_shadowing_is_about_order_alone_and_nothing_else():
    """Guards the pair against a fix that special-cases ``.env`` instead of honouring order.

    A tempting way to "fix" the shadowed case is to teach the engine that secrets always lose —
    which quietly replaces an ordering rule with a hardcoded list of things that are extra-denied.
    Here the deny is about an ordinary target with nothing security-flavoured in it, so only
    precedence can explain the answers.

    Mutation-wise this is the load-bearing one of the three. Against four mutants of `first_match`
    — denies-always-win, a hardcoded ``.env`` deny, allows-always-win, last-match-wins — it catches
    all four; the two above catch three and two respectively and add nothing it does not already
    cover. They are kept anyway, because they name the cases a reader arrives looking for: the
    shadowed example, and the ordering the shipped ``DEPUTY.md`` actually uses.
    Redundancy in a precedence suite costs a millisecond; a reader who cannot find the case they
    came for costs more.
    """
    allow = {"id": "reads", "action": "allow", "match": {"tool": ["Read"]}}
    deny = {"id": "not-the-archive", "action": "deny", "match": {"target_contains": "archive"}}
    card = {"tool": "Read", "target": "/srv/archive/report.txt"}
    assert _deputy(card, doc={"default": "escalate",
                              "rules": [allow, deny]}).action == deputy.ALLOW
    assert _deputy(card, doc={"default": "escalate",
                              "rules": [deny, allow]}).action == deputy.DENY


def test_a_widened_default_is_neutralised_but_explicit_rules_still_apply():
    """``DEPUTY.md``: ``"default": "allow"`` is ignored and forced back to escalate. It narrows
    nothing else — a rules file can only ever narrow authority, and neutralising the whole file
    over one bad key would be a different behaviour than the document promises."""
    widened = {**DEPUTY_DOC, "default": "allow"}
    assert _deputy({"tool": "Terraform", "target": "vpc"}, doc=widened).action == deputy.ESCALATE
    assert _deputy({"tool": "Read", "target": "a"}, doc=widened).action == deputy.ALLOW
    assert alerts.MALFORMED_RULE in alerts.kinds()


@pytest.mark.parametrize("card,doc,why", [
    ({"tool": "Read", "target": "a"}, None, "no rules file"),
    ({"tool": "Read", "target": "a"}, "corrupt", "corrupt rules file"),
    ({"tool": "Bash", "target": "x", "command": "terraform destroy"}, DEPUTY_DOC, "no match"),
    ({"tool": "", "target": "a"}, DEPUTY_DOC, "card lacks tool"),
    ({"tool": "Read", "target": ""}, DEPUTY_DOC, "card lacks target"),
    ({"tool": "Bash", "target": "repo", "command": "", "repo": "checkout-api"},
     DEPUTY_DOC, "empty command"),
    ({"tool": "Bash", "target": "repo", "command": "git push origin feat"},
     DEPUTY_DOC, "branch unknown"),
    ({"tool": "Bash", "target": "repo", "command": "pnpm test", "repo": "checkout-api"},
     DEPUTY_DOC, "risk unknown"),
])
def test_deputy_escalates_on_every_ambiguity(card, doc, why):
    """``DEPUTY.md``'s table, row for row. There is no path from "I don't know" to "allow"."""
    v = _deputy(card, doc=doc) if doc != "corrupt" else _deputy(card, doc={"rules": "nope"})
    assert v.action == deputy.ESCALATE, why


def test_deputy_escalates_when_evaluation_raises(monkeypatch):
    monkeypatch.setattr(deputy.rules_mod, "first_match",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _deputy({"tool": "Read", "target": "a"}).action == deputy.ESCALATE


def test_destructive_is_checked_on_the_card_not_the_rule():
    """``DEPUTY.md``'s smuggling route: a harmless-looking rule and a payload behind ``&&``.

    **The payload deliberately contains no ``/``, and that is the whole test.** This assertion
    used to smuggle ``rm -rf /``, and it passed right up until ``_glob_strict`` landed — at which
    point ``*`` stopped crossing ``/``, the allow rule stopped matching that command at all, and
    the escalation came from the ``default`` instead of from the card check. Same verdict, and the
    test still went green, while the property in its own name had quietly stopped being exercised:
    ``rule_id`` was ``None`` and the reason was "no rule matched".

    So the smuggled command has to be one the allow rule genuinely matches, or this proves nothing
    about cards. ``rule_id == "status"`` is the load-bearing half of the assertion — it is what
    distinguishes "the card was inspected and overrode a matching allow" from "nothing matched and
    the default caught it". The slash case is kept below as its own assertion, because glob
    strictness stopping it earlier is a second barrier worth pinning, not a replacement for this
    one.
    """
    doc = {"default": "escalate", "rules": [
        {"id": "status", "action": "allow", "match": {"command_glob": "git status*"}}]}
    assert _deputy({"tool": "Bash", "target": "repo", "command": "git status"},
                   doc=doc).action == deputy.ALLOW

    # The rule MATCHES this one, so only the card check can stop it.
    v = _deputy({"tool": "Bash", "target": "repo", "command": "git status && rm -rf tmpdir"},
                doc=doc)
    assert v.action == deputy.ESCALATE and v.rule_id == "status"

    # ...and again behind ``;`` rather than ``&&``, so the check is not one separator's worth deep.
    v = _deputy({"tool": "Bash", "target": "repo", "command": "git status; shutdown now"}, doc=doc)
    assert v.action == deputy.ESCALATE and v.rule_id == "status"

    # Second barrier: a payload carrying ``/`` never reaches the card, because ``*`` will not
    # cross a path separator. Escalates via ``default`` — hence ``rule_id is None``.
    v = _deputy({"tool": "Bash", "target": "repo", "command": "git status && rm -rf /"}, doc=doc)
    assert v.action == deputy.ESCALATE and v.rule_id is None


def test_a_deny_rule_still_denies_a_destructive_card():
    """Denying dangerous things is the whole point; ``deny`` carries no such restriction."""
    doc = {"default": "escalate", "rules": [
        {"id": "no-bash", "action": "deny", "match": {"tool": "Bash"}}]}
    assert _deputy({"tool": "Bash", "target": "x", "command": "rm -rf /"},
                   doc=doc).action == deputy.DENY


def test_deputy_hourly_budget_turns_a_firehose_into_a_queue():
    budget = deputy.Budget(max_per_hour=2)
    card = {"tool": "Read", "target": "a"}
    assert [_deputy(card, budget=budget).action for _ in range(4)] == \
        [deputy.ALLOW, deputy.ALLOW, deputy.ESCALATE, deputy.ESCALATE]


def test_a_zero_budget_delegates_nothing():
    assert _deputy({"tool": "Read", "target": "a"},
                   budget=deputy.Budget(max_per_hour=0)).action == deputy.ESCALATE


def test_an_unwritable_audit_record_means_the_decision_does_not_happen():
    """``DEPUTY.md``: doing it and recording it are the same step, in the wrong order to skip."""
    def broken_audit(_verdict):
        raise OSError("ledger is read-only")

    v = _deputy({"tool": "Read", "target": "a"}, audit=broken_audit)
    assert v.action == deputy.ESCALATE and "audit" in v.reason


def test_the_audit_record_is_written_before_the_decision_is_returned():
    written = []
    v = _deputy({"tool": "Read", "target": "a"}, audit=written.append)
    assert written and written[0].action == deputy.ALLOW and v.action == deputy.ALLOW


def test_deputy_answers_a_pending_card_and_the_first_answer_wins():
    """The deputy is a second answerer for the same gate a human watches."""
    install_rules({**APPROVAL_RULE, "approval": {"timeout_s": 2.0}})
    approval.register_approver("deputy", lambda: True)

    def daemon():
        deadline = time.time() + 2.0
        while time.time() < deadline:
            for card in approval.pending():
                v = _deputy({"tool": card.tool, "target": card.target},
                            doc={"default": "escalate", "rules": [
                                {"id": "refunds", "action": "allow",
                                 "match": {"tool": "refund"}}]})
                if v.action == deputy.ALLOW:
                    approval.resolve(card.id, approval.GRANTED, actor=v.actor)
                return
            time.sleep(0.005)

    threading.Thread(target=daemon, daemon=True).start()
    d = policy.decide("tool_action", REFUND)
    assert d.allowed is True and d.approver == "deputy:refunds"
