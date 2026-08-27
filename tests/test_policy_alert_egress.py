"""``policy_alert`` is an egress channel, and this file is the wire observation of it.

Two properties, both asserted against a **real HTTP collector** rather than against
``client.transport._q``. An assertion on an internal queue proves what the SDK intended to send;
only the collector proves what it sent. An earlier proof of this same finding read the queue
and had to be redone, so the wire is the standard here.

**The fixture trap, stated once because it has now cost three agents a wrong result.** A policy
fixture needs *both* an ed25519-signed envelope *and* ``NEXUS_POLICY_PUBKEY``. With either one
missing, ``envelope.verify()`` returns ``(None, "envelope is unsigned")``, every path fail-opens to
``source="no-policy"``, no rule set is ever parsed, no ``MALFORMED_RULE`` is ever raised, and the
collector sees nothing — which reads exactly like the code being safe. Every test below therefore
asserts the policy is *installed* before it asserts anything about what leaked. If you see
``source="no-policy"`` here, the fixture is wrong, not the code.
"""
from __future__ import annotations

import json
import time

import pytest

import nexus
from nexus import policy
from nexus.policy import ed25519, engine
from nexus.policy import envelope as env_mod

SEED = bytes(range(32))
PUB_HEX = ed25519.public_key(SEED).hex()

#: Regulated data an administrator put inside a rule ID. Not hypothetical: this exact shape is
#: what was observed on the wire (``acct-4111111111111111``).
CARD = "4111111111111111"
LEAKY_RULE_ID = "acme-block-acct-" + CARD


def sign_envelope(payload: dict, *, seed: bytes = SEED) -> dict:
    body = {"issued_at": time.time(), **payload}
    return {"policy": body, "signature": ed25519.sign(seed, env_mod.canonical(body)).hex()}


def install_signed(*rule_dicts) -> engine.Snapshot:
    """Install a genuinely signed, genuinely verified policy — and prove it verified."""
    raw = sign_envelope({"version": "1", "rules": list(rule_dicts)})
    snap = policy.install(raw, pubkey_hex=PUB_HEX)
    assert snap.present, (
        "fixture is broken, not the code: the envelope did not verify, so this test would be "
        f"measuring the absence of policy. problem={snap.env.problem!r}")
    return snap


def alert_events(collector) -> "list[dict]":
    return collector.of_type("policy_alert")


def wire_strings(event: dict) -> "list[str]":
    """Every string that actually crossed the wire in this event, keys included."""
    out: list[str] = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                out.append(str(k))
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
    walk(event)
    return out


@pytest.fixture
def wired(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_POLICY_PUBKEY", PUB_HEX)
    nexus.init(service="svc", env="test", version="1")      # default tier: metadata_only
    try:
        yield collector
    finally:
        try:
            nexus.shutdown()
        except Exception:  # noqa: BLE001
            pass


@pytest.fixture
def wired_at_tier(collector, monkeypatch):
    def _go(tier: str):
        monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
        monkeypatch.setenv("NEXUS_POLICY_PUBKEY", PUB_HEX)
        nexus.init(service="svc", env="test", version="1", tier=tier)
        return collector
    try:
        yield _go
    finally:
        try:
            nexus.shutdown()
        except Exception:  # noqa: BLE001
            pass


# ----------------------------------------------------------------------------------------------
# Half one: ``detail``
# ----------------------------------------------------------------------------------------------

def test_a_rule_id_does_not_reach_the_collector_at_the_default_tier(wired):
    """A malformed rule whose *ID* carries regulated data must not put that ID on the wire.

    ``rules._parse_one`` builds ``"rule 'acme-block-acct-4111111111111111' has unknown action
    None"`` and ``alerts._emit_event`` routes it into ``contract.base`` as ``detail``.
    ``contract.base`` never reads ``cfg.tier``, so at ``metadata_only`` — the default — the string
    egresses ungated and unredacted.
    """
    install_signed({"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}})
    nexus.flush()
    assert wired.wait_for(1, timeout=5.0), "no events reached the collector at all"

    alerts_on_wire = alert_events(wired)
    assert alerts_on_wire, "no policy_alert reached the collector — check the fixture, not the code"

    blob = json.dumps(alerts_on_wire)
    assert CARD not in blob, f"card number egressed at metadata_only: {blob}"
    assert LEAKY_RULE_ID not in blob, f"rule id egressed at metadata_only: {blob}"


def test_the_operator_can_still_tell_which_rule_was_malformed(wired):
    """Suppressing the ID is only acceptable if the alert stays useful.

    The rule's *ordinal position in the signed document* identifies it exactly, and reproduces
    none of its text. The operator holds the document they signed; index N resolves against it.
    """
    install_signed(
        {"id": "fine", "action": "allow", "match": {"tool": "db.read"}},
        {"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}},
    )
    nexus.flush()
    assert wired.wait_for(1, timeout=5.0)

    malformed = [e for e in alert_events(wired) if e.get("alert_kind") == "policy.malformed_rule"]
    assert malformed, "the malformed-rule alert never reached the wire"
    assert any(e.get("rule_index") == 1 for e in malformed), (
        f"no alert names the offending rule's position: {malformed}")


def test_the_detail_survives_in_process_even_though_it_never_ships(wired):
    """The ring buffer is not the wire. ``nexus doctor`` and the test suite read the whole detail;
    the collector does not. Reducing the wire must not blind the operator on the host."""
    install_signed({"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}})
    local = policy.alerts.find(policy.alerts.MALFORMED_RULE)
    assert local is not None
    assert LEAKY_RULE_ID in local.detail, (
        "the in-process alert must keep the full detail; only egress is reduced")


# ----------------------------------------------------------------------------------------------
# Half two: the ``**alert.context`` spread — no length bound at all
# ----------------------------------------------------------------------------------------------

def test_context_strings_are_not_splatted_onto_the_wire_unbounded(wired, slow_evaluation):
    """``**{k: v for k, v in alert.context.items() if isinstance(v, (int, float, bool, str))}``.

    Reached end to end: ``engine._decide`` raises ``BUDGET_EXCEEDED`` with
    ``subject_kind=str(kind)``, and ``kind`` is the caller's own first argument to
    ``policy.decide``. Unlike ``detail`` it is not even truncated, so an arbitrarily large
    caller-derived string becomes a wire field.

    The budget path is reached with a slow evaluation rather than ``budget_ms=0.0``: there is now a
    floor under the caller's budget, so nominating zero no longer produces a timeout. The
    ``source`` assertion below already guarded against measuring nothing, and would have caught
    the change on its own.
    """
    install_signed({"id": "r1", "action": "allow", "match": {"tool": "db.read"}})
    huge = "patient-jane-doe@hospital.example-" + ("A" * 8000)
    slow_evaluation.engage()
    d = policy.decide(huge, {"tool": "db.read"})
    assert d.source == "budget-exceeded", (
        f"the budget path did not fire, so nothing is being measured: source={d.source!r}")

    nexus.flush()
    assert wired.wait_for(1, timeout=5.0)
    budget_alerts = [e for e in alert_events(wired)
                     if e.get("alert_kind") == "policy.budget_exceeded"]
    assert budget_alerts, "the budget-exceeded alert never reached the wire"

    for e in budget_alerts:
        for s in wire_strings(e):
            assert "hospital.example" not in s, f"context string egressed verbatim: {s[:120]!r}"
            assert len(s) <= 512, (
                f"an unbounded context string reached the wire: {len(s)} chars, {s[:120]!r}")


def test_unknown_context_keys_are_counted_rather_than_forwarded(wired):
    """A context key nobody vetted must not mint a wire field. Dropping it silently would make a
    suppression indistinguishable from an attribute that was never there, so it is counted."""
    install_signed({"id": "r1", "action": "allow", "match": {"tool": "db.read"}})
    policy.alerts.raise_alert(
        policy.alerts.INTERNAL_ERROR, "something went wrong",
        patient_name="Jane Doe", account="acct-" + CARD, rows=7)
    nexus.flush()
    assert wired.wait_for(1, timeout=5.0)

    hits = [e for e in alert_events(wired) if e.get("alert_kind") == "policy.internal_error"]
    assert hits, "the alert never reached the wire"
    blob = json.dumps(hits)
    assert "Jane Doe" not in blob and CARD not in blob, blob
    assert "patient_name" not in blob and "account" not in blob, (
        f"an unvetted context key became a wire field: {blob}")
    assert any(e.get("context_omitted") for e in hits), (
        f"suppressed context must be visible as a count: {hits}")


# ----------------------------------------------------------------------------------------------
# The ladder — the tier has to mean something in both directions
# ----------------------------------------------------------------------------------------------

def test_the_shape_survives_the_default_tier(wired):
    """T0 must not be a blank. ``detail_chars`` keeps "the same alert as yesterday" answerable
    without the text leaving the process — the same contract ``redact_preview`` already emits."""
    install_signed({"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}})
    nexus.flush()
    assert wired.wait_for(1, timeout=5.0)
    e = [x for x in alert_events(wired) if x.get("rule_index") == 0][0]
    assert "detail" not in e and "detail_preview" not in e
    assert e["detail_chars"] > 0
    assert e["alert_kind"] == "policy.malformed_rule"
    assert "detail_fingerprint" not in e, (
        "an alert detail is a known template plus a short variable part; its digest is recovered "
        "by trying every value, so a fingerprint here is a correlation handle over content")


def test_a_customer_who_asks_for_content_gets_it(wired_at_tier):
    """T2 is documented as emitting the text, and a customer choosing it has made that decision.
    The alert ladder must not invent a fourth answer for itself — one caller quietly doing
    something different from the shared ladder is how that leak happened in the first place.

    The content still goes through ``redact()`` on the way, and the ``detail_redacted`` flag says
    whether anything matched. It says ``False`` for this input, which is worth knowing and is why
    T0 suppresses rather than relies on scanning: ``redact()`` masks ``card 4111111111111111`` but
    **not** ``acct-4111111111111111`` — a hyphen immediately before the digits defeats the card
    and national-ID patterns. That is a ``redact.py`` gap,
    not something this file can fix, and it is exactly the shape a rule ID takes.
    """
    c = wired_at_tier("full")
    install_signed({"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}})
    nexus.flush()
    assert c.wait_for(1, timeout=5.0)
    e = [x for x in alert_events(c) if x.get("rule_index") == 0][0]
    assert "unknown action" in e["detail"], e
    assert "detail_redacted" in e, "the redactor must run even at full"
    assert e["detail_chars"] > 0


def test_the_default_tier_is_the_one_that_protects_this(wired_at_tier):
    """The corollary of the test above, stated as an assertion rather than left implied: what
    keeps the unredactable rule ID off the wire is the *tier*, not the scanner."""
    c = wired_at_tier("metadata_only")
    install_signed({"id": LEAKY_RULE_ID, "action": "obliterate", "match": {"tool": "db.write"}})
    nexus.flush()
    assert c.wait_for(1, timeout=5.0)
    assert CARD not in json.dumps(alert_events(c))
