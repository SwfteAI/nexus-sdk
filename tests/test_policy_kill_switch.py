"""``NEXUS_ENABLED=0`` is documented as the emergency brake. This file asks whether it stops the
one path that can raise into a customer's request.

The asymmetry below is what makes this worth its own file. With
``NEXUS_ENABLED=0`` set, ``__init__.py`` returns early, so no SIGTERM handler is installed and the
``nexus.agent()`` / ``run.action()`` route is genuinely inert — the brake stops everything a reader
can *see* it stopping. But ``policy.gate`` / ``policy.check`` / ``policy.init`` are advertised
directly by ``policy/__init__.py``, and ``settings.current()`` consulted only
``NEXUS_POLICY_ENABLED``. So the brake stopped the half that only loses telemetry and left live the
half that raises ``Denied`` into a request.

``settings.enforcement_enabled`` and ``nexus.enabled()`` must not disagree. Two switches that both
claim to be "off" while one of them is on is worse than one switch.

Fixture note, same as ``test_policy_alert_egress.py``: a policy fixture needs an ed25519-signed
envelope **and** ``NEXUS_POLICY_PUBKEY``. Without both, everything fail-opens to
``source="no-policy"`` and this file would be measuring the absence of policy rather than a
disarmed one. Every test asserts the policy installed first.
"""
from __future__ import annotations

import time

import pytest

import nexus
from nexus import policy
from nexus.policy import ed25519, settings
from nexus.policy import envelope as env_mod

SEED = bytes(range(32))
PUB_HEX = ed25519.public_key(SEED).hex()

#: An ``enforce``-marked deny. Only a marked rule can produce a real denial, so this is the
#: smallest policy that can raise into a request path.
DENY_RULE = {"id": "no-prod-writes", "action": "deny", "enforce": True,
             "match": {"tool": "db.write"}}


def install_deny() -> None:
    body = {"issued_at": time.time(), "version": "1", "rules": [DENY_RULE]}
    raw = {"policy": body, "signature": ed25519.sign(SEED, env_mod.canonical(body)).hex()}
    snap = policy.install(raw, pubkey_hex=PUB_HEX)
    assert snap.present, (
        "fixture is broken, not the code: the envelope did not verify, so every path below would "
        f"fail open to source='no-policy'. problem={snap.env.problem!r}")


def test_the_global_kill_switch_disarms_the_direct_policy_api(monkeypatch):
    """``NEXUS_ENABLED=0`` plus ``policy.gate`` must not raise ``Denied`` into the request path.

    This is the exposure: a customer pulling the documented emergency brake, then calling the API
    ``policy/__init__.py`` advertises. ``nexus.init()`` is deliberately *not* called here — with the
    kill switch set it returns early, and the point of the test is the path that does not go
    through it.
    """
    monkeypatch.setenv("NEXUS_POLICY_PUBKEY", PUB_HEX)
    install_deny()

    # Armed: the rule really does deny, so the assertion below is about the switch, not about a
    # policy that was never going to fire.
    assert policy.decide("tool_action", {"tool": "db.write"}).denied is True

    monkeypatch.setenv("NEXUS_ENABLED", "0")
    d = policy.decide("tool_action", {"tool": "db.write"})
    assert d.source != "no-policy", (
        "the policy vanished instead of being disarmed — fixture problem, not a result")
    assert d.denied is False, "the global kill switch did not disarm the deny"

    with policy.gate("tool_action", {"tool": "db.write"}):
        pass                                    # must not raise Denied


def test_check_does_not_raise_under_the_global_kill_switch(monkeypatch):
    """``policy.check`` is the other advertised entry point and raises on the same condition."""
    monkeypatch.setenv("NEXUS_POLICY_PUBKEY", PUB_HEX)
    install_deny()
    monkeypatch.setenv("NEXUS_ENABLED", "0")
    d = policy.check("tool_action", {"tool": "db.write"})   # must not raise
    assert d.denied is False


def test_the_two_switches_do_not_disagree(tmp_path):
    """``settings.enforcement_enabled is True while nexus.enabled() is False`` was the half of this
    finding that was confirmed independently. It is the invariant, so it is the assertion.

    A subprocess, because ``nexus._ENABLED`` is read **once at import** on purpose
    (``__init__.py:60-64``: a switch that could be flipped mid-process would imply the SDK can be
    armed later, which "no threads, no hooks" cannot deliver). So the honest comparison is a
    process that started with the brake set — which is also the only way an operator applies it.
    """
    from conftest import run_script
    r = run_script(
        "import nexus\n"
        "from nexus.policy import settings\n"
        "print('enabled', nexus.enabled())\n"
        "print('enforcement', settings.current().enforcement_enabled)\n",
        tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    assert "enabled False" in r.stdout, r.stdout
    assert "enforcement False" in r.stdout, (
        f"settings.enforcement_enabled disagrees with nexus.enabled(): {r.stdout}")


def test_code_cannot_override_the_global_kill_switch(monkeypatch):
    """``configure()`` beats the environment for every knob except the kill switches — the one
    documented inversion in ``config.py``. An operator's brake that application code can release
    is not a brake."""
    monkeypatch.setenv("NEXUS_ENABLED", "0")
    settings.configure(enforcement_enabled=True)
    assert settings.current().enforcement_enabled is False


def test_the_policy_kill_switch_still_works_on_its_own(monkeypatch):
    """Regression guard for the narrow switch, which must keep working unchanged."""
    monkeypatch.delenv("NEXUS_ENABLED", raising=False)
    settings.configure(enforcement_enabled=True)
    assert settings.current().enforcement_enabled is True
    monkeypatch.setenv("NEXUS_POLICY_ENABLED", "0")
    assert settings.current().enforcement_enabled is False


def test_disarming_stays_visible(monkeypatch):
    """Turning enforcement off must not turn evaluation off. An operator who disarms during an
    incident still needs the record of what *would* have been blocked — and ``alerts.DISARMED``
    exists so that a one-variable disarm is not silent. This is the property that stops the fix
    above from being a way to make governance quietly disappear."""
    monkeypatch.setenv("NEXUS_POLICY_PUBKEY", PUB_HEX)
    install_deny()
    monkeypatch.setenv("NEXUS_ENABLED", "0")
    policy.alerts.reset()

    d = policy.decide("tool_action", {"tool": "db.write"})
    assert d.denied is False
    assert d.action == "deny", "the matching rule must still be recorded, only not enforced"
    assert policy.alerts.DISARMED in policy.alerts.kinds(), (
        "a disarmed deny must raise an integrity alert, or the brake is a silent hole")
