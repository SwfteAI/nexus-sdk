"""Policy substrate: signature verification, envelope freshness, rule parsing and matching.

The enforcement semantics themselves live in ``test_enforcement.py``; this file tests the layers
underneath them, because every one of those semantics is only as good as the verifier and the
matcher it stands on.

The Ed25519 tests are not optional and not ceremony. A verifier that silently returns ``True`` is
far worse than no verifier at all — it would present a forged policy as an authentic one, which is
the only failure in this package that is worse than not enforcing. So verification is exercised
against RFC 8032's own published vectors, and every negative case (tampered payload, wrong key,
truncated signature, non-canonical ``s``) is asserted to fail.
"""
from __future__ import annotations

import json
import time

import pytest

from nexus import policy
from nexus.policy import alerts, ed25519, engine, envelope as env_mod, rules, settings

# A throwaway signing seed. Real envelopes are signed by a key that never leaves the control
# plane; this exists so the suite exercises the actual verifier against actual signatures rather
# than a mock that would only assert our own beliefs back to us.
SEED = bytes(range(32))
PUB_HEX = ed25519.public_key(SEED).hex()


def sign_envelope(payload: dict, *, seed: bytes = SEED) -> dict:
    """Sign a payload, defaulting ``issued_at`` to now.

    ``issued_at`` goes *inside* the signature, which is the fix: an envelope that does not
    state a signed issue time is not usable at all. The default is here rather than at every call
    site so that a test which forgets it is not silently testing the rejection path — a test that
    accidentally asserts a rejection it did not mean to cause is how this suite ended up asserting
    that the all-zero public key was safe.
    """
    body = {"issued_at": time.time(), **payload}
    return {"policy": body, "signature": ed25519.sign(seed, env_mod.canonical(body)).hex()}


@pytest.fixture(autouse=True)
def _policy_isolation():
    policy.reset_for_tests()
    settings.configure(pubkey_hex=PUB_HEX)
    yield
    policy.reset_for_tests()


# ------------------------------------------------------------------------------------------
# Ed25519 — RFC 8032 §7.1 vectors
# ------------------------------------------------------------------------------------------

RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e"
     "39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3"
     "613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", RFC_VECTORS)
def test_ed25519_matches_rfc8032_vectors(seed_hex, pub_hex, msg_hex, sig_hex):
    seed, pub = bytes.fromhex(seed_hex), bytes.fromhex(pub_hex)
    msg, sig = bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)
    assert ed25519.public_key(seed) == pub
    assert ed25519.sign(seed, msg) == sig
    assert ed25519.verify(pub, msg, sig) is True


def test_ed25519_rejects_every_malformed_input():
    pub = ed25519.public_key(SEED)
    sig = ed25519.sign(SEED, b"hello")
    assert ed25519.verify(pub, b"hello", sig)
    # A verifier that returns True here would present a forged policy as authentic.
    assert not ed25519.verify(pub, b"hellp", sig)                    # message changed
    assert not ed25519.verify(ed25519.public_key(bytes(32)), b"hello", sig)   # wrong key
    assert not ed25519.verify(pub, b"hello", sig[:-1])               # truncated
    assert not ed25519.verify(pub[:-1], b"hello", sig)               # short key
    assert not ed25519.verify(pub, b"hello", bytes(64))              # zeros
    # Non-canonical s (>= group order): the RFC 8032 §5.1.7 malleability guard.
    bad_s = sig[:32] + (2 ** 252 + 27742317777372353535851937790883648493).to_bytes(32, "little")
    assert not ed25519.verify(pub, b"hello", bad_s)


# ------------------------------------------------------------------------------------------
# canonicalisation and envelope verification — case 6.5
# ------------------------------------------------------------------------------------------

def test_canonical_is_stable_across_key_order():
    a = env_mod.canonical({"b": 1, "a": [1, 2], "c": {"y": 1, "x": 2}})
    b = env_mod.canonical({"c": {"x": 2, "y": 1}, "a": [1, 2], "b": 1})
    assert a == b
    assert b" " not in a          # no insignificant whitespace, both sides must agree byte-wise


def test_valid_envelope_verifies():
    """A good envelope verifies and comes back with every authored field intact.

    ``got == payload`` was the assertion until that change, and it is now wrong for a substantive
    reason rather than a cosmetic one: ``issued_at`` lives *inside* the signature, so a verified
    payload carries a signed issue time the author's dict never had. Keeping the equality would
    have meant asserting that the freshness field is absent — precisely the property the blocker
    removed, and precisely the shape of test that made this suite claim the all-zero public key
    was safe.

    Containment plus an explicit check on the new field is strictly stronger than the equality it
    replaces: every authored key survives verification unchanged, and the issue time is present
    *and* numeric rather than merely present.
    """
    payload = {"version": "1", "rules": []}
    got, problem = env_mod.verify(sign_envelope(payload), pubkey_hex=PUB_HEX)
    assert problem is None
    assert {k: got[k] for k in payload} == payload
    assert isinstance(got["issued_at"], (int, float))


@pytest.mark.parametrize("mutate,expected_kind", [
    # 6.5 — every way an envelope can fail to authenticate resolves to "no policy" plus an alert.
    (lambda e: {**e, "policy": {**e["policy"], "rules": [{"id": "x", "action": "allow"}]}},
     alerts.BAD_SIGNATURE),
    (lambda e: {**e, "signature": "00" * 64}, alerts.BAD_SIGNATURE),
    (lambda e: {k: v for k, v in e.items() if k != "signature"}, alerts.UNSIGNED),
    (lambda e: {**e, "signature": ""}, alerts.UNSIGNED),
    (lambda e: {**e, "signature": "zznothex"}, alerts.BAD_SIGNATURE),
    (lambda e: {**e, "policy": "not an object"}, alerts.BAD_SIGNATURE),
    (lambda e: "not an envelope at all", alerts.BAD_SIGNATURE),
])
def test_tampered_envelope_is_no_policy_and_alerts(mutate, expected_kind):
    good = sign_envelope({"version": "1", "rules": [{"id": "r", "action": "deny",
                                                     "enforce": True}]})
    env = env_mod.load(mutate(good), pubkey_hex=PUB_HEX)
    assert env.present is False                     # treated as no policy — fail OPEN
    assert expected_kind in alerts.kinds()          # …but never silently


def test_envelope_signed_by_the_wrong_key_is_rejected():
    other = bytes(range(1, 33))
    env = env_mod.load(sign_envelope({"rules": []}, seed=other), pubkey_hex=PUB_HEX)
    assert env.present is False
    assert alerts.BAD_SIGNATURE in alerts.kinds()


# ------------------------------------------------------------------------------------------
# The unconfigured key, and small-order forgery
#
# The test that used to live here was called ``test_default_pubkey_verifies_nothing``. It asserted
# that ``env_mod.load`` of a *correctly signed* envelope failed under the all-zero default key —
# which it did, because the envelope was signed by a different key, so the test passed for a reason
# that had nothing to do with its name. The property it claimed to protect ("the all-zero default
# verifies nothing") was false the whole time: 32 zero bytes decompress to an order-4 point, and a
# single fixed 64-byte string was accepted as a signature over 23.5% of messages under it. The test
# encoded the vulnerability as an invariant, which is worse than having no test, because it is what
# a reviewer reads instead of checking.
#
# What replaces it: the forgery construction itself, asserted to be *rejected*; the same
# construction against the settings default, so both locks are tested separately; and an RFC 8032
# vector alongside, so "reject everything" cannot pass either.
# ------------------------------------------------------------------------------------------

#: The forgery construction, verbatim: R = the identity encoding, s = 0.
FORGED_SIG = b"\x01" + bytes(31) + bytes(32)


def test_a_small_order_public_key_verifies_nothing():
    """**Regression.** Measured 94/400 accepted before the fix, 0/400 after.

    400 rather than one because the defect is probabilistic: a single message would have passed
    this test 76.5% of the time even against the broken verifier, which is exactly the kind of test
    that lets a hole through. An attacker does not need every message to verify — they add a filler
    field to the policy JSON and re-roll until one does.
    """
    accepted = [i for i in range(400)
                if ed25519.verify(bytes(32), b"attacker-authored policy blob #%d" % i, FORGED_SIG)]
    assert accepted == [], f"{len(accepted)}/400 forged signatures accepted"


@pytest.mark.parametrize("pub_hex", [
    "00" * 32,                                                              # identity-ish, order 4
    "0100000000000000000000000000000000000000000000000000000000000000",     # the identity itself
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",     # order 2
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",     # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",     # order 8
])
def test_every_small_order_key_is_refused(pub_hex):
    """Not just the all-zero one. The whole torsion subgroup, because a fix that special-cased the
    default would have left four other keys with the same property one hex edit away."""
    pub = bytes.fromhex(pub_hex)
    assert not any(ed25519.verify(pub, b"blob #%d" % i, FORGED_SIG) for i in range(64))


def test_a_small_order_R_is_refused_under_a_real_key():
    """``R`` gets the same check as ``A``. A verifier that only guarded the key would still accept
    a signature whose nonce is a torsion point."""
    pub = ed25519.public_key(SEED)
    for tail in (bytes(32), (1).to_bytes(32, "little")):
        assert not ed25519.verify(pub, b"hello", b"\x01" + bytes(31) + tail)


def test_rfc_8032_still_verifies_after_the_small_order_checks():
    """The other half of the falsification: ``return False`` would pass every test above.

    RFC 8032 §7.1's first vector, end to end — key derivation, signature, verification — plus the
    negative that proves it is not matching on length alone.
    """
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed25519.public_key(seed) == pub
    assert ed25519.sign(seed, b"") == sig
    assert ed25519.verify(pub, b"", sig) is True
    assert ed25519.verify(pub, b"\x00", sig) is False


def test_an_unconfigured_key_is_no_key_rather_than_a_usable_one():
    """**Regression.** The default must not be a key at all.

    Two assertions, and the second is the one with teeth: the *problem string* must say we have no
    key, not that the signature is bad. An operator told "bad signature" goes and checks their
    control plane's signer; an operator told "no public key configured" fixes it in a minute.
    """
    settings.reset_for_tests()
    assert settings.current().pubkey_hex == ""
    assert env_mod.key_is_configured("0" * 64) is False
    assert env_mod.key_is_configured("") is False

    _, problem = env_mod.verify(sign_envelope({"rules": []}))
    assert problem == env_mod.NO_KEY

    env = env_mod.load(sign_envelope({"rules": []}))
    assert env.present is False
    assert alerts.NO_PUBKEY in alerts.kinds()


def test_an_unconfigured_deployment_cannot_be_handed_a_forged_kill_switch():
    """The end-to-end reach of it: an attacker who can write the
    policy file ships ``{"action": "deny", "enforce": true}`` and stops the customer's fleet.

    Before the fix this succeeded on the second attempt out of 500.
    """
    settings.reset_for_tests()
    for n in range(500):
        raw = {"policy": {"issued_at": time.time(), "nonce": n,
                          "rules": [{"id": "kill", "action": "deny", "enforce": True}]},
               "signature": FORGED_SIG.hex()}
        assert env_mod.load(raw).present is False, f"forged envelope accepted on attempt {n}"


# ------------------------------------------------------------------------------------------
# freshness — case 6.6
# ------------------------------------------------------------------------------------------

def test_staleness_ladder():
    now = 1_000_000.0
    s = settings.current()
    # Oldest first, because the anti-rollback ratchet refuses an envelope older than one it has
    # already accepted — which is the point of it, and would otherwise make this loop test the
    # ratchet by accident halfway through.
    for age, expected in [(s.hard_stale_s + 1, env_mod.EXPIRED),
                          (s.soft_stale_s + 1, env_mod.HARD_STALE),
                          (s.fresh_s + 1, env_mod.SOFT_STALE),
                          (s.fresh_s - 1, env_mod.FRESH),
                          (0, env_mod.FRESH)]:
        raw = sign_envelope({"rules": [], "issued_at": now - age})
        env = env_mod.load(raw, pubkey_hex=PUB_HEX, now=now)
        assert env.state == expected, f"age {age}s"
        assert env.verified is True          # stale is not the same as unverifiable


def test_explicit_expires_at_outranks_the_ladder():
    now = 1_000_000.0
    raw = sign_envelope({"rules": [], "issued_at": now, "expires_at": now - 1})
    env = env_mod.load(raw, pubkey_hex=PUB_HEX, now=now)
    assert env.state == env_mod.EXPIRED
    assert alerts.EXPIRED in alerts.kinds()


def test_clock_moved_backwards_reads_as_maximally_stale():
    """The direction that would help whoever moved the clock is the one that is guarded."""
    now = 1_000_000.0
    env = env_mod.load(sign_envelope({"rules": [], "issued_at": now + 5000}),
                       pubkey_hex=PUB_HEX, now=now)
    assert env.age_s(now) == float("inf")
    assert env.state == env_mod.EXPIRED


def test_freshness_outside_the_signature_is_ignored_entirely():
    """**Regression.** ``fetched_at`` used to be read off the *unsigned* outer object
    and to default to *now* when absent, so deleting one field from a captured envelope made it
    permanently FRESH. Both halves are asserted here: the outer field cannot make an old envelope
    fresh, and its absence cannot either."""
    now = 1_000_000.0
    old = now - 10 * settings.current().hard_stale_s

    lying = {**sign_envelope({"rules": [], "issued_at": old}), "fetched_at": now}
    env = env_mod.load(lying, pubkey_hex=PUB_HEX, now=now)
    assert env.state == env_mod.EXPIRED, "an unsigned outer field refreshed a stale envelope"
    assert env.issued_at == old


def test_an_envelope_with_no_signed_issue_time_is_not_usable():
    """**Regression.** An undated envelope used to default to *now*, i.e. FRESH forever.

    Rejecting it rather than treating it as infinitely old is deliberate: infinitely old would
    still let its ``enforce``-marked denies apply, which means an attacker holding one validly
    signed undated envelope could pin a fleet to it. It is treated exactly like an envelope we
    could not authenticate — no policy, plus an alert.
    """
    body = {"rules": [{"id": "a", "action": "deny"}]}
    raw = {"policy": body, "signature": ed25519.sign(SEED, env_mod.canonical(body)).hex()}
    env = env_mod.load(raw, pubkey_hex=PUB_HEX)
    assert env.present is False
    assert env.problem == env_mod.NO_ISSUED_AT
    assert alerts.NO_FRESHNESS in alerts.kinds()


@pytest.mark.parametrize("bad", [True, "1700000000", None, 0, -1, float("nan"), float("inf")])
def test_a_nonsense_issued_at_is_refused_rather_than_coerced(bad):
    """``True`` is in this list on purpose: ``bool`` is an ``int`` subclass, so an unguarded
    numeric check turns ``"issued_at": true`` into a 1970 timestamp — a *usable* envelope that
    reads as merely very stale, which is a worse outcome than a rejected one."""
    env = env_mod.load(sign_envelope({"rules": [], "issued_at": bad}), pubkey_hex=PUB_HEX)
    assert env.present is False
    assert env.problem == env_mod.NO_ISSUED_AT


def test_a_replayed_older_envelope_is_refused(tmp_path):
    """**Regression.** The rollback: an attacker serves a policy issued *before* a
    dangerous tool was denied. Both envelopes verify; only the newer one is accepted."""
    settings.configure(state_path=str(tmp_path / "hwm.json"))
    now = time.time()
    new = sign_envelope({"rules": [{"id": "deny-rm", "action": "deny", "enforce": True}],
                         "issued_at": now})
    old = sign_envelope({"rules": [], "issued_at": now - 3600})

    assert env_mod.load(new, pubkey_hex=PUB_HEX).present is True
    rolled = env_mod.load(old, pubkey_hex=PUB_HEX)
    assert rolled.present is False, "a policy older than one already accepted was honoured"
    assert rolled.problem == env_mod.ROLLED_BACK
    assert alerts.ROLLBACK in alerts.kinds()

    # Re-installing the *same* envelope must still work — a restart, or a refresh that returns
    # identical bytes, is not an attack, and a ratchet that failed closed on equality would make
    # every pod restart look like one.
    assert env_mod.load(new, pubkey_hex=PUB_HEX).present is True


def test_the_rollback_mark_survives_a_restart(tmp_path):
    """The in-process half of the mark is free; this is the half that costs a file, and it is the
    half that stops an attacker from simply waiting for a deploy."""
    state = str(tmp_path / "hwm.json")
    settings.configure(state_path=state)
    now = time.time()
    assert env_mod.load(sign_envelope({"rules": [], "issued_at": now}), pubkey_hex=PUB_HEX).present

    env_mod.reset_for_tests()          # a new process, same disk
    assert env_mod.high_water(PUB_HEX) == pytest.approx(now)
    older = env_mod.load(sign_envelope({"rules": [], "issued_at": now - 60}), pubkey_hex=PUB_HEX)
    assert older.present is False


def test_a_key_rotation_starts_its_own_rollback_ladder(tmp_path):
    """A mark keyed by nothing would lock a freshly rotated key out behind the old key's
    timestamps, and "rotate the signing key" would become an outage."""
    settings.configure(state_path=str(tmp_path / "hwm.json"))
    now = time.time()
    assert env_mod.load(sign_envelope({"rules": [], "issued_at": now}), pubkey_hex=PUB_HEX).present

    other_seed = bytes(range(1, 33))
    other_hex = ed25519.public_key(other_seed).hex()
    env = env_mod.load(sign_envelope({"rules": [], "issued_at": now - 3600}, seed=other_seed),
                       pubkey_hex=other_hex)
    assert env.present is True


def test_an_unwritable_state_path_narrows_the_mark_but_never_blocks_policy(tmp_path):
    """Read-only filesystem. The protection degrades to the process lifetime; loading policy does
    not fail, because a governance SDK that refused to start over a cache file gets uninstalled."""
    settings.configure(state_path=str(tmp_path / "no-such-dir" / "hwm.json"))
    now = time.time()
    assert env_mod.load(sign_envelope({"rules": [], "issued_at": now}), pubkey_hex=PUB_HEX).present
    assert alerts.STATE_UNWRITABLE in alerts.kinds()
    # In-process mark still ratchets, so the replay is still refused for this process.
    assert env_mod.load(sign_envelope({"rules": [], "issued_at": now - 60}),
                        pubkey_hex=PUB_HEX).present is False


def test_unreadable_policy_file_is_no_policy_not_an_error(tmp_path):
    env = env_mod.load_file(str(tmp_path / "nope.json"), pubkey_hex=PUB_HEX)
    assert env.present is False
    assert alerts.UNREACHABLE in alerts.kinds()


def test_policy_file_round_trip(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(sign_envelope({"rules": [{"id": "a", "action": "deny"}]})))
    settings.configure(envelope_path=str(p), pubkey_hex=PUB_HEX,
                       state_path=str(tmp_path / "hwm.json"))
    snap = engine.load_from_settings()
    assert snap.present and [r.id for r in snap.ruleset.rules] == ["a"]


# ------------------------------------------------------------------------------------------
# rule parsing — malformed rules are quarantined, never fatal
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "not an object",
    {"action": "deny"},                                     # no id
    {"id": "x", "action": "maybe"},                         # unknown action
    {"id": "x", "action": "allow", "match": "nope"},        # match not an object
    {"id": "x", "action": "allow", "match": {"targt_contains": "a"}},   # typo'd clause
    {"id": "x", "action": "allow", "match": {"max_risk": "catastrophic"}},
    {"id": "x", "action": "allow", "match": {"field_equals": ["a"]}},
    {"id": "x", "action": "require_approval", "approval": {"timeout_s": 0}},
    {"id": "x", "action": "require_approval", "approval": {"timeout_s": -1}},
    {"id": "x", "action": "require_approval", "approval": {"on_timeout": "escalate"}},
    {"id": "x", "action": "require_approval", "approval": "soon"},
])
def test_malformed_rules_are_quarantined_individually(bad):
    rs = rules.parse([{"id": "good", "action": "deny"}, bad,
                      {"id": "also-good", "action": "allow", "match": {"tool": "t"}}])
    # One typo must not disarm every other rule in the envelope, and must not be fatal either way.
    assert [r.id for r in rs.rules] == ["good", "also-good"]
    assert len(rs.quarantined) == 1
    assert alerts.MALFORMED_RULE in alerts.kinds()


def test_a_typod_clause_is_refused_rather_than_ignored():
    """Silently dropping an unknown clause would widen an allow rule to match everything."""
    rs = rules.parse([{"id": "x", "action": "allow", "match": {"targt_contains": ".env"}}])
    assert rs.rules == ()


def test_on_timeout_default_follows_the_enforce_marking():
    rs = rules.parse([
        {"id": "hard", "action": "require_approval", "enforce": True},
        {"id": "soft", "action": "require_approval"},
    ])
    by_id = {r.id: r for r in rs.rules}
    assert by_id["hard"].on_timeout == rules.DENY     # a gate that opens unattended is not a gate
    assert by_id["soft"].on_timeout == rules.ALLOW    # advisory must never become an outage


def test_rule_set_is_bounded():
    rs = rules.parse([{"id": f"r{i}", "action": "allow", "match": {"tool": "t"}}
                      for i in range(50)], max_rules=10)
    assert len(rs.rules) == 10
    assert alerts.MALFORMED_RULE in alerts.kinds()


# ------------------------------------------------------------------------------------------
# matching
# ------------------------------------------------------------------------------------------

def _rule(**kw):
    base = {"id": "r", "action": "deny"}
    base.update(kw)
    rs = rules.parse([base])
    assert rs.rules, rs.quarantined
    return rs.rules[0]


@pytest.mark.parametrize("match,subject,expected", [
    ({"tool": "db.write"}, {"tool": "db.write"}, True),
    ({"tool": ["a", "db.write"]}, {"tool": "db.write"}, True),
    ({"tool": "db.write"}, {"tool": "db.read"}, False),
    ({"target_glob": "prod-*"}, {"target": "prod-orders"}, True),
    ({"target_glob": ["stg-*", "prod-*"]}, {"target": "prod-orders"}, True),
    ({"target_glob": "prod-*"}, {"target": "dev-orders"}, False),
    ({"target_contains": ".env"}, {"target": "/app/.env.local"}, True),
    ({"command_glob": "git push*"}, {"command": "git push origin"}, True),
    ({"repos": "checkout-*"}, {"repo": "checkout-api"}, True),
    ({"branch_not": ["main"]}, {"branch": "feature"}, True),
    ({"branch_not": ["main"]}, {"branch": "main"}, False),
    ({"max_risk": "medium"}, {"risk": "low"}, True),
    ({"max_risk": "medium"}, {"risk": "high"}, False),
    ({"field_equals": {"env": "prod"}}, {"env": "prod"}, True),
    ({"field_equals": {"env": ["prod", "stg"]}}, {"env": "dev"}, False),
    # ANDed
    ({"tool": "db.write", "target_glob": "prod-*"}, {"tool": "db.write", "target": "prod-a"}, True),
    ({"tool": "db.write", "target_glob": "prod-*"}, {"tool": "db.write", "target": "dev-a"}, False),
])
def test_clause_matching(match, subject, expected):
    assert rules.matches(_rule(match=match), subject) is expected


def test_command_glob_is_fnmatch_not_regex():
    """``DEPUTY.md``'s documented trap: the alternation form matches literal text and nothing else."""
    assert not rules.matches(_rule(match={"command_glob": "git (status|diff)*"}),
                             {"command": "git status"})
    assert rules.matches(_rule(match={"command_glob": ["git status*", "git diff*"]}),
                         {"command": "git status -s"})


@pytest.mark.parametrize("match,subject", [
    ({"branch_not": ["main"]}, {"tool": "t"}),          # no branch known
    ({"max_risk": "low"}, {"tool": "t"}),               # no risk block == worst case
    ({"command_glob": "git *"}, {"tool": "t"}),         # command never read
    ({"repos": "checkout-*"}, {"tool": "t"}),           # repo unknown
    ({"target_contains": ".env"}, {"tool": "t"}),       # target unknown
    ({"field_equals": {"env": "prod"}}, {"tool": "t"}),
])
def test_unknown_field_never_satisfies_an_allow_clause(match, subject):
    """There is no path from "I don't know" to "allow" — ``DEPUTY.md``'s governing rule."""
    assert rules.matches(_rule(action="allow", match=match), subject) is False


@pytest.mark.parametrize("match,subject", [
    ({"branch_not": ["main"]}, {"tool": "t"}),
    ({"max_risk": "low"}, {"tool": "t"}),
    ({"target_contains": ".env"}, {"tool": "t"}),
])
def test_unknown_field_does_not_save_a_subject_from_a_deny_clause(match, subject):
    """The mirror image: refusing under uncertainty is never the unsafe direction."""
    assert rules.matches(_rule(action="deny", match=match), subject) is True


def test_unclaused_rules_are_unconditional_only_in_the_refusing_direction():
    assert rules.matches(_rule(action="deny", match={}), {"tool": "anything"}) is True
    assert rules.matches(_rule(action="allow", match={}), {"tool": "anything"}) is False


def test_first_match_wins_and_a_raising_matcher_is_skipped(monkeypatch):
    rs = rules.parse([{"id": "first", "action": "allow", "match": {"tool": "t"}},
                      {"id": "second", "action": "deny", "match": {"tool": "t"}}])
    assert rules.first_match(rs, {"tool": "t"}).id == "first"

    real = rules.matches

    def explode(rule, subject, folded=None):
        if rule.id == "first":
            raise ValueError("bad matcher")
        return real(rule, subject, folded)

    monkeypatch.setattr(rules, "matches", explode)
    # One bad rule must not stop the rules after it from applying.
    assert rules.first_match(rs, {"tool": "t"}).id == "second"
    assert alerts.MALFORMED_RULE in alerts.kinds()


# ------------------------------------------------------------------------------------------
# settings and alerts
# ------------------------------------------------------------------------------------------

def test_env_kill_switch_outranks_code(monkeypatch):
    settings.configure(enforcement_enabled=True)
    assert settings.current().enforcement_enabled is True
    monkeypatch.setenv("NEXUS_POLICY_ENABLED", "0")
    # An operator must be able to disarm enforcement without a redeploy.
    assert settings.current().enforcement_enabled is False


def test_configure_ignores_unknown_keys():
    """Reachable from a customer's init(); an unrecognised knob must not be a startup crash."""
    settings.configure(not_a_real_setting=1, decision_budget_ms=9.0)
    assert settings.current().decision_budget_ms == 9.0


def test_alerts_deduplicate_rather_than_amplify():
    seen = []
    alerts.register_sink(seen.append)
    for _ in range(50):
        alerts.raise_alert(alerts.BAD_SIGNATURE, "same detail")
    assert len(seen) == 1                      # one sink call, not fifty
    assert alerts.find(alerts.BAD_SIGNATURE).count == 50


def test_alert_sink_exceptions_are_contained():
    alerts.register_sink(lambda a: (_ for _ in ()).throw(RuntimeError("sink is broken")))
    alerts.raise_alert(alerts.STALE, "x")       # must not raise
    assert alerts.STALE in alerts.kinds()


def test_alerts_never_carry_rule_bodies_or_subject_content():
    """An integrity alert about a policy must not become the exfiltration route for the thing
    the policy was protecting."""
    payload = {"rules": [{"id": "r", "action": "deny",
                          "match": {"target_contains": "SECRET-CUSTOMER-STRING"}}]}
    env_mod.load({**sign_envelope(payload), "signature": "00" * 64}, pubkey_hex=PUB_HEX)
    blob = json.dumps([{"kind": a.kind, "detail": a.detail, "context": a.context}
                       for a in alerts.snapshot()])
    assert "SECRET-CUSTOMER-STRING" not in blob
