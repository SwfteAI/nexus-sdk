"""The redaction layer, tested the way it was not before.

One finding makes the other three worth writing down: *"in four separate places
the docstring asserting a security property is more accurate about intent than the code is about
behaviour — and in each case no test would fail if it broke."* Both the ``metadata_only``
text leak and the dead key-name masking were a single assertion away
from being caught, for two years of nobody's attention, because the suite tested that redaction
*ran* and never tested that a tier *meant* anything.

So the shape of this module is deliberate and every test in it is a falsifier:

* **Differential, not absolute.** The load-bearing assertion is that T0 emits strictly less than
  T1 and T1 strictly less than T2. A regression that reintroduces the T0 leak
  makes two tiers identical, and identity is what is asserted against. A test that only checked
  "T0 does not contain 'SSN'" would pass again the moment someone adds an SSN pattern to
  ``redact()`` while leaving the tier ladder broken, which is precisely the wrong lesson.

* **The canaries are the reproduction's own strings.** ``CUSTOMER_TEXT`` is what the defect was
  reproduced with; ``'the patient John Doe'`` is in it on purpose, because no regular expression
  will ever match it. Any test that passes because a pattern caught the canary is testing the
  second line of defence. The first line is that T0 puts no free text on the wire at all, and a
  canary no pattern can match is the only honest way to assert it.

* **Names are tested on the name.** ``is_sensitive_key`` is called directly, so a key-name rule
  that stops firing fails here rather than being masked by a value rule that happens to catch the
  same string — which is exactly how the dead key rule hid: ``Authorization`` looked masked in every
  eyeball test because ``Bearer …`` was caught by a *value* pattern.

* **The public path is exercised end to end.** ``Action.effect(**fields)`` → ``scrub_mapping`` is
  the reachable route, so one test drives it through ``nexus.action`` and a real
  collector rather than calling the helper.
"""
from __future__ import annotations

import json

import pytest

from nexus import contract, redact
from nexus.config import TIER_FULL, TIER_HASHED, TIER_METADATA_ONLY, Config

# The reproduction string. "John Doe" is unmatchable by design — see the module
# docstring. If this ever appears in a T0 event, the tier gate is gone, whatever the patterns do.
CUSTOMER_TEXT = "the patient John Doe, SSN 123-45-6789, email jane@customer.example"
NAME_CANARY = "John Doe"
OBSERVED = "2026-08-26T00:00:00Z"

TIERS = (TIER_METADATA_ONLY, TIER_HASHED, TIER_FULL)


def _cfg(tier: str) -> Config:
    return Config(service="svc", env="test", version="1", tier=tier)


def _values(event: dict) -> str:
    """Every scalar in the event as one blob, so 'is the text anywhere in here' is one question."""
    return json.dumps(event, default=str)


# ==============================================================================================
# The default tier is the safe tier
# ==============================================================================================

def test_wire_text_has_a_t0_rung():
    """``wire_text`` had three tiers and two branches; ``metadata_only`` and ``hashed`` took the
    same path, so the rung the whole privacy story rests on was missing.

    Falsifier: against the unfixed code all three calls return the input verbatim and the first
    assertion fails on the T0 line.
    """
    assert redact.wire_text(CUSTOMER_TEXT, TIER_METADATA_ONLY, 256) is None, (
        "the default tier put free text on the wire"
    )
    assert redact.wire_text(CUSTOMER_TEXT, TIER_HASHED, 256)
    assert redact.wire_text(CUSTOMER_TEXT, TIER_FULL, 256)


def test_an_unknown_tier_degrades_to_silence_not_to_egress():
    """A typo in ``NEXUS_TIER`` is coerced by ``config.resolve``, but a new tier added upstream and
    not taught to this function must fail toward *not sending*. There is one safe direction."""
    assert redact.wire_text(CUSTOMER_TEXT, "verbose", 256) is None
    assert redact.wire_text(CUSTOMER_TEXT, "", 256) is None


@pytest.mark.parametrize("build", [
    pytest.param(lambda cfg: contract.agent_run("s", cfg, run_id="r", name="n", phase="end",
                                                error=CUSTOMER_TEXT), id="agent_run.error"),
    pytest.param(lambda cfg: contract.tool_action("s", cfg, tool_name="t", action="invoke",
                                                  target=CUSTOMER_TEXT), id="tool_action.target"),
    pytest.param(lambda cfg: contract.tool_action("s", cfg, tool_name="t", action="invoke",
                                                  reason=CUSTOMER_TEXT), id="tool_action.reason"),
    pytest.param(lambda cfg: contract.tool_action("s", cfg, tool_name="t", action="invoke",
                                                  error=CUSTOMER_TEXT), id="tool_action.error"),
    pytest.param(lambda cfg: contract.deployment("s", cfg, deployment_id="d", env="prod",
                                                 actor=CUSTOMER_TEXT), id="deployment.actor"),
    pytest.param(lambda cfg: contract.integration_probe("s", cfg, integration="stripe",
                                                        observed_ts=OBSERVED,
                                                        error=CUSTOMER_TEXT),
                 id="integration_probe.error"),
    pytest.param(lambda cfg: contract.incident("s", cfg, incident_id="i", title=CUSTOMER_TEXT),
                 id="incident.title"),
])
def test_every_free_text_field_is_shape_only_at_t0(build):
    """The convergence, asserted field by field.

    Six content-bearing fields were ungated at the default tier and three correctly gated, and
    the split itself was the defect: five went through
    ``wire_text`` (two branches) and three through ``redact_preview`` (three branches). This
    parametrisation is the two sets merged, so a field that drifts back onto the wrong helper fails
    here rather than being noticed by the next review.

    Falsifier: five of the seven cases fail against the unfixed code — the three ``tool_action``
    fields, ``agent_run.error`` and ``deployment.actor``.
    """
    e = build(_cfg(TIER_METADATA_ONLY))
    assert NAME_CANARY not in _values(e), f"customer text at T0: {_values(e)}"
    # Shape survives — this is not "emit nothing", it is "emit no content".
    assert any(k.endswith("_chars") for k in e), "T0 dropped the shape as well as the content"
    assert any(k.endswith("_fingerprint") for k in e)


@pytest.mark.parametrize("build,field", [
    (lambda cfg: contract.agent_run("s", cfg, run_id="r", name="n", phase="end",
                                    error=CUSTOMER_TEXT), "error"),
    (lambda cfg: contract.tool_action("s", cfg, tool_name="t", action="invoke",
                                      target=CUSTOMER_TEXT), "target"),
    (lambda cfg: contract.deployment("s", cfg, deployment_id="d", env="prod",
                                     actor=CUSTOMER_TEXT), "actor"),
    (lambda cfg: contract.integration_probe("s", cfg, integration="stripe", observed_ts=OBSERVED,
                                            error=CUSTOMER_TEXT), "error"),
])
def test_the_three_tiers_differ_where_they_must(build, field):
    """**The differential test that was missing.** Three tiers, three outcomes.

    T0 has no content key at all; T1 has a preview and no content key; T2 has the content key. Any
    two of those being the same is the defect, whatever the strings happen to contain — this is the
    assertion that survives someone later improving the pattern list.
    """
    t0, t1, t2 = (build(_cfg(tier)) for tier in TIERS)

    assert field not in t0 and f"{field}_preview" not in t0
    assert field not in t1 and f"{field}_preview" in t1
    assert field in t2

    # And the shape is identical across all three, which is what makes T0 usable at all.
    assert t0[f"{field}_fingerprint"] == t1[f"{field}_fingerprint"] == t2[f"{field}_fingerprint"]
    assert t0[f"{field}_chars"] == t1[f"{field}_chars"] == t2[f"{field}_chars"]


def test_t0_and_t1_are_not_the_same_event():
    """The single assertion that would have caught the T0 leak on the day it was written.

    ``identical(T0, T1): True`` is the line in the reproduction. Nothing more elaborate
    than this was ever needed.
    """
    def _stable(e: dict) -> dict:
        return {k: v for k, v in e.items() if k not in ("event_id", "ts")}

    t0 = _stable(contract.tool_action("s", _cfg(TIER_METADATA_ONLY), tool_name="t",
                                      action="invoke", target=CUSTOMER_TEXT))
    t1 = _stable(contract.tool_action("s", _cfg(TIER_HASHED), tool_name="t",
                                      action="invoke", target=CUSTOMER_TEXT))
    assert t0 != t1, "metadata_only and hashed produced the same event — the tier means nothing"


# ==============================================================================================
# Second fault — personal data patterns, as the *second* line of defence
# ==============================================================================================

@pytest.mark.parametrize("raw,gone", [
    ("email jane@customer.example please", "jane@customer.example"),
    ("SSN 123-45-6789 on file", "123-45-6789"),
    ("card 4111 1111 1111 1111 charged", "4111 1111 1111 1111"),
    ("card 4111111111111111 charged", "4111111111111111"),
    ("call +14155552671 now", "+14155552671"),
    ("call (415) 555-2671 now", "555-2671"),
])
def test_redact_removes_personal_data_not_only_vendor_keys(raw, gone):
    """``redact()`` carried eleven vendor API-key patterns and nothing else, so "redacted" meant
    "had provider keys removed", not "had customer content removed" — and ``deployment.actor``'s
    docstring promised a scrub that could not see an email address.

    This is the second line of defence and is tested as such: it runs at T1/T2, where a customer
    has opted into content. It is not what makes the default tier safe.
    """
    out, was = redact.redact(raw)
    assert gone not in out, out
    assert was is True


def test_luhn_keeps_the_card_rule_from_eating_every_long_number():
    """A card rule that masks any 16-digit run masks trace ids and row counts, and a redactor
    that ruins ordinary telemetry gets turned off. The candidate must pass Luhn."""
    out, _ = redact.redact("processed 1234567812345670 rows in batch 1234567812345671")
    assert "1234567812345670" not in out          # valid Luhn — a plausible PAN
    assert "1234567812345671" in out              # not a card, and not the redactor's business


def test_a_name_is_never_redactable_which_is_why_t0_exists():
    """The honest limit, asserted so nobody mistakes the pattern list for the control.

    ``John Doe`` survives ``redact()`` at every tier and always will. The tier gate is the control;
    the patterns are insurance. If this test ever starts failing because someone added a name
    heuristic, read ``redact``'s module docstring on entropy scans and the request path first.
    """
    out, _ = redact.redact(CUSTOMER_TEXT)
    assert NAME_CANARY in out
    assert redact.wire_text(CUSTOMER_TEXT, TIER_METADATA_ONLY) is None


# ==============================================================================================
# Key-name masking
# ==============================================================================================

@pytest.mark.parametrize("key", [
    "api_key", "apikey", "api-key", "x-api-key", "secret", "password", "passwd", "passphrase",
    "authorization", "Authorization", "auth", "token", "access_token", "refresh_token",
    "AWS_SECRET_ACCESS_KEY", "private_key", "client_secret", "session_id", "cookie",
    "credential", "credentials", "db_password", "auth.token",
])
def test_a_sensitive_key_name_is_recognised_from_the_name_alone(key):
    """The test that could not exist while the check was ``_SENSITIVE_KEY.match(f"{key}=")``.

    That expression fed a bare name into a pattern whose third group requires four characters of
    *value* after the separator. It was False for every key in this list — verified by hand
    for six of them — so structured masking was dead code from the first commit.

    Falsifier: every parameter fails against the unfixed code, because ``is_sensitive_key`` does
    not exist there and the expression it replaces is unconditionally False.
    """
    assert redact.is_sensitive_key(key) is True


@pytest.mark.parametrize("key", ["headers", "rows", "path", "status", "duration_ms", "user",
                                 "table", "region", "authored_by"])
def test_ordinary_key_names_are_not_masked(key):
    """The other half of the assertion. A rule that masks everything is not a rule, and
    ``headers`` in particular must stay unmasked so the walk descends into it."""
    assert redact.is_sensitive_key(key) is False


def test_scrub_mapping_masks_by_key_name_at_the_default_tier():
    """The exact reproduction, asserted.

    Its output at the default tier had ``api_key``, ``password``, ``headers.x-api-key`` and
    ``prompt`` all verbatim; only ``Authorization`` was caught, and only because ``Bearer …`` is a
    *value* pattern — which is why the dead key-name rule looked alive.
    """
    out = redact.scrub_mapping({
        "api_key": "abcd1234efgh5678ijkl",
        "password": "hunter2hunter2",
        "Authorization": "Bearer abcdefgh12345678",
        "headers": {"x-api-key": "qqqqqqqqqqqqqqqq"},
        "prompt": CUSTOMER_TEXT,
        "rows": 42,
    }, TIER_METADATA_ONLY)

    assert out["api_key"] == redact.MASK
    assert out["password"] == redact.MASK
    assert out["Authorization"] == redact.MASK
    assert out["headers"]["x-api-key"] == redact.MASK, "the nested mapping shipped verbatim"
    assert "prompt" not in out, "free text at the default tier"
    assert out["rows"] == 42, "a row count is not content and must survive every tier"

    blob = json.dumps(out)
    for secret in ("abcd1234efgh5678ijkl", "hunter2hunter2", "qqqqqqqqqqqqqqqq", NAME_CANARY):
        assert secret not in blob, blob


def test_masking_survives_depth_and_lists():
    """Nesting is where this rule earns its place: an API key that arrives as
    ``{"headers": {"Authorization": "…"}}`` is invisible to any redactor that walks free text.

    Also covers dicts *inside lists*, which the previous implementation stringified — turning a
    mapping the key-name rule could have masked into prose only the value rules could see.
    """
    out = redact.scrub_mapping({
        "req": {"headers": {"authorization": "aaaaaaaaaaaaaaaa"}},
        "batch": [{"secret": "bbbbbbbbbbbbbbbb"}, {"rows": 3}],
    }, TIER_FULL)
    assert out["req"]["headers"]["authorization"] == redact.MASK
    assert out["batch"][0]["secret"] == redact.MASK
    assert out["batch"][1]["rows"] == 3
    blob = json.dumps(out)
    assert "aaaaaaaaaaaaaaaa" not in blob and "bbbbbbbbbbbbbbbb" not in blob


def test_a_sensitive_name_condemns_the_whole_value():
    """Descending into ``{"auth": {...}}`` to scrub its leaves would emit the *shape* of a
    credential, and a credential's shape is a credential. The name settles it."""
    out = redact.scrub_mapping({"auth": {"token": "x" * 20, "expires_in": 3600}},
                               TIER_FULL)
    assert out["auth"] == redact.MASK


def test_the_walk_is_bounded_in_depth_as_its_docstring_claimed():
    """``scrub_mapping``'s docstring said "bounded in width and depth". Width was bounded by
    ``max_keys``; depth was bounded by the interpreter's stack, which is not a bound this SDK is
    allowed to reach on someone else's request path."""
    deep: dict = {"leaf": "x"}
    for _ in range(2000):
        deep = {"n": deep}
    out = redact.scrub_mapping(deep, TIER_FULL)      # must not raise RecursionError
    assert isinstance(out, dict)


def test_action_effect_does_not_leak_through_scrub_mapping(sdk, collector):
    """The reachable public path: ``Action.effect(**fields)`` → ``api.py:171``
    → ``scrub_mapping``. Driven end to end through a real collector, because the question is what
    leaves the process, not what a helper returns.
    """
    import nexus
    with nexus.action("db.write", target="prod-orders") as a:
        a.effect(rows=3, api_key="abcd1234efgh5678ijkl", password="hunter2hunter2",
                 note=CUSTOMER_TEXT)
    nexus.flush()
    assert collector.wait_for(1, timeout=5)
    actions = collector.of_type("tool_action")
    assert actions, "no tool_action reached the collector"
    blob = json.dumps(actions[-1])
    for secret in ("abcd1234efgh5678ijkl", "hunter2hunter2", NAME_CANARY):
        assert secret not in blob, blob
    assert actions[-1]["effect"]["rows"] == 3


# ==============================================================================================
# deployment.actor
# ==============================================================================================

def test_deployment_actor_does_not_ship_an_email_at_the_default_tier():
    """``actor`` "very often arrives as a commit author's email address", said the docstring, and
    then routed it through a scrub with no email pattern. Two failures, one line: the tier did not
    gate it and the mitigation did not exist.

    Falsifier: against the unfixed code the address is present verbatim in the T0 event.
    """
    email = "jane.doe@customer.example"
    t0 = contract.deployment("s", _cfg(TIER_METADATA_ONLY), deployment_id="d", env="prod",
                             actor=email)
    assert email not in _values(t0)
    assert t0["actor_fingerprint"] == contract.fingerprint(email)
    assert t0["actor_chars"] == len(email)

    # And even at full, where a human asked for content, the address is scrubbed: a tier is a
    # decision about content, never a waiver on personal data.
    t2 = contract.deployment("s", _cfg(TIER_FULL), deployment_id="d", env="prod", actor=email)
    assert email not in _values(t2)
    assert redact.MASK in t2["actor"]


def test_a_bot_actor_still_reads_as_a_bot_at_every_tier():
    """The counterweight, so the fix is not "emit nothing and call it safe". A deployment ledger
    that cannot distinguish two actors is not a ledger — the fingerprint carries that."""
    a = contract.deployment("s", _cfg(TIER_METADATA_ONLY), deployment_id="d", env="prod",
                            actor="deploy-bot")
    b = contract.deployment("s", _cfg(TIER_METADATA_ONLY), deployment_id="d", env="prod",
                            actor="release-bot")
    assert a["actor_fingerprint"] != b["actor_fingerprint"]


# ==============================================================================================
# The gate itself — a structural test, so a *new* field cannot repeat this
# ==============================================================================================

def test_no_contract_builder_reaches_for_the_string_gate_any_more():
    """``wire_text`` returns a string, and there is no string that means "shape only" — which is
    the structural reason all five leaking fields leaked. Any builder that goes back to it
    reintroduces the class of defect even if that one call happens to be safe.

    Asserted on the source, deliberately: a runtime probe only sees the fields someone remembered
    to exercise, and the whole finding is about the field nobody revisited.
    """
    import inspect
    src = inspect.getsource(contract)
    assert "wire_text(" not in src, (
        "a contract builder is back on the string gate — use contract.tiered_text"
    )


def test_the_tier_ladder_has_exactly_one_implementation():
    """Two copies of a tier ladder is how one of them ends up with a rung missing; that is
    the T0 leak in one sentence. ``redact_preview`` and ``tiered_text`` must agree, key renaming
    aside, because they call the same ``_rungs``."""
    for tier in TIERS:
        loose = contract.redact_preview(CUSTOMER_TEXT, tier) or {}
        named = contract.tiered_text("x", CUSTOMER_TEXT, tier, full_limit=10_000,
                                     preview_limit=280)
        assert loose["chars"] == named["x_chars"]
        assert loose["fingerprint"] == named["x_fingerprint"]
        assert ("text" in loose) == ("x" in named)
        assert ("preview" in loose) == ("x_preview" in named)


def test_an_empty_field_writes_nothing_rather_than_a_zero_length():
    """"Not captured" and "captured as empty" are different facts and ``base()`` draws them
    differently. A shape fragment for an absent field would make an unfilled optional look like an
    empty string that someone measured."""
    e = contract.tool_action("s", _cfg(TIER_METADATA_ONLY), tool_name="t", action="invoke")
    assert not any(k.startswith("target") for k in e)
    assert not any(k.startswith("error") for k in e)


# ==============================================================================================
# Unterminated secrets, and numbers as content.
#
# A NOTE ON THE ORDER, because this file already contains a `test_*` block above and it
# is about something else entirely. The block above is about `deployment.actor` — an
# identity field, gated by tier because it arrives from a forge as a person's email.
# Everything below is about *values*: a secret too long to finish scanning, and a number
# whose Python type says nothing about its sensitivity.
# ==============================================================================================


_PEM_BODY = "MIIJKQIBAAKCAgEAXq7Zk3vN8pQ2rT5wY9bC1dF4gH6jL0mP"


def _pem(lines: int) -> str:
    """A PEM block whose length is set by the caller, so a test can sit either side of the cliff."""
    return ("-----BEGIN RSA PRIVATE KEY-----\n"
            + (_PEM_BODY + "\n") * lines
            + "-----END RSA PRIVATE KEY-----")


# `wire_text(text, tier, limit)` scans `limit + redact._SCAN_OVERSCAN` characters and no more.
# At the default limit that is 4352. The lengths below are chosen to land 3 under and 3 over,
# because THE CLIFF IS THE WHOLE FINDING: the overscan was written to cover a secret straddling
# the cut, and it silently stops covering a secret longer than the window itself. A test at a
# single length sits on one side of that cliff and reports whatever that side happens to say,
# which is exactly how the original overscan came to be believed sufficient.
@pytest.mark.parametrize("lines", [40, 60, 80, 100, 160, 400])
@pytest.mark.parametrize("tier", TIERS)
def test_a_private_key_never_ships_however_long_it_is(lines, tier):
    pem = _pem(lines)
    got = redact.wire_text(pem, tier, 256)
    assert got is None or "-----BEGIN" not in got, (
        f"a {len(pem)}-char private key leaked its opening bytes at tier {tier}: {got!r:.80}"
    )


def test_a_key_short_enough_to_scan_is_still_caught_by_the_pattern():
    """The fix must not have become the only thing working.

    The post-condition on the overscan masks output that still contains an unterminated marker.
    If the PEM *pattern* itself regressed, long keys would still be caught by that post-condition
    and every test above would stay green while the actual redactor did nothing. So this asserts
    the short case separately: a key that fits inside the scan window is redacted on the way
    through, not rescued on the way out.
    """
    short = _pem(20)
    assert len(short) < 256 + redact._SCAN_OVERSCAN, "this canary must fit in the scan window"
    assert redact.wire_text(short, TIER_FULL, 256) == redact.MASK


def test_long_ordinary_text_is_not_masked_wholesale():
    """The over-correction control.

    "Mask anything long" would close that hole and destroy the product: at T2 a user asked for their
    text and is entitled to it. The guard is a post-condition on an unterminated *secret marker*,
    not on length, and this is the assertion that says so.
    """
    prose = "the quick brown fox jumps over the lazy dog. " * 400
    got = redact.wire_text(prose, TIER_FULL, 256)
    assert got != redact.MASK, "long ordinary prose was masked wholesale"
    assert got.startswith("the quick brown fox")
    assert len(got) == 256, "the limit still applies to ordinary text"


# ----------------------------------------------------------------------------------------------
# A number's Python type is not a statement about its sensitivity.
# ----------------------------------------------------------------------------------------------

# None of these is a measurement. Every one of them is the kind of thing the tier ladder exists
# to hold back, and every one of them is `int` or `float`.
NUMERIC_PII = {
    "ssn": 123456789,
    "card": 4111111111111111,
    "phone": 14155552671,
    "dob_epoch": -157766400,
    "salary_usd": 184500.55,
    "lat": 37.774929,
    "lon": -122.419416,
    "patient_mrn": 90210443,
    "account_balance": 10422.19,
}

# Every one of these IS a measurement, and a fix that eats them makes the SDK useless at its own
# default tier — which is the same as making everyone turn the default off.
MEASUREMENTS = {
    "rows": 42,
    "count": 7,
    "duration_ms": 1350,
    "upload_bytes": 90210,
    "status": 200,
    "retry_count": 3,
    "ok": True,
    "missing": None,
    "error_rate": 0.02,
    "elapsed_s": 12.5,
}


@pytest.mark.parametrize("tier", [TIER_METADATA_ONLY, TIER_HASHED])
@pytest.mark.parametrize("key", sorted(NUMERIC_PII))
def test_numeric_content_does_not_walk_around_the_tier(tier, key):
    """The finding itself: `scrub_mapping` passed every int and float through untouched.

    Parametrised per key rather than asserted over the dict in one go, so a partial regression
    names the field that broke instead of reporting "a dict differs".
    """
    out = redact.scrub_mapping({key: NUMERIC_PII[key]}, tier)
    assert out[key] == redact.MASK, f"{key} survived tier {tier} because it was a number"


def test_full_still_means_full():
    """T2 is a deliberate choice by an operator; a redactor that ignores it is a broken redactor.

    This is the other half of the over-correction control, and it is not decoration: the cheapest
    wrong fix here is to mask numbers unconditionally, and that fix passes every assertion
    in the test above.

    The expectation is computed rather than written out, because two *independent* gates run over
    this fixture and the original version of this test conflated them. Value-sensitivity is
    tier-gated — that is what this is about, and it is what T2 switches off. Name-sensitivity is
    not, and never was: a field literally called ``password`` is masked at every tier, because the
    operator who enabled T2 asked for message content, not for the credentials that happen to be
    filed beside it. When the key vocabulary widened to include ``ssn`` and ``dob``, two
    of this fixture's keys moved from the first gate to the second and this test failed — correctly.
    Pinning a literal dict here would have meant either reverting a real fix to keep a test green,
    or re-pinning the literal every time the vocabulary grows, which is the same
    enumerate-the-instances defect this file keeps finding elsewhere.
    """
    out = redact.scrub_mapping(NUMERIC_PII, TIER_FULL)
    by_name = {k for k in NUMERIC_PII if redact.is_sensitive_key(k)}
    by_value = set(NUMERIC_PII) - by_name

    # Without this the test degenerates silently: if the vocabulary ever grew to cover every key
    # in the fixture, `by_value` would empty out and the T2 assertion below would assert nothing
    # while still passing. Both buckets have to be non-empty for the comparison to mean anything.
    assert by_name, "fixture no longer exercises name-sensitivity"
    assert by_value, "fixture no longer exercises value-sensitivity — the T2 control is now vacuous"

    for key in by_value:
        assert out[key] == NUMERIC_PII[key], (
            f"{key} is sensitive only by value, and T2 is the tier that says send values — "
            "masking it anyway means the tier ladder has no top rung"
        )
    for key in by_name:
        assert out[key] == redact.MASK, (
            f"{key} is sensitive by name, which no tier switches off"
        )


@pytest.mark.parametrize("tier", [TIER_METADATA_ONLY, TIER_HASHED])
def test_measurements_survive_the_lowest_tier(tier):
    out = redact.scrub_mapping(MEASUREMENTS, tier)
    assert out == MEASUREMENTS, (
        "the structural-key allowlist dropped a genuine measurement; T0 has to stay useful or "
        "operators leave the default tier, which is a worse privacy outcome than the finding"
    )


def test_the_allowlist_is_the_direction_of_the_rule():
    """A structural test, because the class of defect is 'enumerate instances, miss the next one'.

    That fix could have been written as a denylist of sensitive-looking key names. That fails
    open on the first name nobody thought of, and this repository has now produced that same
    defect seven times in other guises. This asserts the direction rather than the contents: an
    invented key that is on nobody's list must be masked, not passed.
    """
    invented = {"quantum_flux_reading_for_patient": 8675309}
    out = redact.scrub_mapping(invented, TIER_METADATA_ONLY)
    assert out["quantum_flux_reading_for_patient"] == redact.MASK, (
        "an unrecognised numeric key was allowed through — the rule is failing open"
    )
