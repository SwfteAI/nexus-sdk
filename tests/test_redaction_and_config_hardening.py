"""The second review pass's MEDIUM and LOW findings, each with the hole closed and the feature kept.

Every test here comes in a pair by construction. One half proves the reported leak is gone; the
other proves the fix did not achieve that by breaking the thing the code is for. The pairing is not
stylistic. Every finding in this file had a one-line "fix" available that would have passed the
first half — mask every number, reject every key with a digit, refuse every URL — and each of those
would have made the SDK useless at the tier it ships in by default, which is a worse privacy outcome
than the finding, because an operator whose telemetry says nothing turns the tier up.

Every hole-closed test here was watched failing against the unfixed code before being kept, by
mutation: one symbol at a time reverted to its pre-fix definition, and for the two fixes older than
HEAD, the guard deliberately removed. The matrix is worth summarising because building it caught
more than it confirmed.

Three tests failed on first run and were rewritten rather than believed. One of those failures was
a live defect (see ``..._a_secret_split_by_the_window_is_not_half_emitted``), one was an overclaim
I had just written into the README (see ``..._the_middle_tier_really_does_emit_plaintext``), and
one was this file forbidding a string it contained (see ``..._no_internal_identifiers...``).

The harness was wrong twice before the tests were, in the same way both times: appending a reverted
symbol to the end of a module cannot undo work already done at import time. A derived value
re-derives from the *fixed* inputs, and an object already captured in a list is not affected by
rebinding its name — so an early mutation run reported three of these findings as "caught by
nothing" when the mutants were simply the fix wearing an old name. Reverting each file's changed
symbols as a group, in the file's own order, settled all three. A third mutant swapped two
statements at different indentation depths, failed to import, and "caught" 139 of 139 tests; a
broken tree is not a control, and that one was rebuilt from the real pre-fix file in git history.

Source-reading tests (the two that assert a property of a file's text) cannot be reached by
append-mutation at all. Those were controlled against HEAD's actual file text instead.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys
import time

import pytest

from nexus import config, contract, redact
from nexus.config import TIER_FULL, TIER_HASHED, TIER_METADATA_ONLY
from nexus.otel import semconv
from nexus.policy import ed25519 as ed

REPO = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------------------------
# A dict two levels inside lists was stringified, defeating key-name masking
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tier", [TIER_METADATA_ONLY, TIER_HASHED, TIER_FULL])
def test_credentials_nested_in_lists_are_masked_at_every_depth(tier):
    """`_scrub_item` recursed into dicts and stopped. A list of lists of dicts was `str()`ed.

    Parametrised over all three tiers because this is not a tier question: a value under a key
    called ``password`` is masked at T2 as well, and the original defect leaked at all three.
    """
    payload = {"batch": [[{"api_key": "sk-live-abcdefghijklmnop", "password": "hunter2"}]]}
    out = redact.scrub_mapping(payload, tier)
    flat = repr(out)
    assert "hunter2" not in flat, "a password two levels inside lists reached the wire"
    assert "sk-live-abcdefghijklmnop" not in flat


def test_ordinary_nested_structure_still_arrives():
    """The over-correction: masking every container would close the finding and lose the data."""
    payload = {"steps": [[{"name": "fetch", "rows": 3}], [{"name": "write", "rows": 9}]]}
    out = redact.scrub_mapping(payload, TIER_FULL)
    assert out["steps"][0][0]["name"] == "fetch"
    assert out["steps"][1][0]["name"] == "write"


# ---------------------------------------------------------------------------------------------
# The unfiled sibling — numbers in dicts were gated, numbers in lists were never reached
# ---------------------------------------------------------------------------------------------

def test_sibling_numbers_inside_lists_are_gated_too():
    """Found while reproducing the finding above, and not filed with it.

    It was established that a number is content — an account number, a dose, a national ID — and
    gated it by tier inside `scrub_mapping`. `_scrub_item`, which handles everything reached
    through a list, never received the same treatment, so ``{"rows": [123456789]}`` shipped raw at
    the tier that promises no content. Same finding, one container deeper.
    """
    out = redact.scrub_mapping({"rows": [123456789, 4111111111111111]}, TIER_METADATA_ONLY)
    assert not any(ch.isdigit() for ch in repr(out["rows"]))


@pytest.mark.parametrize("key,values", [("durations_ms", [12, 15, 402]),
                                        ("latencies_ms", [1.5, 2.5]),
                                        ("sizes_bytes", [900, 1024])])
def test_sibling_measurements_in_lists_survive_the_default_tier(key, values):
    """The over-correction, and the reason the inheritance rule is narrower than the scalar one.

    A *unit* suffix (``_ms``, ``_bytes``) means the same thing singular or plural, so it inherits
    into list elements. A *quantity* bare name (``count``, ``rows``, ``batch``) means the tally as
    a scalar and the tallied things as a list — the opposite of structural — so it does not. The
    first version of this fix inherited the whole allowlist and let ``rows: [4111…]`` through.
    """
    out = redact.scrub_mapping({key: values}, TIER_METADATA_ONLY)
    assert out[key] == values


# ---------------------------------------------------------------------------------------------
# Key-name vocabulary gaps, and a trailing space defeating the rule
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "api_key", "apikey", "x-api-key", "Authorization", "password", "client_secret", "pwd",
    "pin", "ssn", "cvv", "cvc", "dob", "jwt", "bearer", "otp", "mfa_code", "totp",
    "recovery_code", "mnemonic", "passphrase", "private_key", "session_id", "cookie",
])
def test_the_vocabulary_covers_what_an_agent_sdk_actually_sees(name):
    assert redact.is_sensitive_key(name)


@pytest.mark.parametrize("name", ["API_KEY ", " api_key", "api_key\t", "аpi_key"])
def test_whitespace_and_script_confusables_do_not_defeat_the_rule(name):
    """A trailing space made a key ordinary. So did one Cyrillic 'а' in ``api_key``.

    The confusable case is answered structurally rather than with a homoglyph table: a name that
    mixes ASCII letters with Cyrillic or Greek ones is treated as sensitive, whatever the letters
    are. A table would need an entry for every pair somebody thought of, which is this
    repository's most-repeated defect. Note NFKC does *not* fold Cyrillic to Latin and should not
    — they are different letters — so normalisation alone would not have caught this one.
    """
    assert redact.is_sensitive_key(name)


@pytest.mark.parametrize("name", [
    "author", "authored_by", "pass_rate", "shipping", "dobson", "signature", "salt", "nonce",
    "seed", "headers", "user_name", "pinned_version", "duration_ms", "row_count", "spinner",
])
def test_widening_the_vocabulary_did_not_swallow_ordinary_names(name):
    """The over-correction, and the reason segment words are segment-anchored.

    ``pin`` as a bare substring matches ``shipping``, ``pinned_version`` and ``spinner``; ``otp``
    matches ``dotproduct``; ``dob`` matches ``dobson``; ``auth`` matches ``authored_by``, which is
    a governance field this package emits by name. Anchoring them to whole ``_``/``-`` segments is
    what makes them affordable. ``pass``, ``salt``, ``nonce``, ``sig`` and ``refresh`` are
    deliberately absent from the vocabulary — ``pass_rate`` and ``first_pass`` are ordinary, and a
    signature and a nonce are public by construction.
    """
    assert not redact.is_sensitive_key(name)


# ---------------------------------------------------------------------------------------------
# The vendor credential list missed formats an agent SDK actually sees
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("secret", [
    "sk_live_" + "a" * 24,
    "rk_test_" + "b" * 24,
    "SG." + "c" * 22 + "." + "d" * 43,
    "npm_" + "e" * 36,
    "pypi-" + "f" * 40,
    "glpat-" + "g" * 20,
    "dop_v1_" + "0" * 64,
])
def test_vendor_credentials_are_masked(secret):
    out, was = redact.redact(f"token is {secret} ok")
    assert secret not in out and was


@pytest.mark.parametrize("text", [
    "commit 3f2a9c1e4b7d8a6f5c2e1b9d0a8f7c6e",
    "sha256:e3b0c44298fc1c149afbf4c8996fb924",
    "signature = 3045022100abcdef",
])
def test_hex_that_is_not_a_credential_survives(text):
    """The over-correction, and the reason bare 32-hex is deliberately not a pattern.

    A 32-character hex run is every MD5, every short git object, every content digest this SDK is
    built to report. Matching it would mask the identifiers the ledger exists to correlate on, to
    catch a credential format no vendor actually issues in that shape.
    """
    assert redact.redact(text)[0] == text


# ---------------------------------------------------------------------------------------------
# Personal-data patterns missed common written forms
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "ssn 123 45 6789 here",
    "ssn 123.45.6789 here",
    "ssn 123‑4519999 here".replace("4519999", "45‑6789"),
    "card 4111 1111 1111 1111 ok",
    "card 4111.1111.1111.1111 ok",
    "card 4111‑1111‑1111‑1111 ok",
    "iban GB82WEST12345698765432 ok",
    "call +1 415 555 2671 x1234 now",
])
def test_written_forms_of_personal_data_are_masked(text):
    out, was = redact.redact(text)
    assert was and redact.MASK in out, f"{text!r} came through as {out!r}"


@pytest.mark.parametrize("text", [
    "order 4111111111111112 shipped",          # fails Luhn by one digit
    "ref DE49PRODUCTSKU12345678 ok",           # IBAN-shaped, fails ISO 7064 mod-97
    "version 1.2.3.4.5.6.7.8.9.10.11.12.13",
    "the build finished in 1234.5678 seconds",
    "elapsed 123456789 ms",
])
def test_lookalikes_that_are_not_personal_data_survive(text):
    """The over-correction, and the reason Luhn and mod-97 are worth their cost on a request path.

    Sixteen digits in a row is a card number *and* an order id *and* a snowflake id. A shape-only
    rule would mask all three. The checksum is what makes a shape-based rule affordable — and it
    is also why a bare nine-digit run is deliberately not treated as a national ID: nothing
    distinguishes it from an autoincrement key, so the tier gate is the control there, not a
    pattern.
    """
    assert redact.redact(text)[0] == text


# ---------------------------------------------------------------------------------------------
# `hashed` does not hash
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", ["redacted_preview", "hashed", "HASHED", " redacted_preview "])
def test_the_honest_name_is_accepted_and_the_wire_value_is_unchanged(spelling):
    """Both halves matter, and they pull in opposite directions.

    The name had to change because "hashed" reads as "one-way digest" to the privacy officer most
    likely to pick the middle rung on the strength of the word, and what it emits is redacted
    plaintext. The wire value had to *not* change, because it is what the collector's schema
    validates against, and trading an honest label for a version-skew outage is not a fix.
    """
    assert config.resolve(tier=spelling).tier == TIER_HASHED


def test_an_unrecognised_tier_is_still_the_quiet_one():
    """The over-correction: an alias table that swallows unknown values fails open."""
    assert config.resolve(tier="hashed_definitely_trust_me").tier == TIER_METADATA_ONLY


def test_the_alias_is_not_a_wire_value():
    """`_TIERS` is the set of values that may travel. An alias in it would travel on first use."""
    assert config.TIER_REDACTED_PREVIEW not in config._TIERS


def test_the_readme_says_no_field_is_hashed():
    """The finding is a documentation defect as much as a naming one, so the docs are the test.

    Asserted on content rather than trusted to review: the tier table is the only place an
    operator learns what the middle rung does, and it is the artefact that silently goes stale.
    """
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "No field is hashed except `*_fingerprint`" in readme
    assert "`metadata_only` / `redacted_preview` / `full`" in readme


def test_the_middle_tier_really_does_emit_plaintext():
    """Stated as an executable fact, because the whole finding is that the name denied it.

    negative-controlled, and it failed — against the *documentation*, not the code. The first
    version asserted the README's own example: that "her password is hunter2" comes out with the
    password struck. It does not. The credential patterns are anchored to an assignment operator,
    so ``password = "hunter2"`` is caught and the conversational form is prose. I wrote that README
    sentence while fixing that lie — the finding that the tier's name promised more than it
    delivered — and put a fresh overclaim into the paragraph correcting an overclaim.
    ``config.py:46`` carried the accurate version the whole time and nothing compared the two.
    The README now matches this test.

    If a future change ever makes T1 genuinely hash, this test fails and whoever did it gets to
    delete the alias and the README paragraph in the same commit.
    """
    cfg = config.resolve(tier=TIER_HASHED, service="s", env="e", version="v")
    out = contract.tiered_text(
        "m", "Patient Jane Doe, SSN 123-45-6789, said: my password is hunter2", cfg.tier)
    assert "Jane Doe" in out["m_preview"], "T1 is documented as redacted plaintext"
    assert "123-45-6789" not in out["m_preview"], "a national ID has a shape and must be caught"
    assert "hunter2" in out["m_preview"], (
        "if the redactor has learned to read prose then the README example is now wrong in the "
        "other direction — update it rather than deleting this assertion"
    )


# ---------------------------------------------------------------------------------------------
# `contract._rungs` had no input bound: 10s of regex on the caller's thread
# ---------------------------------------------------------------------------------------------

def test_tiered_text_is_bounded_by_its_limit_not_its_input():
    """Measured, because the finding is a measurement: 10.03s before, on this input.

    The threshold is 2s against a measured 13.5s — a margin wide enough that a loaded CI runner
    does not make it flaky, and narrow enough that a regression to whole-input scanning (which is
    linear, so ~7x this budget) cannot hide under it.
    """
    big = "the quick brown fox " * 1_080_000  # ~21 MB
    t0 = time.monotonic()
    contract.tiered_text("m", big, TIER_FULL)
    assert time.monotonic() - t0 < 2.0


def test_the_window_has_one_implementation():
    """Structural, because the finding *is* a second copy: the fix landed in `redact.wire_text`
    and not in `_rungs`, which is the same function's job done twice in two places.

    Asserting that `_rungs` calls the shared helper is what stops the next bounded-scan fix from
    landing in one of them again.
    """
    src = (REPO / "src" / "nexus" / "contract.py").read_text(encoding="utf-8")
    body = src[src.index("def _rungs"):src.index("def tiered_text")]
    assert "scan_window(" in body
    assert "redact(text)" not in body, "_rungs is redacting the whole input again"


def test_a_secret_split_by_the_window_is_not_half_emitted():
    """The bound and the overscan post-condition have to land together or the bound *is* a bypass.

    negative-controlled, and this one found a live defect rather than confirming a fix. Written as
    an over-correction control for the input bound, it failed against the shipped code: the 9 kB
    ``password = "…"`` came back as its first 280 plaintext characters. `_UNTERMINATED_MARKERS` was
    a one-element tuple holding ``-----BEGIN``, under a `scan_window` docstring asserting it
    "generalises to the next unterminated pattern instead of enumerating this one". A quoted
    assignment that never meets its closing quote inside the window matches nothing, so
    ``unfinished`` read False and the prefix shipped — reintroduced by the very bound that
    closed the latency. Filler here; in the real case, the header and half the payload of a JWT.

    The post-condition is now what the docstring always claimed it was: the last assignment
    visible in the emitted text is looked up in `is_sensitive_key`, and if the mask does not follow
    it, the value was still running when the output stopped.
    """
    monster = 'password = "' + "a" * 9000 + '"'
    out = contract.tiered_text("m", monster, TIER_FULL, full_limit=280)
    assert out["m"] == redact.MASK and out["m_redacted"]
    assert redact.wire_text(monster, TIER_FULL, limit=280) == redact.MASK


def test_an_unterminated_pem_is_still_caught():
    """The case the marker list was written for, kept as a regression guard on the general rule."""
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEow" * 3000
    assert redact.scan_window(pem, 280)[2], "the PEM path regressed while generalising it"


def test_a_long_harmless_assignment_is_not_masked():
    """The over-correction on the over-correction: the rule keys on the *name*, not the length.

    Truncating a long ``description`` or ``prompt`` is the normal case at T2 and must not become a
    mask, or the tier that exists to show text stops showing text.
    """
    out = contract.tiered_text("m", 'description = "' + "a" * 9000 + '"', TIER_FULL, full_limit=280)
    assert out["m"].startswith('description = "aaa') and out["m_truncated"]
    assert not out["m_redacted"]


def test_ordinary_long_text_is_still_delivered():
    """The over-correction: masking anything that overruns the window would be the cheap fix."""
    prose = "the quick brown fox " * 400
    out = contract.tiered_text("m", prose, TIER_FULL, full_limit=280)
    assert out["m"].startswith("the quick brown fox") and out["m_truncated"]


# ---------------------------------------------------------------------------------------------
# The SDK spent the first third of the shutdown grace window before the app's handler
# ---------------------------------------------------------------------------------------------

def test_the_application_handler_is_chained_before_any_flush():
    """Structural, and deliberately so — the behavioural version of this needs a wedged collector.

    negative-controlled: the first behavioural probe scored 0.00s against *both* orderings,
    because it queued nothing and the flush had no work. With a real queue and a collector that
    accepts and never answers, the pre-fix ordering measures 8.74s (8.75s when first measured) and
    the current one measures 0.00s. The structural assertion is what survives into CI, since a
    30-second Kubernetes grace window is not something to spend in a test suite.

    Two things are asserted because the finding has two halves: the *order* (the app drains first)
    and the *size* of the bite (a fifth of the window, not four fifths).
    """
    src = (REPO / "src" / "nexus" / "runtime.py").read_text(encoding="utf-8")
    assert "_TELEMETRY_GRACE_SHARE = 0.2" in src

    handler = src[src.index("def _handler(signum, frame)"):]
    handler = handler[:handler.index("\n    def ", 1)] if "\n    def " in handler[1:] else handler
    chain_at = handler.index("previous(signum, frame)")
    flush_at = handler.index("_inline_flush()")
    assert chain_at < flush_at, (
        "the SDK flushes before handing control to the application's own SIGTERM handler, so the "
        "pod stops serving only after telemetry finishes"
    )


# ---------------------------------------------------------------------------------------------
# The CI guard for "zero required dependencies" no longer ran
# ---------------------------------------------------------------------------------------------

def test_the_dependency_guard_names_no_distribution_of_its_own():
    """The guard looked up ``nexus-sdk`` after the package was renamed ``swfte-nexus-sdk``.

    It failed loudly, which is the safe direction, but for that whole period the zero-dependency
    claim — the one property of this package that cannot be walked back after a release — was
    protected by nothing. Asserting the *absence* of a hardcoded name is what stops the drift from
    recurring; asserting ``swfte-nexus-sdk`` appears would just pin today's spelling.
    """
    src = (REPO / ".github" / "scripts" / "assert_no_deps.py").read_text(encoding="utf-8")
    body = src[src.index('"""', src.index('"""') + 3):]
    assert 'distribution("' not in body, "the distribution name is hardcoded again"
    assert "pyproject.toml" in src


def test_the_guard_actually_passes_when_run():
    """A guard that cannot run is not a guard, which is the entire finding.

    Skipped rather than failed when the package is not installed: this asserts a property of the
    *installed distribution*, and an editable install is a precondition, not something the test
    can conjure. The skip message says so, so a silent skip cannot be mistaken for a pass.
    """
    pytest.importorskip("importlib.metadata")
    from importlib.metadata import PackageNotFoundError, distribution
    try:
        distribution("swfte-nexus-sdk")
    except PackageNotFoundError:
        pytest.skip("swfte-nexus-sdk is not installed; run `pip install -e .` first")
    r = subprocess.run([sys.executable, str(REPO / ".github" / "scripts" / "assert_no_deps.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no required dependencies" in r.stdout


# ---------------------------------------------------------------------------------------------
# The small-order check on `R` was untested
# ---------------------------------------------------------------------------------------------

def test_a_small_order_R_the_equation_accepts_is_refused_by_the_guard():
    """Mutation check: removing `_is_small_order(R)` from `verify` used to break no test at all.

    The existing test named for this control builds ``R = b"\\x01" + bytes(31) + tail`` and is
    rejected by the verification equation itself, so it passes with the guard deleted. Getting a
    case that reaches the guard needs a signature the bare equation *accepts*.

    Points of order 2, 4 and 8 cannot produce one: they sit outside the prime-order subgroup while
    [s]B and [h]A both sit inside it, and that coset does not collapse. The identity can. With
    R = 0 the equation reduces to [s]B == [h]A, and with A = [a]B that is s == h*a mod L, which is
    solvable exactly. This test asserts both facts — that the equation accepts, and that `verify`
    does not — because the first is what makes the second mean anything.

    Honest about what this is: constructing it requires the private scalar, so it is not a
    forgery, and RFC 8032 §5.1.7 permits a verifier to skip the check. What it does buy is
    libsodium parity and signature uniqueness — without the guard, two distinct encodings verify
    for the same message under the same key, which breaks anything treating a signature as an
    identifier for replay or dedup purposes.
    """
    seed = bytes(range(32))
    pub = ed.public_key(seed)
    scalar, _prefix = ed._secret_expand(seed)
    msg = b"budget: unlimited"

    r_bytes = ed._point_compress(ed._NEUTRAL)
    assert ed._is_small_order(ed._point_decompress(r_bytes))

    h = ed._sha512_modq(r_bytes + pub + msg)
    forged = r_bytes + ((h * scalar) % ed._Q).to_bytes(32, "little")

    equation_holds = ed._point_equal(
        ed._point_mul((h * scalar) % ed._Q, ed._G),
        ed._point_add(ed._point_decompress(r_bytes), ed._point_mul(h, ed._point_decompress(pub))),
    )
    assert equation_holds, "the case does not reach the guard; it fails the equation first"
    assert not ed.verify(pub, msg, forged), "the small-order R guard is not load-bearing"


def test_honest_signatures_still_verify():
    """The over-correction: a guard that rejects real signatures closes the finding and the SDK.

    An honestly generated R is small-order only if the SHA-512-derived nonce is zero mod L — a
    2^-252 event — so this must never fire in practice, and a test that says so is the difference
    between a defence-in-depth check and a liveness bug.
    """
    seed = bytes(range(32))
    pub = ed.public_key(seed)
    for msg in (b"", b"hello", b"budget: unlimited", bytes(range(256))):
        assert ed.verify(pub, msg, ed.sign(seed, msg))


# ---------------------------------------------------------------------------------------------
# The sdist shipped internal identifiers
# ---------------------------------------------------------------------------------------------

# Assembled rather than written out, because this file ships too and a literal here would be the
# very thing the test forbids. The first version enumerated the four known slugs and failed against
# itself — which was the right failure for the wrong reason, and pointed at the better rule below.
_ORG = "sw" + "fte"


@pytest.mark.parametrize("needle,what", [
    (_ORG + "/", "an internal repository slug"),
    ("customer-" + "portal", "an internal application name"),
])
def test_no_internal_identifiers_in_anything_that_ships(needle, what):
    """`tests/` is in the sdist by deliberate decision — distribution packagers run the suite.

    That decision is fine, and the test-file *names* are fine too: this repository is public, so
    "an index of which attacks were considered" is on GitHub either way. What was not fine was
    publishing a real internal repository slug and application name permanently and
    world-readably, in fixtures where ``example-org/example-app`` does the same job.

    Matching ``<org>/`` rather than the three known slugs is the point: the finding was three
    fixtures, the class is any repository under our org, and the next one gets added by somebody
    who has never read this file. ``swfte-nexus-sdk`` is the distribution's own name and does not
    match, because a slug needs the slash.
    """
    hits = [p for p in list((REPO / "tests").rglob("*.py")) + list((REPO / "src").rglob("*.py"))
            if needle in p.read_text(encoding="utf-8")]
    assert not hits, f"{what} ({needle!r}) still appears in {[p.name for p in hits]}"


# ---------------------------------------------------------------------------------------------
# Identifier-shaped dict keys shipped verbatim at `metadata_only`
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"patient_90210443": 1, "mrn_44521": 2},
    {"acme.customer.90210443": 1},
    {"order_2026_08_27_001": {"total": 5}},
    {"user-8675309": "x"},
    {"acct90210443": 1},
])
def test_identifier_shaped_keys_do_not_reach_the_wire(payload):
    """`_SAFE_KEY_RE`'s own comment names this case and the regex does not implement it.

    A per-patient, per-account or per-order dict is the ordinary shape of a payload an agent hands
    a tool, and the names in it *are* the identifiers. The distinction being drawn is between a
    schema name, written once by a developer, and an instance name, minted per record: identifiers
    are made of digit runs and schema names, being words, are not.
    """
    shape = semconv.shape_of(payload)
    assert not any(ch.isdigit() for name in shape["fields"] for ch in name)
    assert shape["fields_unnamed"] == len(payload)


def test_a_rejected_name_is_not_a_rejected_field():
    """Dropping the entry would make eight per-patient numbers look like an empty object.

    The type is safe to emit for the same reason it is safe for a named field — it is not a value
    — and reporting it is both more useful and more honest than a silent hole. Reported as a
    sibling list rather than synthesised ``field_0`` keys, because ``field_0`` is a name the safe
    pattern admits and a real key spelled that way would collide with the placeholder.
    """
    shape = semconv.shape_of({"patient_90210443": 1, "mrn_44521": "x"})
    assert shape["unnamed_types"] == ["number", "string"]


@pytest.mark.parametrize("payload", [
    {"query": "hello", "limit": 10, "user_name": "x"},
    {"path": "/tmp/a", "recursive": True},
    {"start_date": "2026-01-01", "end_date": "2026-02-01"},
    {"sha256": "abc", "md5": "def", "base64": True, "oauth2_token_url": "x"},
    {"address_line1": "a", "address_line2": "b", "ipv6": False, "p99_ms": 4},
])
def test_ordinary_schema_names_survive(payload):
    """The over-correction, and the reason the threshold is a four-digit *run*, not any digit.

    ``address_line1``, ``p99_ms``, ``sha256``, ``base64``, ``oauth2`` and ``ipv6`` are all names a
    real tool schema uses, and a rule keyed on "contains a digit" would take every one of them.
    """
    assert set(semconv.shape_of(payload)["fields"]) == set(payload)


def test_the_known_casualties_are_counted_not_vanished():
    """``iso8601`` and ``rfc3339`` are legitimate names with a four-digit run, and they lose.

    Stated as a test rather than left as a comment, because it is a real cost and the next person
    to widen this rule should be able to see exactly what it already costs. It is the right side
    to be wrong on: a false positive reports a field by type instead of by name, and a false
    negative puts a patient identifier on the wire at the tier that promises no content.
    """
    shape = semconv.shape_of({"iso8601": "x", "rfc3339": "y"})
    assert shape["fields"] == {} and shape["fields_unnamed"] == 2


# ---------------------------------------------------------------------------------------------
# `safe_url` kept path-borne tokens
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url,secret", [
    ("https://host/reset/TOKEN123ABCDEF", "TOKEN123ABCDEF"),
    ("https://host/invite/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "eyJhbGciOiJIUzI1NiJ9"),
    ("https://host/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit", "1BxiMVs0XRA5nFMdKvBdBZ"),
])
def test_single_use_tokens_in_paths_are_masked(url, secret):
    """Reset and invite tokens live in paths far more often than in query strings, and `safe_url`
    dropped the query and kept the path."""
    assert secret not in redact.safe_url(url)


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1/messages",
    "https://api.example.com/v1/chat/completions",
    "https://example.com/blog/pancreatic-carcinoma-review",
    "https://example.com/users/12345",
    "https://example.com/2026-08-27/report",
])
def test_ordinary_paths_survive(url):
    """The over-correction, and it is the whole difficulty of this finding.

    `safe_url` exists so an operator can see which endpoint was called. Keeping only the first
    path segment would close the finding and leave every LLM call looking identical. Numeric-only
    segments are deliberately kept: ``/users/12345`` is the shape of every REST path in existence,
    and the tier gate is the control for the id itself.
    """
    assert redact.safe_url(url) == url


# ---------------------------------------------------------------------------------------------
# Identity fields shipped ungated at every tier
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("tier", [TIER_METADATA_ONLY, TIER_HASHED, TIER_FULL])
def test_ownership_identities_are_tier_gated(tier):
    """`principal` and `asserted_by` are the two fields here that are a person by definition.

    They went straight into `base()`, which does not consult `cfg.tier` at all, so both shipped
    verbatim at the tier whose entire promise is that no content leaves the process.
    """
    cfg = config.resolve(tier=tier, service="s", env="e", version="v")
    out = contract.ownership("sess", cfg, app_id="app", principal="jane.doe@acme.example",
                             role="owner", asserted_by="john.smith@acme.example")
    assert "jane.doe@acme.example" not in repr(out)
    assert "john.smith@acme.example" not in repr(out)


def test_the_ledger_can_still_count_and_correlate_people():
    """The over-correction: dropping the fields would make the ownership record unreadable.

    A fingerprint is stable, so "the same person asserted these forty records" still resolves at
    T0; only *which* person waits for a tier where the operator has said content may leave.
    """
    cfg = config.resolve(tier=TIER_METADATA_ONLY, service="s", env="e", version="v")
    a = contract.ownership("s1", cfg, app_id="app", principal="jane@acme.example", role="owner")
    b = contract.ownership("s2", cfg, app_id="app", principal="jane@acme.example", role="owner")
    c = contract.ownership("s3", cfg, app_id="app", principal="bob@acme.example", role="owner")
    assert a["principal_fingerprint"] == b["principal_fingerprint"]
    assert a["principal_fingerprint"] != c["principal_fingerprint"]
    assert a["principal_chars"] == len("jane@acme.example")


def test_role_is_deliberately_not_gated():
    """A five-value enum is a category, not an identity, and its digest is reversible by trying
    all five. Gating it would cost readability and buy nothing."""
    cfg = config.resolve(tier=TIER_METADATA_ONLY, service="s", env="e", version="v")
    out = contract.ownership("s", cfg, app_id="app", principal="jane@acme.example", role="approver")
    assert out["role"] == "approver"


# ---------------------------------------------------------------------------------------------
# `_checked_url` was a prefix check, and NEXUS_COLLECTOR_HOST bypassed it entirely
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://a b/",
    "http://evil\n.example/",
    "http://evil\r.example/",
    "http://evil\t.example/",
    "http://127.0.0.1@evil.example/",
    "https://user:pass@collector.example/",
    "http:///v1/events",
    "http://collector.example:notaport/",
    "http://collector.example:99999/",
])
def test_a_url_that_is_not_a_url_is_refused(url):
    """Reading the front of a string is not parsing it — the same class as
    ``startswith("127.")``, on the same string, one function away.

    Control characters are refused rather than stripped on purpose: `urlsplit` removes tab, CR and
    LF silently, so a stripping fix would have *accepted* these and then connected somewhere other
    than what the operator configured. A misconfiguration here has to be loud; that is this
    function's whole contract.
    """
    with pytest.raises(ValueError):
        config._checked_url(url)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8791",
    "https://collector.example/v1/events",
    "http://[::1]:8791",
    "  http://127.0.0.1:8791  ",
    "https://collector.example:4318",
])
def test_legitimate_collector_urls_still_resolve(url):
    """The over-correction. IPv6 in particular: the bracketed form is full of characters a
    hand-rolled validator would reject, and sidecar deployments depend on it."""
    assert config._checked_url(url)


def test_collector_host_cannot_restructure_the_url(monkeypatch):
    """The bypass, and the reason validating the *result* could not have caught it.

    ``NEXUS_COLLECTOR_HOST='evil.example/x?'`` built ``http://evil.example/x?:8791`` — a
    completely valid URL. Right scheme, real hostname, no userinfo, no control characters; every
    check in `_checked_url` passes. It is simply not the URL that was configured. The port became
    a query string and `events_url` then appended `/v1/events` to a path that should not exist.

    So the check is a round-trip post-condition, not a denylist of ``/?#@``. A character list here
    would be this repository's most-repeated defect one more time — correct until the next
    separator. A round-trip does not need to know which characters are dangerous.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "evil.example/x?")
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    with pytest.raises(ValueError):
        config._collector_url(None)


@pytest.mark.parametrize("host,port,expect", [
    ("collector.internal", "4318", "http://collector.internal:4318"),
    ("10.0.0.7", "8791", "http://10.0.0.7:8791"),
    ("::1", "8791", "http://[::1]:8791"),
    ("[fd00::1]", "8791", "http://[fd00::1]:8791"),
])
def test_sidecar_hosts_still_work(monkeypatch, host, port, expect):
    """The over-correction, and the case the whole HOST/PORT route exists for.

    A bare IPv6 address is bracketed for the operator rather than refused: `$(NODE_IP)` in a
    Kubernetes manifest expands to an unbracketed address, and requiring brackets there would
    break the deployment shape this feature was added to support.
    """
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", host)
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", port)
    assert config._collector_url(None) == expect


# ---------------------------------------------------------------------------------------------
# The class-level rule this file keeps rediscovering
# ---------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------
# One loopback decision, not two that disagree
# ---------------------------------------------------------------------------------------------

def test_only_one_module_decides_what_loopback_means():
    """There were two, with different host lists and the same string-prefix flaw.

    Structural rather than behavioural, deliberately. A test calling ``_is_loopback("127.0.0.1")``
    and asserting True would pass with two contradictory copies installed, which is precisely the
    condition the finding describes: `config`'s list held ``0.0.0.0`` and `transport`'s did not, so
    a fix applied to one left the other answering differently. What has to hold is that the
    question has one answer, so that is what is asserted.
    """
    import ast

    src_root = REPO / "src" / "nexus"
    definers = []
    for path in src_root.rglob("*.py"):
        if "vendor" in path.parts:
            continue                    # vendored code is not ours to deduplicate
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                    "loopback" in node.name.lower():
                definers.append(f"{path.relative_to(src_root)}::{node.name}")

    assert len(definers) == 1, (
        f"loopback is decided in {len(definers)} places and they will drift: {definers}")


def test_the_transport_asks_config_rather_than_answering_for_itself():
    """The other half: one definition is only one *decision* if everyone reaches it.

    `transport` is the module that had the second copy, and it is the one where getting the answer
    wrong leaks a bearer token to a proxy — see its own comment at the ``_proxies`` guard. So the
    import is asserted by name.
    """
    import ast

    tree = ast.parse((REPO / "src" / "nexus" / "transport.py").read_text(encoding="utf-8"))
    imported = {alias.name
                for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                for alias in node.names
                if (node.module or "").endswith("config")}
    assert "_is_loopback" in imported, (
        "transport no longer imports the shared loopback test; if it grew its own again, "
        f"the split is back. imported from config: {sorted(imported)}")


def test_neither_loopback_path_is_written_as_a_string_prefix():
    """The string-prefix flaw, asserted across both modules rather than the one it was found in.

    ``startswith("127.")`` accepts ``127.0.0.1.evil.com``. The recurring-defect test at the end of
    this module already parses `config.py` for it; this covers `transport.py` too, because the
    whole point of this pin is that a fix landed on one file and not its twin.
    """
    import ast

    for name in ("config.py", "transport.py"):
        tree = ast.parse((REPO / "src" / "nexus" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("startswith", "endswith") and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value.strip('"\'').startswith("127")):
                raise AssertionError(
                    f"{name} tests a loopback address by string prefix: "
                    f"{ast.unparse(node)!r} — 127.0.0.1.evil.com passes it")


def test_the_recurring_defect_has_a_name_and_this_is_it():
    """Eight findings across two passes are the same mistake: a rule that enumerates instances.

    `startswith("127.")` for loopback, a homoglyph table for confusables, a denylist of sensitive
    number keys, a character blocklist for URL injection, a hardcoded distribution name, a literal
    tier dict in a test. Each was correct for the cases its author pictured and wrong for the
    ninth. The answers that held were all the same shape: describe the class (mixed script,
    round-trip equality, fail-closed allowlist, read the name from its source), not the members.

    This test asserts the cheapest mechanical proxy for that discipline — that the fixes which
    replaced enumerations did not quietly grow new ones — and exists mostly to put the sentence
    somewhere a future reader will run into it.

    negative-controlled, and the first version was itself an instance. It grepped config.py for
    ``"127."`` with a regex and matched the *docstring* that describes the defect, because a text
    search cannot tell code from prose about code. Parsing the module and looking for a real
    ``.startswith("127…")`` call is the same correction the finding itself demanded: parse the
    thing, do not pattern-match its surface.
    """
    import ast

    redact_src = (REPO / "src" / "nexus" / "redact.py").read_text(encoding="utf-8")
    assert "_CONFUSABLE_RANGES" in redact_src, "confusables are a range rule, not a pair list"

    config_path = REPO / "src" / "nexus" / "config.py"
    config_src = config_path.read_text(encoding="utf-8")
    assert "urlsplit" in config_src, "URL validation parses rather than pattern-matches"

    for node in ast.walk(ast.parse(config_src)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "startswith" and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                and node.args[0].value.startswith("127")):
            raise AssertionError(
                f"{config_path.name}:{node.lineno} decides loopback by string prefix again — "
                "127.0.0.1.attacker.example is a routable domain anyone can register"
            )
