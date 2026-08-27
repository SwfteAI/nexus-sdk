"""In-process scrubbing, before anything is queued.

Obfuscation happens at the source, never at the backend — the one thing from Datadog's design
worth copying without modification. Once a secret has left the process it has left the process;
"we redact on ingest" is a promise about someone else's infrastructure that the customer's security
review cannot verify.

This is a deliberately smaller redactor than the wrapper's ``nexus_devtools/redact.py``, and the
difference is a design decision rather than an omission. That one runs on a developer's laptop
against arbitrary shell output and can afford entropy heuristics and a wide pattern set. This one
runs on the request path of a production service, where the cost is paid per call by someone else's
end users — so it is a bounded set of anchored patterns plus key-name matching, all
``re``-compiled once, with no entropy scan over unbounded text.

The compensating control is that the **default tier is ``metadata_only``**: at T0 no free text is
transmitted at all, so redaction is a second line of defence rather than the only one. A call site
that says nothing about tier gets the safe behaviour — the same "conservative default" rule that
``events._wire_text`` enforces in the wrapper, and for the same reason: per-call-site redaction
leaks, because one path gets it and the next path added does not.

Case 5.8: **redaction failing must fail closed on the field, not on the event.** Dropping the whole
event because one string could not be scrubbed also drops the governance record, which is exactly
the record you most want when something odd is happening.
"""
from __future__ import annotations

import re
import typing as t
import unicodedata
from urllib.parse import urlsplit, urlunsplit

MASK = "[REDACTED]"

#: Opening markers of secrets whose pattern has **no bounded length**, so a match can require
#: arbitrarily many characters to complete. Everything else this module hunts (API keys, tokens)
#: is short and either matches inside the scan window or starts past the emitted prefix and is
#: truncated away regardless. See ``scan_window``.
_UNTERMINATED_MARKERS = ("-----BEGIN",)

#: A ``name =`` / ``name:`` opener. Used to answer the question the marker list above cannot:
#: *did the emitted prefix stop in the middle of somebody's secret?*
#:
#: The marker list was, for one release, the whole of that answer — a single-element tuple
#: holding ``-----BEGIN``, under a docstring claiming it "generalises to the next unterminated
#: pattern instead of enumerating this one". It did not. A 9 kB ``password = "…"`` runs past the
#: scan window, never meets its closing quote, matches no pattern, and shipped its first 280
#: characters with ``unfinished`` reading False. That is the scan-window defect exactly, reintroduced
#: by the bound that fixed the latency — the bound and the post-condition have to travel together or
#: the bound is itself the bypass.
#:
#: This is a post-condition on the output, which is what the docstring always claimed: the last
#: assignment visible in the emitted text is looked up in ``is_sensitive_key`` and, if the mask
#: does not follow it, the value ran past what we could scan. It needs no list of secret shapes,
#: so a vendor format nobody has invented yet is covered on the day it appears.
_ASSIGN_OPENER_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_\-]{0,63})\s*[:=]")

# Anchored, high-precision patterns. Order matters only in that longer forms come first.
_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"\bsk-ant-[A-Za-z0-9_\-]{16,}",                  # Anthropic
        r"\bsk-proj-[A-Za-z0-9_\-]{16,}",                 # OpenAI project keys
        r"\bsk-[A-Za-z0-9]{20,}",                         # OpenAI classic
        r"\bAIza[0-9A-Za-z_\-]{30,}",                     # Google API
        r"\bAKIA[0-9A-Z]{16}\b",                          # AWS access key id
        r"\bASIA[0-9A-Z]{16}\b",                          # AWS temporary key id
        r"\bgh[pousr]_[A-Za-z0-9]{20,}",                  # GitHub
        r"\bxox[baprs]-[A-Za-z0-9\-]{10,}",               # Slack
        r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",   # JWT
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        r"\bhf_[A-Za-z0-9]{20,}",                         # HuggingFace
        # The set above was chosen from the LLM-vendor list, which is the wrong axis:
        # this SDK watches agents *calling tools*, and the credential an agent hands a tool is a
        # payments key or a package-registry token far more often than it is a model key. Each of
        # these was measured leaking through `redact()` in full before being added.
        r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}",                        # Stripe secret/restricted
        r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}",                 # SendGrid
        r"\bnpm_[A-Za-z0-9]{30,}",                                        # npm automation token
        r"\bpypi-[A-Za-z0-9_\-]{32,}",                                    # PyPI API token
        r"\bglpat-[A-Za-z0-9_\-]{20}",                                    # GitLab PAT
        r"\bdop_v1_[a-f0-9]{64}",                                         # DigitalOcean
        # Deliberately NOT here: bare 32-hex. It is the shape of an Azure key and also the shape of
        # every MD5 in every log line this SDK will ever see, and a rule that masks content hashes
        # deletes the record it exists to protect. `sk_test_` IS included alongside `sk_live_`: a
        # test key is still a credential, and telling them apart is the customer's job, not ours.
    )
]

# The words that make a *name* sensitive, written once. Two rules consume this alternation — the
# ``key=value`` rule that runs over prose, and the key-name rule that runs over mapping keys — and
# they are deliberately two separately compiled patterns rather than one built out of the other.
# An earlier defect was exactly that mistake: the key-name test was spelled
# ``_SENSITIVE_KEY.match(f"{key}=")``, feeding a bare name into a pattern whose third group requires
# four characters of *value* after the separator, so it returned False for every key that has ever
# existed and structured masking was dead code from the first commit. A name is a whole string; a
# ``key=value`` is a fragment inside a sentence. Sharing the vocabulary keeps the two from drifting.
# Building one from the other makes one of them a no-op.
_SENSITIVE_WORDS = (
    r"api[_\-]?key|secret|token|password|passwd|passphrase|credential|"
    r"authorization|session[_\-]?id|private[_\-]?key|access[_\-]?key|cookie|"
    # Half one. These are safe as substrings — no ordinary English or field-name word
    # contains them — so they live here rather than in the segment list below. The test for
    # membership is not "is this secret" but "can this word appear inside an innocent name":
    # `cvv` cannot, `pin` can (`shipping`), and that is the whole basis for the split.
    r"mnemonic|totp|cvv|cvc|mfa[_\-]?code|recovery[_\-]?code|seed[_\-]?phrase"
)

#: Words sensitive only as a **whole segment** of a name. ``auth`` is the whole list, and it is
#: separated out because as a substring it also condemns ``author`` and ``authored_by`` — which are
#: not secrets, and are precisely the fields a governance ledger exists to carry. A rule that masks
#: the author of a deploy has stopped protecting anything and started deleting the record.
#: Half two. Each of these condemns a value but appears inside innocent names:
#: `pin` inside `shipping`, `otp` inside `dotproduct`, `dob` inside `dobson`. Segment-scoping is
#: what makes them affordable. Deliberately absent, having been considered and rejected:
#: `pass` (`pass_rate`, `first_pass` are metrics, and `password`/`passwd`/`passphrase` already
#: cover the credential), `salt`, `nonce` and `sig` (public by construction — masking a signature
#: deletes the governance record without protecting anything), and `refresh` (`refresh_token` is
#: already caught by `token`; `refresh` alone is an interval).
_SEGMENT_WORDS = r"auth|pwd|pin|otp|ssn|dob|jwt|bearer"

# `KEY=value` / `"key": "value"` / `--token value` / `Authorization: Bearer …`
# Prose, so ``auth`` stays in: ``auth = hunter2hunter2`` in a log line is a credential whatever the
# surrounding sentence is, and the value group's four-character floor keeps it off ordinary text.
#
# The two vocabularies are spelled with the scope each one requires, in BOTH rules. Splicing the
# segment words in as bare substrings here — which is what this line used to do, when the list was
# just ``auth`` and it did not matter — makes `pin` mask `shipping: 12345` and `otp` mask
# `dotproduct = 0.9871`. A word has to mean the same thing to the prose rule and the key-name rule
# or the two drift, which is the defect the shared vocabulary exists to prevent.
_SEGMENT_IN_NAME = (r"(?:[A-Za-z0-9]+[_\-])*(?:" + _SEGMENT_WORDS + r")(?:[_\-][A-Za-z0-9]+)*")
_SENSITIVE_KEY = re.compile(
    r"(?i)\b(" + _SEGMENT_IN_NAME + r"|[A-Za-z0-9_\-]*(?:" + _SENSITIVE_WORDS + r")[A-Za-z0-9_\-]*)"
    r"(\s*[:=]\s*|\s+)"
    r"(\"[^\"]{4,}\"|'[^']{4,}'|[^\s,;'\"}\)]{4,})"
)

#: A mapping key whose *name* alone condemns its value. Anchored end to end, over a character class
#: that includes ``.``: the whole key must be the sensitive word plus optional affixes, so
#: ``x-api-key``, ``AWS_SECRET_ACCESS_KEY`` and ``db_password`` match while ``headers`` does not —
#: that one is recursed into instead.
_SENSITIVE_NAME = re.compile(
    r"(?i)\A[A-Za-z0-9_\-.]*(?:" + _SENSITIVE_WORDS + r")[A-Za-z0-9_\-.]*\Z"
)

#: The segment-scoped rule: the word must occupy whole ``_``/``-``/``.``-delimited segments of the
#: name. ``auth``, ``auth_token`` and ``req.auth`` match; ``authored_by`` does not.
_SENSITIVE_SEGMENT = re.compile(
    r"(?i)\A(?:[A-Za-z0-9]+[_\-.])*(?:" + _SEGMENT_WORDS + r")(?:[_\-.][A-Za-z0-9]+)*\Z"
)

_BEARER = re.compile(r"(?i)\b(bearer|basic|token)\s+([A-Za-z0-9._\-+/=]{8,})")

# userinfo in a URL: https://user:pass@host/…
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/@\s:]+):([^/@\s]+)@")

# --------------------------------------------------------------------------------------------
# Personal data — the *second* line of defence, never the first.
#
# The first line is the tier: at ``metadata_only`` no free text reaches the wire at all, so none of
# the patterns below has to be right for the default configuration to be safe. They earn their
# place at T1/T2, where a customer has consciously opted into content and still should not ship a
# card number by accident.
#
# The set is small and anchored, for the reason in the module docstring: this runs on someone
# else's request path. It is also, by construction, incomplete — ``John Doe`` is not recognisable
# by any regular expression, and a field that names a patient will always leak at T2. That is an
# argument for the tier gate being the primary control, not for a longer pattern list here.
# --------------------------------------------------------------------------------------------
#: Unicode dashes. A card number pasted out of a word processor, a PDF or a CRM arrives with
#: U+2011 (non-breaking hyphen) or U+2013 (en dash) where the author typed a hyphen, and to the
#: reader it is identical. Written as a character class rather than by normalising the input,
#: because normalising would change the very text we are about to emit — NFKC is not
#: length-preserving, so every match offset would then be an offset into a string the caller never
#: gave us. Widening the class costs nothing and keeps the output byte-faithful.
_DASHES = "\\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uff0d"

#: The TLD class was ASCII-only, so `jane@example.\u4e2d\u56fd` — an internationalised domain,
#: ordinary in half the world — was not an email address as far as this rule was concerned.
#: ``[^\W\d_]`` is "a letter in any script", which is what the rule meant all along.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[^\W\d_0-9](?:[\w.\-]*\w)?"
                    r"\.[^\W\d_]{2,24}\b", re.UNICODE)
#: US SSN and the national-ID shapes that share its form. Applied before the phone rules, which
#: overlap it; the more specific rule must win.
#:
#: The separator is now any of space / dot / dash, but **the same one twice** — the
#: backreference is what keeps this off `123 45-6789`-shaped coincidences and, more importantly,
#: off arbitrary digit soup. A bare `123456789` is deliberately NOT matched: nine digits with no
#: separator is also every order id, every epoch-ish counter and every autoincrement primary key
#: in the corpus, and a rule that masks all of them stops being a redactor and starts being a
#: censor. The tier gate is the control for the bare form; this is the second line.
_NATIONAL_ID = re.compile(r"(?<![\d" + _DASHES + r"])\d{3}([ ." + _DASHES + r"])\d{2}\1\d{4}"
                          r"(?![\d" + _DASHES + r"])")

#: IBAN. Gated on the ISO 7064 mod-97 checksum for the same reason ``_CARD`` is gated on Luhn:
#: the shape alone (two letters, two digits, alphanumerics) matches product SKUs and git refs.
_IBAN = re.compile(r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b")
#: E.164 and the written NANP forms. The lookarounds keep it off version strings and durations.
_PHONE = re.compile(
    r"(?<![\w.\-])(?:\+\d{1,3}[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}"
    # An extension has to be *consumed*, not merely tolerated. The trailing
    # ``(?![\w\-])`` is doing real work — it is what keeps this rule off version strings — so it
    # cannot simply be relaxed; the extension must be part of the match instead. Without this,
    # `415.555.2671x22` was not a phone number, and a direct line with an extension is more
    # identifying than one without, not less.
    r"(?:[ ]?(?:x|ext\.?|extension)[ ]?\d{1,6})?(?![\w\-])"
    r"|(?<![\w.\-])\+\d{9,15}(?![\w\-])"
)
#: Payment-card candidates. Shape alone over-matches every long integer in a log line, so a
#: candidate is masked only once it passes Luhn — precision bought for a few microseconds.
_CARD = re.compile(r"(?<![\d" + _DASHES + r"])(?:\d[ ." + _DASHES + r"]?){12,18}\d"
                   r"(?![\d" + _DASHES + r"])")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_card(m: "re.Match") -> str:
    digits = "".join(c for c in m.group(0) if c.isdigit())
    return MASK if 13 <= len(digits) <= 19 and _luhn(digits) else m.group(0)


def _iban_ok(s: str) -> bool:
    """ISO 7064 mod-97: rotate the first four characters to the end, letters as A=10..Z=35, %97==1.

    Same role as ``_luhn`` — it turns a shape that over-matches into a rule precise enough to run
    on someone else's request path. `GB29NWBK60161331926819` passes; `DE49PRODUCTSKU12345` does
    not, and neither does a git ref that happens to start with two letters and two digits.
    """
    s = s.upper()
    rotated = s[4:] + s[:4]
    try:
        n = int("".join(str(ord(c) - 55) if c.isalpha() else c for c in rotated))
    except ValueError:
        return False
    return n % 97 == 1


def _mask_iban(m: "re.Match") -> str:
    return MASK if _iban_ok(m.group(0)) else m.group(0)


#: ``(pattern, replacement)``; the replacement is either the mask or a callable that decides.
#: IBAN runs before ``_CARD``: an IBAN's digit run can be long enough for the card rule to
#: consider it, and the more specific rule must win — the same ordering argument as
#: ``_NATIONAL_ID`` before ``_PHONE``.
_PII_RULES: t.Sequence[t.Tuple["re.Pattern", t.Any]] = (
    (_EMAIL, MASK),
    (_NATIONAL_ID, MASK),
    (_IBAN, _mask_iban),
    (_CARD, _mask_card),
    (_PHONE, MASK),
)


def redact(text: str) -> t.Tuple[str, bool]:
    """Return ``(scrubbed, was_redacted)``. Never raises: see case 5.8."""
    if not text:
        return text or "", False
    try:
        out = str(text)
        before = out
        for pat in _PATTERNS:
            out = pat.sub(MASK, out)
        out = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{m.group(2)}:{MASK}@", out)
        out = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", out)
        out = _SENSITIVE_KEY.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", out)
        for pat, repl in _PII_RULES:
            out = pat.sub(repl, out)
        return out, out != before
    except Exception:  # noqa: BLE001
        # Fail closed on the field. The caller keeps its event; this one string becomes the mask.
        return MASK, True


#: A path segment that carries a secret rather than naming a resource. Two shapes, both
#: measured against the corpus of paths this SDK actually sees:
#:
#: * twelve or more characters containing **both** a letter and a digit — `TOKEN123ABCDEF`,
#:   `ORD-2026-0012`, a base62 invite code. Requiring both is what keeps `messages`, `completions`
#:   and `pancreatic-carcinoma` out of it; requiring twelve is what keeps `v1` and `2026-08-27`
#:   out.
#: * thirty-two or more characters of anything path-safe — the length alone is the tell, whatever
#:   the alphabet.
#:
#: Numeric-only segments are deliberately kept. `/users/12345` is a resource id, it is what makes
#: a path groupable, and it is the same judgement ``_identifier`` makes in ``otel/semconv.py``.
_PATH_TOKEN = re.compile(
    r"\A(?=[A-Za-z0-9._~\-]{12,}\Z)(?=[^A-Za-z]*[A-Za-z])(?=[^0-9]*[0-9])[A-Za-z0-9._~\-]+\Z"
    r"|\A[A-Za-z0-9._~\-]{32,}\Z"
)


def _safe_path(path: str) -> str:
    """The path with token-shaped segments masked, then run through ``redact``.

    ``safe_url`` dropped the query string and kept the path, on the reasoning that a query
    string is free text and a path is structure. Half right: single-use credentials live in paths
    far more often than in queries — ``/reset/<token>``, ``/invite/<token>``, ``/verify/<token>``
    are the standard shape of every password-reset email ever sent — and this function was the
    thing telemetry called to make a URL safe to store.

    Both steps are needed and neither subsumes the other. ``redact`` catches a JWT or an API key
    sitting in a path, because those have recognisable shapes; it cannot catch
    ``/reset/TOKEN123ABCDEF``, because a random opaque string has no shape to recognise. The
    segment rule catches exactly that, by position and entropy-ish shape rather than by pattern.
    """
    return redact("/".join(MASK if _PATH_TOKEN.match(seg) else seg
                           for seg in path.split("/")))[0]


def safe_url(u: str) -> str:
    """scheme + host + path. Query, fragment and userinfo are dropped.

    A URL stops being metadata the moment it has a query string: ``?q=…`` is free text of exactly
    the class the tier gate just refused to store, and password-reset / magic links carry
    single-use tokens that no pattern above can recognise.
    """
    try:
        parts = urlsplit(str(u))
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, _safe_path(parts.path), "", ""))
    except Exception:  # noqa: BLE001
        return MASK


#: Key names whose numeric value describes the *operation* rather than the subject of it. These
#: are the numbers telemetry exists to carry, and they are what makes the tier gate affordable —
#: without them ``metadata_only`` would emit no measurements at all and nobody would leave it on.
#:
#: An allowlist, not a denylist, and that direction is the whole point. A denylist of sensitive
#: numeric names has to anticipate ``ssn``, ``mrn``, ``iban``, ``lat``, ``salary`` and whatever the
#: next customer's schema calls them; it fails open on the first one nobody thought of. This fails
#: closed: an unrecognised numeric key is masked, and the cost of being wrong is one masked metric
#: that somebody notices and adds here.
_STRUCTURAL_NUMBER_KEYS = frozenset({
    "attempt", "attempts", "batch", "capacity", "code", "concurrency", "count", "depth",
    "dropped", "duration", "elapsed", "errors", "exit_code", "failures", "hits", "index",
    "iteration", "length", "limit", "lines", "misses", "offset", "page", "pending", "port",
    "position", "priority", "queued", "retries", "rows", "size", "status", "status_code",
    "step", "timeout", "tokens", "total", "version", "weight",
})

#: Suffixes that make a numeric key structural whatever its stem: ``upload_bytes``,
#: ``render_duration_ms``, ``retry_count``. Matching on the suffix rather than the whole name is
#: what keeps the allowlist from needing an entry per metric a customer invents.
_STRUCTURAL_NUMBER_SUFFIXES = (
    "_bytes", "_count", "_duration", "_elapsed", "_index", "_len", "_length", "_limit", "_ms",
    "_ns", "_offset", "_pct", "_percent", "_rate", "_ratio", "_retries", "_rows", "_s",
    "_seconds", "_size", "_status", "_total", "_us",
)


def _is_structural_number_key(key: str) -> bool:
    """Whether a numeric value under this key is a measurement rather than a fact about a person.

    Deliberately conservative: it decides on the *name*, which is the only evidence available, and
    a name is weak evidence. ``lat``/``lon``, ``ssn``, ``card`` and ``balance`` are absent and
    therefore masked below ``full``; ``duration_ms`` and ``rows`` are present and survive.
    """
    k = key.strip().lower()
    return k in _STRUCTURAL_NUMBER_KEYS or k.endswith(_STRUCTURAL_NUMBER_SUFFIXES)


def _is_structural_number_key_for_sequence(key: str) -> bool:
    """The same question for the elements of a *list* under this key — and a stricter answer.

    A list element has no name of its own, so it can only inherit its parent key's verdict. But
    the two halves of the allowlist do not survive that inheritance equally, and treating them as
    if they did is how ``{"rows": [123456789, 4111111111111111]}`` would ship at
    ``metadata_only``:

    * The **suffix** half names a *unit* — ``_ms``, ``_bytes``, ``_pct``, ``_seconds``. A unit
      means the same thing whether the key holds one measurement or a hundred, so
      ``durations_ms: [12, 15, 402]`` is exactly as structural as ``duration_ms: 12``. These
      inherit.
    * The **bare-name** half names a *quantity* — ``count``, ``rows``, ``batch``, ``depth``.
      Under a scalar that is the tally; under a list it is the things being tallied, which is the
      opposite of structural. ``rows: 400`` is a measurement, ``rows: [...]`` is the data. These
      do not inherit.

    So the fail-closed direction here is stricter than for scalars, and it is stricter for a
    reason that can be stated rather than tuned.
    """
    return key.strip().lower().endswith(_STRUCTURAL_NUMBER_SUFFIXES)


#: Codepoint ranges for the scripts whose letterforms are confusable with ASCII: Cyrillic and
#: Greek. Named as *classes* rather than as a list of homoglyph characters, because a list of
#: characters is a list and the attacker picks the character — the same argument that replaced
#: ``host.startswith("127.")`` with a parse in ``config._is_loopback``.
_CONFUSABLE_RANGES = ((0x0370, 0x03FF), (0x0400, 0x052F), (0x1F00, 0x1FFF))


def _has_confusable_script(name: str) -> bool:
    """Whether ``name`` mixes ASCII letters with Cyrillic or Greek ones.

    ``аpi_key`` with a Cyrillic ``а`` renders identically to ``api_key`` and matches neither
    pattern, so the value ships. NFKC does not help: Cyrillic ``а`` and Latin ``a`` are different
    letters in different scripts, not compatibility variants of one letter, and Unicode is right
    about that.

    So this asks a different question — not "is this character a homoglyph" but "is this name
    written in one script". A field name that mixes ASCII with Cyrillic is mojibake or an attack;
    it is not a name a developer typed on purpose. Fails closed on the mix.

    Only these two scripts are named, and only against ASCII. A name written wholly in Cyrillic,
    Greek, Japanese or Arabic is somebody's ordinary field name and is left entirely alone — the
    rule is about the *mixture*, which is the thing that has no innocent reading.
    """
    has_ascii = has_confusable = False
    for ch in name:
        if not ch.isalpha():
            continue
        o = ord(ch)
        if o < 128:
            has_ascii = True
        elif any(lo <= o <= hi for lo, hi in _CONFUSABLE_RANGES):
            has_confusable = True
        if has_ascii and has_confusable:
            return True
    return False


def is_sensitive_key(key: t.Any) -> bool:
    """Does this mapping key's *name* alone condemn its value?

    Split out of ``scrub_mapping`` and made public-ish so it is directly testable. The defect it
    replaces could not be tested through ``scrub_mapping`` alone without also asserting on the
    value, which is why nothing caught it.

    Fails closed: an unrepresentable key is treated as sensitive. Masking a harmless value costs a
    field; not masking a harmful one costs a credential.

    **The name is normalised before it is matched, and that is a bug fix rather than a courtesy.**
    Both patterns are anchored ``\\A…\\Z`` over a character class that excludes whitespace, so
    ``"API_KEY "`` — one trailing space — failed the match outright and shipped the value. Keys
    arrive with stray whitespace constantly: parsed headers, CSV columns, YAML round-trips,
    hand-written JSON. NFKC additionally folds the compatibility forms (fullwidth ``ａｐｉ＿ｋｅｙ``
    is the same key wearing a different codepoint).
    """
    try:
        name = unicodedata.normalize("NFKC", str(key)).strip()
        if _has_confusable_script(name):
            return True
        return bool(_SENSITIVE_NAME.match(name) or _SENSITIVE_SEGMENT.match(name))
    except Exception:  # noqa: BLE001
        return True


#: How much text ``wire_text`` scans before truncating. Redacting the whole input and then keeping
#: 256 characters made eleven regexes walk a megabyte to produce a tweet (~0.18 s for
#: 1 MB, charged to someone else's request). Scanning a window slightly wider than the limit keeps
#: the cost constant while leaving room for a secret that straddles the cut — truncating first,
#: exactly at the limit, would slice a key in half and ship the surviving prefix.
_SCAN_OVERSCAN = 4096


def wire_text(text: t.Optional[str], tier: str, limit: int = 512) -> t.Optional[str]:
    """The single gate every free-text field passes through — the SDK's ``events._wire_text``.

    It lives in one function rather than at the call sites because that is precisely how these
    fields leaked in the wrapper: one shell command was redacted on the ``tool_action`` path and
    shipped raw on three others. A gate here cannot be forgotten by the next call site.

    **Three tiers, three branches.** The version this replaces had three tiers and two: T0 and T1
    shared the redact-and-truncate path, so the default tier — the one a call site that says
    nothing about tier gets, the one the module docstring above calls the compensating control —
    emitted customer free text. At T0 this now returns ``None``, and ``contract.base``
    drops keys whose value is ``None``, so the field is *absent* rather than blanked: a reader can
    tell "no content was captured" from "the content was empty".

    Returning ``None`` also means a *new* tier, or a typo, degrades to silence rather than to
    egress. That is the only failure direction worth having here.

    Callers that want shape at T0 rather than nothing — a length, a fingerprint — should use
    ``contract.tiered_text``, which is where the five contract fields that used to call this
    function now go. This remains as the last-resort gate for anything that only wants a string.
    """
    from .config import TIER_FULL, TIER_HASHED
    if not text:
        return text
    if tier not in (TIER_FULL, TIER_HASHED):
        return None                                   # T0, and anything unrecognised
    # One implementation of the window and of the unfinished-scan post-condition, shared with
    # ``contract._rungs`` — see ``scan_window``. It used to live here and only here, which is
    # exactly why the tier ladder had neither.
    out, _was, unfinished = scan_window(text, limit)
    return MASK if unfinished else out


#: Ceiling on how much text is scanned when the caller asked for no truncation at all
#: (``contract.redact_preview`` at T2 passes ``full_limit=None``). Some bound has to exist or the
#: absence of a limit is an unbounded regex walk on the caller's request thread; 64 KiB is far
#: above any free-text field a sane caller emits and far below the point where the walk is felt.
_FULL_SCAN_CEILING = 65_536


def scan_window(text: str, limit: t.Optional[int]) -> t.Tuple[str, bool, bool]:
    """Redact with a bounded scan. Returns ``(scrubbed, was_redacted, unfinished)``.

    The single implementation of the two rules ``wire_text`` learned the hard way, so the tier
    ladder in ``contract._rungs`` cannot hold a different opinion about either one:

    * **Scan a bounded window, not the whole input.** Redacting a 20 MB
      string to produce a 280-character preview walked every pattern over all 20 MB. Measured at
      10 s of CPU on the caller's thread — a latency defect that ``wire_text`` fixed and the
      ladder never got, so ``contract.tiered_text`` still cost 13.5 s where ``redact.wire_text``
      cost 0.003 s on the same input.
    * **Never emit the prefix of something you could not finish scanning.** The overscan
      covers a secret straddling the cut. It cannot cover one *longer than the window*, because a
      PEM needs its ``-----END`` terminator before the pattern fires — so the first ``limit``
      characters, which are the start of the key, shipped untouched. ``unfinished`` reports that,
      and every caller turns it into a mask.

    ``unfinished`` is a post-condition on the *output* rather than a guess about the input, so it
    generalises to the next unterminated pattern instead of enumerating this one. That sentence
    stood over a one-element tuple for a release and was not true; see ``_ASSIGN_OPENER_RE``. It
    is true now, and the test that says so is the one that caught it.

    Two questions are asked of the emitted text, not of the input:

    * does an unbounded-length opener survive in it (a PEM header), and
    * does the last assignment in it name something sensitive with no mask after it — meaning the
      value is still running when the output stops.

    Both are linear in the emitted prefix, which is already bounded by ``limit``, so neither costs
    anything the bound was introduced to save.
    """
    text = str(text)
    window = _FULL_SCAN_CEILING if limit is None else limit + _SCAN_OVERSCAN
    truncated = len(text) > window
    scrubbed, was = redact(text[:window])
    if limit is not None:
        scrubbed = scrubbed[:limit]
    unfinished = any(marker in scrubbed for marker in _UNTERMINATED_MARKERS)
    if not unfinished and truncated:
        last = None
        for last in _ASSIGN_OPENER_RE.finditer(scrubbed):
            pass
        if last is not None and is_sensitive_key(last.group(1)):
            unfinished = MASK not in scrubbed[last.end(1):]
    return scrubbed, was, unfinished


def scrub_mapping(data: t.Optional[dict], tier: str, *, max_keys: int = 32,
                  limit: int = 256, max_depth: int = 6) -> dict:
    """Structured redaction — case 5.5, the common miss.

    Tool arguments and structured outputs are dicts, not prompt strings, and a redactor that only
    walks free text passes an API key straight through when it arrives as ``{"headers":
    {"Authorization": "Bearer …"}}``. Bounded in width and depth so a pathological payload cannot
    turn scrubbing into the slow part of a request.

    Three things changed here:

    * The key-name test is ``is_sensitive_key(key)`` rather than a ``key=value`` pattern fed a
      valueless string. See the comment on ``_SENSITIVE_WORDS``.
    * A sensitive *name* now masks the whole value whatever its type. ``{"api_key": 12345678}`` and
      ``{"auth": {"token": "…"}}`` are both condemned by the name; descending into them to scrub
      the leaves would emit the shape of a credential, and a credential's shape is a credential.
      This over-approximates — a field named ``token_count`` masks a harmless integer — and that
      trade is deliberate: a false positive costs one number, a false negative costs a secret.
    * ``max_depth`` exists. The docstring claimed the walk was bounded in depth and it was not;
      recursion was capped only by the interpreter's stack.

    At T0 string values are dropped rather than blanked, for the reason in ``wire_text``: the tier
    says no free text, and an absent key reads as "not captured" where ``None`` reads as "empty".
    Numbers, booleans and ``None`` survive every tier — a row count is not content.
    """
    if not isinstance(data, dict) or max_depth <= 0:
        return {}
    out: dict = {}
    for k, v in list(data.items())[:max_keys]:
        key = str(k)[:64]
        if is_sensitive_key(key):
            out[key] = MASK
            continue
        if isinstance(v, dict):
            out[key] = scrub_mapping(v, tier, max_keys=max_keys, limit=limit,
                                     max_depth=max_depth - 1)
        elif isinstance(v, (list, tuple)):
            # The key's verdict travels with its elements, but only the half of it that
            # survives the trip — see ``_is_structural_number_key_for_sequence``. Without any
            # inheritance a list under ``durations_ms`` would have every measurement masked
            # below ``full``, and the allowlist exists precisely so ``metadata_only`` still
            # carries numbers somebody will look at.
            out[key] = [_scrub_item(i, tier, max_keys, limit, max_depth - 1,
                                    numbers_ok=_is_structural_number_key_for_sequence(key))
                        for i in list(v)[:16]]
        elif v is None or isinstance(v, bool):
            # ``bool`` first: ``isinstance(True, int)`` is True, so testing int first would
            # classify every boolean as a number and route it through the allowlist below.
            out[key] = v
        elif isinstance(v, (int, float)):
            # A number's Python type says nothing about its sensitivity. `metadata_only`
            # promises no content, and `{"ssn": 123456789, "card": 4111111111111111}` came through
            # every tier unchanged while the same values as *strings* were correctly dropped —
            # a type-confusion hole, not a policy decision.
            #
            # `otel/semconv.py::shape_of` already resolves this exact question on the
            # auto-instrumentation path, reducing every number to `{"type": "number"}` because a
            # number can be "a zip code, a member of a five-value enum" and is "recoverable by
            # trying every input". This is the manual path agreeing with it.
            from .config import TIER_FULL
            if tier == TIER_FULL or _is_structural_number_key(key):
                out[key] = v
            else:
                out[key] = MASK
        else:
            scrubbed = wire_text(str(v), tier, limit)
            if scrubbed is not None:
                out[key] = scrubbed
    return out


def _scrub_item(item: t.Any, tier: str, max_keys: int, limit: int, max_depth: int,
                *, numbers_ok: bool = False) -> t.Any:
    """One element of a list.

    Dicts nested in lists used to be stringified, which turned a mapping the key-name
    rule could have masked into prose only the value rules could see. That was fixed for a dict
    sitting *directly* in a list and nowhere else, so the hole moved down one level rather than
    closing: ``{"batch": [[{"api_key": "…"}]]}`` and ``{"batch": [({"password": "…"},)]}`` both
    reached ``str(item)`` and shipped the credential verbatim at ``hashed`` and ``full``. A list
    of lists is not exotic — it is a batch insert, a JSON-RPC batch, a paged tool result.

    Fixing it at the level it was found (one more ``isinstance`` for the two-deep case)
    would have moved the hole to three deep. The container types recurse into each other now, and
    the depth budget is what stops it, which is what ``max_depth`` was always for.

    **The number branch is the same hole closed on the mapping side, still open on this
    one.** ``scrub_mapping`` learned that a number's Python type says nothing about its
    sensitivity; ``_scrub_item`` did not, so ``{"rows": [123456789, 4111111111111111]}`` came
    through ``metadata_only`` — the tier that promises no content — completely unchanged. A list
    element has no key of its own to judge, so it inherits its parent key's verdict.
    """
    if max_depth <= 0:
        return MASK
    if isinstance(item, dict):
        return scrub_mapping(item, tier, max_keys=max_keys, limit=limit, max_depth=max_depth)
    if isinstance(item, (list, tuple)):
        return [_scrub_item(i, tier, max_keys, limit, max_depth - 1, numbers_ok=numbers_ok)
                for i in list(item)[:16]]
    if item is None or isinstance(item, bool):
        # ``bool`` before ``int``: ``isinstance(True, int)`` is True. Same ordering as
        # ``scrub_mapping``, same reason.
        return item
    if isinstance(item, (int, float)):
        from .config import TIER_FULL
        return item if (tier == TIER_FULL or numbers_ok) else MASK
    return wire_text(str(item), tier, limit)
