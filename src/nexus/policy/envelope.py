"""The signed policy envelope: verification, freshness, and what to believe when either fails.

Ported from ``nexus_devtools/policy_gate.py`` (``verify_envelope`` at :137, ``_apply_staleness``
at :273), with the canonicalisation kept byte-identical so that one signer serves both attach
points. If this file and the CLI's ever disagree about which bytes were signed, the symptom is an
envelope that verifies in one product and not the other — which presents as "enforcement randomly
stopped working" and takes a very long day to find.

Three states this module distinguishes, and the difference between them is the whole of case 6.5
and 6.6:

* **verified** — the control plane signed exactly these bytes. Honour it, subject to freshness.
* **unverified** — signed by the wrong key, not signed at all, or tampered with. This is *not*
  evidence of anything, in either direction. It becomes **no policy** plus an integrity alert.
  Deliberately not a deny: blocking on a bad signature turns one botched key rotation into a
  fleet-wide outage, and the fleet-wide outage is a worse day than the window of unenforced calls.
* **stale / expired** — verified, but old. Old is not the same as absent, and the asymmetry in
  ``freshness`` is where the fail-open/fail-closed split actually lives.

The one thing that never decays is a verified **deny on an enforce-marked rule**. If it decayed,
then "disconnect the pod from the control plane" would be the documented bypass for every control
we sell, and every enforcement claim in the product would carry a footnote saying so.

**Freshness is inside the signature, and it is mandatory.** It did not used to be. ``fetched_at``
was read off the *outer* object — the part nobody signs — and defaulted to "now" when absent, so
deleting one field from a captured envelope made it permanently FRESH. Anyone who could hand this
SDK bytes could therefore replay a validly-signed policy forever, or serve a policy issued before
a dangerous tool was denied and roll the fleet back to it. The whole staleness ladder was
decoration against an active attacker. Now the control plane signs ``issued_at`` as part of the
payload, an envelope without it is not usable at all, and a monotonic per-host high-water mark
refuses anything older than the newest envelope that host has already accepted.

Note what that changes about the *meaning* of staleness, and it is an improvement: the ladder now
measures how old the control plane's statement is, not how recently we happened to re-download the
same old bytes. Re-fetching a year-old policy every minute used to present as fresh forever.
"""
from __future__ import annotations

import json
import os
import threading
import time
import typing as t
from dataclasses import dataclass, field

from . import alerts, settings

#: Freshness states, ordered from most to least trustworthy.
FRESH = "fresh"
SOFT_STALE = "soft-stale"
HARD_STALE = "hard-stale"
EXPIRED = "expired"


def canonical(payload: t.Mapping) -> bytes:
    """The exact bytes the control plane signed.

    Sorted keys, no insignificant whitespace, and deliberately the most boring canonicalisation
    available. Both sides must agree byte-for-byte; anything clever here is a future
    interoperability bug with a cryptographic failure mode.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Envelope:
    """A loaded policy envelope and everything known about how much to trust it."""

    payload: dict = field(default_factory=dict)
    verified: bool = False
    #: Wall clock at which the *control plane* issued this policy, taken from ``payload["issued_at"]``
    #: and therefore covered by the signature. Wall clock rather than monotonic because an envelope
    #: outlives the process that fetched it — it is cached on disk — and monotonic does not survive
    #: a restart. There is deliberately no local "when did I download this" input to freshness: a
    #: number the holder of the bytes can choose is not a freshness statement, it is a request.
    issued_at: float = 0.0
    state: str = FRESH
    #: Why we have no usable payload, when we have none.
    problem: t.Optional[str] = None

    @property
    def present(self) -> bool:
        """True iff there is a payload we are willing to evaluate against.

        Unverified is *not* present. An envelope we cannot authenticate is treated exactly like an
        envelope we never received — which is what makes case 6.5 fail open rather than fail into
        whatever an attacker wrote in the file.
        """
        return bool(self.verified and self.payload)

    @property
    def rules(self) -> list:
        r = self.payload.get("rules")
        return r if isinstance(r, list) else []

    def age_s(self, now: t.Optional[float] = None) -> float:
        """Seconds since the control plane issued this policy. Infinite if that cannot be trusted.

        A clock moved *backwards* makes a cached envelope look newer than it is, which is the
        direction that helps whoever moved it — so a negative age is treated as maximally stale
        rather than maximally fresh. The same guard as ``policy_gate._cache_age``.
        """
        if not self.issued_at:
            return float("inf")
        age = (now if now is not None else time.time()) - self.issued_at
        return float("inf") if age < 0 else age


ABSENT = Envelope(payload={}, verified=False, state=EXPIRED, problem="absent")

#: Problem strings that are not really *signature* problems, mapped to the alert kind that sends an
#: operator to the right place. Anything not listed is a bad signature.
_PROBLEM_ALERTS = {
    "envelope is unsigned": alerts.UNSIGNED,
    "no policy public key is configured": alerts.NO_PUBKEY,
}

NO_KEY = "no policy public key is configured"
NO_ISSUED_AT = "envelope carries no signed issued_at"
ROLLED_BACK = "envelope is older than one already accepted"


def _resolved_key(pubkey_hex: t.Optional[str]) -> str:
    return pubkey_hex if pubkey_hex is not None else settings.current().pubkey_hex


def key_is_configured(key_hex: t.Optional[str]) -> bool:
    """True iff ``key_hex`` is a key at all.

    Absent, blank, wrong length, not hex, or all-zero are all *no key*. The all-zero case is the
    one that mattered: it used to be the shipped default on the theory that a nonsense key verifies
    nothing, and it verified 23.5% of forgeries because 32 zero bytes decompress to an order-4
    point. ``ed25519.verify`` now rejects that point on its own, so this function is the second of
    two independent locks — but it is also the *honest* one, because a deployment that set
    ``NEXUS_POLICY_FILE`` and forgot ``NEXUS_POLICY_PUBKEY`` should be told it has no key rather
    than be told its control plane's signature is bad.
    """
    k = (key_hex or "").strip()
    if not k:
        return False
    try:
        raw = bytes.fromhex(k)
    except ValueError:
        return False
    return len(raw) == 32 and any(raw)


def verify(raw: t.Any, *, pubkey_hex: t.Optional[str] = None) -> "tuple[t.Optional[dict], t.Optional[str]]":
    """Return ``(payload, problem)``. ``payload`` is non-None only for a valid signature.

    Every malformed input resolves to a problem string rather than an exception. Callers are all
    going to treat an exception as "do not trust this policy" anyway, and a verifier that can
    throw invites exactly one bare ``except`` too many.
    """
    from . import ed25519

    if not isinstance(raw, dict):
        return None, "envelope is not an object"
    payload = raw.get("policy")
    sig_hex = raw.get("signature")
    if not isinstance(payload, dict):
        return None, "envelope has no policy object"
    if not isinstance(sig_hex, str) or not sig_hex:
        return None, "envelope is unsigned"
    key_hex = _resolved_key(pubkey_hex)
    if not key_is_configured(key_hex):
        return None, NO_KEY
    try:
        signature = bytes.fromhex(sig_hex)
        pubkey = bytes.fromhex(key_hex)
    except ValueError:
        return None, "signature or public key is not hex"
    try:
        ok = ed25519.verify(pubkey, canonical(payload), signature)
    except Exception:  # noqa: BLE001 — a verifier that raises must still mean "do not trust"
        return None, "verification raised"
    if not ok:
        return None, "signature does not verify"
    return payload, None


def _issued_at(payload: t.Mapping) -> t.Optional[float]:
    """The signed issue time, or ``None`` if the envelope does not state one.

    ``issued_at`` is the name; ``iat`` is accepted because the control plane's JWT-shaped tooling
    spells it that way and one signer serves both attach points. ``bool`` is excluded explicitly —
    it is an ``int`` subclass in Python, and ``"issued_at": true`` becoming ``1.0`` would be a
    1970 timestamp that reads as maximally stale rather than as the malformed envelope it is.
    NaN, infinities and non-positive values are refused for the same reason: a freshness input we
    cannot compare is not a freshness input.
    """
    for name in ("issued_at", "iat"):
        v = payload.get(name)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")) or f <= 0:
            continue
        return f
    return None


def load(raw: t.Any, *, pubkey_hex: t.Optional[str] = None,
         now: t.Optional[float] = None) -> Envelope:
    """Verify ``raw``, check it is not a rollback, and classify its freshness.

    Raises an integrity alert on every downgrade. There is no ``fetched_at`` parameter any more,
    and its absence is the fix: freshness comes from the signed payload or the
    envelope is not usable. A caller that could supply the timestamp could also supply it for a
    captured envelope from last year.
    """
    payload, problem = verify(raw, pubkey_hex=pubkey_hex)
    if payload is None:
        alerts.raise_alert(_PROBLEM_ALERTS.get(problem or "", alerts.BAD_SIGNATURE),
                           problem or "unverifiable envelope")
        return Envelope(payload={}, verified=False, state=EXPIRED, problem=problem)

    issued = _issued_at(payload)
    if issued is None:
        # Verified, but it says nothing about when it was true. Treated exactly like an envelope we
        # could not authenticate: an attacker holding one validly-signed undated envelope would
        # otherwise hold a policy that is fresh forever.
        alerts.raise_alert(alerts.NO_FRESHNESS, NO_ISSUED_AT)
        return Envelope(payload={}, verified=False, state=EXPIRED, problem=NO_ISSUED_AT)

    if not _accept_high_water(_resolved_key(pubkey_hex), issued):
        alerts.raise_alert(alerts.ROLLBACK, ROLLED_BACK)
        return Envelope(payload={}, verified=False, state=EXPIRED, problem=ROLLED_BACK)

    env = Envelope(payload=payload, verified=True, issued_at=issued)
    return _classify(env, now=now)


# ------------------------------------------------------------------------------------------
# anti-rollback high-water mark
# ------------------------------------------------------------------------------------------
#
# **What it is.** The greatest ``issued_at`` this host has ever accepted under a given signing key.
# An envelope older than the mark is refused however well it verifies, which is what stops a
# captured-and-replayed envelope from rolling a fleet back to a policy issued before a dangerous
# tool was denied.
#
# **Where it lives, and why there.** Two tiers, and the split is the whole design:
#
# 1. *In process*, always, in ``_hwm`` below. Free, needs no filesystem, and covers the attack that
#    actually motivates this — swapping the policy file under a running pod. Nothing can disable it.
# 2. *On disk*, best effort, at ``settings.state_path`` or ``<envelope_path>.hwm``. This is what
#    survives a restart, so an attacker cannot simply wait for a deploy to reset the mark.
#
# It is keyed by public key, so a signing-key rotation starts a fresh ladder rather than locking the
# new key out behind the old key's timestamps.
#
# **Failure modes, stated rather than discovered later.**
#
# * *First run.* No file, mark is 0, everything is accepted. There is no history to detect a
#   rollback against, so the first envelope a host sees becomes its floor. Unavoidable, and the
#   reason this is a ratchet rather than a proof of freshness — ``expires_at`` and the staleness
#   ladder are what bound the very first envelope.
# * *Read-only filesystem, or no permission.* The write fails, ``STATE_UNWRITABLE`` is raised once,
#   and the in-process mark carries on alone. Protection narrows to the process lifetime; it never
#   turns into a failure to load policy. A governance SDK that refused to start because it could
#   not write a cache file would be uninstalled the same afternoon.
# * *Across a fleet.* The mark is per host, deliberately. Sharing it would put a network or
#   filesystem read on the policy-load path and would let one compromised host poison every other,
#   and it would make a rollback attack against a host that has *never seen* the newer policy — the
#   case a shared mark is supposed to cover — depend on that shared store being reachable, which is
#   exactly when it will not be. Per host means the attack window is "a host that has not yet seen
#   the newer policy", which the control plane closes by re-issuing rather than by us.
# * *An intentional rollback by an operator.* Re-serving old bytes will now be refused. Rolling back
#   is done by re-issuing the old rules with a new ``issued_at`` — which is also the only version of
#   a rollback that leaves an audit trail. The escape hatch for a host that has ratcheted too far is
#   deleting the state file, and ``NEXUS_POLICY_STATE=`` (empty) turns persistence off entirely.
# * *Equal timestamps are accepted.* Re-installing the same envelope after a restart, or a refresh
#   that returns identical bytes, must not fail. Replaying the *same* envelope therefore still
#   works — and grants nothing, because it is the same policy and, now that ``issued_at`` is
#   signed, it visibly ages: its ``allow`` rules decay to advisory and its enforcing denies stay.

_hwm_lock = threading.Lock()
_hwm: "dict[str, float]" = {}
_hwm_loaded: "set[str]" = set()
_hwm_unwritable = False


def _state_path() -> t.Optional[str]:
    s = settings.current()
    if s.state_path is not None:
        return s.state_path or None      # explicit empty string disables persistence
    return f"{s.envelope_path}.hwm" if s.envelope_path else None


def _read_state(key: str) -> float:
    path = _state_path()
    if not path:
        return 0.0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return 0.0
    if not isinstance(data, dict) or str(data.get("pubkey") or "").lower() != key:
        return 0.0          # a different signing key: rotation starts its own ladder
    v = data.get("issued_at")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return 0.0
    f = float(v)
    return f if f == f and f > 0 and f != float("inf") else 0.0


def _write_state(key: str, issued: float) -> None:
    global _hwm_unwritable
    path = _state_path()
    if not path:
        return
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pubkey": key, "issued_at": issued}, fh)
        os.replace(tmp, path)          # atomic: a torn mark would be worse than no mark
    except OSError as exc:
        if not _hwm_unwritable:
            _hwm_unwritable = True
            alerts.raise_alert(alerts.STATE_UNWRITABLE,
                               f"cannot persist rollback mark: {type(exc).__name__}")
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _accept_high_water(key_hex: str, issued: float) -> bool:
    """Ratchet. False means ``issued`` is behind the mark and the envelope must be refused."""
    key = (key_hex or "").strip().lower()
    with _hwm_lock:
        if key not in _hwm_loaded:
            _hwm_loaded.add(key)
            _hwm[key] = _read_state(key)
        mark = _hwm.get(key, 0.0)
        if issued < mark:
            return False
        advance = issued > mark
        if advance:
            _hwm[key] = issued
    if advance:
        _write_state(key, issued)
    return True


def high_water(pubkey_hex: t.Optional[str] = None) -> float:
    """The current mark for a key. Exposed for ``nexus doctor``-style checks and for tests."""
    key = (_resolved_key(pubkey_hex) or "").strip().lower()
    with _hwm_lock:
        if key not in _hwm_loaded:
            _hwm_loaded.add(key)
            _hwm[key] = _read_state(key)
        return _hwm.get(key, 0.0)


def reset_for_tests() -> None:
    global _hwm_unwritable
    with _hwm_lock:
        _hwm.clear()
        _hwm_loaded.clear()
        _hwm_unwritable = False


def _classify(env: Envelope, now: t.Optional[float] = None) -> Envelope:
    """Attach a freshness state. Separate from ``load`` so that a long-lived in-memory envelope
    can be re-classified as time passes without being verified again — verification is the
    expensive part and the bytes have not changed."""
    from dataclasses import replace

    s = settings.current()
    clock = now if now is not None else time.time()

    # An explicit expiry in the payload outranks our own ladder. The control plane knows things we
    # do not — a scheduled key rotation, a policy that is only valid for a maintenance window.
    exp = env.payload.get("expires_at")
    if isinstance(exp, (int, float)) and clock >= exp:
        alerts.raise_alert(alerts.EXPIRED, "envelope past expires_at")
        return replace(env, state=EXPIRED)

    age = env.age_s(clock)
    if age <= s.fresh_s:
        return replace(env, state=FRESH)
    if age <= s.soft_stale_s:
        return replace(env, state=SOFT_STALE)
    if age <= s.hard_stale_s:
        alerts.raise_alert(alerts.STALE, "envelope beyond soft-stale window")
        return replace(env, state=HARD_STALE)
    alerts.raise_alert(alerts.EXPIRED, "envelope beyond hard-stale window")
    return replace(env, state=EXPIRED)


def reclassify(env: Envelope, now: t.Optional[float] = None) -> Envelope:
    """Public re-classification, for an envelope held in memory across time."""
    if not env.verified:
        return env
    return _classify(env, now=now)


def load_file(path: str, *, pubkey_hex: t.Optional[str] = None,
              now: t.Optional[float] = None) -> Envelope:
    """Load an envelope from disk. An unreadable file is 'no policy', never a failure.

    Freshness comes from the signed ``issued_at`` inside the file — never from its mtime, which is
    reset by anything that copies the file into a container image and would present a year-old
    policy as freshly fetched on every deploy, and never from an unsigned outer field, which the
    holder of the file chooses.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        alerts.raise_alert(alerts.UNREACHABLE, f"cannot read policy file: {type(exc).__name__}")
        return Envelope(payload={}, verified=False, state=EXPIRED, problem="unreadable")
    return load(raw, pubkey_hex=pubkey_hex, now=now)
