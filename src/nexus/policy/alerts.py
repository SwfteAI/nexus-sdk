"""Integrity alerts — the visibility half of every fail-open in this package.

Case 6.5 is two clauses and the second one is what makes the first one safe. *"Treat an invalid
signature as no policy"* on its own is a silent downgrade: the day someone rotates the signing key
badly, every rule in the fleet stops applying and nothing anywhere says so. Enforcement quietly
becomes advice, and the first person to notice is whoever reads the incident report about the
thing that should have been blocked.

So the rule is: **every path in this package that resolves an uncertainty in the permissive
direction raises an alert here.** Bad signature, expired envelope, malformed rule, exceeded
latency budget, approval timeout, unreachable control plane. The fail-open keeps the customer's
service up; the alert is the reason it does not stay broken.

Alerts go three places, deliberately:

1. an in-process ring buffer, readable synchronously — so ``nexus doctor``-style checks and the
   test suite can assert on them without a collector;
2. any sink registered by the host;
3. the event pipeline, as a ``policy_alert`` event, best-effort.

**Those three destinations are not the same trust boundary, and this module is where they stop
being treated as one.** (1) and (2) stay inside the customer's process; (3) leaves it. So an alert
carries its full detail locally — an operator running ``nexus doctor`` on the host sees the whole
message — and a *reduced projection* of itself on the wire. See :func:`_wire_fields`, which is the
only place in this package that decides what an alert may say to a collector.

The ring is bounded and deduplicated by ``(kind, detail)``. An SDK that emitted one alert per
request for a rotated key would turn a signing mistake into a second, louder outage — the same
log-amplification reasoning as ``_safety._contain``, which warns once per hook name. What is
recorded here instead is first-seen, last-seen and a count.
"""
from __future__ import annotations

import re
import threading
import time
import typing as t
from dataclasses import dataclass, field

#: Alert kinds. Literals, so a typo is an ImportError at build time rather than an alert nobody
#: ever greps for.
BAD_SIGNATURE = "policy.bad_signature"
UNSIGNED = "policy.unsigned"
#: No signing key is configured, so an envelope cannot be authenticated at all. Distinct from
#: ``BAD_SIGNATURE`` on purpose: there is nothing wrong with the signature, we simply have nothing
#: to check it against, and an operator chasing a key-rotation bug should not be sent to the wrong
#: place. This is the state a deployment lands in when it sets ``NEXUS_POLICY_FILE`` and forgets
#: ``NEXUS_POLICY_PUBKEY``.
NO_PUBKEY = "policy.no_pubkey"
#: The envelope verified but carries no signed issue time, so its freshness is unknowable. See
#: ``envelope._issued_at``.
NO_FRESHNESS = "policy.no_freshness"
#: The envelope verified but is older than the newest one this host has already accepted under the
#: same key — a replay or a rollback. See ``envelope._accept_high_water``.
ROLLBACK = "policy.rollback"
#: The anti-rollback high-water mark could not be persisted (read-only filesystem, no permission).
#: Enforcement continues on the in-process mark alone; the protection is simply narrower.
STATE_UNWRITABLE = "policy.state_unwritable"
#: An envelope we could not authenticate was refused as a *replacement* for one we already had.
#: The old policy is still in force. Without this, handing the SDK a garbage file would be a
#: cheaper disarm than forging a signature.
REJECTED_REPLACEMENT = "policy.rejected_replacement"
#: Enforcement is switched off — ``NEXUS_POLICY_ENABLED=0``, ``NEXUS_ENABLED=0`` or
#: ``configure(enforcement_enabled=False)`` — and it has actually cost something: an
#: ``enforce``-marked deny was downgraded to advice. A governance product that can be disarmed by
#: one environment variable with no signal is not governing, and a counter is not a signal.
DISARMED = "policy.disarmed"
EXPIRED = "policy.expired"
STALE = "policy.stale"
MALFORMED_RULE = "policy.malformed_rule"
BUDGET_EXCEEDED = "policy.budget_exceeded"
APPROVAL_TIMEOUT = "policy.approval_timeout"
UNREACHABLE = "policy.unreachable"
NO_POLICY = "policy.no_policy"
INTERNAL_ERROR = "policy.internal_error"
TIMEOUT_CLAMPED = "policy.timeout_clamped"

_MAX_ALERTS = 64


@dataclass
class Alert:
    kind: str
    detail: str = ""
    count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    #: Free-form context, kept in full **in process**. It was documented as never carrying rule
    #: bodies or subject content; that was a rule for callers, and a rule for callers is not a
    #: control. ``rule_id`` and ``subject_kind`` already carry strings authored inside the
    #: customer's boundary, and ``subject_kind`` is whatever the caller passed to
    #: ``policy.decide``. What keeps this from being the exfiltration route for the thing the
    #: policy was protecting is :func:`_wire_fields`, applied at the egress point rather than
    #: trusted at each of the twenty-odd call sites.
    context: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.kind, self.detail)


_lock = threading.Lock()
_alerts: "dict[tuple, Alert]" = {}
_sinks: "list[t.Callable[[Alert], None]]" = []


def register_sink(fn: "t.Callable[[Alert], None]") -> None:
    """Add a host callback. Exceptions from it are swallowed — an alert sink that can break the
    request path defeats the purpose of alerting about a fail-open in the first place."""
    with _lock:
        _sinks.append(fn)


def raise_alert(kind: str, detail: str = "", /, **context: t.Any) -> Alert:
    """Record an integrity alert. Never raises.

    ``kind`` and ``detail`` are positional-only for a reason discovered the hard way: a caller
    passing ``kind=`` as *context* (the subject's event kind, say) would otherwise collide with
    this function's own first parameter and raise ``TypeError`` — at the call site, before the
    body's ``try`` can contain it. Every one of these calls sits on a fail-open path, so the
    collision would be swallowed by the caller's own guard and reported as "internal error,
    allowing", losing the alert that was the entire point of the call. The ``/`` makes any
    ``kind=`` keyword land in ``context`` where it belongs.
    """
    try:
        now = time.time()
        with _lock:
            key = (kind, detail)
            existing = _alerts.get(key)
            if existing is not None:
                existing.count += 1
                existing.last_seen = now
                alert = existing
                first = False
            else:
                if len(_alerts) >= _MAX_ALERTS:
                    # Drop the oldest by first_seen. A full ring means something is very wrong
                    # already; keeping the newest kinds is more useful than keeping the first
                    # sixty-four we happened to see.
                    oldest = min(_alerts.values(), key=lambda a: a.first_seen)
                    _alerts.pop(oldest.key(), None)
                alert = Alert(kind=kind, detail=detail, context=dict(context))
                _alerts[key] = alert
                first = True
            sinks = list(_sinks)
        if first:
            for fn in sinks:
                try:
                    fn(alert)
                except Exception:  # noqa: BLE001
                    pass
            _emit_event(alert)
        return alert
    except Exception:  # noqa: BLE001
        return Alert(kind=kind, detail=detail)


# ----------------------------------------------------------------------------------------------
# Egress projection — what an alert may say to a collector
# ----------------------------------------------------------------------------------------------
#
# ``_emit_event`` used to route ``detail`` and a ``**alert.context`` spread straight
# into ``contract.base``, and ``contract.base`` never reads ``cfg.tier`` — so *any* field handed
# to it egresses ungated by construction. At ``metadata_only``, the default, that put
# ``rule 'acme-block-acct-4111111111111111' has unknown action 'obliterate'`` on the wire.
#
# The precedent followed here is the earlier tool-argument leak, where arguments were shipping as
# a ``target``. That fix did **not** truncate, on the grounds that a truncated payload is still a
# payload; it rejected non-identifiers outright and emitted a bounded *shape* instead. Same shape
# of answer here, with one deliberate divergence noted at :data:`_WIRE_TEXT`.
#
# ``otel/semconv._identifier`` was evaluated for reuse and does **not** fit: its character class
# ``[A-Za-z0-9_.:/-]{1,128}`` admits ``acct-4111111111111111`` and ``acme-block-ssn-123-45-6789``
# verbatim. It answers "is this a handle or a payload", which is a different question from "does
# this contain regulated data". Forcing it would have passed the exact string this fix exists to
# stop. ``semconv.shape_of``'s *reasoning* is reused instead — see :func:`_wire_text`.

#: Context keys that may become wire fields at all. An allowlist, not a type filter: the previous
#: code asked ``isinstance(v, (int, float, bool, str))``, and a Python type is not evidence about
#: the sensitivity of a value. This is the "``base`` should refuse unknown kwargs" invariant the
#: review asked for, applied at the one door every alert goes through. A key not listed here is
#: counted, not forwarded — a new caller adding context gets silence on the wire and a visible
#: ``context_omitted``, which is the safe direction and the discoverable one.
#:
#: Structural integers. Facts about the *document*, not about anything authored inside it.
_WIRE_NUMERIC = ("rule_index", "dropped", "quarantined")

#: Closed-vocabulary tokens the SDK itself produced: an exception *type* name
#: (``rules.py``'s ``error=type(exc).__name__``) and an SDK event kind. Emitted only if the value
#: still looks like one — see :func:`_wire_token`. A value that fails falls through to the text
#: ladder rather than being dropped, so the reduction is visible rather than silent.
_WIRE_TOKEN = ("error", "subject_kind")

#: Free text authored inside the customer's boundary, gated by :func:`_wire_text`. ``rule_id``
#: lives here, and that is the load-bearing decision in this fix — see :func:`_wire_text`.
_WIRE_TEXT = ("rule_id",)

#: A token is a short bare identifier with no long digit run. The digit-run clause is the
#: remediation for identifier-shaped keys with embedded record numbers, applied here for the
#: same reason: ``RuntimeError``, ``ValueError``, ``tool_action``
#: and ``agent_run`` pass; ``acct_4111111111111111`` and ``patient_90210443`` do not.
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_DIGIT_RUN_RE = re.compile(r"\d{4}")

#: Bound on what reaches the redactor. ``contract._rungs`` has no input bound of its own,
#: and ``raise_alert`` accepts arbitrary detail from twenty-odd call sites, so the
#: bound belongs on this side of the call.
_SCAN_CAP = 4096
_WIRE_TEXT_LIMIT = 256


def _wire_token(v: t.Any) -> "t.Optional[str]":
    """``v`` if it is still a bare SDK-authored token, else ``None``."""
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not _TOKEN_RE.match(s) or _DIGIT_RUN_RE.search(s):
        return None
    return s


def _wire_text(name: str, value: t.Any, tier: str) -> dict:
    """A free-text field as a tier-gated fragment: shape at T0, preview at T1, text at T2.

    **Is a rule ID customer content?** It is authored by the policy administrator, not by an end
    user, and the instinct is that this makes it configuration. The decision here is that it is
    customer content anyway, for four reasons:

    1. *The observed leak settles the empirical question.* ``acme-block-ssn-123-45-6789`` is what
       administrators actually type — a rule gets named after the ticket, the case or the subject
       it was written for. A rule ID is a free-text field with a naming convention, and a naming
       convention is not a schema.
    2. *Authorship is not a privacy property.* The administrator authored the string; the person
       whose SSN is inside it did not consent to it reaching a telemetry collector. Who typed a
       value says nothing about whose value it is.
    3. *The tier is a promise to the data subject, not to the author.* ``metadata_only`` is
       documented as emitting no content. A reader of that table will not carve out an exception
       for strings that happen to have come from an admin console.
    4. *The errors are not symmetric.* Suppressing a harmless rule ID costs an operator a
       convenience that :data:`_WIRE_NUMERIC`'s ``rule_index`` already replaces. Shipping one that
       carried an SSN is unrecoverable.

    **What identifies a rule without reproducing it**, since an alert that cannot name the broken
    rule is useless: its **ordinal position in the signed policy document**. The operator holds
    that document — they signed it — so ``rule_index`` is an exact, lossless pointer that
    reproduces none of its text, and ``rules.parse`` already passes it. Where a caller supplies no
    ordinal (``approval.py`` passes only ``rule_id``), the wire carries the alert kind plus
    ``rule_id_chars``, and the full ID remains in the ring buffer on the host. Adding
    ``rule_index`` to those call sites is a one-line follow-up in a file this change does not own.

    **No fingerprint**, which is the one deliberate divergence from ``contract.tiered_text``.
    That helper pairs ``chars`` with a digest because a paragraph of prose has the entropy to make
    the digest one-way. An alert detail does not: it is a template from open-source code plus a
    short variable part, so a digest of ``rule 'acme-block-ssn-<SSN>' has unknown action`` is
    recovered by trying 10^9 SSNs. That is ``semconv.shape_of``'s "recoverable by trying every
    input" argument verbatim, and it applies here for the same reason — so this follows
    ``shape_of``'s answer rather than ``tiered_text``'s, while reusing ``tiered_text``'s tested
    ladder for everything else.
    """
    from .. import contract
    s = value if isinstance(value, str) else str(value)
    if not s.strip():
        return {}
    frag = contract.tiered_text(name, s[:_SCAN_CAP], tier,
                               full_limit=_WIRE_TEXT_LIMIT, preview_limit=_WIRE_TEXT_LIMIT)
    frag.pop(f"{name}_fingerprint", None)
    # ``tiered_text`` measures what it was handed; report the true length.
    frag[f"{name}_chars"] = len(s.strip())
    return frag


def _wire_fields(alert: Alert, tier: str) -> dict:
    """The projection of an alert onto the wire. The only egress decision in this module.

    ``kind`` is safe by construction — it is one of the literals declared at the top of this file,
    which is why they are literals. Everything else is either a vetted structural number, a vetted
    token, or shape.
    """
    out: dict = {"alert_kind": alert.kind}
    out.update(_wire_text("detail", alert.detail, tier))

    omitted = 0
    for k, v in alert.context.items():
        if k in _WIRE_NUMERIC:
            # ``bool`` first: ``isinstance(True, int)`` is ``True``, and a flag is not a count.
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                omitted += 1
                continue
            out[k] = v
        elif k in _WIRE_TOKEN:
            tok = _wire_token(v)
            if tok is not None:
                out[k] = tok
            else:
                out.update(_wire_text(k, v, tier))
        elif k in _WIRE_TEXT:
            out.update(_wire_text(k, v, tier))
        else:
            omitted += 1
    if omitted:
        # Counted rather than dropped in silence, for ``_tool_arg_shape``'s reason: a suppression
        # and an attribute that was never there must not look the same to the reader.
        out["context_omitted"] = omitted
    return out


def _emit_event(alert: Alert) -> None:
    """Best-effort ``policy_alert`` event.

    Imported lazily and wrapped whole. The event pipeline is the *least* important of the three
    destinations: if emitting an alert about a broken policy required a working collector, then
    the case where both are broken — which is the case that matters — would be the silent one.

    ``policy_alert`` is not yet in the generated contract artifact. It is tracked as a contract
    addition rather than added to ``contract.py`` unilaterally: the contract has two producers,
    and them drifting on a shape is exactly the failure the generated artifact exists to prevent.

    Nothing is splatted into ``base`` from ``alert`` directly: everything goes through
    :func:`_wire_fields` first. ``contract.base`` does not consult ``cfg.tier``, so a builder that
    hands it a field has already made the tier decision, and this is where that decision is made.
    """
    try:
        from .. import contract
        from ..client import get_client
        client = get_client()
        if client is None:
            return
        client.emit(contract.base(
            "policy_alert", client.session_id, client.cfg,
            epistemic_class=contract.EPISTEMIC_BEHAVIOR,
            **_wire_fields(alert, client.cfg.tier)))
    except Exception:  # noqa: BLE001
        pass


def snapshot() -> "list[Alert]":
    with _lock:
        return list(_alerts.values())


def kinds() -> "set[str]":
    with _lock:
        return {a.kind for a in _alerts.values()}


def find(kind: str) -> "t.Optional[Alert]":
    with _lock:
        for a in _alerts.values():
            if a.kind == kind:
                return a
    return None


def reset() -> None:
    """Test-only, and used by the fork hook: an alert raised before ``fork()`` reported once per
    worker is the same over-counting ``_counters.reset_for_fork`` avoids."""
    with _lock:
        _alerts.clear()
        _sinks.clear()
