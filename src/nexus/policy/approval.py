"""Human approval on a production request path — case 6.8.

`DECISIONS.md` files the production approval timeout as deferred, and is precise about which half
was deferred: *"Default must be per-rule and mandatory; the number is the open part."* This module
implements the decided half as structure and fills in the open half with a number that can be
changed without touching any of the structure.

**The timeout is not optional and there is no code path that waits without one.** ``request()``
takes ``timeout_s`` as a required argument, clamps it to ``settings.approval_timeout_max_s``, and
uses ``Event.wait(timeout)`` rather than any unbounded primitive. An approval request that can
wait forever is not a slow feature, it is a connection leak with a governance story attached: the
first time a reviewer goes to lunch, every worker in the pool ends up parked on a threading
primitive and the service stops serving.

**A gate is only armed when someone can actually answer it** — ``DEPUTY.md``'s rule, and the
reason a laptop with no gateway still works. "Live" means a recent heartbeat, not a config flag.
``deputy.enabled: true`` with no daemon running would arm the gate for an approver that does not
exist, and every gated call would sit out its full budget before falling through. With no live
approver at all we do not wait at all: the rule resolves immediately by its ``on_timeout``
disposition, which for an enforce-marked rule is a deny with an explanation, not a hang.

What ``on_timeout`` means, and why it is not a single constant: for an ``enforce``-marked rule,
timing out **denies** — the whole point of requiring approval is that the effect does not happen
unattended. For an unmarked rule it **allows** — the customer never asked us to block anything, so
a silent reviewer must not become an outage. That split is set at parse time in ``rules._parse_one``.
"""
from __future__ import annotations

import threading
import time
import typing as t
from dataclasses import dataclass, field

from . import alerts, settings

PENDING = "pending"
GRANTED = "granted"
DENIED = "denied"
TIMEOUT = "timeout"
NO_APPROVER = "no_approver"


@dataclass
class Card:
    """What an approver is shown. Deliberately not the raw subject.

    Redaction happens before this object exists (``PRIVACY-EGRESS-AND-GUARD-ERGONOMICS.md``): an
    approval card travels to a dashboard, so a card carrying the prompt that triggered it is an
    egress path that no tier setting was consulted about.
    """
    id: str
    rule_id: str
    kind: str
    tool: t.Optional[str] = None
    target: t.Optional[str] = None
    reason: str = ""
    destructive: bool = False
    risk: t.Optional[str] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class Pending:
    card: Card
    event: threading.Event = field(default_factory=threading.Event)
    outcome: str = PENDING
    actor: t.Optional[str] = None


_lock = threading.Lock()
_pending: "dict[str, Pending]" = {}
#: Registered approvers: ``name -> heartbeat_fn``. A heartbeat returning False means "not live",
#: and a registration whose heartbeat has gone quiet disarms the gate within one decision.
_approvers: "dict[str, t.Callable[[], bool]]" = {}


def register_approver(name: str, heartbeat: "t.Callable[[], bool]") -> None:
    with _lock:
        _approvers[name] = heartbeat


def unregister_approver(name: str) -> None:
    with _lock:
        _approvers.pop(name, None)


def live_approvers() -> "list[str]":
    """Which approvers could answer right now. A heartbeat that raises counts as not live —
    an approver we cannot even ask about is not one we should park a request on."""
    with _lock:
        items = list(_approvers.items())
    out = []
    for name, hb in items:
        try:
            if hb():
                out.append(name)
        except Exception:  # noqa: BLE001
            pass
    return out


def pending() -> "list[Card]":
    with _lock:
        return [p.card for p in _pending.values() if p.outcome == PENDING]


def resolve(card_id: str, outcome: str, actor: str = "human") -> bool:
    """Record a decision an approver has taken. Returns False if there was nothing to resolve.

    This **reports**; it never decides. ``DEPUTY.md``: *"The API key cannot decide. The resolve
    endpoint reports a decision the host already took and never enqueues a command."* Here that
    means resolve unblocks a call that this process is already holding — it cannot originate one,
    cannot reach a process that is not waiting, and cannot manufacture an approval for a call that
    has already timed out. Whoever answers first wins, and a late answer loses.
    """
    if outcome not in (GRANTED, DENIED):
        return False
    with _lock:
        p = _pending.get(card_id)
        if p is None or p.outcome != PENDING:
            return False
        p.outcome = outcome
        p.actor = actor
    p.event.set()
    return True


def request(card: Card, *, timeout_s: float, on_timeout: str,
            max_block_s: t.Optional[float] = None) -> "tuple[str, t.Optional[str]]":
    """Ask for approval, bounded. Returns ``(outcome, actor)``.

    ``timeout_s`` is required by signature. That is the enforcement mechanism for "mandatory
    timeout" — not a check inside the body, which a future caller could route around, but the fact
    that there is no way to call this function without naming a bound.

    **Three bounds, and the tightest wins.** ``timeout_s`` is what the *rule* asked for.
    ``settings.approval_timeout_max_s`` is the absolute ceiling, which the environment can only
    lower. ``max_block_s`` — defaulting to ``settings.approval_block_max_s``, 30s — is what the
    *call site* will tolerate on its own thread, and it is the one that answers the actual
    complaint: this wait happens on a customer's worker, so a rule written by somebody else must
    not be able to park it for two minutes just because it said 120. A caller that genuinely is not
    on a request path raises its own bound with ``decide(..., approval_max_s=…)``.
    """
    s = settings.current()
    block = s.approval_block_max_s if max_block_s is None else max(0.0, float(max_block_s))
    ceiling = min(s.approval_timeout_max_s, block)
    budget = min(max(0.0, float(timeout_s)), ceiling)
    if budget < timeout_s:
        alerts.raise_alert(alerts.TIMEOUT_CLAMPED,
                           f"rule asked for {timeout_s:g}s, clamped to {budget:g}s",
                           rule_id=card.rule_id)

    approvers = live_approvers()
    if not approvers:
        # Nobody is listening. Waiting out the full budget here would be the exact hang the design
        # refuses — and it would be a hang whose outcome was already determined before it started.
        alerts.raise_alert(alerts.APPROVAL_TIMEOUT, "no live approver", rule_id=card.rule_id)
        return NO_APPROVER, None

    p = Pending(card=card)
    with _lock:
        _pending[card.id] = p
    try:
        answered = p.event.wait(budget)
        if answered and p.outcome in (GRANTED, DENIED):
            return p.outcome, p.actor
        with _lock:
            # Close the card under the lock so a resolve racing the timeout cannot land after we
            # have already told the caller it timed out. Whoever answers first wins, and past this
            # point the timeout has answered.
            if p.outcome == PENDING:
                p.outcome = TIMEOUT
            elif p.outcome in (GRANTED, DENIED):
                return p.outcome, p.actor
        alerts.raise_alert(alerts.APPROVAL_TIMEOUT,
                           f"no answer in {budget:g}s -> {on_timeout}", rule_id=card.rule_id)
        return TIMEOUT, None
    finally:
        with _lock:
            _pending.pop(card.id, None)


def reset_for_tests() -> None:
    with _lock:
        for p in _pending.values():
            p.event.set()
        _pending.clear()
        _approvers.clear()
