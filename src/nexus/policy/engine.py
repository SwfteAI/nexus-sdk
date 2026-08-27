"""The decision core. The only synchronous thing this SDK is allowed to do.

Everywhere else, capture is off the hot path — bounded queue, background drain, drop rather than
block (§4). Here we sit *between the customer's request and its effect*, because a gate that runs
after the effect is not enforcement, it is journalism. That privilege is why this file is mostly
about giving the privilege back:

**Nothing on the decision path does I/O.** No fetch, no file read, no DNS, no lock held across a
syscall. ``decide`` reads an in-memory ``Snapshot`` — an already-verified envelope and an
already-parsed rule set — and walks a tuple. Refreshing that snapshot is somebody else's thread's
problem (``refresh``/``install``), and if the control plane is down the snapshot simply gets
older. Signature verification, which is the expensive part at ~10ms of pure-Python elliptic curve
arithmetic, happens exactly once per envelope at load time and never once per decision.

**The latency budget is a real cap with an honest guarantee** (case 6.4). Exceeding it *allows*
and records a timeout, because an SDK that adds unbounded latency to a customer's checkout does
not survive its first incident review. The honest statement of the guarantee: the deadline is
polled between rules, so the bound is *one rule's matching time* past the budget, not zero. Python
cannot pre-empt a running frame, and the alternative — evaluating every decision on a worker
thread so it can be abandoned — costs more latency in thread handoff than it saves in the
pathological case it protects against. Individual matchers here are ``fnmatch`` and substring
tests over short strings; the measured p99 for a realistic rule set is in
``tests/test_decision_latency.py`` and is three orders of magnitude under the default budget.

**Where the fail-open line is drawn, and the argument for drawing it there.** The critique
is right that five failure states all resolve to ALLOW and that a governance gate which silently
stops governing is this product's defining failure. It does not follow that the fix is to deny on
uncertainty. A denial we cannot justify is an outage in a customer's checkout caused by *our*
control plane having a bad afternoon, and an SDK that does that once is removed rather than
patched — at which point it governs nothing at all, permanently. So the line is drawn three times
rather than once:

1. **On the request path, uncertainty still allows — by default.** No envelope, an unverifiable
   one, a budget overrun or a bug in our own code: allow, count, alert. Unchanged.
2. **Uncertainty must not be able to *remove* certainty.** ``install`` and ``load_from_settings``
   refuse to replace a snapshot that is present with one that is not. Handing the SDK a corrupt
   file used to be a cheaper disarm than forging a signature; now it keeps the last good policy and
   raises ``REJECTED_REPLACEMENT``. This costs a customer nothing, so there is no argument for
   fail-open here and it is simply a bug that it did.
3. **Fail-closed is available, explicit and visible.** ``settings.fail_closed`` (env
   ``NEXUS_POLICY_FAIL_CLOSED=1``) makes "no usable policy" a deny. Off by default, because a
   customer must choose to trade availability for governance rather than discover the trade during
   an incident. It covers exactly the *"we have no governance"* class — missing, malformed,
   unsigned, wrong key, rolled back. It deliberately does **not** cover ``budget-exceeded`` or
   ``error``: those are *our* code misbehaving, the customer has no lever to fix them, and turning
   our bug into their 500 is the failure mode that gets an SDK deleted. A customer can tell the two
   apart from ``Decision.source`` and from the alert kind.

And disarming is no longer silent: the first time ``enforcement_enabled=False`` actually costs
something — an ``enforce``-marked deny downgraded to advice — a ``DISARMED`` alert is raised. A
counter is not a signal; ``policy.init()`` raises the same alert at startup.

**The asymmetry, stated once.** When policy is unavailable, unverifiable or stale:

* no envelope at all, or one that fails verification → **allow**, alert, ``source="no-policy"``
  (unless ``fail_closed``). A policy fetch failure must never silently start denying. This is
  ``policy_gate``'s ``_from_cache_or_allow`` (:373) and its ``unverified-cache`` branch, unchanged
  in spirit.
* a verified but stale envelope, matched by a rule **not** marked ``enforce`` → allow, record the
  verdict, mark ``stale``.
* a verified but stale envelope, matched by a rule **marked** ``enforce`` → **still denies.** A
  cached deny never decays. If it did, "disconnect the pod from the control plane" would be the
  documented bypass for every control we sell.

**Two flags must agree before anything is blocked.** The rule must carry ``enforce: true``, and
the call site must not have opted out. A call site cannot promote an unmarked rule to enforcing —
if it could, ``enforce``-marked would mean nothing and the asymmetry above would collapse. The
call site can only decline, which is what makes a staging dry-run possible without a policy edit.

**Denial is the one exception to "never raise into the host".** ``_safety`` exists because a
telemetry bug must not become a 500. A denial is not a bug; it is the product working, and the
host opted into it twice (rule marking, call-site mode). ``Denied`` is therefore a deliberate
control-flow signal with a stable type and a reason string, raised only from a gate the caller
opened on purpose. Everything else in this file catches.
"""
from __future__ import annotations

import threading
import time
import typing as t
import uuid
from dataclasses import dataclass, field, replace

from . import alerts, approval, envelope as envelope_mod, rules as rules_mod, settings

ALLOW = "allow"
DENY = "deny"

#: Counter names. Not in ``_counters``' own literal list because this package may not edit it;
#: they are declared here instead. Moving them is a change to a module this package does not
#: own, so it is coordinated rather than done unilaterally.
C_EVALUATED = "policy_evaluated"
C_DENIED = "policy_denied"
C_ADVISED_DENY = "policy_advised_deny"
C_BUDGET_EXCEEDED = "policy_budget_exceeded"
C_APPROVAL_TIMEOUT = "policy_approval_timeout"
C_NO_POLICY = "policy_no_policy"
C_ERROR = "policy_error"


class Denied(Exception):
    """Raised when an enforcing rule denies. The one exception this SDK puts in a host traceback.

    Carries the rule id and reason because a block a developer cannot explain is a block they will
    disable, and a disabled control is worth less than no control at all — it still shows green on
    a coverage report.
    """

    def __init__(self, decision: "Decision") -> None:
        super().__init__(decision.reason or f"denied by policy rule {decision.rule_id}")
        self.decision = decision
        self.rule_id = decision.rule_id
        self.reason = decision.reason


@dataclass(frozen=True)
class Decision:
    """The outcome of a policy evaluation.

    ``action`` is the *verdict* — what policy thinks. ``enforced`` is whether that verdict will
    actually stop anything. Keeping them separate is what makes advise mode (6.1) a first-class
    state rather than a mode flag somewhere else: a shadow-mode deployment records
    ``action="deny", enforced=False`` for months, and the customer can count exactly what turning
    enforcement on would have blocked before they turn it on.
    """

    action: str = ALLOW
    reason: t.Optional[str] = None
    rule_id: t.Optional[str] = None
    #: Where the verdict came from — ``policy``, ``no-policy``, ``no-match``, ``stale-advisory``,
    #: ``budget-exceeded``, ``approval``, ``deputy:<rule>``, ``error``, ``disabled``.
    source: str = "no-policy"
    enforced: bool = False
    mutations: dict = field(default_factory=dict)
    #: Wall time spent inside ``decide``, milliseconds, including any approval wait.
    latency_ms: float = 0.0
    #: Evaluation time only, excluding an approval wait. This is what the budget bounds.
    eval_ms: float = 0.0
    #: True when evaluation was abandoned against the budget (6.4) — always paired with an allow.
    timed_out: bool = False
    #: True when the verdict came from an envelope past its freshness window.
    stale: bool = False
    #: ``granted`` / ``denied`` / ``timeout`` / ``no_approver`` when a human gate was involved.
    approval: t.Optional[str] = None
    approver: t.Optional[str] = None

    @property
    def allowed(self) -> bool:
        """Whether the call may proceed. A deny that is not enforced still allows — that is
        advise mode, and reading ``action`` when you meant ``allowed`` is the mistake this
        property exists to make hard."""
        return not (self.action == DENY and self.enforced)

    @property
    def denied(self) -> bool:
        return not self.allowed


_ALLOW_NO_POLICY = Decision(source="no-policy")


# ------------------------------------------------------------------------------------------
# the snapshot — verified once, read many
# ------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Snapshot:
    env: envelope_mod.Envelope = envelope_mod.ABSENT
    ruleset: rules_mod.RuleSet = rules_mod.EMPTY
    installed_at: float = 0.0

    @property
    def present(self) -> bool:
        return self.env.present


_snapshot = Snapshot()
_snap_lock = threading.Lock()
_no_policy_alerted = False
_disarm_alerted = False


def _alert_disarmed(detail: str) -> None:
    """Raise ``DISARMED`` once per process. Guarded by a plain bool rather than by ``alerts``' own
    deduplication because this is reachable from the decision path, and ``raise_alert`` takes a
    lock — one lock acquisition per request to re-learn a fact we already know is not a trade the
    budget can afford."""
    global _disarm_alerted
    if _disarm_alerted:
        return
    _disarm_alerted = True
    alerts.raise_alert(alerts.DISARMED, detail)


def _publish(snap: Snapshot) -> None:
    """Swap the snapshot in. A plain rebind of a module global is atomic under the GIL and under
    free-threaded 3.13+ for a single name, which is the whole reason ``Snapshot`` is frozen and
    replaced wholesale rather than mutated in place."""
    global _snapshot
    _snapshot = snap


def _adopt(env: "envelope_mod.Envelope") -> Snapshot:
    """Parse and publish a loaded envelope, unless doing so would be a downgrade.

    **An envelope we cannot authenticate must not be able to remove one we could.** Otherwise the
    cheapest attack on this package is not forging a signature, it is truncating a file: hand the
    SDK garbage and every enforcing rule in the process stops applying. That is the same reasoning
    that makes ``refresh`` keep the previous snapshot on a failed fetch, applied one layer down
    where the failure is "these bytes are not trustworthy" rather than "we could not get bytes".
    Keeping the old policy costs a customer nothing — it is the policy that was already in force a
    millisecond ago — so there is no availability argument on the other side of this one.
    """
    if not env.present:
        prev = _snapshot
        if prev.present:
            alerts.raise_alert(alerts.REJECTED_REPLACEMENT,
                               env.problem or "unusable envelope; keeping the last good policy")
            return prev
    ruleset = (rules_mod.parse(env.rules, max_rules=settings.current().max_rules)
               if env.present else rules_mod.EMPTY)
    if env.present and ruleset.quarantined:
        # Named rather than counted: a quarantined ``enforce`` rule is an enforcement gap, and a
        # gap that only shows up as a number is a gap nobody investigates.
        alerts.raise_alert(alerts.MALFORMED_RULE,
                           f"{len(ruleset.quarantined)} rule(s) quarantined",
                           quarantined=len(ruleset.quarantined))
    snap = Snapshot(env=env, ruleset=ruleset, installed_at=time.time())
    _publish(snap)
    return snap


def install(raw_envelope: t.Any, *, pubkey_hex: t.Optional[str] = None) -> Snapshot:
    """Verify, parse and publish an envelope. The only place verification happens.

    Publishing is a single atomic rebind of ``_snapshot``, so a decision in flight either sees the
    whole old snapshot or the whole new one. A half-swapped rule set would mean a request
    evaluated against two different policies, which is unreproducible by construction and would be
    the worst possible bug to be told about by a customer.

    There is no ``fetched_at`` parameter. Freshness is read from the signed payload and from
    nowhere else — see ``envelope.load``.
    """
    return _adopt(envelope_mod.load(raw_envelope, pubkey_hex=pubkey_hex))


def refresh(fetcher: "t.Callable[[], t.Any]", *, pubkey_hex: t.Optional[str] = None) -> bool:
    """Re-install from ``fetcher()``. Call from a background thread, never from ``decide``.

    A failed fetch keeps the previous snapshot rather than clearing it. Clearing would mean a
    momentary control-plane blip disarms every enforcing rule in the fleet at once — the fetch
    failure would *become* the bypass, which is precisely the thing the staleness ladder exists to
    make gradual and visible instead.
    """
    try:
        raw = fetcher()
    except Exception as exc:  # noqa: BLE001
        alerts.raise_alert(alerts.UNREACHABLE, f"policy fetch failed: {type(exc).__name__}")
        return False
    if raw is None:
        alerts.raise_alert(alerts.UNREACHABLE, "policy fetch returned nothing")
        return False
    return install(raw, pubkey_hex=pubkey_hex).present


def load_from_settings() -> Snapshot:
    """Install from ``NEXUS_POLICY_FILE`` if one is configured. No file is not an error."""
    s = settings.current()
    if not s.envelope_path:
        return _snapshot
    return _adopt(envelope_mod.load_file(s.envelope_path, pubkey_hex=s.pubkey_hex))


def snapshot() -> Snapshot:
    return _snapshot


def reset_for_tests() -> None:
    global _no_policy_alerted, _disarm_alerted
    _publish(Snapshot())
    _no_policy_alerted = False
    _disarm_alerted = False
    envelope_mod.reset_for_tests()


# ------------------------------------------------------------------------------------------
# the decision
# ------------------------------------------------------------------------------------------

def decide(kind: str, subject: t.Mapping[str, t.Any], *,
           enforce: t.Optional[bool] = None,
           budget_ms: t.Optional[float] = None,
           approval_max_s: t.Optional[float] = None,
           now: t.Optional[float] = None) -> Decision:
    """Evaluate ``subject`` against the installed policy. Never raises.

    ``enforce=False`` forces advise for this call site regardless of rule markings — the dry-run
    switch. ``enforce=True`` or ``None`` defers to the rule, which is the only thing that can make
    a denial real. See the module docstring on why the call site cannot promote.

    ``approval_max_s`` caps how long *this thread* may be parked waiting for a human, overriding
    ``settings.approval_block_max_s`` up to the absolute ``MAX_APPROVAL_TIMEOUT_S``. It exists
    because the rule that asks for the wait is control-plane data and the thread being parked
    belongs to the customer: a batch job can offer two minutes, a checkout handler cannot, and
    neither of them should be decided by a JSON file somebody else edits.
    """
    t0 = _perf()
    try:
        return _decide(kind, subject, enforce, budget_ms, approval_max_s, now, t0)
    except Exception as exc:  # noqa: BLE001
        # A bug in policy degrades to allow + alert. The alternative — a policy bug becoming a 500
        # in a customer's service — is the failure that gets an SDK removed rather than patched.
        _incr(C_ERROR)
        alerts.raise_alert(alerts.INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")
        return replace(_ALLOW_NO_POLICY, source="error",
                       latency_ms=(_perf() - t0) * 1000.0)


#: The deadline clock, as one name rather than five call sites. Tests drive the budget path by
#: replacing this; nothing else should. Patching `time.perf_counter` itself would reach pytest's
#: own timing, and racing a real 1ms budget is flaky at the ~0.1% level on measured hardware —
#: neither is a way to prove a security property.
_perf = time.perf_counter


def _decide(kind, subject, enforce, budget_ms, approval_max_s, now, t0) -> Decision:
    s = settings.current()
    _incr(C_EVALUATED)
    subj = dict(subject or {})
    subj.setdefault("kind", kind)

    # A caller may lower the budget for its own latency reasons — a checkout handler and a batch
    # job do not owe each other the same patience — but not below the floor the operator's own
    # budget is held to. Unfloored, ``budget_ms=0.0`` expired on the first check and every deny
    # became ``budget-exceeded`` with no rule named: not a bypass (``enforce=False`` already
    # declines enforcement, and honestly) but an erasure, shaped like infrastructure.
    requested = budget_ms if budget_ms is not None else s.decision_budget_ms
    budget = max(settings.MIN_DECISION_BUDGET_MS, requested) / 1000.0
    expired = {"hit": False}

    def past_deadline() -> bool:
        if _perf() - t0 > budget:
            expired["hit"] = True
            return True
        return False

    snap = _snapshot
    if not snap.present:
        # Case 6.3 / 6.5, the fail-open half. No envelope, or one that would not verify. Alerted
        # once per process: a fleet with no policy configured must not emit one alert per request.
        global _no_policy_alerted
        if not _no_policy_alerted:
            _no_policy_alerted = True
            alerts.raise_alert(alerts.NO_POLICY, snap.env.problem or "no policy installed")
        _incr(C_NO_POLICY)
        if s.fail_closed and s.enforcement_enabled and enforce is not False:
            # The other half of that argument. The customer asked for governance over availability, in so many
            # words, and the deny says so in ``reason`` rather than leaving them to work out why
            # their service started refusing. Note this covers only "we have no policy" — not the
            # budget overrun below, and not the ``error`` path in ``decide``.
            _incr(C_DENIED)
            return _finish(Decision(action=DENY, source="no-policy", enforced=True,
                                    reason="no verified policy is installed and this deployment "
                                           "is configured to fail closed"), t0, None)
        return _finish(_ALLOW_NO_POLICY, t0, None)

    env = envelope_mod.reclassify(snap.env, now=now)
    stale = env.state in (envelope_mod.HARD_STALE, envelope_mod.EXPIRED)

    rule = rules_mod.first_match(snap.ruleset, subj, deadline=past_deadline)
    if expired["hit"]:
        # Case 6.4. Abandon and allow. Recording the timeout is what keeps this from being a
        # silent hole: a rule set that consistently blows the budget is a control-plane bug that
        # shows up as a counter rather than as an unexplained gap in the enforcement record.
        _incr(C_BUDGET_EXCEEDED)
        alerts.raise_alert(alerts.BUDGET_EXCEEDED,
                           f"decision abandoned after {budget * 1000:.0f}ms",
                           subject_kind=str(kind))
        return _finish(replace(_ALLOW_NO_POLICY, source="budget-exceeded", timed_out=True),
                       t0, None)

    if rule is None:
        return _finish(Decision(source="no-match", stale=stale), t0, None)

    # Both flags must agree. The rule marking is necessary; the call site can only decline.
    may_enforce = rule.enforcing and s.enforcement_enabled and enforce is not False

    if stale and not rule.enforcing:
        # A verified-but-stale envelope keeps advising, but an unmarked rule stops mattering. The
        # marked ones do not decay — that branch is below, and its absence here is the point.
        if rule.action == rules_mod.ALLOW:
            return _finish(Decision(action=ALLOW, rule_id=rule.id, reason=rule.reason,
                                    source="stale-advisory", stale=True), t0, None)
        return _finish(Decision(action=DENY, rule_id=rule.id, reason=rule.reason,
                                source="stale-advisory", enforced=False, stale=True), t0, None)

    if rule.action == rules_mod.ALLOW:
        return _finish(Decision(action=ALLOW, rule_id=rule.id, reason=rule.reason,
                                source="policy", stale=stale), t0, None)

    if rule.action == rules_mod.DENY:
        if may_enforce:
            _incr(C_DENIED)
        else:
            _incr(C_ADVISED_DENY)
            if rule.enforcing and not s.enforcement_enabled:
                # The moment disarming actually costs something. Raised here rather than at
                # ``settings`` load time because "enforcement is off" is only a finding once a
                # rule that would have blocked something does not.
                _alert_disarmed("enforcement disabled: an enforce-marked deny became advice")
        return _finish(Decision(action=DENY, rule_id=rule.id,
                                reason=rule.reason or "denied by policy",
                                source="policy", enforced=may_enforce, stale=stale), t0, None)

    # require_approval — case 6.8. The evaluation is over; everything past here is the human wait,
    # which is bounded separately and deliberately excluded from the decision budget.
    if rule.enforcing and not s.enforcement_enabled:
        _alert_disarmed("enforcement disabled: an enforce-marked approval gate became advice")
    t_eval_end = _perf()
    return _approve(rule, subj, may_enforce, stale, s, t0, t_eval_end, approval_max_s)


def _approve(rule, subj, may_enforce, stale, s, t0, t_eval_end, approval_max_s) -> Decision:
    timeout = rule.approval_timeout_s if rule.approval_timeout_s is not None \
        else s.approval_timeout_s
    card = approval.Card(
        id=uuid.uuid4().hex, rule_id=rule.id, kind=str(subj.get("kind") or "action"),
        tool=_short(subj.get("tool")), target=_short(subj.get("target")),
        reason=rule.reason, risk=_short(subj.get("risk")),
        destructive=bool(subj.get("destructive")))
    outcome, actor = approval.request(card, timeout_s=timeout, on_timeout=rule.on_timeout,
                                      max_block_s=approval_max_s)

    if outcome == approval.GRANTED:
        return _finish(Decision(action=ALLOW, rule_id=rule.id, source="approval",
                                reason=rule.reason, approval=outcome, approver=actor,
                                stale=stale), t0, t_eval_end)
    if outcome == approval.DENIED:
        return _finish(Decision(action=DENY, rule_id=rule.id, source="approval",
                                reason=rule.reason or "an approver declined",
                                enforced=may_enforce, approval=outcome, approver=actor,
                                stale=stale), t0, t_eval_end)

    # timeout, or nobody live to ask. ``on_timeout`` is DENY for enforce-marked rules and ALLOW
    # for advisory ones — set at parse time, see ``rules._parse_one``.
    _incr(C_APPROVAL_TIMEOUT)
    if rule.on_timeout == rules_mod.DENY:
        why = ("no approver was available" if outcome == approval.NO_APPROVER
               else f"no answer within {timeout:g}s")
        return _finish(Decision(action=DENY, rule_id=rule.id, source="approval",
                                reason=f"{rule.reason or 'approval required'} — {why}",
                                enforced=may_enforce, approval=outcome, stale=stale),
                       t0, t_eval_end)
    return _finish(Decision(action=ALLOW, rule_id=rule.id, source="approval",
                            reason=rule.reason, approval=outcome, stale=stale), t0, t_eval_end)


def _finish(d: Decision, t0: float, t_eval_end: t.Optional[float]) -> Decision:
    """Stamp timings. ``t_eval_end=None`` means evaluation ran to the end of the call — i.e. no
    approval wait — so evaluation time and total time are the same number. Keeping them as two
    fields rather than one matters for case 6.4: the published budget bounds ``eval_ms``, and a
    decision that spent 20 seconds waiting for a human has not breached it."""
    end = _perf()
    total = (end - t0) * 1000.0
    return replace(d, latency_ms=total,
                   eval_ms=total if t_eval_end is None else (t_eval_end - t0) * 1000.0)


def _short(v: t.Any) -> t.Optional[str]:
    return None if v is None else str(v)[:256]


def _incr(name: str, n: int = 1) -> None:
    try:
        from .. import _counters
        _counters.incr(name, n)
    except Exception:  # noqa: BLE001
        pass
