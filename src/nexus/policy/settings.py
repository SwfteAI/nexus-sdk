"""Policy settings — the numbers that decide how much of a customer's request we may spend.

These live here rather than in ``nexus.config`` for one structural reason: every other knob in
``Config`` tunes *telemetry*, and telemetry knobs are safe to get wrong. These tune the only code
path allowed to sit between a customer's request and its effect, so they carry a different kind of
risk and a different review bar. Keeping them separate also means a policy setting cannot be
silently changed by a config file that was written for a capture concern.

**Every timing default here is a ceiling, not a target.** The evaluation itself is in-process and
takes microseconds (see ``tests/test_decision_latency.py``); the budgets exist to bound the
pathological cases — an oversized rule set, a slow custom matcher, a human who went to lunch.

Why the staleness ladder is far tighter than the CLI's (``policy_gate.py``: 6h / 72h / 14d): that
ladder is sized for a laptop that goes offline for a long weekend and must keep working on a
plane. A production service does not board a plane. It has a network, it is restarted regularly,
and a policy change an operator makes at 09:00 must not still be un-applied at 15:00 across a
fleet. So: fresh for 5 minutes, soft-stale for an hour, hard-stale after a day.

Precedence follows the SDK's documented rule with the SDK's documented inversion (``config.py``):
explicit ``configure()`` argument wins over environment, *except* ``NEXUS_POLICY_ENABLED=0``,
which wins over everything. An operator must be able to disarm enforcement from outside the
application without a redeploy — the same reasoning that makes ``NEXUS_ENABLED=0`` absolute. Note
what disarming does: it stops us *denying*. It does not stop us evaluating and recording, because
an operator turning off enforcement during an incident still wants to know what would have been
blocked.
"""
from __future__ import annotations

import os
import typing as t
from dataclasses import dataclass, replace

# The global kill switch lives in ``config`` because it governs the whole SDK, not just policy.
# Safe to import at module level: ``config`` imports only ``provenance``, and ``nexus/__init__``
# imports ``policy`` from inside ``init()`` rather than at module scope, so there is no cycle.
from .. import config

#: Hard cap on a single ``decide()`` call, excluding an approval wait (which is bounded
#: separately and far more generously, because the caller opted into waiting for a human).
#: 25ms is chosen to be an order of magnitude below any plausible provider call and small enough
#: that it is invisible next to a database round trip. Exceeding it allows — see case 6.4.
DEFAULT_DECISION_BUDGET_MS = 25.0

#: Floor under *any* decision budget, whoever asks for it. This number was already here as a bare
#: ``max(1.0, ...)`` on the environment path; it is named because `engine._decide` needs the same
#: one, and a floor enforced at one of two entry points is not a floor. Below it, evaluation is
#: abandoned before a rule is read, which turns an enforcing deny into a record that reads exactly
#: like a slow control plane. See case 6.4: exceeding a budget allows, but a budget that cannot be
#: met is not an overrun, it is an erasure.
MIN_DECISION_BUDGET_MS = 1.0

#: Default wait for a human approval, when a rule requests approval without naming its own
#: timeout. `DECISIONS.md` deferred the number and made the *mandatoriness* the decided part; this
#: is that number. 30s is long enough that an attentive approver in a dashboard makes it, and
#: short enough that a request path holding a connection for it is survivable.
DEFAULT_APPROVAL_TIMEOUT_S = 30.0

#: The ceiling a rule may not exceed however it is written. A rule that asks for 3600s in a
#: checkout path is not a policy, it is an outage with a JSON file in front of it — so the rule is
#: honoured up to here and the overreach is reported as an integrity alert.
#:
#: This is an *absolute* ceiling: ``NEXUS_POLICY_APPROVAL_MAX_S`` and ``configure()`` can only
#: lower it, never raise it. A bound that the thing it bounds can widen is not a bound, and this
#: one governs how long a customer's worker thread may be parked inside their own request path.
MAX_APPROVAL_TIMEOUT_S = 120.0

#: The ceiling that applies to an approval wait *on the calling thread*, which today is every
#: approval wait. Separate from ``MAX_APPROVAL_TIMEOUT_S`` because the two answer different
#: questions: that one is "how long may a rule ask for", this one is "how long may this call site
#: be blocked". The rule is control-plane data and the call site is the customer's own code, so
#: the call site gets the last word — ``decide(..., approval_max_s=N)`` raises this per call up to
#: the absolute ceiling, for a batch or agent loop that is genuinely not on a request path.
DEFAULT_APPROVAL_BLOCK_MAX_S = 30.0

#: Envelope staleness ladder, in seconds. See the module docstring for why these are not the
#: CLI's numbers.
FRESH_S = 300.0
SOFT_STALE_S = 3600.0
HARD_STALE_S = 86400.0

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError, TypeError):
        return default


@dataclass(frozen=True)
class Settings:
    """Resolved policy settings. Frozen for the same reason ``Config`` is: the refresher thread
    reads these while the request path also reads them, and a mutable settings object is a data
    race whose only symptom is a decision nobody can reproduce."""

    #: Master switch for *denial*. False means evaluate and record, never block.
    enforcement_enabled: bool = True
    #: Hard cap per ``decide()``, milliseconds.
    decision_budget_ms: float = DEFAULT_DECISION_BUDGET_MS
    #: Fallback approval wait when a rule does not name one.
    approval_timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S
    #: Ceiling no rule may exceed. Clamped to ``MAX_APPROVAL_TIMEOUT_S`` on every write.
    approval_timeout_max_s: float = MAX_APPROVAL_TIMEOUT_S
    #: Ceiling on an approval wait that blocks the calling thread. Also clamped.
    approval_block_max_s: float = DEFAULT_APPROVAL_BLOCK_MAX_S
    #: Staleness ladder.
    fresh_s: float = FRESH_S
    soft_stale_s: float = SOFT_STALE_S
    hard_stale_s: float = HARD_STALE_S
    #: Hex-encoded Ed25519 public key that signs envelopes.
    #:
    #: The default is the **empty string**, meaning *no key configured*, and an envelope offered to
    #: an unconfigured deployment is refused before any curve arithmetic runs. It used to be 32
    #: zero bytes on the theory that a nonsense key verifies nothing; that theory was wrong. The
    #: all-zero encoding decompresses to a valid order-4 point, and against a small-order key the
    #: verification equation degenerates — a single fixed 64-byte "signature" was accepted for
    #: 23.5% of messages, which an attacker grinds to certainty by adding a filler field to the
    #: policy JSON and re-rolling. ``ed25519.verify`` now rejects small-order points too, so this
    #: default and that check are independent locks on the same door: neither one alone was enough
    #: and neither one is load-bearing on its own.
    pubkey_hex: str = ""
    #: Where to load an envelope from, if it is not handed to us in code.
    envelope_path: t.Optional[str] = None
    #: Where the anti-rollback high-water mark is persisted. ``None`` means "derive it from
    #: ``envelope_path``"; the empty string disables persistence entirely (in-process only).
    #: See ``envelope._accept_high_water``.
    state_path: t.Optional[str] = None
    #: When True, *no usable policy* denies instead of allowing. Off by default and deliberately
    #: so — see ``engine``'s module docstring for the whole of that argument. A customer who bought
    #: a governance control and would rather 503 than run ungoverned turns this on; nobody gets it
    #: by accident, and turning it on is visible in the decision (``source="no-policy"``,
    #: ``enforced=True``) rather than only in a config file.
    fail_closed: bool = False
    #: Bound on rules evaluated per decision. A rule set larger than this is a control-plane bug;
    #: honouring it unbounded would let the control plane set our latency.
    max_rules: int = 1000


def _clamped(s: "Settings") -> "Settings":
    """Apply the ceilings that no input may raise.

    Both approval bounds exist to stop a rule — or an operator who read one blog post — from
    parking a customer's worker thread. A ceiling that the environment can raise is decoration, so
    this runs on every write to ``_settings``, whether it came from ``configure()`` or from the
    environment. Lowering is always allowed; that direction is never the unsafe one.
    """
    return replace(
        s,
        approval_timeout_max_s=min(max(0.0, s.approval_timeout_max_s), MAX_APPROVAL_TIMEOUT_S),
        approval_block_max_s=min(max(0.0, s.approval_block_max_s), MAX_APPROVAL_TIMEOUT_S),
    )


_settings = _clamped(Settings())


def current() -> Settings:
    """The settings in force, with **both** env kill switches applied last so that neither can be
    overridden by ``configure()``.

    ``NEXUS_ENABLED=0`` is documented as the global brake, and it used not to reach here. The
    consequence was narrow and bad: ``nexus.init()`` returns early under the kill switch, so the
    ``nexus.agent()`` / ``run.action()`` route was genuinely inert — but ``policy.gate`` /
    ``policy.check`` / ``policy.init`` are advertised directly by ``policy/__init__``, and they
    kept raising ``Denied`` into a customer's request path. The brake stopped the half a reader
    can see it stopping and left live the half that raises. Worse, the same flag *does* reliably
    prevent the SIGTERM deadlock — no handler is installed — so an operator pulling it during an
    incident had every reason to believe the SDK was off.

    ``settings.enforcement_enabled`` and ``nexus.enabled()`` must not disagree. Two switches both
    claiming to be off while one of them is on is worse than one switch.

    ``config.enabled_from_env`` rather than ``nexus.enabled()``, deliberately: the kill switch is
    an *environment* fact an operator sets without a redeploy, whereas ``nexus.enabled()`` is also
    ``False`` before ``init()`` has ever run — and a customer who calls ``policy.init()`` on its
    own, without ``nexus.init()``, has armed enforcement and must keep it. The extra environment
    read on the decision path is the same cost the narrow switch beside it already pays.

    That read is *live*, where ``nexus._ENABLED`` is sampled once at import — a deliberate
    difference, and the one direction of disagreement left. ``NEXUS_ENABLED`` flipped to ``0``
    mid-process therefore disarms enforcement while telemetry keeps running. That is the safe
    direction (policy can only ever be *more* off than the SDK, never less), it matches
    ``NEXUS_POLICY_ENABLED`` on the same line of the same function, and in the way the brake is
    actually applied — set the variable, restart the pod — the two readings are identical.

    Note what disarming does *not* do, here as for ``NEXUS_POLICY_ENABLED``: evaluation and
    recording continue, and ``engine`` raises ``alerts.DISARMED`` the first time it costs a
    denial. A brake that made governance disappear silently would be a worse hole than the one
    this closes.
    """
    s = _settings
    if not _env_flag("NEXUS_POLICY_ENABLED", True) or not config.enabled_from_env():
        s = replace(s, enforcement_enabled=False)
    return s


def configure(**kw: t.Any) -> Settings:
    """Set policy settings from code. Unknown keys are ignored rather than raising — this is
    reachable from a customer's ``init()`` and an unrecognised knob must not be a startup crash."""
    global _settings
    fields = {f for f in Settings.__dataclass_fields__}
    clean = {k: v for k, v in kw.items() if k in fields and v is not None}
    _settings = _clamped(replace(_settings, **clean))
    return current()


def resolve_from_env() -> Settings:
    """Apply the ``NEXUS_POLICY_*`` environment to the current settings.

    Called at init. Kept separate from ``current()`` so that reading settings on the decision path
    never touches ``os.environ`` — environment lookups are cheap but not free, and this runs
    inside the one budget we publish.
    """
    global _settings
    _settings = _clamped(replace(
        _settings,
        enforcement_enabled=_env_flag("NEXUS_POLICY_ENABLED", _settings.enforcement_enabled),
        decision_budget_ms=max(MIN_DECISION_BUDGET_MS,
                              _env_float("NEXUS_POLICY_BUDGET_MS",
                                         _settings.decision_budget_ms)),
        approval_timeout_s=max(0.0, _env_float("NEXUS_POLICY_APPROVAL_TIMEOUT_S",
                                               _settings.approval_timeout_s)),
        approval_timeout_max_s=max(0.0, _env_float("NEXUS_POLICY_APPROVAL_MAX_S",
                                                   _settings.approval_timeout_max_s)),
        approval_block_max_s=max(0.0, _env_float("NEXUS_POLICY_APPROVAL_BLOCK_MAX_S",
                                                 _settings.approval_block_max_s)),
        fail_closed=_env_flag("NEXUS_POLICY_FAIL_CLOSED", _settings.fail_closed),
        pubkey_hex=os.environ.get("NEXUS_POLICY_PUBKEY", _settings.pubkey_hex),
        envelope_path=os.environ.get("NEXUS_POLICY_FILE", _settings.envelope_path),
        state_path=os.environ.get("NEXUS_POLICY_STATE", _settings.state_path),
    ))
    return current()


def reset_for_tests() -> None:
    global _settings
    _settings = _clamped(Settings())
