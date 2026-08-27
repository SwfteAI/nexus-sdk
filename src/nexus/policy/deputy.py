"""The deputy — delegated approval authority, ported from ``DEPUTY.md``.

One governing rule, and everything in this file is a consequence of it:

    **There is no path from "I don't know" to "allow".**

Every ambiguity resolves to ``ESCALATE`` — no rules, corrupt rules, ``"default": "allow"`` in the
file, an exception mid-evaluation, no rule matched, a card that does not identify tool and target,
an audit record that could not be written, a spent hourly budget. The table in ``DEPUTY.md`` is
reproduced as ``test_enforcement.py::test_deputy_escalates_on_every_ambiguity``, row for row,
because a delegated-authority engine that quietly gains a new allow path is the single worst bug
this package could ship.

Two subtleties worth keeping in the reader's head:

**Destructive is checked on the card, not the rule.** A rule matching ``Bash(git status:*)`` looks
harmless right up until the command is ``git status && rm -rf /``. Checking the rule that matched
rather than the thing in front of you is how a benign policy becomes a smuggling route. A human
may approve a destructive action because they are looking at it; a standing policy may not
pre-authorise one, because nobody is. ``allow`` therefore never covers a destructive card —
``deny`` has no such restriction, since denying dangerous things is the entire point.

**A rules file can only ever narrow authority.** There is no key in it that widens the default.
``"default": "allow"`` parses, is recorded as an integrity alert, and is forced back to escalate.

The daemon, the ledger and the ``…/approvals/{id}/resolve`` relay are the CLI's concern and stay
there. What the SDK needs is the *decision function*, so that a service running an agent gets the
same answers as a laptop does, and so that "whoever answers first wins" has a second answerer.
"""
from __future__ import annotations

import threading
import time
import typing as t
from dataclasses import dataclass

from . import alerts, rules as rules_mod

ALLOW = "allow"
DENY = "deny"
ESCALATE = "escalate"

#: Hourly circuit breaker (``deputy.max_decisions_per_hour``). A rules file that matches far more
#: than its author intended becomes a visible queue of escalations rather than a quiet firehose.
#: ``0`` delegates nothing.
DEFAULT_MAX_PER_HOUR = 200

#: Command fragments that make a card destructive whatever rule matched it. Checked against every
#: segment of the command, because ``&&``, ``;`` and ``|`` are how a benign prefix carries a
#: payload past a prefix-matching rule.
_DESTRUCTIVE = (
    "rm -rf", "rm -fr", "mkfs", "dd if=", ":(){", "shutdown", "reboot",
    "drop table", "drop database", "truncate table", "delete from",
    "git push --force", "git push -f", "git reset --hard", "git clean -fd",
    "chmod -r 777", "chown -r", "curl", "wget",
)
_SEGMENT_SPLIT = ("&&", "||", ";", "|", "\n")


@dataclass(frozen=True)
class Verdict:
    action: str
    rule_id: t.Optional[str] = None
    reason: str = ""

    @property
    def actor(self) -> str:
        """Every decision is stamped ``deputy:<rule-id>``, never a bare actor — so *"what did a
        person actually approve?"* stays an answerable question."""
        return f"deputy:{self.rule_id}" if self.rule_id else "deputy:none"


class Budget:
    """The hourly circuit breaker. A sliding window rather than a fixed hour, because a fixed hour
    lets a runaway rules file spend the whole allowance in the last minute of one hour and again
    in the first minute of the next."""

    def __init__(self, max_per_hour: int = DEFAULT_MAX_PER_HOUR) -> None:
        self.max_per_hour = max_per_hour
        self._lock = threading.Lock()
        self._stamps: "list[float]" = []

    def spend(self, now: t.Optional[float] = None) -> bool:
        clock = now if now is not None else time.time()
        with self._lock:
            cutoff = clock - 3600.0
            self._stamps = [s for s in self._stamps if s > cutoff]
            if len(self._stamps) >= self.max_per_hour:
                return False
            self._stamps.append(clock)
            return True


def parse_rules(raw: t.Any) -> "tuple[t.Optional[rules_mod.RuleSet], str]":
    """Parse a deputy rules document. Returns ``(ruleset, default_action)``.

    ``None`` for the ruleset means *escalate everything* — no file, corrupt file, wrong shape. The
    default action is forced to ``escalate`` whatever the file says.
    """
    if not isinstance(raw, dict):
        return None, ESCALATE
    if raw.get("default") not in (None, ESCALATE):
        alerts.raise_alert(alerts.MALFORMED_RULE,
                           "deputy rules tried to widen the default; forced to escalate")
    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list):
        return None, ESCALATE
    return rules_mod.parse(raw_rules), ESCALATE


def is_destructive(card: t.Mapping) -> bool:
    """Destructive-by-card. Unparseable counts as destructive: unknown is not harmless."""
    command = card.get("command")
    target = card.get("target")
    if card.get("destructive") is True:
        return True
    text = command if isinstance(command, str) else ""
    if not text and isinstance(target, str):
        text = target
    if not text:
        # No command and no target to read. We cannot tell what this does, so we do not get to
        # say it is safe.
        return True
    lowered = text.lower()
    segments = [lowered]
    for sep in _SEGMENT_SPLIT:
        segments = [part for seg in segments for part in seg.split(sep)]
    return any(marker in seg for seg in segments for marker in _DESTRUCTIVE)


def decide(card: t.Mapping, ruleset: "t.Optional[rules_mod.RuleSet]", *,
           default: str = ESCALATE, budget: t.Optional[Budget] = None,
           audit: "t.Optional[t.Callable[[Verdict], None]]" = None) -> Verdict:
    """Answer *is this specific call something I was told I may approve without asking?*

    Most of the time the answer is no, and that is the point. Never raises: an exception mid
    evaluation is itself an ambiguity and escalates like every other one.
    """
    try:
        return _decide(card, ruleset, default, budget, audit)
    except Exception as exc:  # noqa: BLE001
        alerts.raise_alert(alerts.INTERNAL_ERROR, f"deputy raised: {type(exc).__name__}")
        return Verdict(ESCALATE, None, "deputy evaluation raised")


def _decide(card, ruleset, default, budget, audit) -> Verdict:
    if ruleset is None:
        return Verdict(ESCALATE, None, "no delegated authority")
    if default != ESCALATE:
        return Verdict(ESCALATE, None, "default was not escalate")
    if not card.get("tool") or not card.get("target"):
        # "The card doesn't identify tool + target" — a card we cannot describe is a card we
        # cannot have been told about in advance.
        return Verdict(ESCALATE, None, "card does not identify tool and target")

    rule = rules_mod.first_match(ruleset, card)
    if rule is None:
        return Verdict(ESCALATE, None, "no rule matched")

    if rule.action == rules_mod.DENY:
        verdict = Verdict(DENY, rule.id, rule.reason or "denied by deputy policy")
    elif rule.action == rules_mod.ALLOW:
        if is_destructive(card):
            # Checked on the card, not on the rule that matched. See the module docstring.
            return Verdict(ESCALATE, rule.id, "matched an allow rule but the card is destructive")
        if budget is not None and not budget.spend():
            return Verdict(ESCALATE, rule.id, "hourly delegation budget spent")
        verdict = Verdict(ALLOW, rule.id, rule.reason or "delegated by deputy policy")
    else:
        return Verdict(ESCALATE, rule.id, "rule requires human approval")

    # The decision is written to the ledger BEFORE it is applied. A write that fails means the
    # decision does not happen and the human still gets the card — doing it and recording it are
    # the same step, in the wrong order to skip.
    if audit is not None:
        try:
            audit(verdict)
        except Exception:  # noqa: BLE001
            alerts.raise_alert(alerts.INTERNAL_ERROR, "deputy audit write failed")
            return Verdict(ESCALATE, rule.id, "audit record could not be written")
    return verdict
