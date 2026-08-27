"""Rules: the shape, the matcher, and the two asymmetries that make the matcher safe.

**Asymmetry one — ``enforce`` is a property of the rule, not of the caller.** A rule denies for
real only if it carries ``"enforce": true``. Everything else evaluates and records and lets the
call through. This is case 6.2's "opt-in per rule" and case 6.3's "fail closed only for rules
explicitly marked ``enforce``", and it is one flag rather than two because a mode that could be
inferred from context is a mode somebody will infer wrongly at 3am. A call site cannot promote an
unmarked rule to enforcing; it can only decline to enforce a marked one (see ``engine.decide``).

**Asymmetry two — an unknown field never satisfies an ``allow`` clause, but does not save a
subject from a ``deny`` clause.** Straight from ``DEPUTY.md``: ``branch_not: ["main"]`` against a
card with no branch must not read as *"well, it isn't main"*. That step, from "I don't know" to
"allow", is the one this package exists to refuse. The mirror holds too: refusing under
uncertainty is never the unsafe direction, so a ``deny`` rule whose clause references a field the
subject lacks still denies. One predicate, two polarities, decided by the rule's own action.

Malformed rules are **quarantined individually**, not fatal to the envelope. The alternative —
rejecting the whole rule set over one typo — means a single bad character in a control-plane
deploy disarms every control at once, or, worse, if we failed closed on it, denies everything at
once. Quarantining keeps the other rules working and raises an integrity alert so the typo is
visible rather than merely survivable. The cost is honest and worth naming: a malformed
``enforce`` rule is an enforcement gap, so ``RuleSet.quarantined`` is reported, not just counted.

Glob clauses are ``fnmatch``, never regex — the same choice, for the same reason, as
``DEPUTY.md``'s ``command_glob``. There is no alternation: ``"git (status|diff)*"`` matches that
literal text and nothing else. The list form is how you spell alternation, which is why the
matcher needs no pattern language of its own.

**Asymmetry three — normalisation and glob strictness follow the same polarity as the other two.**
The matcher used to be exactly case-sensitive and exactly ``fnmatch``, which gave an attacker two
free evasions: ``target_contains: ["prod"]`` missed ``PROD``, and because ``fnmatch``'s ``*``
crosses every character including ``/`` and ``?``, the *allow* rule ``target_glob:
"https://*.safe.com/*"`` matched ``https://evil.com/a?z=.safe.com/b``. Both are fixed, and both
fixes move only in the direction that is safe for the rule's own polarity:

* For a ``deny`` or ``require_approval`` rule, both sides are NFKC-normalised and casefolded.
  That can only make a refusing rule match *more*, and refusing under uncertainty is never the
  unsafe direction — the same sentence that justifies asymmetry two. (``deputy.py`` already
  casefolded; the two matchers in this subsystem disagreeing about what a rule meant is how the
  evasion survived review, and they now agree.)
* For an ``allow`` rule, both sides stay case-sensitive *and* ``*``/``?`` stop crossing the
  structural delimiters ``/``, ``?``, ``#`` and ``@``. Both changes can only make a permitting rule
  match *less*. An author who really wants a wildcard that crosses delimiters writes ``**`` and has
  said so on purpose.

The reason these are opposite rather than uniform is that "casefold everything" would have widened
allow rules, and a widened allow is an authorisation bug. There is one clause where the polarity
inverts again — ``branch_not``, which is a negative clause — and it is handled where it lives.
"""
from __future__ import annotations

import fnmatch
import re
import typing as t
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache

from . import alerts

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
_ACTIONS = (ALLOW, DENY, REQUIRE_APPROVAL)

#: Risk ladder for ``max_risk``. An unknown risk is the worst case, not the best.
_RISK = {"low": 0, "medium": 1, "high": 2}

#: Every clause the matcher understands. A rule naming anything else is malformed — silently
#: ignoring an unrecognised clause would turn a typo'd ``targt_contains`` into a rule that matches
#: far more than its author wrote, which for an ``allow`` rule is an authorisation bug.
_CLAUSES = frozenset({
    "kind", "tool", "tool_glob", "target", "target_glob", "target_contains",
    "command_glob", "repos", "branch_not", "max_risk", "field_equals",
})


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    enforce: bool = False
    reason: str = ""
    match: dict = field(default_factory=dict)
    approval_timeout_s: t.Optional[float] = None
    #: What happens when a human does not answer in time. Only meaningful for
    #: ``require_approval``. Defaults are set in ``parse``, not here, because the default depends
    #: on ``enforce`` and a dataclass default cannot see a sibling field.
    on_timeout: str = DENY

    @property
    def enforcing(self) -> bool:
        """True iff this rule may actually stop something."""
        return bool(self.enforce) and self.action in (DENY, REQUIRE_APPROVAL)


@dataclass(frozen=True)
class RuleSet:
    rules: "tuple[Rule, ...]" = ()
    #: ``(index, why)`` for every rule we refused to load. Surfaced, not just counted — see the
    #: module docstring on why a quarantined ``enforce`` rule is an enforcement gap.
    quarantined: "tuple[tuple[int, str], ...]" = ()

    @property
    def has_enforcing(self) -> bool:
        return any(r.enforcing for r in self.rules)


EMPTY = RuleSet()


def parse(raw_rules: t.Any, *, max_rules: int = 1000) -> RuleSet:
    """Build a ``RuleSet``. Never raises; anything unusable becomes a quarantine entry."""
    good: "list[Rule]" = []
    bad: "list[tuple[int, str]]" = []
    if not isinstance(raw_rules, list):
        return EMPTY
    for i, raw in enumerate(raw_rules[:max_rules]):
        try:
            rule, why = _parse_one(raw)
        except Exception as exc:  # noqa: BLE001
            rule, why = None, f"{type(exc).__name__}: {exc}"
        if rule is None:
            bad.append((i, why or "unparseable"))
            alerts.raise_alert(alerts.MALFORMED_RULE, why or "unparseable", rule_index=i)
        else:
            good.append(rule)
    if len(raw_rules) > max_rules:
        alerts.raise_alert(alerts.MALFORMED_RULE,
                           f"rule set truncated at {max_rules}", dropped=len(raw_rules) - max_rules)
    return RuleSet(rules=tuple(good), quarantined=tuple(bad))


def _parse_one(raw: t.Any) -> "tuple[t.Optional[Rule], t.Optional[str]]":
    if not isinstance(raw, dict):
        return None, "rule is not an object"
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid.strip():
        return None, "rule has no id"
    action = raw.get("action")
    if action not in _ACTIONS:
        return None, f"rule {rid!r} has unknown action {action!r}"
    match = raw.get("match", {})
    if not isinstance(match, dict):
        return None, f"rule {rid!r} has a non-object match"
    unknown = set(match) - _CLAUSES
    if unknown:
        return None, f"rule {rid!r} has unknown clauses {sorted(unknown)}"
    mr = match.get("max_risk")
    if mr is not None and mr not in _RISK:
        return None, f"rule {rid!r} has unknown max_risk {mr!r}"
    fe = match.get("field_equals")
    if fe is not None and not isinstance(fe, dict):
        return None, f"rule {rid!r} has a non-object field_equals"

    enforce = raw.get("enforce") is True
    approval = raw.get("approval") or {}
    if not isinstance(approval, dict):
        return None, f"rule {rid!r} has a non-object approval block"

    timeout = approval.get("timeout_s")
    if timeout is not None and (not isinstance(timeout, (int, float))
                                or isinstance(timeout, bool) or timeout <= 0):
        return None, f"rule {rid!r} has a non-positive approval timeout"

    on_timeout = approval.get("on_timeout")
    if on_timeout is None:
        # An approval gate that allows when nobody answers is not a gate; an *advisory* one that
        # denied when nobody answered would block calls the customer never asked us to block. So
        # the default follows the marking rather than being a constant.
        on_timeout = DENY if enforce else ALLOW
    if on_timeout not in (ALLOW, DENY):
        return None, f"rule {rid!r} has unknown on_timeout {on_timeout!r}"

    return Rule(
        id=rid.strip()[:128],
        action=action,
        enforce=enforce,
        reason=str(raw.get("reason") or "")[:256],
        match=match,
        approval_timeout_s=float(timeout) if timeout is not None else None,
        on_timeout=on_timeout,
    ), None


# ------------------------------------------------------------------------------------------
# matching
# ------------------------------------------------------------------------------------------

_MISSING = object()
_UNCACHED = object()

#: Structural delimiters an ``allow`` rule's ``*`` may not cross. Chosen as the characters that
#: change what a URL or path *means*: authority (``@``), path (``/``), query (``?``) and fragment
#: (``#``). Space is deliberately not one — ``command_glob: "git status*"`` must keep matching
#: ``git status -s``, and a space does not reinterpret the rest of the string.
_SEPARATORS = "/?#@"
_SEP_SPLIT = re.compile("([%s])" % re.escape(_SEPARATORS))


def _fold(s: str) -> str:
    """NFKC-normalise and casefold. Applied only where matching *more* is the safe direction."""
    return unicodedata.normalize("NFKC", s).casefold()


@lru_cache(maxsize=4096)
def _fold_pattern(p: str) -> str:
    """``_fold`` for the rule side. Cached because rule patterns are few, signed, and re-used on
    every decision; subject values are neither and are folded once per decision instead."""
    return _fold(p)


@lru_cache(maxsize=1024)
def _segments(s: str) -> tuple:
    return tuple(_SEP_SPLIT.split(s))


def _glob_strict(text: str, pattern: str) -> bool:
    """``fnmatch``, except ``*`` and ``?`` do not cross ``/``, ``?``, ``#`` or ``@``.

    Implemented by splitting both sides on those delimiters and matching the pieces pairwise, which
    is the same thing as compiling a stricter wildcard but does not require hand-writing a glob-to-
    regex translator inside a security control. A differing number of pieces is an immediate no,
    which is what stops ``https://*.safe.com/*`` from matching
    ``https://evil.com/a?z=.safe.com/b``: eleven pieces against seven.

    ``**`` anywhere in the pattern opts back into plain ``fnmatch`` for that pattern. An author who
    writes it has asked for a wildcard that crosses delimiters in as many words, which is different
    from getting one by accident.
    """
    if "**" in pattern:
        return fnmatch.fnmatchcase(text, pattern)
    pat = _segments(pattern)
    txt = tuple(_SEP_SPLIT.split(text))
    if len(txt) != len(pat):
        return False
    for i, (a, b) in enumerate(zip(txt, pat)):
        # ``re.split`` with a capturing group alternates piece, delimiter, piece, …, so odd indices
        # are delimiters and must be identical rather than matched.
        if i % 2:
            if a != b:
                return False
        elif not fnmatch.fnmatchcase(a, b):
            return False
    return True


def _as_list(v: t.Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _get(subject: t.Mapping, name: str) -> t.Any:
    v = subject.get(name, _MISSING)
    if v is _MISSING or v is None or v == "":
        return _MISSING
    return v


def matches(rule: Rule, subject: t.Mapping,
            folded: t.Optional[dict] = None) -> bool:
    """True iff ``rule`` covers ``subject``. Clauses are ANDed; a list matches if any entry does.

    ``allowing`` is the polarity switch described in the module docstring, and it now drives all
    three asymmetries: for an ``allow`` rule a missing field fails the clause, comparison stays
    case-sensitive, and globs do not cross structural delimiters; for a ``deny`` or
    ``require_approval`` rule a missing field does not save the subject and both sides are
    normalised.

    ``folded`` is a per-decision scratch dict so that a subject value is NFKC-normalised once
    rather than once per rule — ``first_match`` supplies it. Passing ``None`` is correct and simply
    means no sharing, which is what a direct caller (a test, ``deputy``) wants.
    """
    allowing = rule.action == ALLOW
    if folded is None:
        folded = {}
    m = rule.match
    if not m:
        # A rule with no clauses is unconditional. For a deny that is a legitimate thing to ship —
        # `{"action": "deny", "enforce": true}` is the kill switch, and the control plane is
        # entitled to send it. For an *allow* it is almost always a mistake (a match block that
        # failed to serialise, a template that rendered empty), and the mistake authorises
        # everything. So unconditional means "everything" in the refusing direction only.
        return rule.action != ALLOW

    for clause, want in m.items():
        if not _clause_ok(clause, want, subject, allowing, folded):
            return False
    return True


def _field(subject: t.Mapping, name: str, allowing: bool, folded: dict) -> t.Any:
    """``_get`` as a comparison string, normalised unless the rule is an ``allow``.

    The cache is keyed by field name and lives for one decision, so a 50-rule set that reads
    ``target`` in every rule normalises it once rather than fifty times. That matters: this is on
    the request path under a published p99 cap.
    """
    if allowing:
        v = _get(subject, name)
        return _MISSING if v is _MISSING else str(v)
    hit = folded.get(name, _UNCACHED)
    if hit is _UNCACHED:
        v = _get(subject, name)
        hit = _MISSING if v is _MISSING else _fold(str(v))
        folded[name] = hit
    return hit


def _pat(x: t.Any, allowing: bool) -> str:
    return str(x) if allowing else _fold_pattern(str(x))


def _clause_ok(clause: str, want: t.Any, subject: t.Mapping, allowing: bool, folded: dict) -> bool:
    if clause == "kind":
        return _exact(_field(subject, "kind", allowing, folded), want, allowing)
    if clause == "tool":
        return _exact(_field(subject, "tool", allowing, folded), want, allowing)
    if clause == "target":
        return _exact(_field(subject, "target", allowing, folded), want, allowing)
    if clause == "tool_glob":
        return _glob(_field(subject, "tool", allowing, folded), want, allowing)
    if clause == "target_glob":
        return _glob(_field(subject, "target", allowing, folded), want, allowing)
    if clause == "command_glob":
        return _glob(_field(subject, "command", allowing, folded), want, allowing)
    if clause == "repos":
        return _glob(_field(subject, "repo", allowing, folded), want, allowing)
    if clause == "target_contains":
        return _contains(_field(subject, "target", allowing, folded), want, allowing)
    if clause == "branch_not":
        # The polarity inverts here, because the clause is negative. ``branch_not: ["main"]`` in a
        # *deny* rule exempts main, so folding would *widen the exemption* and weaken the deny;
        # in an *allow* rule it restricts the allow, so folding narrows it. Safe direction is
        # therefore the opposite of everywhere else: normalise for ``allow``, not for ``deny``.
        branch = _field(subject, "branch", not allowing, folded)
        if branch is _MISSING:
            # DEPUTY.md, verbatim in behaviour: a card with no branch does not satisfy
            # `branch_not`. "It isn't main because I couldn't tell" is the smuggling route.
            return not allowing
        return branch not in {_pat(x, not allowing) for x in _as_list(want)}
    if clause == "max_risk":
        risk = _field(subject, "risk", allowing, folded)
        if risk is _MISSING:
            return not allowing           # no risk block == worst case
        # Unknown risk is still 99, i.e. worse than anything named. Folding only means ``"HIGH"``
        # is recognised as high — which makes a ``deny`` with ``max_risk: "high"`` fire where it
        # previously fell through, and leaves an ``allow`` case-sensitive as above.
        return _RISK.get(risk, 99) <= _RISK.get(str(want), -1)
    if clause == "field_equals":
        for name, expected in (want or {}).items():
            got = _field(subject, name, allowing, folded)
            if got is _MISSING:
                if allowing:
                    return False
                continue
            if got not in {_pat(x, allowing) for x in _as_list(expected)}:
                return False
        return True
    return False      # unreachable: parse rejects unknown clauses


def _exact(got: t.Any, want: t.Any, allowing: bool) -> bool:
    if got is _MISSING:
        return not allowing
    return got in {_pat(x, allowing) for x in _as_list(want)}


def _glob(got: t.Any, want: t.Any, allowing: bool) -> bool:
    if got is _MISSING:
        return not allowing
    if allowing:
        return any(_glob_strict(got, str(p)) for p in _as_list(want))
    return any(fnmatch.fnmatchcase(got, _pat(p, False)) for p in _as_list(want))


def _contains(got: t.Any, want: t.Any, allowing: bool) -> bool:
    if got is _MISSING:
        return not allowing
    return any(_pat(p, allowing) in got for p in _as_list(want))


def first_match(ruleset: RuleSet, subject: t.Mapping,
                deadline: t.Optional[t.Callable[[], bool]] = None) -> "t.Optional[Rule]":
    """First matching rule wins — the same convention as ``DEPUTY.md``'s rules file.

    ``deadline`` is polled between rules. Cooperative rather than pre-emptive, because Python
    cannot interrupt a running frame; the honest statement of the guarantee is in
    ``engine.decide``'s docstring and it is bounded per-rule, not per-decision.
    """
    folded: dict = {}
    for rule in ruleset.rules:
        if deadline is not None and deadline():
            return None
        try:
            if matches(rule, subject, folded):
                return rule
        except Exception as exc:  # noqa: BLE001
            # A matcher that raises is a malformed rule we failed to catch at parse time. Skip it
            # and keep going: one bad rule must not stop the rules after it from applying.
            alerts.raise_alert(alerts.MALFORMED_RULE, f"matcher raised for {rule.id!r}",
                               error=type(exc).__name__)
    return None
