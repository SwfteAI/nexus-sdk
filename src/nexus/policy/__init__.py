"""The enforcement seam — the one thing in this product that can say *no*.

`REPLICATION-EFFORT.md` row 11 is the reason this package exists. Capture of coding agents is now
free: OpenLIT is Apache-2.0, `o11y-dev/opentelemetry-hooks` is MIT, and ddtrace, OpenLLMetry and
OpenInference all read the same provider call sites we do. None of them can stop a call. Every
agent-observability vendor observes; the differentiator is not what we see, it is that we can
refuse. That is what is implemented here.

Everything a caller needs is three names:

    from nexus import policy

    d = policy.decide("tool_action", {"tool": "db.write", "target": "prod-orders"})
    if d.denied:
        ...

    with policy.gate("tool_action", {"tool": "db.write", "target": "prod-orders"}):
        write_the_rows()          # never runs if an enforcing rule denies

    policy.install(signed_envelope)

``gate`` is the important one, and its shape is the acceptance criterion for this work package:
**the decision happens before the body, not around it.** A denial raised after the write already
went out is not enforcement, it is journalism — so ``gate`` decides, and only then yields. The
test that proves it (``test_enforcement.py::test_deny_lands_before_the_effect``) asserts on a side
effect list that stays empty, and inverting the order is exactly what would make it fail.

**What raises and what does not.** ``Denied`` is the single exception this SDK will ever put in a
host traceback, and the host opted into it twice — the rule carried ``enforce: true`` and the call
site did not decline. Everything else is caught: a bug in policy evaluation degrades to allow plus
an integrity alert, never to a 500 in a customer's service (``_safety``, case 4.7). ``decide``
never raises at all; only ``gate`` and ``check`` do, and only on a real denial.

**Failure semantics, in one paragraph**, because this is the part that must be exactly right.
Policy that is missing, unverifiable or unparseable is *no policy*: allow, and raise an integrity
alert so the gap is visible rather than merely survived (6.3, 6.5). Policy that is verified but
stale keeps enforcing its ``enforce``-marked rules — a cached deny never decays, or disconnecting
from the control plane would be the documented bypass — while its unmarked rules degrade to
advice (6.3, 6.6). Evaluation is capped by a latency budget; exceeding it allows and records the
timeout (6.4). A rule that requires a human is bounded by a mandatory per-rule timeout, and times
out to deny when the rule is enforce-marked and to allow when it is not (6.8). Denying because we
could not reach something is never a default anywhere in this package.
"""
from __future__ import annotations

import contextlib
import typing as t

from . import alerts, approval, deputy, engine, envelope, rules, settings
from .engine import ALLOW, DENY, Decision, Denied, Snapshot, decide, install, refresh, snapshot
from .settings import Settings, configure

__all__ = [
    "ALLOW", "DENY", "Decision", "Denied", "Settings", "Snapshot",
    "alerts", "approval", "check", "configure", "decide", "deputy", "envelope", "evaluate",
    "gate", "init", "install", "refresh", "rules", "settings", "snapshot",
]


def init() -> Settings:
    """Arm policy from the environment. Called from ``nexus.init()``; safe to call twice.

    Loading an envelope from ``NEXUS_POLICY_FILE`` here rather than lazily on first decision is
    deliberate: verification is ~10ms of pure-Python curve arithmetic, and paying it inside
    whichever request happens to be first is how an SDK acquires a mysterious p99 spike at
    startup. Pay it at init, where the customer expects startup cost to live.
    """
    s = settings.resolve_from_env()
    if not s.enforcement_enabled:
        # A governance product that can be switched off by one environment variable, and says
        # nothing when it is, has a silent-disarm problem rather than a configuration feature.
        # ``engine`` raises the same alert the first time the switch actually costs a denial; this
        # one fires at startup, which is where an operator is looking.
        alerts.raise_alert(alerts.DISARMED, "policy enforcement is disabled at startup")
    if s.envelope_path and not envelope.key_is_configured(s.pubkey_hex):
        # The exact shape of the forged-signature hazard: a policy file configured, no key to
        # check it with. Said plainly at startup rather than discovered as a BAD_SIGNATURE later.
        alerts.raise_alert(alerts.NO_PUBKEY,
                           "a policy file is configured but NEXUS_POLICY_PUBKEY is not; "
                           "no envelope can be trusted")
    try:
        engine.load_from_settings()
    except Exception:  # noqa: BLE001
        alerts.raise_alert(alerts.INTERNAL_ERROR, "policy init failed")
    return s


def check(kind: str, subject: t.Mapping[str, t.Any], *,
          enforce: t.Optional[bool] = None,
          approval_max_s: t.Optional[float] = None) -> Decision:
    """Decide, and raise ``Denied`` if an enforcing rule refuses. Returns the decision otherwise.

    The raising counterpart to ``decide``. Use it where the effect is the next statement and there
    is no block to wrap.
    """
    d = decide(kind, subject, enforce=enforce, approval_max_s=approval_max_s)
    if d.denied:
        raise Denied(d)
    return d


@contextlib.contextmanager
def gate(kind: str, subject: t.Mapping[str, t.Any], *,
         enforce: t.Optional[bool] = None,
         approval_max_s: t.Optional[float] = None) -> t.Iterator[Decision]:
    """Guard a block of code. Decides *first*, then yields.

    ::

        with policy.gate("tool_action", {"tool": "email.send", "target": user}) as d:
            send_email()

    On a denial the body never executes and ``Denied`` propagates to the caller. On an allow the
    decision is yielded, so a caller in advise mode can see that policy *would* have refused —
    which is the whole value of a shadow deployment.

    ``approval_max_s`` bounds how long this thread may be parked waiting for a human approver,
    overriding ``settings.approval_block_max_s`` for this call site only. See ``engine.decide``.
    """
    d = check(kind, subject, enforce=enforce, approval_max_s=approval_max_s)
    yield d


def evaluate(kind: str, subject: t.Mapping[str, t.Any], *, enforce: bool = False) -> Decision:
    """The M0–M1 seam, preserved so WP-5's call sites keep compiling.

    The old signature took ``enforce`` as a call-site mode and always allowed. It now routes to
    the real engine with the same meaning it will have forever: ``enforce=False`` declines to
    block at this call site whatever the rules say. Note that the default is still ``False``, so
    an adapter written against the no-op seam does not start blocking traffic the moment a policy
    is installed — enabling enforcement at a call site is a deliberate edit, not an upgrade
    side effect.
    """
    return decide(kind, subject, enforce=enforce)


def reset_for_tests() -> None:
    """Return the package to a pristine state. Called from the test fixture."""
    engine.reset_for_tests()
    approval.reset_for_tests()
    settings.reset_for_tests()
    envelope.reset_for_tests()
    alerts.reset()
