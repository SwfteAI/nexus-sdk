"""The SDK must never replace the host application's exception.

`_safety.py` opens with the rule this file enforces: *"nothing in this SDK may raise into the host
application… a telemetry SDK must never be the reason a request fails."* `test_fault_injection.py`
already proves that for the SDK's own bugs, by making guarded hooks raise on demand. It cannot
reach this defect, because this defect is not in a guarded hook — it is in the *unguarded frame
just outside one*:

    def __exit__(self, exc_type, exc, tb):
        self._close(error=None if exc is None else f"{exc_type.__name__}: {exc}")

`_close` is guarded. The f-string is not, and `{exc}` calls `str()` on an object the customer
wrote. Measured before the fix, on all four call sites:

    Action.__exit__ : SDK REPLACED it with RuntimeError('exception __str__ exploded')
    Action.__aexit__: SDK REPLACED it with RuntimeError('exception __str__ exploded')
    Run.__exit__    : SDK REPLACED it with RuntimeError('exception __str__ exploded')
    Run.__aexit__   : SDK REPLACED it with RuntimeError('exception __str__ exploded')

The severity is not the crash. It is that the exception *type* changes, so the customer's
`except MyPaymentError:` never runs and their error path silently takes the wrong branch — a
telemetry SDK rewriting control flow in someone else's service.

Two kinds of test here, and the second is the one that matters in a year:

* **Behavioural**, driving each of the four context managers with a hostile exception.
* **Structural** (`test_no_context_manager_formats_a_host_exception_inline`), asserting on the
  source that no `__exit__` builds such a string itself. The behavioural tests protect four call
  sites that enumeration happened to reach; the structural test protects the *fifth one somebody
  adds next year*. This repository has produced "enumerate the instances, miss the next one"
  seven times now, and it happened here too — the first list held four
  sites, and there was a fifth in the same file (`Integration._close`, which happened to be safe
  because it passes the objects into the guard instead of formatting outside it).
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

from nexus import api
from nexus._safety import _ERROR_MESSAGE_LIMIT, describe_exception


class HostileStr(Exception):
    """An exception whose ``__str__`` raises.

    Not a contrivance: SQLAlchemy exceptions holding detached instances, Django lazy translation
    proxies, and anything doing lazy formatting behave this way once the session or context they
    captured is gone — which is precisely the moment an error is being handled.
    """

    def __str__(self) -> str:
        raise RuntimeError("exception __str__ exploded")


class HugeStr(Exception):
    """The commoner shape. ``__str__`` works, and returns five megabytes."""

    def __str__(self) -> str:
        return "x" * 5_000_000


class Ordinary(Exception):
    pass


# ==============================================================================================
# Behavioural: the host's exception survives, unchanged, through all four context managers.
# ==============================================================================================

def test_a_hostile_exception_survives_action_sync(sdk):
    with pytest.raises(HostileStr):
        with sdk.agent("job"):
            with sdk.action("pay"):
                raise HostileStr()


def test_a_hostile_exception_survives_action_async(sdk):
    async def body():
        with sdk.agent("job"):
            async with sdk.action("pay"):
                raise HostileStr()

    with pytest.raises(HostileStr):
        asyncio.run(body())


def test_a_hostile_exception_survives_run_sync(sdk):
    with pytest.raises(HostileStr):
        with sdk.agent("job"):
            raise HostileStr()


def test_a_hostile_exception_survives_run_async(sdk):
    async def body():
        async with sdk.agent("job"):
            raise HostileStr()

    with pytest.raises(HostileStr):
        asyncio.run(body())


@pytest.mark.parametrize("bad", [HostileStr, HugeStr])
def test_the_exception_identity_is_preserved_not_merely_the_type(sdk, bad):
    """`pytest.raises(HostileStr)` would also pass if the SDK caught and re-raised a fresh one.

    The customer's handler often inspects the instance — `err.response`, `err.retry_after`,
    `err.__cause__`. A re-raised copy passes a type check and still loses their data, so this
    asserts on identity.
    """
    original = bad()
    try:
        with sdk.agent("job"):
            with sdk.action("pay"):
                raise original
    except BaseException as caught:  # noqa: BLE001
        assert caught is original, "the SDK returned a different exception object"


def test_a_clean_block_is_still_clean(sdk):
    """Over-correction control #1: a blanket `try/except` around `__exit__` could pass every test
    above while breaking the ordinary path or swallowing exceptions entirely."""
    with sdk.agent("job"):
        with sdk.action("pay"):
            pass


def test_an_ordinary_exception_still_propagates(sdk):
    """Over-correction control #2: the fix must not start *suppressing* exceptions. `__exit__`
    returning True instead of False would make every test above pass and quietly eat the
    customer's errors, which is a worse bug than the one being fixed."""
    with pytest.raises(Ordinary, match="boom"):
        with sdk.agent("job"):
            with sdk.action("pay"):
                raise Ordinary("boom")


# ==============================================================================================
# The diagnosis must survive too. "Emit nothing, call it safe" is not a fix.
# ==============================================================================================

def test_the_error_still_reaches_the_event_at_full_tier(collector, monkeypatch):
    """The point of the string was telemetry. A fix that drops it trades a real bug for a blind
    operator, so this asserts type and message still reach the wire where the tier permits it.

    Full tier is required for the assertion to be about the *fix* rather than about the tier
    ladder. At the default tier this same block ships no message at all — deliberately, that is
    the tier ladder's doing — and a test written against T0 would pass whether the error string were
    constructed correctly or not constructed at all.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_TIER", "full")
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    try:
        with pytest.raises(Ordinary):
            with nexus.agent("job"):
                with nexus.action("pay"):
                    raise Ordinary("boom")
        nexus.flush()
        blob = str(collector.events)
        assert "Ordinary" in blob, "the exception type never reached the wire"
        assert "boom" in blob, "the exception message never reached the wire at T2"
    finally:
        nexus.shutdown()


def test_the_message_does_not_walk_around_the_tier_ladder(sdk, collector):
    """The counterweight, and the reason the test above needed splitting.

    ``describe_exception`` produces free text derived from customer data. Routing it to the wire
    outside ``tiered_text`` would fix one leak by reintroducing another. At the default tier the
    failure must still be *visible* — an operator has to know the action errored — while the
    message itself stays home.
    """
    with pytest.raises(Ordinary):
        with sdk.agent("job"):
            with sdk.action("pay"):
                raise Ordinary("boom-tier-canary")
    sdk.flush()
    blob = str(collector.events)
    assert "boom-tier-canary" not in blob, "T0 shipped an exception message"
    assert "error" in blob, "T0 hid the fact that anything went wrong at all"


def test_a_hostile_exception_still_reports_its_type():
    """The half that is free is the more useful half.

    `exc_type.__name__` is an attribute read on a class; `str(exc)` is a call into foreign code.
    When the second fails the first is still true and still worth shipping — an operator seeing
    `TimeoutError` with no message can act; an operator seeing nothing cannot.
    """
    assert describe_exception(HostileStr, HostileStr()) == "HostileStr"


def test_a_giant_message_is_truncated_not_shipped():
    got = describe_exception(HugeStr, HugeStr())
    assert got is not None
    assert len(got) <= _ERROR_MESSAGE_LIMIT + len("HugeStr: ")


def test_describe_exception_survives_a_type_with_no_name():
    """Defence in depth: the fix's own first line, `exc_type.__name__`, is itself an attribute
    lookup on a customer object. A metaclass with a raising `__name__` is rare, but the whole
    finding is that rare foreign behaviour reached an unguarded frame."""

    class Meta(type):
        @property
        def __name__(cls):  # noqa: N805
            raise RuntimeError("even the name explodes")

    class Nameless(Exception, metaclass=Meta):
        pass

    assert describe_exception(Nameless, Nameless()) is not None


# ==============================================================================================
# Structural: the rule, not the four instances of it.
# ==============================================================================================

def test_no_context_manager_formats_a_host_exception_inline():
    """The class-level assertion.

    Every `__exit__`/`__aexit__` in `api.py` must hand `exc` to guarded code rather than render it
    where a raise cannot be contained. Asserted on source rather than by driving each manager,
    because a runtime test only covers the managers someone remembered to exercise — and the
    entire finding is about the site nobody revisited.
    """
    offenders = []
    for cls_name, cls in vars(api).items():
        if not inspect.isclass(cls) or cls.__module__ != api.__name__:
            continue
        for meth_name in ("__exit__", "__aexit__"):
            meth = cls.__dict__.get(meth_name)
            if meth is None:
                continue
            src = inspect.getsource(meth)
            if "{exc}" in src or "str(exc)" in src or "format(exc)" in src:
                offenders.append(f"{cls_name}.{meth_name}")
    assert not offenders, (
        "these context managers render the host's exception outside the guard, which is the defect "
        f"returning: {offenders}. Pass exc to guarded code, or use _safety.describe_exception."
    )
