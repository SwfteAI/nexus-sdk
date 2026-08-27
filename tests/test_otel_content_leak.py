"""Auto-instrumentation must not harvest model input into an untiered field.

The defect these tests exist to falsify: ``semconv._TOOL_TARGET_KEYS`` read ``tool.parameters``
(a tool call's arguments) and ``input.value`` (OpenInference's raw span input) into
``SpanFacts.tool_target``, the bridge passed that to ``contract.tool_action(target=...)``, and the
only thing between it and the collector was ``wire_text(target, cfg.tier, 256)`` — a gate that
the tier tests prove is a no-op at the default tier.

Two rules shape every assertion here:

* **The tier is not the subject.** These tests run at the *default* tier and never set one. A test
  that had to configure ``metadata_only`` to see the leak would be testing the gate; the finding is
  that the bridge hands a payload to a gate at all. If ``wire_text`` were fixed tomorrow and broken
  again the day after, these tests would still fail on the day it broke.
* **The assertion is on the whole event, not on one field.** ``"Rumpelstiltskin" not in
  repr(event)`` is the only form that survives someone moving the value to a different key.

The canary strings are deliberately not URL-shaped and contain no ``key=value`` pair. The test this
file replaces used ``https://internal.example/?token=s3cret`` and passed against the vulnerable
code — not because the field was gated but because ``redact``'s one working rule happened to catch
``token=``. A canary that only the intended defence can catch is the point of the exercise.
"""
from __future__ import annotations

import json

import pytest

from test_bridge import FakeSpan, bridge  # noqa: F401


# A sentence, a name and a number, none of which any pattern in ``redact`` matches, none of which
# is shaped like a credential. If any of these reaches the collector, content reached the collector.
CANARY_PROSE = "the patient Rumpelstiltskin reports chest pain radiating to the left arm"
CANARY_NAME = "Rumpelstiltskin"
CANARY_ID = "MRN-88213371"


def _tool_action(bridge, collector, sdk, attrs: dict) -> dict:
    span = FakeSpan("lookup_patient", attrs, scope="openinference.langchain")
    bridge.on_start(span)
    bridge.on_end(span)
    sdk.flush(2.0)
    actions = collector.of_type("tool_action")
    assert len(actions) == 1, f"expected exactly one tool_action, got {collector.types()}"
    return actions[0]


# --------------------------------------------------------------------------------------------
# The leak itself
# --------------------------------------------------------------------------------------------

def test_tool_parameters_never_reach_the_collector_at_the_default_tier(bridge, collector, sdk):
    """``tool.parameters`` is the model's chosen arguments. It is content, not a target.

    No tier is set: this is what a customer gets by installing the SDK, running an instrumented
    library and reading nothing.
    """
    event = _tool_action(bridge, collector, sdk, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.parameters": json.dumps({"complaint": CANARY_PROSE, "mrn": CANARY_ID}),
    })
    blob = json.dumps(event)
    assert CANARY_NAME not in blob, f"raw tool arguments reached the wire: {blob}"
    assert CANARY_ID not in blob, f"raw tool arguments reached the wire: {blob}"
    assert "chest pain" not in blob, f"raw tool arguments reached the wire: {blob}"


def test_input_value_never_reaches_the_collector_at_the_default_tier(bridge, collector, sdk):
    """OpenInference's ``input.value`` is the span's raw input — the customer's own text."""
    event = _tool_action(bridge, collector, sdk, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "input.value": CANARY_PROSE,
    })
    blob = json.dumps(event)
    assert CANARY_NAME not in blob, f"raw span input reached the wire: {blob}"
    assert "chest pain" not in blob, f"raw span input reached the wire: {blob}"


def test_a_span_carrying_both_leaks_neither(bridge, collector, sdk):
    """The exact scenario: one OpenInference tool span, both keys populated, no tier set."""
    event = _tool_action(bridge, collector, sdk, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.id": "call_01H8XQ",
        "tool.parameters": json.dumps({"mrn": CANARY_ID}),
        "input.value": CANARY_PROSE,
    })
    blob = json.dumps(event)
    for canary in (CANARY_NAME, CANARY_ID, "chest pain", "radiating"):
        assert canary not in blob, f"{canary!r} reached the wire: {blob}"
    # And the observation survived, so this is a fix and not an amputation: the call is still
    # identified (fingerprint over the call id, which is what T0 keeps) and still described.
    assert event["target_fingerprint"]
    assert event["effect"]["arg_shape"]["field_count"] == 1


def test_even_at_the_full_tier_the_target_is_not_the_payload(collector, monkeypatch):
    """The test that no amount of gate-fixing can make pass on its own.

    ``full`` is a decision about *content the customer authored or the model produced* — prompts,
    completions, errors. It is not a decision to relabel a payload as an identifier. A reader
    querying ``tool_action.target`` is asking "which tool call", and at T2 the old code answered
    with seventy characters of somebody's medical history. The gate is working perfectly here and
    the leak is still a leak, which is the whole argument for fixing the reader.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_TIER", "full")
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    from nexus.client import get_client
    from nexus.otel.bridge import Bridge

    span = FakeSpan("lookup_patient", {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.parameters": json.dumps({"complaint": CANARY_PROSE}),
    }, scope="openinference.langchain")
    b = Bridge(get_client(), strict=True)
    b.on_start(span)
    b.on_end(span)
    nexus.flush(2.0)

    actions = collector.of_type("tool_action")
    assert len(actions) == 1
    blob = json.dumps(actions[0])
    assert CANARY_NAME not in blob, f"tool arguments shipped as a target at T2: {blob}"
    assert "chest pain" not in blob, f"tool arguments shipped as a target at T2: {blob}"


def test_the_leak_is_closed_in_the_reader_not_only_in_the_gate(bridge, collector, sdk):
    """Defence in depth, stated as an assertion.

    ``normalise`` is what the gate is downstream of. If ``tool_target`` still carried the payload,
    this suite would be relying on ``wire_text`` — the thing that was broken — to save it.
    """
    from nexus.otel.semconv import normalise

    facts = normalise(FakeSpan("lookup_patient", {
        "openinference.span.kind": "TOOL",
        "tool.parameters": json.dumps({"complaint": CANARY_PROSE}),
        "input.value": CANARY_PROSE,
    }))
    assert facts.tool_target is None or CANARY_NAME not in facts.tool_target
    assert CANARY_NAME not in json.dumps(facts.tool_arg_shape or {})


# --------------------------------------------------------------------------------------------
# What replaces it: a bounded, shape-only summary
# --------------------------------------------------------------------------------------------

def test_the_shape_summary_carries_structure_and_no_values(bridge, collector, sdk):
    """Losing the payload must not mean losing the observation. Field names, types and counts are
    what a ledger needs to tell "the model called this tool with three arguments" from "with none"."""
    event = _tool_action(bridge, collector, sdk, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.parameters": json.dumps({"mrn": CANARY_ID, "complaint": CANARY_PROSE, "urgent": True}),
    })
    shape = event["effect"]["arg_shape"]
    assert shape["type"] == "object"
    assert shape["field_count"] == 3
    assert set(shape["fields"]) == {"mrn", "complaint", "urgent"}
    assert shape["fields"]["complaint"]["type"] == "string"
    assert shape["fields"]["urgent"]["type"] == "bool"
    assert CANARY_ID not in json.dumps(shape)


def test_a_field_name_that_is_not_identifier_shaped_is_counted_not_named(bridge, collector, sdk):
    """Field *names* are schema, but only when they look like schema.

    A dict keyed by customer data — an address book, a per-user map — would turn "key names are
    safe" into the same leak wearing a different hat. Anything that is not identifier-shaped is
    counted and dropped.
    """
    from nexus.otel.semconv import shape_of

    shape = shape_of({"jane@customer.example": 1, "the patient's full name": 2, "mrn": 3})
    assert set(shape["fields"]) == {"mrn"}
    assert shape["fields_unnamed"] == 2
    assert "jane@customer.example" not in json.dumps(shape)
    assert "patient" not in json.dumps(shape)


def test_a_target_that_is_not_an_identifier_is_dropped(bridge, collector, sdk):
    """A target is a tool name, a call id, an endpoint. Never a payload.

    This is the second line of the same defence: even the keys we still read for ``tool_target``
    are somebody else's instrumentation writing whatever it likes. Prose in ``tool.id`` is not an
    id, so it does not become a target.
    """
    from nexus.otel.semconv import normalise

    facts = normalise(FakeSpan("t", {"openinference.span.kind": "TOOL", "tool.id": CANARY_PROSE}))
    assert facts.tool_target is None
    assert facts.tool_arg_shape is not None
    assert facts.tool_arg_shape["target"]["type"] == "string"
    assert CANARY_NAME not in json.dumps(facts.tool_arg_shape)


def test_identifier_shaped_targets_still_pass(bridge, collector, sdk):
    """The regression this fix could plausibly cause, asserted so it cannot happen silently."""
    from nexus.otel.semconv import normalise

    for value in ("call_01H8XQ7", "toolu_01ABCdef", "urn:tool:search", "pkg.mod.fn",
                  "https://api.internal/search"):
        facts = normalise(FakeSpan("t", {"openinference.span.kind": "TOOL", "tool.id": value}))
        assert facts.tool_target == value, f"{value!r} is an identifier and must survive"


def test_the_shape_is_bounded(bridge, collector, sdk):
    """An unbounded summary of an unbounded payload is the memory event ``_text`` already avoids,
    and a 400-key summary is a payload again by another route."""
    from nexus.otel.semconv import MAX_SHAPE_FIELDS, shape_of

    shape = shape_of({f"field_{i}": i for i in range(200)})
    assert len(shape["fields"]) == MAX_SHAPE_FIELDS
    assert shape["field_count"] == 200
    assert shape["fields_omitted"] == 200 - MAX_SHAPE_FIELDS

    deep: dict = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    assert len(json.dumps(shape_of(deep))) < 400


def test_nested_values_do_not_survive_the_shape(bridge, collector, sdk):
    """The obvious hole in a recursive summariser: depth 0 is scrubbed, depth 3 is not."""
    from nexus.otel.semconv import shape_of

    shape = shape_of({"outer": {"inner": {"note": CANARY_PROSE}}, "items": [CANARY_PROSE] * 4})
    blob = json.dumps(shape)
    assert CANARY_NAME not in blob
    assert "chest pain" not in blob
    assert shape["fields"]["items"]["count"] == 4


# ---------------------------------------------------------------------------------------------
# The same leak, one layer down, where the tier gate is not there to catch it
# ---------------------------------------------------------------------------------------------

@pytest.fixture()
def sdk_full(collector, monkeypatch):
    """An initialised client at ``full`` — the tier an operator picks to see prompt text.

    Every test above runs at the default tier, deliberately, and that is what makes them blind to
    the defect they are named for: `contract._rungs` drops all free text at T0, so the reader can
    hand it a whole patient record and nothing reaches the wire. Removing both reader controls
    breaks none of them.

    At T2 the operator has said content may leave, so the gate stands aside and the reader is the
    only remaining control. That is the layer these three exercise. Note what is *not* being said:
    at T2 the prose in ``input.value`` is expected on the wire — that is the tier working. What
    must never happen at any tier is a tool call's arguments arriving as ``target``, a field that
    is documented as an identifier, carried untruncated, and read by operators as one.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_TIER", "full")
    import nexus
    nexus.init(service="test-svc", env="test", version="0.0.1")
    yield nexus
    try:
        nexus.shutdown()
    except Exception:  # noqa: BLE001
        pass


#: Content that is *shaped* like an identifier. This is the canary the key list can actually be
#: tested with: `_identifier` admits it on shape, so if it reaches ``target`` the only thing that
#: could have stopped it is `_TOOL_TARGET_KEYS`. A prose canary cannot test the key list at all —
#: it is dropped on shape first, which is why the tests above pass with the key list reverted.
CANARY_IDENTIFIERISH = "MRN90210443"


def test_tool_parameters_never_become_the_target_even_at_full(bridge, collector, sdk_full):
    """`_TOOL_TARGET_KEYS` read ``tool.parameters`` into ``tool_target``. This is that test.

    negative-controlled, and the first version of it failed the control — it passed with the key
    list reverted, exactly like the three tests it was written to supplement. The canary was prose,
    and `_identifier` drops prose on shape before the key list is consulted. Two guards in series,
    each masking the other, and a canary that only the outer one ever sees.

    A medical record number is the fix: identifier-shaped, so `_identifier` admits it, and content,
    so it must not appear. The assertion is on ``target`` specifically rather than on the whole
    event, which is the opposite of the rule the tests above follow, and deliberately: at ``full``
    the arguments may legitimately appear elsewhere as tiered, truncated, redacted content. The
    defect was never "this text is present", it was "this text is present *as the identifier*" —
    a field that is untruncated, ungated, and read by operators as a join key.
    """
    event = _tool_action(bridge, collector, sdk_full, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.parameters": CANARY_IDENTIFIERISH,
    })
    target = event.get("target")
    assert CANARY_IDENTIFIERISH not in (target or ""), (
        f"tool arguments became the target: {target!r}"
    )


def test_input_value_never_becomes_the_target_even_at_full(bridge, collector, sdk_full):
    """The OpenInference half of the same defect: ``input.value`` is the raw span input.

    Same canary and the same reason. An agent that calls a tool with a bare record number — which
    is the ordinary shape of a lookup — produces exactly this span.
    """
    event = _tool_action(bridge, collector, sdk_full, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "input.value": CANARY_IDENTIFIERISH,
    })
    target = event.get("target")
    assert CANARY_IDENTIFIERISH not in (target or ""), (
        f"raw span input became the target: {target!r}"
    )


def test_a_json_payload_is_still_refused_by_shape(bridge, collector, sdk_full):
    """The prose case kept as its own test, since it is the guard-in-depth the others now bypass.

    Both guards have to hold. This one fails if `_identifier` is loosened; the two above fail if
    the key list is. Before this split, no test distinguished them and reverting either one alone
    broke nothing.
    """
    event = _tool_action(bridge, collector, sdk_full, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "tool.parameters": json.dumps({"complaint": CANARY_PROSE, "mrn": CANARY_ID}),
    })
    target = event.get("target")
    assert CANARY_NAME not in (target or ""), f"tool arguments became the target: {target!r}"
    assert CANARY_ID not in (target or ""), f"tool arguments became the target: {target!r}"


def test_a_prose_target_is_dropped_rather_than_truncated_at_full(bridge, collector, sdk_full):
    """`_identifier` is the second reader control, and it is the one with no other test at all.

    A key that is *supposed* to hold a call id, holding prose instead, is either a broken caller or
    an attempt to launder content through a field the tier ladder does not gate. Either way the
    honest answer is to emit nothing: truncating it to 128 characters would ship the first 128
    characters of a patient record and call it an identifier.
    """
    event = _tool_action(bridge, collector, sdk_full, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "gen_ai.tool.call.id": CANARY_PROSE,
    })
    target = event.get("target")
    assert CANARY_NAME not in (target or ""), f"prose survived as an identifier: {target!r}"
    assert target in (None, ""), f"expected no target at all, got {target!r}"


def test_a_real_call_id_still_arrives_at_full(bridge, collector, sdk_full):
    """The over-correction. `target` exists so an operator can join a tool call to its provider
    record; an `_identifier` strict enough to drop real call ids would close the finding by
    deleting the feature."""
    event = _tool_action(bridge, collector, sdk_full, {
        "openinference.span.kind": "TOOL",
        "tool.name": "lookup_patient",
        "gen_ai.tool.call.id": "call_abc123XYZ",
    })
    assert event.get("target") == "call_abc123XYZ"
