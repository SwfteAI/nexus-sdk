"""Exact model cost from real usage — a deliberate mirror of ``nexus_devtools/pricing.py``.

Two repos, one rate card. This is a copy, and the copy is intentional rather than lazy: the SDK
ships to customers under Apache-2.0 with **zero required dependencies**, so it cannot import a
module from the proprietary wrapper repo, and a network call to fetch rates on a request path is
not a serious proposal. What keeps the copy honest is a parity test
(``tests/test_providers.py::test_cost_matches_devtools_pricing``) that loads the wrapper's module by
path and asserts identical dollars across a matrix that includes the cache split. If the rate card
moves in one repo and not the other, that test is the thing that fails.

The property being defended is a product claim, not a rounding preference. "Exact cost" is what
distinguishes this ledger from every observability tool that multiplies total tokens by a blended
$/Mtok — and cache-heavy agent traffic is where that blend is *badly* wrong in both directions:
cache reads are 10× cheaper than fresh input, cache writes 1.25–2× more expensive. A bridge that
folds both into ``input_tokens`` reports a number the customer can disprove against their invoice,
which is worse than reporting nothing.

Unpriced models return ``None`` rather than a guess. A missing cost is a gap somebody can fill; an
invented cost is a gap nobody can see.
"""
from __future__ import annotations

import re
import typing as t

# (matcher substring, input $/Mtok, output $/Mtok). Ordered most-specific → least so the first hit
# on a normalized id wins. Mirrors nexus_devtools/pricing.py::_RATES verbatim.
_RATES: list[tuple[str, float, float]] = [
    ("fable-5", 10.0, 50.0),
    ("mythos-5", 10.0, 50.0),
    # Mirrors the row nexus_devtools added when it found `"opus"`'s catch-all swallowing
    # `claude-opus-5`. In devtools that mattered because the catch-all is marked as a
    # family-default *guess* and a measurement gate refuses to price one. This copy has no
    # such gate, so the number here is what `("opus", ...)` already returned — the row is
    # for parity, and for the day the catch-all's rate changes and this one should not.
    ("opus-5", 5.0, 25.0),
    ("opus-4-8", 5.0, 25.0),
    ("opus-4-7", 5.0, 25.0),
    ("opus-4-6", 5.0, 25.0),
    ("opus-4-5", 5.0, 25.0),
    ("opus-4-1", 15.0, 75.0),
    ("opus-4-0", 15.0, 75.0),
    ("opus-4", 15.0, 75.0),
    ("3-opus", 15.0, 75.0),
    ("opus", 5.0, 25.0),
    ("sonnet-5", 3.0, 15.0),
    ("sonnet-4-6", 3.0, 15.0),
    ("sonnet-4-5", 3.0, 15.0),
    ("sonnet-4", 3.0, 15.0),
    ("3-7-sonnet", 3.0, 15.0),
    ("3-5-sonnet", 3.0, 15.0),
    ("sonnet", 3.0, 15.0),
    ("haiku-4-5", 1.0, 5.0),
    ("3-5-haiku", 0.80, 4.0),
    ("3-haiku", 0.25, 1.25),
    ("haiku", 1.0, 5.0),
]

_CACHE_WRITE_5M = 1.25   # × input rate
_CACHE_WRITE_1H = 2.0    # × input rate
_CACHE_READ = 0.10       # × input rate

#: ``cost_source`` values. Provenance is part of the record: a figure derived from our rate card is
#: an inference and must be legible as one next to a figure the provider itself reported.
SOURCE_USAGE = "usage"        # computed here from the provider's own token breakdown
SOURCE_PROVIDER = "provider"  # the provider/instrumentation reported dollars directly


def normalize(model: str) -> str:
    """Reduce a provider/span model id to its matchable core.

    The peel order is load-bearing because the decorations nest — a Bedrock id carries a regional
    prefix, a vendor prefix, a date *and* a model version at once::

        claude-haiku-4-5-20251001                         → claude-haiku-4-5
        claude-fable-5[1m]                                → claude-fable-5
        us.anthropic.claude-haiku-4-5-v1:0                → claude-haiku-4-5
        bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0 → claude-3-5-sonnet
        vertex_ai/claude-opus-4-8@20260101                → claude-opus-4-8

    Beyond pricing this keeps per-model aggregates whole: a serving route that normalised to a
    different string than the same weights reached first-party would split one model across two
    buckets and silently under-count every total.
    """
    m = (model or "").lower().strip()
    m = re.sub(r"^[a-z][a-z0-9_-]*/", "", m)        # bedrock/ , vertex_ai/ , <vendor>/ prefixes
    m = re.sub(r"^(?:us|eu|apac|global)\.", "", m)  # Bedrock cross-region inference prefixes
    m = re.sub(r"^anthropic\.", "", m)
    m = re.sub(r"\[[^\]]*\]", "", m)                # drop [1m] / [200k] context tags
    m = re.sub(r"-v\d+:\d+$", "", m)                # drop Bedrock model-version suffix (-v1:0)
    m = re.sub(r"[@-]\d{8}$", "", m)                # drop dated snapshot suffix
    m = re.sub(r"-fast$", "", m)
    return m


def rates(model: str) -> t.Optional[tuple[float, float]]:
    """(input, output) $/Mtok for a model, or ``None`` when unpriced."""
    norm = normalize(model)
    for needle, tin, tout in _RATES:
        if needle in norm:
            return tin, tout
    return None


def cost_from_usage(model: str, usage: dict) -> t.Optional[float]:
    """Exact USD for one usage breakdown, or ``None`` when the model is unpriced. Never raises.

    ``usage`` uses the transcript's own field names — ``input_tokens`` (uncached),
    ``output_tokens``, ``cache_read_input_tokens``, and either the split
    ``cache_creation.ephemeral_5m_input_tokens`` / ``ephemeral_1h_input_tokens`` or the flat
    ``cache_creation_input_tokens`` (priced at the 5-minute rate).
    """
    r = rates(model)
    if not r:
        return None
    tin, tout = r
    try:
        u = usage or {}
        # `cache_creation` is whatever the caller put there. A bridge reading a hostile or
        # half-written span can hand us a string, and `"nope".get(...)` would raise into the
        # blanket `except` below — turning one malformed field into a *None cost for the whole
        # call*. Nothing about the other four numbers is unknowable just because this one is junk.
        cc = u.get("cache_creation")
        cc = cc if isinstance(cc, dict) else {}
        w5 = _num(cc.get("ephemeral_5m_input_tokens"))
        w1 = _num(cc.get("ephemeral_1h_input_tokens"))
        if not (w5 or w1):                       # no split → flat cache_creation, treat as 5m
            w5 = _num(u.get("cache_creation_input_tokens"))
        dollars = (
            _num(u.get("input_tokens")) * tin
            + _num(u.get("output_tokens")) * tout
            + _num(u.get("cache_read_input_tokens")) * tin * _CACHE_READ
            + w5 * tin * _CACHE_WRITE_5M
            + w1 * tin * _CACHE_WRITE_1H
        ) / 1_000_000
        return round(dollars, 6)
    except Exception:  # noqa: BLE001
        return None


def cost_from_tokens(model: str, *, input_tokens: t.Any = None, output_tokens: t.Any = None,
                     cache_read_tokens: t.Any = None,
                     cache_write_tokens: t.Any = None) -> t.Optional[float]:
    """The same calculation over the field names ``nexus.usage()`` uses, rather than the
    transcript's.

    A thin adapter on purpose. The rate card and the arithmetic stay in one function that is
    diff-able against the Node SDK's ``pricing.cjs`` line by line; only the naming differs, and
    naming is exactly what a port gets wrong quietly. ``cache_write_tokens`` maps to the flat
    ``cache_creation_input_tokens`` and is therefore priced at the 5-minute rate — neither
    ``usage()`` nor any bridge here exposes the 5m/1h split, and inventing one would be a guess
    about a number the customer is billed for.
    """
    return cost_from_usage(model, {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_input_tokens": cache_read_tokens,
        "cache_creation_input_tokens": cache_write_tokens,
    })


def _num(v: t.Any) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0
