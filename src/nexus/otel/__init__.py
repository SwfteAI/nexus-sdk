"""OTLP bridge — an *optional ingest path*, not the native model (D-3, ``[otel]`` extra).

WP-0 settled this deliberately: native nexus events first, OTLP as a bridge. The reason is that an
OTel span is the wrong shape for what this product sells. A span carries duration, status and
attributes; it has nowhere to put an epistemic class, no notion of a privacy tier applied per
field, and no way to say *"this record is the billable one and these two are structure"* when three
SDKs wrapped the same call. Modelling our contract as attributes on a generic span would mean
encoding all of that as stringly-typed keys and reconstructing it downstream — the contract would
still exist, just unenforced.

What WP-5 adds is the other direction: **spans in**. The customer already runs OpenInference or
OpenLLMetry against thirty providers; consuming their spans is how we get provider coverage without
writing ~931 lines per provider ourselves. The bridge is where an OTel span becomes an admissible
governance record — classified, re-gated to our privacy tier, costed exactly, and deduplicated to
one billable record per logical call.

Two properties are fixed and non-negotiable:

* **HTTP/protobuf only, never gRPC.** ``opentelemetry-exporter-otlp-proto-grpc`` pulls ``grpcio``,
  a C extension with a long history of fork-safety problems in exactly the pre-fork servers
  ``runtime.py`` exists to survive. The core ring's rule is zero dependencies; the extra's rule is
  no C extensions on the egress path.
* **Context is read, not owned.** We attach to the application's ``TracerProvider``; we never
  install one.

Submodules:

* :mod:`nexus.otel.semconv` — three vocabularies read into one shape. No OTel import.
* :mod:`nexus.otel.classify` — the epistemic class. Nothing unclassified reaches the ledger.
* :mod:`nexus.otel.bridge` — spans → events. No OTel import; fully usable without the extra.
* :mod:`nexus.otel.processor` — the ``SpanProcessor``. The only module that needs the extra.
"""
from __future__ import annotations

import typing as t


def available() -> bool:
    """True when the ``[otel]`` extra is installed. Import is local: the core ring has no deps."""
    try:
        import opentelemetry.trace  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def bridge() -> t.Any:
    """The process-wide :class:`~nexus.otel.bridge.Bridge`.

    Works with or without the extra: spans can be handed to it directly by any integration, which
    is what keeps "the SDK works fully with none of them installed" true rather than aspirational.
    """
    from .bridge import get_bridge
    return get_bridge()


def install() -> bool:
    """Attach the bridge to the application's existing OTel ``TracerProvider``.

    Returns ``False`` — never raises — when the extra is absent or the application configured no
    provider. That is the honest answer in both cases, and the caller is ``auto.install``, which
    must not care.
    """
    try:
        from .processor import attach
        return bool(attach())
    except Exception:  # noqa: BLE001
        return False


def flush(reason: str = "shutdown") -> int:
    """Emit a partial for every logical call still in flight — case 2.12 at process exit."""
    try:
        return int(bridge().flush_open(reason))
    except Exception:  # noqa: BLE001
        return 0
