"""The only module here that needs ``opentelemetry`` — and it needs it lazily.

Zero required runtime dependencies is a core-ring rule, not an aspiration: the SDK must work
completely with no OTel installed, so the import lives inside the factory rather than at module
scope. Importing ``nexus.otel.processor`` is always safe; calling :func:`span_processor` without the
``[otel]`` extra raises ``MissingOTel``, and :func:`attach` returns ``False`` instead.

**Context is read, not owned.** ``attach`` hangs our processor off whatever ``TracerProvider`` the
application already configured. It never installs one. A library that takes over global OTel state
is how an APM agent breaks an application's own tracing, and the customer's conclusion is never
"our config was wrong" — it is "we removed the vendor's SDK".

**HTTP/protobuf only, never gRPC** (D-3). Not enforced here — we install no exporter — but stated
here because this is the file where somebody will be tempted to add one.
``opentelemetry-exporter-otlp-proto-grpc`` pulls ``grpcio``, a C extension with a long history of
fork-safety problems in exactly the pre-fork servers ``runtime.py`` exists to survive, and it fails
to build on musl and some ARM images. A telemetry SDK that breaks a customer's Docker build has
already lost.
"""
from __future__ import annotations

import typing as t

from .bridge import Bridge, get_bridge


class MissingOTel(RuntimeError):
    """The ``[otel]`` extra is not installed. Never raised on any automatic path."""


def available() -> bool:
    try:
        import opentelemetry.sdk.trace  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def span_processor(bridge: t.Optional[Bridge] = None) -> t.Any:
    """Build a ``SpanProcessor`` that feeds the bridge. Requires the ``[otel]`` extra.

    Built as a class *inside* a function because the base class does not exist until the extra is
    installed — the alternative, a module-level subclass, would make ``import nexus.otel`` fail on
    a machine without OTel, which is most of them.
    """
    try:
        from opentelemetry.sdk.trace import SpanProcessor
    except Exception as exc:  # noqa: BLE001
        raise MissingOTel(
            "nexus[otel] is not installed; install `nexus-sdk[otel]` "
            "(opentelemetry-api/sdk + opentelemetry-exporter-otlp-proto-http)") from exc

    target = bridge or get_bridge()

    class NexusBridgeProcessor(SpanProcessor):  # type: ignore[misc, valid-type]
        """Both callbacks are needed, and the reason is structural rather than stylistic.

        Deduplicating layered instrumentation (cases 2.6/2.8) requires knowing which span is
        *inside* which, and a finished span cannot tell you: children finish before their parents,
        so at ``on_end`` time an inner span's ancestors have not been reported yet. ``on_start``
        fires outermost-first, which is the only ordering from which the nesting can be built.
        """

        def on_start(self, span, parent_context=None):  # noqa: ANN001
            target.on_start(span)

        def on_end(self, span):  # noqa: ANN001
            target.on_end(span)

        def shutdown(self):
            target.flush_open("otel_shutdown")

        def force_flush(self, timeout_millis: int = 30000) -> bool:  # noqa: ARG002
            return True

    return NexusBridgeProcessor()


def attach(bridge: t.Optional[Bridge] = None) -> bool:
    """Attach to the application's existing ``TracerProvider``. ``False`` when there is none.

    Idempotent by marker attribute: OTel's ``add_span_processor`` will happily register the same
    processor twice, and two processors mean every span ingested twice — which is precisely the
    double-count this work package exists to prevent, arriving through our own front door.
    """
    if not available():
        return False
    try:
        from opentelemetry import trace as _trace
        provider = _trace.get_tracer_provider()
        if not hasattr(provider, "add_span_processor"):
            # A no-op/proxy provider: the application configured nothing. Installing our own would
            # take ownership of global tracing state, which this module explicitly does not do.
            return False
        if getattr(provider, "__nexus_bridge_attached__", False):
            return True
        provider.add_span_processor(span_processor(bridge))
        try:
            provider.__nexus_bridge_attached__ = True
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False
