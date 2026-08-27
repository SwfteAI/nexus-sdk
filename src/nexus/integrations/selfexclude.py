"""Case 2.19: capture must not trigger capture.

The loop is short and fatal. Our transport POSTs a batch to the collector. The customer's HTTP
instrumentation — which they installed for their own reasons, and which knows nothing about us —
produces a span for that POST. The bridge ingests the span and emits an event. The event is queued.
The queue flushes. Another POST. Another span.

This is not a slowdown that shows up as a latency regression. It is unbounded feedback that
consumes the process, and it presents to the customer as "your SDK hung our service", which is the
one outcome ``_safety`` exists to prevent.

Three independent defences, because each has a hole the others cover:

1. **Module exclusion** — no adapter may ever instrument our own egress path. Enforced at the
   registry (``integrations.register``), not inside each adapter, because the adapter that breaks
   the rule will be the one written last by someone who has not read this file.
2. **Destination exclusion** — a span whose target is the configured collector or gateway is ours
   by definition, whoever produced it. This is the defence that actually catches the loop above,
   since the offending span comes from *their* instrumentation and carries none of our names.
3. **Re-entrancy** — a hard depth latch around the bridge's own emission, so that any synchronous
   path from emit back into the bridge terminates at depth 1 instead of recursing.

Defence 2 needs the collector host and port. Those come from ``Config``; parsing is cached per URL
string because it happens on a span-ingest path that a busy service hits thousands of times a
second, and ``urlsplit`` is not free.
"""
from __future__ import annotations

import threading
import typing as t
from urllib.parse import urlsplit

#: Module prefixes no adapter may instrument. Prefix match, not exact: ``nexus.transport`` and
#: ``nexus.transport.http`` are equally forbidden and a future submodule must not need an edit here.
SELF_MODULE_PREFIXES: tuple[str, ...] = ("nexus",)

_local = threading.local()

_endpoint_cache: dict[str, t.Optional[tuple[str, t.Optional[int]]]] = {}
_cache_lock = threading.Lock()


def is_self_module(module_name: str) -> bool:
    """True when ``module_name`` is ours and therefore never instrumentable."""
    name = str(module_name or "")
    return any(name == p or name.startswith(p + ".") for p in SELF_MODULE_PREFIXES)


def _endpoint(url: t.Optional[str]) -> t.Optional[tuple[str, t.Optional[int]]]:
    if not url:
        return None
    with _cache_lock:
        if url in _endpoint_cache:
            return _endpoint_cache[url]
    try:
        parts = urlsplit(str(url))
        host = (parts.hostname or "").lower()
        got: t.Optional[tuple[str, t.Optional[int]]] = (host, parts.port) if host else None
    except Exception:  # noqa: BLE001
        got = None
    with _cache_lock:
        if len(_endpoint_cache) > 64:      # bounded: config is not user-supplied, but be certain
            _endpoint_cache.clear()
        _endpoint_cache[url] = got
    return got


def _span_endpoints(facts: t.Any) -> list[tuple[str, t.Optional[int]]]:
    """Every (host, port) this span appears to be talking to."""
    attrs = getattr(facts, "attributes", None) or {}
    out: list[tuple[str, t.Optional[int]]] = []
    for key in ("url.full", "http.url", "http.uri"):
        ep = _endpoint(attrs.get(key))
        if ep:
            out.append(ep)
    host = attrs.get("server.address") or attrs.get("net.peer.name") or attrs.get("http.host")
    if host:
        port = attrs.get("server.port") or attrs.get("net.peer.port")
        try:
            port_i = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_i = None
        out.append((str(host).lower(), port_i))
    return out


def is_self_span(facts: t.Any, cfg: t.Any = None) -> bool:
    """True when this span describes our own telemetry egress and must never be ingested.

    Deliberately generous. A false positive costs one dropped span describing a request to the
    collector's host — data nobody wants. A false negative costs the process.
    """
    scope = str(getattr(facts, "scope", "") or "")
    if is_self_module(scope):
        return True
    attrs = getattr(facts, "attributes", None) or {}
    if attrs.get("nexus.internal") or attrs.get("nexus.egress"):
        return True
    for key in ("code.namespace", "otel.library.name", "peer.service"):
        if is_self_module(str(attrs.get(key) or "")):
            return True
    if cfg is None:
        return False
    ours = [e for e in (_endpoint(getattr(cfg, "collector_url", None)),
                        _endpoint(getattr(cfg, "gateway_url", None))) if e]
    if not ours:
        return False
    for host, port in _span_endpoints(facts):
        for ohost, oport in ours:
            # Port-insensitive when either side omits it: a customer's HTTP instrumentation may
            # record only `server.address`, and matching on host alone is the safe direction.
            if host == ohost and (port is None or oport is None or port == oport):
                return True
    return False


class _Reentry:
    """Context manager that is falsey when already inside itself on this thread."""

    __slots__ = ("_entered",)

    def __init__(self) -> None:
        self._entered = False

    def __enter__(self) -> bool:
        if getattr(_local, "depth", 0) > 0:
            return False
        _local.depth = getattr(_local, "depth", 0) + 1
        self._entered = True
        return True

    def __exit__(self, *exc: t.Any) -> bool:
        if self._entered:
            _local.depth = max(0, getattr(_local, "depth", 1) - 1)
            self._entered = False
        return False


def no_reentry() -> _Reentry:
    """``with no_reentry() as ok:`` — ``ok`` is False when this thread is already inside the bridge.

    The latch is per-thread rather than per-process on purpose: two request threads ingesting spans
    concurrently are not recursion, and serialising them would put our lock on the customer's
    request path.
    """
    return _Reentry()


def depth() -> int:
    """Current re-entrancy depth on this thread. Exposed for the assertion in the 2.19 test."""
    return int(getattr(_local, "depth", 0))


def reset_for_fork() -> None:
    """A forked child inherits a thread-local whose owning thread does not exist. Clearing the
    latch matters: a child that starts life believing it is already inside the bridge would drop
    every span it ever sees, silently."""
    global _local
    _local = threading.local()
