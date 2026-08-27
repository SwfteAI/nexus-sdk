"""Case 2.12: a stream the caller stops consuming must still produce a record.

This is the most commonly missed streaming bug, and it is missed for a structural reason: every
instrumentation reads usage totals at *stream end*, and an abandoned stream has no end. The caller
takes the first chunk, decides it has what it needs (or the client disconnects, or an exception
unwinds past the loop), and drops the generator. No totals, no span close, no event. The absence is
indistinguishable from an idle service, which is how these bugs survive for months.

Three exits, all of which must produce exactly one record:

* **exhausted** — the normal path; usage totals are present, ``incomplete`` is false;
* **closed** — ``GeneratorExit`` from ``.close()`` or from the caller's ``break``. Partial, flagged;
* **garbage-collected** — nobody closed anything. The finalizer is the only hook left.

``GeneratorExit`` is re-raised, never swallowed. Eating it turns the caller's ``break`` into a hang,
and ``_safety`` explicitly does not catch ``BaseException`` for the same reason.

The record goes through the same ``Bridge`` path as everything else, so an abandoned stream is
costed, tier-gated and deduplicated identically to a completed one — it just carries
``incomplete=true``.
"""
from __future__ import annotations

import threading
import typing as t
import weakref

from .. import _counters
from .._safety import guard

STREAMS_ABANDONED = "bridge_streams_abandoned"
STREAMS_COMPLETED = "bridge_streams_completed"


class StreamRecord:
    """Accumulates what was seen and guarantees exactly one emission.

    Exposed rather than hidden because an adapter that reads usage out of chunk objects needs
    somewhere to put the numbers as they arrive, and the guarantee ("emitted at most once, from
    whichever exit happens first") has to live next to the state it protects.
    """

    __slots__ = ("model", "provider", "input_tokens", "output_tokens", "cache_read_tokens",
                 "cache_write_tokens", "chunks", "error", "_emitted", "_lock", "_emit")

    def __init__(self, *, model: str, provider: t.Optional[str] = None,
                 emit: t.Optional[t.Callable[["StreamRecord", bool, t.Optional[str]], None]] = None) -> None:
        self.model = model
        self.provider = provider
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_read_tokens = 0
        self.cache_write_tokens = 0
        self.chunks = 0
        self.error: t.Optional[str] = None
        self._emitted = False
        self._lock = threading.Lock()
        self._emit = emit or _emit_usage

    def observe(self, **usage: t.Any) -> None:
        """Fold a chunk's usage in. Additive for output, last-wins for the rest — providers report
        prompt totals once and completion counts incrementally, and summing the former would
        multiply a prompt by the number of chunks."""
        self.chunks += 1
        if usage.get("output_tokens"):
            self.output_tokens += int(usage["output_tokens"])
        for name in ("input_tokens", "cache_read_tokens", "cache_write_tokens"):
            if usage.get(name):
                setattr(self, name, int(usage[name]))

    def finish(self, *, incomplete: bool, reason: t.Optional[str] = None) -> bool:
        with self._lock:
            if self._emitted:
                return False
            self._emitted = True
        try:
            self._emit(self, incomplete, reason)
        except Exception:  # noqa: BLE001
            _counters.incr(_counters.BUILD_FAILED)
        _counters.incr(STREAMS_ABANDONED if incomplete else STREAMS_COMPLETED)
        return True

    @property
    def emitted(self) -> bool:
        return self._emitted


def _emit_usage(rec: StreamRecord, incomplete: bool, reason: t.Optional[str]) -> None:
    from .. import contract
    from ..client import ensure_client
    from ..context import current
    from . import pricing

    client = ensure_client()
    cfg = client.cfg
    ref = current()
    usage = {"input_tokens": rec.input_tokens, "output_tokens": rec.output_tokens,
             "cache_read_input_tokens": rec.cache_read_tokens,
             "cache_creation_input_tokens": rec.cache_write_tokens}
    cost = pricing.cost_from_usage(rec.model, usage)
    ev = contract.token_usage(
        client.session_id, cfg, model=rec.model, provider=rec.provider,
        input_tokens=rec.input_tokens, output_tokens=rec.output_tokens,
        cache_read_tokens=rec.cache_read_tokens or None,
        cache_write_tokens=rec.cache_write_tokens or None,
        cost_usd=cost, cost_source=(pricing.SOURCE_USAGE if cost is not None else None),
        run_id=(ref.run_id if ref else None), incomplete=incomplete)
    ev["bridge"] = {"stream_chunks": rec.chunks, "incomplete_reason": reason,
                    "error": rec.error}
    client.emit(ev)


@guard("integrations.instrument_stream")
def instrument_stream(source: t.Iterable, record: StreamRecord,
                      usage_of: t.Optional[t.Callable[[t.Any], t.Optional[dict]]] = None) -> t.Iterator:
    """Wrap a streaming response so that *every* exit produces exactly one usage record.

    ``usage_of(chunk)`` returns a usage mapping when a chunk carries one — provider-specific, and
    therefore supplied by the adapter rather than guessed here.
    """
    return _StreamProxy(source, record, usage_of)


class _StreamProxy:
    """A generator wrapper with a finalizer.

    A bare generator function cannot do this job: its ``finally`` runs on GC in CPython, but only
    once the generator has been *started*, and a stream abandoned before its first ``next()`` would
    leave no record at all. A small object with ``weakref.finalize`` covers every case, including
    the one where the caller never iterates.
    """

    __slots__ = ("_it", "_rec", "_usage_of", "_fin", "__weakref__")

    def __init__(self, source: t.Iterable, record: StreamRecord,
                 usage_of: t.Optional[t.Callable[[t.Any], t.Optional[dict]]]) -> None:
        self._it = iter(source)
        self._rec = record
        self._usage_of = usage_of
        self._fin = weakref.finalize(self, _finalize_record, record)
        self._fin.atexit = False

    def __iter__(self) -> "_StreamProxy":
        return self

    def __next__(self) -> t.Any:
        try:
            chunk = next(self._it)
        except StopIteration:
            self._rec.finish(incomplete=False)
            self._fin.detach()
            raise
        except GeneratorExit:                      # never swallowed — see the module docstring
            self._rec.finish(incomplete=True, reason="generator_exit")
            self._fin.detach()
            raise
        except Exception as exc:                   # noqa: BLE001 — case 2.13
            self._rec.error = f"{type(exc).__name__}: {exc}"
            self._rec.finish(incomplete=True, reason="stream_error")
            self._fin.detach()
            raise
        if self._usage_of is not None:
            try:
                u = self._usage_of(chunk)
            except Exception:  # noqa: BLE001 — a broken extractor costs numbers, not the response
                u = None
            if u:
                self._rec.observe(**u)
        return chunk

    def close(self) -> None:
        self._rec.finish(incomplete=True, reason="closed")
        self._fin.detach()
        closer = getattr(self._it, "close", None)
        if callable(closer):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass


def _finalize_record(record: StreamRecord) -> None:
    try:
        record.finish(incomplete=True, reason="abandoned")
    except Exception:  # noqa: BLE001
        pass
