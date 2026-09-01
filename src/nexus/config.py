"""Configuration and unified service tagging.

**Unified tagging.** ``service`` / ``env`` / ``version`` are Datadog's three-tag convention, and we
copy it deliberately rather than inventing a fourth vocabulary: they are what a customer already
puts in their deployment templates, and they are the join keys that let one ledger correlate a
model call with the deploy that introduced it. Note what is *absent*: there is no ``user``. The
wrapper stamps a human because a laptop has one; a service does not, and inventing one is how PII
gets into a governance ledger (design §6.1).

**Precedence: explicit argument > environment > default.** Code wins over the environment because
``nexus.init(service="checkout")`` is a statement of fact about the program that contains it, and a
stale ``NEXUS_SERVICE`` inherited from a base image should not silently relabel it.

There is exactly one deliberate inversion, and it is the important one:

    ``NEXUS_ENABLED=0`` wins over everything, including ``nexus.init(enabled=True)``.

An operator must be able to turn this SDK off from outside the application, without a code change
and without a redeploy of anything but an env var — that is the whole point of a kill switch, and a
security reviewer will test exactly this. (``F3-SDK-RUNTIME-CASES.md`` §7.6 states the general rule
as ``env > code``; we implement ``code > env`` for everything except the kill switch, on the
reasoning above. The divergence is intentional and is recorded in the case checklist.)

**No ``~/.nexus``.** Containers are ephemeral and frequently read-only. Config comes from arguments
and the environment; a config *file* is read only when ``NEXUS_CONFIG_FILE`` explicitly names one,
and a failure to read it is a warning, never an exception.
"""
from __future__ import annotations

import json
import os
import sys
import typing as t
from dataclasses import dataclass, field, replace

from . import provenance

# Privacy tiers — identical strings to nexus_devtools/events.py:22-24. They are wire values in a
# shared ledger, so they are copied verbatim rather than re-derived.
TIER_METADATA_ONLY = "metadata_only"   # T0 — the default. Shape and fingerprints, no content.
TIER_HASHED = "hashed"                 # T1 — redacted, truncated previews. NOT digests; see below.
#: ``hashed`` is a lie, and it is the specific kind of lie that gets someone hurt: the
#: person who reads a three-rung ladder and picks the middle one is a privacy officer choosing on
#: the strength of the word. "Hashed" means one-way. What this tier actually emits is redacted,
#: truncated **plaintext** — it differs from ``full`` in the length limit and the field name, and
#: in nothing else. At T1, ``"Patient Jane Doe, SSN 123-45-6789, said: my password is hunter2"``
#: goes out as ``"Patient Jane Doe, SSN [REDACTED], said: my password is hunter2"``. The name
#: promised a digest and delivered the sentence. The only genuine hash anywhere on the wire is
#: ``*_fingerprint``, which T0 already emits.
#:
#: ``redacted_preview`` is the true name, and it is now the accepted and documented spelling.
#: ``hashed`` stays as an alias rather than being deleted, for two separate reasons that happen to
#: point the same way: a config file in a customer's cluster that says ``hashed`` must keep
#: working, and — the load-bearing one — ``hashed`` is the *wire* value the collector's schema
#: validates against (``nexus_devtools/events.py``). Changing what goes on the wire to fix a
#: naming problem would trade an honest label for a version-skew outage. So the alias is resolved
#: at configuration time and the wire is untouched: operators write the true name, the collector
#: keeps receiving the value it knows, and nobody has to coordinate a release to stop lying.
TIER_REDACTED_PREVIEW = "redacted_preview"
TIER_FULL = "full"                     # T2 — the text. In production this is someone else's
                                       #      customer data under someone else's DPA; see §5.3.
_TIERS = (TIER_METADATA_ONLY, TIER_HASHED, TIER_FULL)

#: Configuration spellings that resolve to a tier. Deliberately *not* merged into ``_TIERS``:
#: ``_TIERS`` is the set of values that may appear on the wire, and adding an alias to it would
#: put the alias on the wire the first time somebody iterated it.
_TIER_ALIASES = {TIER_REDACTED_PREVIEW: TIER_HASHED}

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")

DEFAULT_COLLECTOR_HOST = "127.0.0.1"
DEFAULT_COLLECTOR_PORT = 8791


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def enabled_from_env() -> bool:
    """The kill switch, read with nothing but ``os.environ``.

    Called from ``nexus/__init__.py`` before any other module is imported, which is what makes
    ``NEXUS_ENABLED=0`` a *true* zero-cost switch (case 4.12) rather than "initialise, then no-op":
    no queue, no thread, no import hooks, no vendored code loaded, and an import cost that is a
    handful of microseconds of ``os.environ`` lookup.
    """
    return env_flag("NEXUS_ENABLED", True)


def _default_service() -> str:
    """A service name we can stand behind when nobody supplied one.

    Case 4.11 requires that auto-instrumentation with no ``init()`` still captures, with identity
    ``unknown`` — capturing under a wrong-but-plausible name is worse than capturing under an
    obviously-missing one, because the first silently merges two services in the rollup.
    """
    for var in ("NEXUS_SERVICE", "OTEL_SERVICE_NAME", "DD_SERVICE", "K_SERVICE",
                "AWS_LAMBDA_FUNCTION_NAME"):
        v = os.environ.get(var)
        if v and v.strip():
            return v.strip()[:128]
    return "unknown"


def _default_version() -> str:
    for var in ("NEXUS_VERSION", "OTEL_SERVICE_VERSION", "DD_VERSION", "K_REVISION"):
        v = os.environ.get(var)
        if v and v.strip():
            return v.strip()[:64]
    return "unknown"


@dataclass(frozen=True)
class Config:
    """Resolved, immutable configuration. Frozen because a running transport reads these fields
    from a background thread; a mutable config is a data race with no visible symptom."""

    enabled: bool = True
    # ---- unified tagging (7.1) -------------------------------------------------------------
    service: str = "unknown"
    env: str = "unknown"
    version: str = "unknown"
    # ---- provenance (ANCHOR-INTEGRATION §6.1) -----------------------------------------------
    #: The join keys between a running process and the commit-anchored ledger. Note the type:
    #: ``Optional[str]`` with a ``None`` default, **not** ``"unknown"`` like the three tags above.
    #: That difference is the whole feature. ``service="unknown"`` is a nuisance; a
    #: ``commit="unknown"`` would be a claim, and the console draws a *break* in the provenance
    #: chain where a value is missing — a break whose accent means "production contains software
    #: of unknown origin". A sentinel here silences that alarm permanently. See ``provenance``.
    application: t.Optional[str] = None
    repo: t.Optional[str] = None
    commit: t.Optional[str] = None
    branch: t.Optional[str] = None
    deployment_id: t.Optional[str] = None
    #: Which variable supplied ``commit``, e.g. ``"env:VERCEL_GIT_COMMIT_SHA"`` or ``"explicit"``.
    #: Absent when ``commit`` is absent, because a provenance claim about a link that does not
    #: exist is worse than no claim.
    provenance_source: t.Optional[str] = None
    #: Per-field detail behind the line above — ``{"commit": "env:GITHUB_SHA", ...}``.
    provenance_sources: dict = field(default_factory=dict)
    # ---- privacy ---------------------------------------------------------------------------
    tier: str = TIER_METADATA_ONLY
    # ---- transport -------------------------------------------------------------------------
    collector_url: str = f"http://{DEFAULT_COLLECTOR_HOST}:{DEFAULT_COLLECTOR_PORT}"
    gateway_url: t.Optional[str] = None
    api_key: t.Optional[str] = None
    #: Bounded, and bounded *by events* rather than bytes because the drop policy has to be
    #: decidable without serialising. 10k events is roughly a few MB at our event sizes.
    queue_capacity: int = 10_000
    batch_size: int = 100
    flush_interval_s: float = 2.0
    http_timeout_s: float = 2.0
    max_retries: int = 3
    #: Hard cap on ``flush()`` and on shutdown (4.8). A hung flush must not hang the container:
    #: the default is below every platform grace period we know of (Cloud Run 10s, k8s 30s).
    flush_deadline_s: float = 5.0
    #: Window over which the worker thread aggregates observed action spans into one
    #: ``service_health`` event (§6.3). ``0`` disables the rollup entirely. Deliberately much
    #: longer than ``flush_interval_s``: the flush interval is a latency budget for egress, this is
    #: a statistical window, and equating them would emit a p99 computed over two seconds.
    health_interval_s: float = 60.0
    #: 1.2/1.4 — "thread" is the normal path, "sync" flushes inline (uWSGI without --enable-threads,
    #: Lambda), "auto" decides from the detected runtime. Never silently spin a thread that cannot run.
    transport_mode: str = "auto"
    #: Optional durable spill. Off by default: containers are often read-only, and a telemetry SDK
    #: that fails on a read-only filesystem is a telemetry SDK that gets removed.
    spill_dir: t.Optional[str] = None
    #: Free-form, bounded tags. Bounded on purpose — see case 3.5.
    tags: dict = field(default_factory=dict)

    def with_overrides(self, **kw: t.Any) -> "Config":
        return replace(self, **{k: v for k, v in kw.items() if v is not None})

    @property
    def events_url(self) -> str:
        return self.collector_url.rstrip("/") + "/v1/events"


#: The only schemes a collector may speak. `build_opener` installs FileHandler,
#: FTPHandler and DataHandler by default, so without this allowlist a single
#: environment variable redirects the whole telemetry stream — `file:///etc/passwd`,
#: `ftp://…` and `gopher://…` were all accepted and turned into an events URL.
#: Anything able to set one env var in the customer's process — a
#: compromised sidecar, a leaked CI config, a mis-templated Helm chart — could
#: use it.
_ALLOWED_SCHEMES = ("http", "https")

#: Loopback host *names*. Addresses are not listed here — they are parsed, because a list of
#: address spellings is a list, and ``127.0.0.1``, ``127.1``, ``127.000.000.001`` and
#: ``[::ffff:127.0.0.1]`` are all the same machine while looking nothing alike.
_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def host_of(url: str) -> str:
    """The host a client will actually connect to, extracted the way a URL parser extracts it.

    Written out rather than delegated to ``urllib.parse`` because this is called from the send
    path and from ``_auth_allowed``, and ``urllib`` is imported lazily in this package (see
    ``transport._load_urllib``) specifically to keep it off the import-cost path.

    Two pieces of the grammar matter here and are the reason a prefix test is not good enough:

    * **userinfo.** In ``http://127.0.0.1@evil.example/`` the host is ``evil.example``; everything
      before the last ``@`` is credentials. Reading left to right finds ``127.0.0.1`` and gets the
      destination exactly backwards.
    * **IPv6 literals.** ``http://[::1]:8791/`` has a bracketed host and a port that is *outside*
      the brackets, so splitting on the first ``:`` mangles it.
    """
    rest = url.partition("://")[2]
    authority = rest.partition("/")[0].partition("?")[0].partition("#")[0]
    authority = authority.rpartition("@")[2]          # drop userinfo; the LAST '@' wins
    if authority.startswith("["):
        return authority.partition("]")[0][1:].strip().lower()
    return authority.partition(":")[0].strip().lower()


def _is_loopback(host: str) -> bool:
    """Whether traffic to ``host`` stays on this machine.

    Answered by parsing the host as an IP address rather than by comparing its text, because the
    text has an unbounded number of spellings and an attacker picks the spelling. The version this
    replaced ended in ``host.startswith("127.")``, which is true of the perfectly routable
    ``127.0.0.1.attacker.example`` — a domain anyone can register, pointing anywhere they like.

    Unrecognised input answers **False**. Every caller uses this to decide whether it is safe to
    do something (send a credential in cleartext, skip a proxy), so the direction of a parse
    failure has to be "assume it leaves the machine".

    ``0.0.0.0`` is deliberately *not* loopback. It is a bind-any address, not a destination; where
    a stack does route it to localhost that is a convenience, not a guarantee, and guessing wrong
    here means a credential on the wire.
    """
    h = host.strip().strip("[]").lower()
    if not h:
        return False
    if h in _LOOPBACK_NAMES:
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(h).is_loopback
    except (ValueError, ImportError):
        return False


def _checked_url(url: str) -> str:
    """Reject a collector URL this SDK must not speak to.

    Fails LOUD rather than falling back to a default. A telemetry SDK must never
    break its host, and everywhere else in this package a bad input degrades
    quietly — but silently rewriting a misconfigured endpoint to loopback would
    send a customer's events somewhere they did not choose while reporting
    success, and quietly disabling would hide the misconfiguration. The
    configuration is wrong and the operator has to know.

    What this used to be was a *prefix* check — ``partition("://")``, look at the front,
    return the string unexamined. Everything after the scheme was accepted verbatim, so
    ``http://a b/``, ``http://evil\n.example/`` and ``http://127.0.0.1@evil.example/`` all passed.
    Same class of defect as the ``startswith("127.")`` in ``_is_loopback``, on the same
    string, one function away: reading the front of a URL is not parsing it.

    Three additions, each rejecting rather than repairing, because this function's whole contract
    is that a wrong configuration is loud:

    * **Control characters and spaces are refused, not stripped.** ``urlsplit`` silently removes
      tab, CR and LF (WHATWG request-splitting defence), which means a URL carrying them would
      have been *accepted* here and then quietly become a different URL downstream. If the value
      is not the value the operator typed, nobody should have to discover that at 3 a.m.
    * **The authority must parse and be non-empty.** ``http:///v1/events`` has no host.
    * **Userinfo is refused.** ``http://user:pass@collector/`` puts a credential in a URL that is
      then logged, echoed in errors and compared against allowlists. ``host_of`` now reads the
      host correctly even with userinfo present, so this is no longer a *safety* hole —
      it is refused because the supported way to authenticate to a collector is ``NEXUS_TOKEN``,
      and quietly accepting a second, worse way is how the worse way becomes load-bearing.
    """
    stripped = url.strip()
    scheme, sep, rest = stripped.partition("://")
    if not sep or scheme.lower() not in _ALLOWED_SCHEMES or not rest:
        raise ValueError(
            f"collector URL must be http:// or https:// — got {stripped!r}. "
            "Other schemes are refused because urllib would happily open them."
        )
    if any(ch <= " " or ch == "\x7f" for ch in stripped):
        raise ValueError(
            f"collector URL contains a control character or space — got {stripped!r}. "
            "Refused rather than stripped: urllib would remove it silently and connect "
            "somewhere other than what you configured."
        )
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(stripped)
        hostname = parts.hostname
        has_userinfo = parts.username is not None or parts.password is not None
        parts.port  # noqa: B018 — raises ValueError on a non-numeric or out-of-range port
    except ValueError as exc:
        raise ValueError(f"collector URL does not parse — got {stripped!r} ({exc})") from None
    if not hostname:
        raise ValueError(f"collector URL has no host — got {stripped!r}.")
    if has_userinfo:
        raise ValueError(
            f"collector URL must not carry credentials — got {stripped!r}. "
            "Use NEXUS_TOKEN for the bearer token; a secret in a URL ends up in logs."
        )
    return stripped


def _collector_url(explicit: t.Optional[str]) -> str:
    """Resolve the collector endpoint, host and port separately configurable.

    Case 1.13: the wrapper's collector binds loopback, which is right for a laptop and wrong for a
    pod. A sidecar lives at ``$(NODE_IP):8791`` or at a service DNS name, and a Kubernetes user
    supplies it through the downward API — so the host must be a first-class knob, not a constant
    someone has to override with a full URL.
    """
    if explicit:
        return _checked_url(explicit)
    url = os.environ.get("NEXUS_COLLECTOR_URL")
    if url:
        return _checked_url(url.strip())
    host = os.environ.get("NEXUS_COLLECTOR_HOST", DEFAULT_COLLECTOR_HOST).strip()
    port = _env_int("NEXUS_COLLECTOR_PORT", DEFAULT_COLLECTOR_PORT)
    if ":" in host and not host.startswith("["):     # bare IPv6 literal
        host = f"[{host}]"
    # Half one: the scheme was hard-coded, so HTTPS was unreachable
    # through the documented HOST/PORT route — an operator wanting TLS had to
    # abandon both variables for a whole URL, and most did not.
    #
    # The default deliberately stays `http`. Forcing TLS on any non-loopback
    # host was the first fix attempted here and it was WRONG: the case this
    # route exists for is a Kubernetes sidecar at `$(NODE_IP):8791`, reached
    # over the pod network, where cluster-internal plaintext is normal and no
    # certificate exists. Two shipped tests encode that (`test_1_13_*`), and
    # they are right — breaking every sidecar deployment to close a credential
    # leak would be fixing the wrong half.
    #
    # The credential is protected in `transport._auth_allowed` instead: the
    # bearer token is withheld from non-loopback cleartext regardless of scheme.
    # Events still flow; the secret does not.
    scheme = os.environ.get("NEXUS_COLLECTOR_SCHEME", "").strip().lower()
    if scheme not in _ALLOWED_SCHEMES:
        scheme = "http"
    # Half two: the host/port route goes through the same check as the URL route.
    return _checked_url(_host_port_url(scheme, host, port))


def _host_port_url(scheme: str, host: str, port: t.Any) -> str:
    """Build ``scheme://host:port`` and refuse to return it unless it *is* that.

    ``NEXUS_COLLECTOR_HOST`` is documented as a host. It is read from the environment and dropped
    into an f-string, so what it actually is, is whatever the environment says — and a host is a
    substring of a URL, which means anything written there can restructure the URL around it.
    ``NEXUS_COLLECTOR_HOST='evil.example/x?'`` built ``http://evil.example/x?:8791``: the port
    became part of a query string, and ``events_url`` then appended ``/v1/events`` to a path that
    was never supposed to exist. Events went to ``evil.example``.

    Routing that string through ``_checked_url`` does not help, and finding that out is the useful
    part of this finding. ``http://evil.example/x?:8791`` is a *valid* URL — correct scheme, real
    hostname, no userinfo, no control characters. Every check in ``_checked_url`` passes, because
    every one of them asks whether the result is a well-formed URL, and it is. It is simply not
    the URL the operator configured. Validating the output cannot detect a well-formed lie; only
    comparing the output against the intent can.

    So this asserts the intent instead: parse the URL back and require that the three components
    are the three inputs, and that nothing else exists. That is a post-condition, not a filter,
    and it is deliberately not a denylist of ``/?#@`` — this repository's most-repeated defect is
    a rule that enumerates the bad inputs somebody thought of, and a character list here would be
    exactly that, one exotic separator away from being wrong again. A round-trip check does not
    need to know which characters are dangerous. Anything that changes the shape of the URL fails
    it, including whatever gets added to the URL grammar after this is written.
    """
    from urllib.parse import urlsplit

    bare = str(host).strip()
    # An IPv6 literal is the one host that legitimately contains the reserved characters, and it
    # carries its own brackets to say so. Add them if the operator gave a bare address.
    if ":" in bare and not bare.startswith("["):
        bare = f"[{bare}]"
    built = f"{scheme}://{bare}:{port}"
    try:
        parts = urlsplit(built)
        ok = (
            parts.scheme == scheme
            and parts.hostname is not None
            and parts.port == int(port)
            and parts.username is None
            and parts.password is None
            and not parts.path
            and not parts.query
            and not parts.fragment
        )
    except ValueError:
        ok = False
    if not ok:
        raise ValueError(
            f"NEXUS_COLLECTOR_HOST must be a host name or IP address, not a URL or a path — "
            f"got {host!r}, which builds {built!r}. Set NEXUS_COLLECTOR_URL if you need to "
            "specify a full URL including a path."
        )
    return built


def _file_overrides() -> dict:
    path = os.environ.get("NEXUS_CONFIG_FILE")
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 — an unreadable config file must not stop the process
        return {}


def _health_interval(raw: t.Any) -> float:
    """``0`` means off; anything else is floored at 1s. Never raises — a bad string is 'off'."""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return 60.0
    if v <= 0:
        return 0.0
    return max(1.0, v)


def resolve(**kw: t.Any) -> Config:
    """Build the effective config. ``kw`` are the explicit ``nexus.init()`` arguments."""
    # Deferred, and it has to be: ``contract`` imports ``Config`` from this module, so a top-level
    # import here would be a cycle. By the time anything calls ``resolve()`` this module is fully
    # initialised, so the cycle does not exist at call time.
    from .contract import label

    fileconf = _file_overrides()

    def pick(name: str, envname: str, default: t.Any, cast: t.Callable[[str], t.Any] = str) -> t.Any:
        if kw.get(name) is not None:
            return kw[name]
        raw = os.environ.get(envname)
        if raw is not None and raw.strip() != "":
            try:
                return cast(raw.strip())
            except (TypeError, ValueError):
                pass
        if fileconf.get(name) is not None:
            return fileconf[name]
        return default

    tier = pick("tier", "NEXUS_TIER", TIER_METADATA_ONLY)
    if isinstance(tier, str):
        tier = _TIER_ALIASES.get(tier.strip().lower(), tier.strip().lower())
    if tier not in _TIERS:
        tier = TIER_METADATA_ONLY  # conservative default: an unrecognised tier is never the loud one

    tags = kw.get("tags") or fileconf.get("tags") or {}
    if not isinstance(tags, dict):
        tags = {}
    # Bounded tag space (3.5): a customer looping user ids into tags would otherwise blow up the
    # rollup's cardinality on our side of the wire, where it is expensive and nobody can see it.
    tags = {str(k)[:64]: str(v)[:128] for k, v in list(tags.items())[:32]}

    # -- provenance (§6.1) --------------------------------------------------------------------
    # Same precedence ladder as everything else — explicit argument, then ``NEXUS_*``, then the
    # config file — and only then platform detection, which may add fields but never replace one.
    # ``pick`` with a ``None`` default is what keeps "we did not read it" distinct from a value:
    # the three unified tags fall back to the string ``"unknown"``, these fall back to nothing.
    resolved_env = str(pick("env", "NEXUS_ENV", "unknown"))[:64]
    resolved_version = str(kw.get("version") or _default_version())[:64]
    prov = provenance.resolve(
        {
            "application": pick("application", "NEXUS_APPLICATION", None),
            "repo": pick("repo", "NEXUS_REPO", None),
            "commit": pick("commit", "NEXUS_COMMIT", None),
            "branch": pick("branch", "NEXUS_BRANCH", None),
            "deployment_id": pick("deployment_id", "NEXUS_DEPLOYMENT_ID", None),
            "env": None if resolved_env == "unknown" else resolved_env,
            "version": None if resolved_version == "unknown" else resolved_version,
        },
        env_is_unknown=(resolved_env == "unknown"),
        version_is_unknown=(resolved_version == "unknown"),
    )

    return Config(
        # the one env-authoritative key; see the module docstring
        enabled=enabled_from_env() and bool(kw.get("enabled", True)),
        service=str(kw.get("service") or _default_service())[:128],
        # ``env``/``version`` keep their ``"unknown"`` sentinel — three years of unified tagging
        # depend on those two never being null — but a value the platform published beats the
        # sentinel, and only the sentinel. ``provenance.resolve`` was told which of the two were
        # unknown and refuses to return the other kind, so this ``or`` can never overwrite a
        # caller's answer.
        env=str(prov.values.get("env") or resolved_env)[:64],
        version=str(prov.values.get("version") or resolved_version)[:64],
        # -- provenance (§6.1). ``.get`` with no default: a field we did not read is ``None``,
        # which the dataclass declares and the builders drop before the wire. Nothing here has a
        # fallback, and adding one would silence the shadow-deploy alarm permanently.
        #
        # Bounded HERE rather than in each builder, for the reason ``service``/``env``/``version``
        # two lines up already are: these five are dimensions that ride the base envelope, so an
        # unbounded ``commit`` is not one oversized field, it is one oversized field multiplied by
        # every row this process ever emits. Bounding at the point of resolution also means no
        # builder can forget, and there is exactly one place to read the bound off.
        #
        # ``contract.label`` and not ``str(...)[:n]``: a value that is only whitespace becomes
        # ``None`` rather than ``""``, so "we read nothing" and "we read a blank" stay different
        # facts all the way to the wire, which is the whole point of dropping ``None`` keys.
        application=label(prov.values.get("application"), 128),
        repo=label(prov.values.get("repo"), 200),
        commit=label(prov.values.get("commit"), 128),
        branch=label(prov.values.get("branch"), 128),
        deployment_id=label(prov.values.get("deployment_id"), 128),
        provenance_source=prov.provenance_source,
        provenance_sources=dict(prov.sources),
        tier=tier,
        collector_url=_collector_url(kw.get("collector_url") or fileconf.get("collector_url")),
        gateway_url=pick("gateway_url", "NEXUS_GATEWAY_URL", None),
        api_key=pick("api_key", "NEXUS_API_KEY", None),
        queue_capacity=max(1, int(pick("queue_capacity", "NEXUS_QUEUE_CAPACITY", 10_000, int))),
        batch_size=max(1, int(pick("batch_size", "NEXUS_BATCH_SIZE", 100, int))),
        flush_interval_s=max(0.05, float(pick("flush_interval_s", "NEXUS_FLUSH_INTERVAL_S", 2.0, float))),
        http_timeout_s=max(0.05, float(pick("http_timeout_s", "NEXUS_HTTP_TIMEOUT_S", 2.0, float))),
        max_retries=max(0, int(pick("max_retries", "NEXUS_MAX_RETRIES", 3, int))),
        flush_deadline_s=max(0.05, float(pick("flush_deadline_s", "NEXUS_FLUSH_DEADLINE_S", 5.0, float))),
        # 0 disables the rollup; anything positive is floored at one second so a typo cannot turn
        # the worker loop into a p99-per-tick emitter.
        health_interval_s=_health_interval(pick("health_interval_s", "NEXUS_HEALTH_INTERVAL_S", 60.0, float)),
        transport_mode=str(pick("transport_mode", "NEXUS_TRANSPORT_MODE", "auto")),
        spill_dir=pick("spill_dir", "NEXUS_SPILL_DIR", None),
        tags=tags,
    )


def describe(cfg: Config) -> dict:
    """Config as a dict safe to log or emit. ``api_key`` is never included — not masked, absent.
    A masked secret in a log still tells an attacker the key exists and how long it is."""
    d = {k: v for k, v in vars(cfg).items() if k != "api_key"}
    d["api_key_configured"] = bool(cfg.api_key)
    d["python"] = sys.version.split()[0]
    return d


# `_env_float` is exported for the runtime module's deadline handling; keep the name stable.
__all__ = ["Config", "resolve", "describe", "enabled_from_env", "env_flag",
           "TIER_METADATA_ONLY", "TIER_HASHED", "TIER_REDACTED_PREVIEW", "TIER_FULL",
           "_env_float"]
