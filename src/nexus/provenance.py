"""Where this process came from — repo, commit, application — read, never guessed.

``ANCHOR-INTEGRATION.md`` §6.1. The left half of Nexus (``nexus wrap``) knows *repo + commit +
who*. The right half (this SDK) knows *service + env + version*. Nothing has ever recorded the join
between them, so a running process cannot be pointed back at the commit that produced it. Three
optional arguments on ``init()`` close that, and this module fills them in from the platform when
the application did not.

**The one rule that governs every line below: an absent value stays absent.**

The console draws the provenance chain as five stations with the *breaks* rendered — a running
version that no deployment record accounts for takes the accent colour, because it means production
contains software of unknown origin. A fabricated commit, a ``repo`` guessed from a service name, a
host inferred from a provider string: each of those silences a real shadow-deploy alarm and makes it
unfalsifiable. There is therefore no default, no fallback, no ``or "unknown"`` in this file. If we
did not read it, it is not here.

**Every value carries the variable it came from.** ``provenance_sources`` maps each field to the
exact source — ``"env:VERCEL_GIT_COMMIT_SHA"``, ``"file:/etc/podinfo/labels#app.kubernetes.io/name"``,
``"explicit"``. ``provenance_source`` (singular, the field the console's ribbon reads) is the source
of ``commit`` specifically, because commit is the join key to the commit-anchored ledger and the
field the shadow-deploy alarm turns on. When there is no commit there is no ``provenance_source``.

Detection order, first hit wins per field: Vercel → GitHub Actions → Kubernetes → generic OCI.

---

**Two deliberate refusals, because both are the sort of small convenience that would quietly
destroy the product's central claim:**

1. **``application`` is never inferred from a repository name.** ``app_id`` identifies a declared
   registry object; one application may span three repos and five services, and
   ``explore/estate.ts`` already refuses to prefix-match ``haiku-4-5`` against ``claude-haiku-4-5``
   on exactly this reasoning. A repo slug that happens to equal an app slug is a coincidence, not a
   join. The only auto-detected ``application`` comes from ``app.kubernetes.io/name``, which is an
   operator's *declaration*, not a similarity.

2. **``repo`` never acquires a host we did not read.** Vercel exposes owner and slug and a provider
   word (``github``); it does not expose the host. Mapping ``github`` → ``github.com`` is correct
   for the common case and wrong for every GitHub Enterprise install, and a wrong host is a join key
   that silently matches nothing. So on Vercel ``repo`` is ``owner/name``; on GitHub Actions, where
   ``GITHUB_SERVER_URL`` *is* published, it is ``host/owner/name``. The consumer parses two- and
   three-segment forms; a fabricated segment it cannot detect.

---

**Kubernetes — the manifest snippet.** Environment variable names cannot contain ``.`` or ``/``, so
the recommended labels have to be projected. Either form is read:

.. code-block:: yaml

    # Deployment.spec.template.metadata
    labels:
      app.kubernetes.io/name: example-app
      app.kubernetes.io/version: "2026.8.1"

    # ...spec.containers[0] — as env, via the downward API
    env:
      - name: APP_KUBERNETES_IO_NAME
        valueFrom: { fieldRef: { fieldPath: "metadata.labels['app.kubernetes.io/name']" } }
      - name: APP_KUBERNETES_IO_VERSION
        valueFrom: { fieldRef: { fieldPath: "metadata.labels['app.kubernetes.io/version']" } }

    # ...or as a projected file, which needs no per-label wiring
    volumes:
      - name: podinfo
        downwardAPI:
          items:
            - path: labels
              fieldRef: { fieldPath: metadata.labels }
    volumeMounts:
      - name: podinfo
        mountPath: /etc/podinfo

The file form is preferred: it needs no change when a label is added. ``NEXUS_PODINFO_DIR``
overrides ``/etc/podinfo`` (the same knob ``runtime._k8s_identity`` already uses).

**Generic OCI.** ``org.opencontainers.image.{revision,source,version}`` are *image* labels; a
process cannot read its own image labels without talking to a runtime socket, which this SDK will
never do. They have to be projected into the environment at build time:

.. code-block:: docker

    ARG GIT_SHA
    ARG GIT_SOURCE
    LABEL org.opencontainers.image.revision=$GIT_SHA \
          org.opencontainers.image.source=$GIT_SOURCE
    ENV OCI_IMAGE_REVISION=$GIT_SHA \
        OCI_IMAGE_SOURCE=$GIT_SOURCE

Both the short spelling (``OCI_IMAGE_REVISION``) and the mechanical dots-to-underscores spelling
(``ORG_OPENCONTAINERS_IMAGE_REVISION``) are read.
"""
from __future__ import annotations

import os
import typing as t

#: Fields this module can supply. ``env`` and ``version`` are here because the platform publishes
#: them and the existing resolver's answer for both is the string ``"unknown"`` — a sourced value
#: strictly beats that. They are filled only when the resolver would otherwise say ``"unknown"``,
#: so an explicit argument or ``NEXUS_ENV`` is never overridden.
FIELDS = ("application", "repo", "commit", "branch", "deployment_id", "env", "version")

#: Cap on any single value. Provenance values are identifiers; a 4 kB one is a bug or an attack.
_MAX = 256


class Detected(t.NamedTuple):
    """What we read, and where each value came from. Neither dict ever contains a value we
    invented, and the two always have identical key sets."""

    values: dict
    sources: dict

    @property
    def provenance_source(self) -> t.Optional[str]:
        """The single string the console's ribbon prints under the ``running`` station.

        The source of ``commit``, and of nothing else. Commit is the join key to the
        commit-anchored ledger; a ribbon that printed the source of some *other* field while the
        commit was absent would attach a provenance claim to a link that does not exist.
        """
        return self.sources.get("commit")


def _get(*names: str) -> t.Tuple[t.Optional[str], t.Optional[str]]:
    """First non-empty environment variable among ``names``, with the name that supplied it."""
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()[:_MAX], f"env:{n}"
    return None, None


def _put(out: dict, src: dict, field: str, value: t.Optional[str],
         source: t.Optional[str]) -> None:
    """Record a value and its source. First writer wins; an absent value writes nothing at all —
    not a ``None`` entry, because a key present with a null value is a claim that we looked and
    found emptiness, which is a different fact from not having looked."""
    if value is None or field in out:
        return
    out[field] = value
    src[field] = source


# --------------------------------------------------------------------------------------------
# platform detectors — each reads only, and reports what it read
# --------------------------------------------------------------------------------------------

def _vercel(out: dict, src: dict) -> None:
    """Vercel build and runtime environment.

    ``VERCEL_GIT_REPO_OWNER`` + ``VERCEL_GIT_REPO_SLUG`` give ``owner/name`` and no host. See the
    module docstring for why no host is manufactured from ``VERCEL_GIT_PROVIDER``: it is recorded
    as read, alongside the repo, and left for the consumer to reconcile against a connector that
    actually knows the forge.
    """
    if not os.environ.get("VERCEL"):
        # Every Vercel runtime sets VERCEL=1. Without it the VERCEL_* names could be anything a
        # customer happened to export, and reading them would be a guess about the platform.
        if not os.environ.get("VERCEL_ENV"):
            return

    commit, cs = _get("VERCEL_GIT_COMMIT_SHA")
    _put(out, src, "commit", commit, cs)

    owner, _os_ = _get("VERCEL_GIT_REPO_OWNER")
    slug, _ss = _get("VERCEL_GIT_REPO_SLUG")
    if owner and slug:
        _put(out, src, "repo", f"{owner}/{slug}",
             "env:VERCEL_GIT_REPO_OWNER+VERCEL_GIT_REPO_SLUG")
    elif slug:
        # Owner absent: a bare name is not a repo identity, and half a join key joins to the wrong
        # thing rather than to nothing. Dropped.
        pass

    branch, bs = _get("VERCEL_GIT_COMMIT_REF")
    _put(out, src, "branch", branch, bs)

    dep, ds = _get("VERCEL_DEPLOYMENT_ID")
    _put(out, src, "deployment_id", dep, ds)

    # Verbatim: "production" / "preview" / "development". Mapping those onto the console's
    # prod|staging|dev|preview vocabulary is the consumer's job — a mapping applied here would be
    # an unsourced translation of a value we were told.
    env, es = _get("VERCEL_ENV")
    _put(out, src, "env", env, es)


def _github_actions(out: dict, src: dict) -> None:
    """GitHub Actions. The only platform in this file that publishes its own host."""
    if not os.environ.get("GITHUB_ACTIONS"):
        return

    commit, cs = _get("GITHUB_SHA")
    _put(out, src, "commit", commit, cs)

    repo, rs = _get("GITHUB_REPOSITORY")       # "owner/name"
    if repo:
        server = os.environ.get("GITHUB_SERVER_URL", "").strip()
        host = server.split("://", 1)[-1].strip("/") if server else ""
        if host:
            _put(out, src, "repo", f"{host}/{repo}",
                 "env:GITHUB_SERVER_URL+GITHUB_REPOSITORY")
        else:
            _put(out, src, "repo", repo, rs)

    branch, bs = _get("GITHUB_REF_NAME")
    _put(out, src, "branch", branch, bs)


def _kubernetes(out: dict, src: dict) -> None:
    """The recommended labels, from projected env or from the projected labels file.

    This is the *only* auto-detected source of ``application``, and it qualifies precisely because
    ``app.kubernetes.io/name`` is something an operator wrote down. It is a declaration we are
    relaying, not a similarity we noticed.
    """
    name, ns = _get("APP_KUBERNETES_IO_NAME", "K8S_APP_NAME")
    _put(out, src, "application", name, ns)
    ver, vs = _get("APP_KUBERNETES_IO_VERSION", "K8S_APP_VERSION")
    _put(out, src, "version", ver, vs)

    if "application" in out and "version" in out:
        return

    podinfo = os.environ.get("NEXUS_PODINFO_DIR", "/etc/podinfo")
    labels = _read_labels(os.path.join(podinfo, "labels"))
    if not labels:
        return
    where = os.path.join(podinfo, "labels")
    _put(out, src, "application", labels.get("app.kubernetes.io/name"),
         f"file:{where}#app.kubernetes.io/name")
    _put(out, src, "version", labels.get("app.kubernetes.io/version"),
         f"file:{where}#app.kubernetes.io/version")


def _read_labels(path: str) -> dict:
    """Parse a downward-API labels projection: one ``key="value"`` per line.

    Bounded and total. A projected volume that is not mounted is the normal case, not an error, and
    a malformed line is skipped rather than raised on — this runs inside ``init()``, and ``init()``
    raising because a sidecar wrote a stray byte would be the SDK becoming the outage.
    """
    out: dict = {}
    try:
        if not os.path.isfile(path):
            return out
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= 128:
                    break
                k, sep, v = line.strip().partition("=")
                if not sep:
                    continue
                out[k.strip()] = v.strip().strip('"')[:_MAX]
    except OSError:
        pass
    return out


def _oci(out: dict, src: dict) -> None:
    """Generic OCI image labels, projected into the environment at build time."""
    commit, cs = _get("OCI_IMAGE_REVISION", "ORG_OPENCONTAINERS_IMAGE_REVISION")
    _put(out, src, "commit", commit, cs)

    source, ss = _get("OCI_IMAGE_SOURCE", "ORG_OPENCONTAINERS_IMAGE_SOURCE")
    if source:
        # The label is a URL by convention. Stripping the scheme and any trailing ".git" is a
        # normalisation of a value we were given, not an inference about a value we were not.
        repo = source.split("://", 1)[-1].strip("/")
        if repo.endswith(".git"):
            repo = repo[:-4]
        _put(out, src, "repo", repo or None, ss)

    ver, vs = _get("OCI_IMAGE_VERSION", "ORG_OPENCONTAINERS_IMAGE_VERSION")
    _put(out, src, "version", ver, vs)


_DETECTORS = (_vercel, _github_actions, _kubernetes, _oci)


def detect() -> Detected:
    """Read provenance from the environment. Never raises; returns only what it actually read."""
    values: dict = {}
    sources: dict = {}
    for fn in _DETECTORS:
        try:
            fn(values, sources)
        except Exception:  # noqa: BLE001 — a detector must never be why init() failed
            continue
    return Detected(values, sources)


def resolve(explicit: dict, *, env_is_unknown: bool, version_is_unknown: bool) -> Detected:
    """Merge explicit arguments over environment variables over platform detection.

    ``explicit`` holds the values the application passed to ``init()`` (already merged with the
    ``NEXUS_*`` variables by the caller, which is why anything present here is stamped
    ``"explicit"``). Precedence matches the rest of ``config``: code beats environment beats
    detection — with the twist that detection can only *add*, never replace.

    ``env`` and ``version`` are special-cased: the existing resolver answers ``"unknown"`` for
    both rather than ``None``, so a detected value is adopted only when that is what it would
    otherwise say. A caller who set them keeps them.
    """
    detected = detect()
    values: dict = {}
    sources: dict = {}

    for field in FIELDS:
        if field in ("env", "version"):
            # Deliberately not stamped when explicit. ``env`` and ``version`` are unified tags that
            # every process already has and that already carry their own ``"unknown"`` sentinel;
            # they appear in ``FIELDS`` only so a *detected* value can beat that sentinel. Recording
            # ``{"env": "explicit"}`` here would make ``provenance_sources`` non-empty on every
            # ordinary ``init()``, and a console reading "this process has provenance" off a
            # non-empty map would then see provenance everywhere and a break nowhere.
            continue
        v = explicit.get(field)
        if v is not None and str(v).strip():
            values[field] = str(v).strip()[:_MAX]
            sources[field] = "explicit"

    for field, v in detected.values.items():
        if field == "env" and not env_is_unknown:
            continue
        if field == "version" and not version_is_unknown:
            continue
        if field in values:
            continue
        values[field] = v
        sources[field] = detected.sources.get(field)

    return Detected(values, sources)
