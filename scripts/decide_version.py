#!/usr/bin/env python3
"""Decide, once per push to the default branch, whether this push is a release.

The trigger is the version field in the committed manifest CHANGING. Not a tag, not a commit-message
parser. That is a measured decision, not taste: in this estate 300 of 300 cortex commits and 20 of 20
nexus-harness commits fail the conventional-commits header regex (every subject is emoji-prefixed),
and nexus-devtools fails it 46% of the time. A parser-driven tool (semantic-release, release-please)
responds to a subject it cannot parse by deciding today is not a release day. It does not error.
The version field cannot skip and cannot duplicate: it is in the diff, reviewed as code.

Five guards, each of which turns a silent failure into a loud one:

  1. the version must be valid (semver, or PEP 440 for --kind pyproject);
  2. it must differ from the previous commit's version — otherwise "no release", stated explicitly;
  3. no git tag v<version> may exist;
  4. the REGISTRY must not already hold <version>. Tags can lie (a publish that succeeded and then
     failed to tag; a repo re-created from a fork); npm and PyPI cannot, because neither ever lets
     a version number be reused. This is the guard that protects against the 409 / E403 twenty
     minutes into a build;
  5. it must be greater than the highest released version — publishing a lower number does not roll
     consumers back, it strands anyone whose updater or lockfile only moves forward.

Portable on purpose: stdlib only, no `packaging`, no `semver`, so it runs identically on
ubuntu-latest, GitHub's macOS runners, and the self-hosted Macs the nexus repos are pinned to.

Usage:
  decide_version.py --kind package.json  --file package.json            [--registry npm:@scope/name]
  decide_version.py --kind pyproject     --file pyproject.toml          [--registry pypi:name]
  decide_version.py --kind python-init   --file pkg/__init__.py         [--registry pypi:name]
  common: [--base HEAD^] [--tag-prefix v] [--prerelease-dist-tag next]

Writes GitHub Actions outputs (should_release, version, tag, prerelease, dist_tag, reason) when
GITHUB_OUTPUT is set. Exit 0 for "release" and for "no release"; exit 1 only for a refusal.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

SEMVER = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
# PEP 440 subset that covers what these repos actually use: N(.N)* with an optional a/b/rc/dev tail.
PEP440 = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(a|b|rc)(\d+))?(?:\.dev(\d+))?$")


def sh(args: list[str]) -> str | None:
    try:
        return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()
    except subprocess.CalledProcessError:
        return None


def emit(k: str, v: str) -> None:
    print(f"  {k}={v}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"{k}={v}\n")


def summary(md: str) -> None:
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(md + "\n")


def refuse(msg: str, extra: str = "") -> None:
    print(f"\ndecide-version: REFUSING — {msg}\n{extra}", file=sys.stderr)
    print(f"::error title=Release refused::{msg}")
    summary(f"### Release blocked\n\n{msg}\n\n{extra}")
    sys.exit(1)


# ---- read the version out of a blob ------------------------------------------------------------
def read_version(kind: str, blob: str) -> str | None:
    if kind == "package.json":
        return json.loads(blob).get("version")
    if kind == "pyproject":
        m = re.search(r'^\s*version\s*=\s*"([^"]+)"', blob, re.M)
        return m.group(1) if m else None
    if kind == "python-init":
        m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', blob, re.M)
        return m.group(1) if m else None
    raise SystemExit(f"unknown --kind {kind}")


# ---- ordering ----------------------------------------------------------------------------------
def key_semver(v: str):
    m = SEMVER.match(v)
    if not m:
        return None
    pre = m.group(4)
    # a release ranks above any prerelease of the same triple: (…, 1, ()) > (…, 0, (ids))
    ids: list[tuple[int, int | str]] = []
    if pre:
        for p in pre.split("."):
            ids.append((0, int(p)) if p.isdigit() else (1, p))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, tuple(ids))


def key_pep440(v: str):
    m = PEP440.match(v)
    if not m:
        return None
    rel = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    # PEP 440 ordering: .devN < aN < bN < rcN < final, for the same release triple.
    stage = -1 if m.group(6) is not None and m.group(4) is None else {"a": 0, "b": 1, "rc": 2, None: 3}[m.group(4)]
    return (*rel, stage, int(m.group(5) or 0), int(m.group(6) or 0))


def is_prerelease(kind: str, v: str) -> bool:
    if kind == "pyproject" or kind == "python-init":
        m = PEP440.match(v)
        return bool(m and (m.group(4) or m.group(6)))
    m = SEMVER.match(v)
    return bool(m and m.group(4))


# ---- registry ----------------------------------------------------------------------------------
def registry_has(spec: str, version: str) -> bool | None:
    """True if the registry already holds this version, False if not, None if unreachable."""
    scheme, _, name = spec.partition(":")
    if scheme == "npm":
        url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}/{version}"
    elif scheme == "pypi":
        url = f"https://pypi.org/pypi/{name}/{version}/json"
    else:
        raise SystemExit(f"unknown registry scheme in {spec}")
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=20) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=["package.json", "pyproject", "python-init"])
    ap.add_argument("--file", required=True)
    ap.add_argument("--base", default="HEAD^", help="ref holding the PREVIOUS manifest (first parent = the branch before the merge)")
    ap.add_argument("--registry", default=None, help="npm:<name> or pypi:<name>")
    ap.add_argument("--tag-prefix", default="v")
    ap.add_argument("--prerelease-dist-tag", default="next")
    a = ap.parse_args()

    pyish = a.kind in ("pyproject", "python-init")
    key = key_pep440 if pyish else key_semver
    what = "PEP 440" if pyish else "semver"

    with open(a.file, encoding="utf-8") as fh:
        current = read_version(a.kind, fh.read())
    if not current:
        refuse(f"could not find a version in {a.file}")
    if key(current) is None:
        refuse(f'{a.file} version "{current}" is not valid {what}')

    prev_blob = sh(["git", "show", f"{a.base}:{a.file}"])
    previous = read_version(a.kind, prev_blob) if prev_blob else None

    # guard 2 -------------------------------------------------------------------------------------
    if previous is not None and previous == current:
        emit("should_release", "false")
        emit("version", current)
        emit("reason", f"{a.file} version is unchanged at {current}")
        print(
            f"decide-version: no release — {a.file} version is unchanged at {current}.\n"
            "  A push to the default branch ships only when this field changes. Stated, not skipped."
        )
        summary(f"### No release\n\n`{a.file}` version is unchanged at `{current}`.")
        return

    tag = f"{a.tag_prefix}{current}"

    # guard 3 -------------------------------------------------------------------------------------
    if sh(["git", "tag", "--list", tag]):
        refuse(
            f"tag {tag} already exists — this version has been released before",
            "    Released versions are immutable. Bump to a new version instead of re-releasing this one.",
        )

    # guard 4 -------------------------------------------------------------------------------------
    if a.registry:
        has = registry_has(a.registry, current)
        if has is True:
            refuse(
                f"{a.registry} already holds {current}",
                "    The registry is the source of truth for what has shipped; a tag can be missing, a\n"
                "    published version cannot be un-published. Bump the version.",
            )
        if has is None:
            refuse(f"could not reach the registry for {a.registry}; refusing to guess whether {current} exists")

    # guard 5 -------------------------------------------------------------------------------------
    tags = (sh(["git", "tag", "--list", f"{a.tag_prefix}*"]) or "").split()
    released = [(t, key(t[len(a.tag_prefix):])) for t in tags]
    released = [(t, k) for t, k in released if k is not None]
    if released:
        top_tag, top_key = max(released, key=lambda x: x[1])
        if key(current) <= top_key:
            refuse(
                f"{current} is not greater than the highest released version ({top_tag})",
                "    Consumers only move forward. A lower version does not roll anyone back; it strands them.",
            )

    pre = is_prerelease(a.kind, current)
    emit("should_release", "true")
    emit("version", current)
    emit("tag", tag)
    emit("previous", previous or "unknown")
    emit("prerelease", "true" if pre else "false")
    emit("dist_tag", a.prerelease_dist_tag if pre else "latest")
    print(f"decide-version: releasing {current} (tag {tag}{', prerelease' if pre else ''})")
    summary(
        f"### Release\n\n**Releasing `{current}`** (tag `{tag}`)\n\n"
        f"- previous version on the default branch: `{previous or 'unknown'}`\n"
        f"- prerelease: `{pre}`\n"
    )


if __name__ == "__main__":
    main()
