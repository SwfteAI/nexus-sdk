#!/usr/bin/env python3
"""Fail a release before the version is not the same number in every place that states it.

``src/nexus/_version.py`` is the intended single source, and its own docstring says so:

    Kept in a module of its own, with no imports, because ``pyproject.toml`` reads it at build time
    and the SDK stamps it onto self-telemetry at runtime.

**The first half of that is not true.** ``pyproject.toml`` hardcodes ``version = "0.1.0"``; nothing
reads ``_version.py`` at build time. So the number is written out three times — in the packaging
metadata, in ``_version.py``, and again in ``__init__.py`` — and the only thing keeping them equal is
that nobody has bumped one of them yet.

The docstring's second half is exactly why that matters. This SDK stamps its version onto
``sdk_version``, which rides the base envelope of **every event it emits** and is now a declared
field in the devtools contract. A wheel published as 0.2.0 whose events say 0.1.0 is not a cosmetic
mismatch: it is a fleet where the version column cannot be trusted to identify which build produced
a row, which is the column you reach for first when a regression appears in production. As
``_version.py`` puts it, a version that disagrees between the wheel metadata and the events is a
support ticket nobody can close.

Prints ``version=<v>`` on stdout so a workflow step can append it to ``$GITHUB_OUTPUT``.
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _literal(path: Path, pattern: str) -> str | None:
    m = re.search(pattern, path.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def main() -> int:
    sources: dict[str, str | None] = {}

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    if "version" in project:
        sources["pyproject.toml"] = project["version"]
    elif "version" in project.get("dynamic", []):
        # If somebody wires this up properly later, that is a fix rather than a failure: a version
        # derived at build time cannot drift from the module it is derived from.
        sources["pyproject.toml"] = None
    else:
        print("check_versions: pyproject declares neither a static nor a dynamic version",
              file=sys.stderr)
        return 1

    sources["src/nexus/_version.py"] = _literal(
        ROOT / "src/nexus/_version.py", r'__version__\s*=\s*"([^"]+)"')
    sources["src/nexus/__init__.py"] = _literal(
        ROOT / "src/nexus/__init__.py", r'__version__\s*=\s*"([^"]+)"')

    stated = {k: v for k, v in sources.items() if v is not None}
    missing = [k for k, v in sources.items() if v is None and k != "pyproject.toml"]
    if missing:
        print(f"check_versions: no version literal found in {', '.join(missing)}", file=sys.stderr)
        return 1

    distinct = set(stated.values())
    if len(distinct) != 1:
        print("check_versions: the version disagrees between files —", file=sys.stderr)
        for name, value in sorted(stated.items()):
            print(f"  {value}  {name}", file=sys.stderr)
        print("\nEvery one of these is written by hand. `sdk_version` rides every event this SDK\n"
              "emits, so a disagreement here publishes a wheel whose events name a different build.",
              file=sys.stderr)
        return 1

    print(f"version={distinct.pop()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
