"""Fail the build if the core ring ever grows a required dependency.

This is the one property of this package that cannot be recovered after the fact. A dependency
added in a hurry ships in a release, lands in someone's resolver, conflicts with the version their
application already pins, and the conversation about adopting the SDK ends there. Extras may carry
whatever they like; ``nexus`` itself may carry nothing.

Run against the *installed distribution*, not the source tree, because the question is what a
customer's ``pip install`` actually pulls.

The distribution name used to be written here as a literal, and when the package was
renamed to ``swfte-nexus-sdk`` (``nexus-sdk`` is taken on PyPI) this file was not renamed with it.
The guard raised ``PackageNotFoundError`` on every run, so for that whole period the zero-dependency
claim — which the README makes prominently, and which is the single property of this package that
cannot be walked back after a release — was protected by nothing at all.

It failed loudly, which is the safe direction, but a red CI job whose message is "no package
metadata was found" invites exactly one repair: wrap it in ``try``. Then it is green and blind.

So the name is read from ``pyproject.toml`` rather than repeated here. Two copies of a fact drift;
one copy cannot. And a rename now breaks this script's *parse* — a loud, specific failure that
names the file to look in — instead of silently pointing it at a package that is not installed.
"""
import pathlib
import re
import sys
from importlib.metadata import PackageNotFoundError, distribution

_PYPROJECT = pathlib.Path(__file__).resolve().parents[2] / "pyproject.toml"
try:
    _text = _PYPROJECT.read_text(encoding="utf-8")
except OSError as exc:  # pragma: no cover — CI layout error, not a code path
    raise SystemExit(f"FAIL: cannot read {_PYPROJECT}: {exc}")

_match = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', _text)
if not _match:
    raise SystemExit(f"FAIL: no project name found in {_PYPROJECT}")
_name = _match.group(1)

try:
    dist = distribution(_name)
except PackageNotFoundError:
    raise SystemExit(
        f"FAIL: {_name!r} (read from pyproject.toml) is not installed, so this guard checked "
        "nothing. Install the package before running it — do not silence this."
    )
required = [r for r in (dist.requires or []) if "extra ==" not in r]
if required:
    print("FAIL: the core ring has acquired dependencies:", file=sys.stderr)
    for r in required:
        print(f"  - {r}", file=sys.stderr)
    raise SystemExit(1)

extras = sorted({r.split("extra ==")[1].strip().strip('"\'') for r in (dist.requires or [])
                 if "extra ==" in r})
print(f"OK: {_name} has no required dependencies. Optional extras: {', '.join(extras) or 'none'}")
