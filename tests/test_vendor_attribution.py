"""Attribution for vendored third-party code is a build-breaking requirement, not a chore.

``src/nexus/vendor/`` contains code we did not write: ``wrapt`` (BSD-2) and dd-trace-py's import
machinery (Apache-2.0/BSD-3). Shipping either in a wheel without its licence text is a licence
violation, and it is the kind that is discovered by a customer's legal review rather than by us.
The check is mechanical so it cannot rot: any directory that appears under ``vendor/`` must carry a
LICENSE and must be named in the top-level NOTICE.
"""
from __future__ import annotations

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "src", "nexus", "vendor")


def _vendor_dirs() -> list[str]:
    return sorted(d for d in os.listdir(VENDOR)
                  if os.path.isdir(os.path.join(VENDOR, d)) and not d.startswith("__"))


def test_there_is_something_to_attribute():
    assert _vendor_dirs(), "vendor tree is empty — the test would pass vacuously"


@pytest.mark.parametrize("name", _vendor_dirs())
def test_every_vendored_tree_carries_a_licence(name):
    d = os.path.join(VENDOR, name)
    licences = [f for f in os.listdir(d) if f.upper().startswith("LICENSE")]
    assert licences, f"vendor/{name} ships third-party code with no LICENSE file"
    # dd-trace-py's own LICENSE is a two-line dual-licence pointer at LICENSE.Apache and
    # LICENSE.BSD3, so the requirement is that the *full* text is present somewhere in the tree,
    # not that every file is long.
    texts = [open(os.path.join(d, f), encoding="utf-8").read() for f in licences]
    assert max(len(x) for x in texts) > 1000, (
        f"vendor/{name} has licence stubs but no full licence text: {licences}")


@pytest.mark.parametrize("name", _vendor_dirs())
def test_every_vendored_tree_is_named_in_the_notice(name):
    notice = open(os.path.join(ROOT, "NOTICE"), encoding="utf-8").read()
    assert name in notice, f"vendor/{name} is not mentioned in NOTICE"


def test_our_own_licence_is_permissive():
    """The whole reason this repo exists separately from ``nexus-devtools``.

    The parent repo is ``LicenseRef-Proprietary`` and its build system actively prevents source
    from shipping (``build/hatch_guard.py``, a deleted sdist target, ``scripts/npm-guard.js``). An
    SDK that customers embed cannot live under those terms.
    """
    text = open(os.path.join(ROOT, "LICENSE"), encoding="utf-8").read()
    assert "Apache License" in text and "Version 2.0" in text
    assert "Proprietary" not in text
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert "Apache-2.0" in pyproject


def test_wrapt_is_the_pure_python_build():
    """We vendor the Python implementation deliberately: the C extension would make the "zero
    dependencies, no compiler, any platform" claim false."""
    from nexus.vendor.wrapt import __wrapt__ as impl
    assert impl._using_c_extension is False
    # ...and no compiled artefact was carried in with the source.
    for dirpath, _dirs, files in os.walk(os.path.join(VENDOR, "wrapt")):
        assert not [f for f in files if f.endswith((".so", ".pyd", ".c"))], dirpath


def test_vendored_module_watchdog_is_renamed_to_coexist_with_ddtrace():
    """A customer running Datadog has ddtrace's ``ModuleWatchdog`` in ``sys.meta_path`` already.

    ``_find_in_meta_path`` matches on exact type, and the anti-double-wrap marker is looked up by
    attribute name, so sharing either would mean the two SDKs silently uninstalling each other's
    hooks. Renaming the markers is the whole mitigation, so it is asserted rather than trusted.
    """
    src = open(os.path.join(VENDOR, "ddtrace_module", "module.py"), encoding="utf-8").read()
    # The module docstring names the upstream identifiers to document the rename, so the check is
    # against the code below it rather than the file as a whole.
    code = src.split('"""', 2)[2]
    assert "__nexus_origin__" in code and "__dd_origin__" not in code
    assert "_nexus_get_code" in code and "_dd_get_code" not in code


def test_vendored_code_does_not_import_ddtrace_or_wrapt_from_site_packages():
    """The vendored tree must be self-contained; a stray absolute import silently reintroduces the
    dependency we vendored to avoid."""
    bad = []
    for dirpath, _dirs, files in os.walk(VENDOR):
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dirpath, f)
            for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
                s = line.strip()
                if s.startswith(("import ddtrace", "from ddtrace")):
                    bad.append(f"{p}:{i}")
                if s.startswith("import wrapt") or s.startswith("from wrapt"):
                    bad.append(f"{p}:{i}")
    assert bad == [], f"vendored code reaches outside the vendor tree: {bad}"


def test_importing_nexus_does_not_import_the_vendor_tree():
    """Vendored import machinery is only needed for auto-instrumentation. Paying for it at
    ``import nexus`` would put it in the cold-start budget of every Lambda that never uses it."""
    from conftest import run_script
    import json
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as td:
        r = run_script(
            "import sys, json, nexus\n"
            "print(json.dumps([m for m in sys.modules if 'vendor' in m]))\n",
            pathlib.Path(td))
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout.strip().splitlines()[-1]) == []
