"""Third-party source redistributed inside this package.

Every subdirectory here is someone else's code, carries its own LICENSE file, and is listed in
the top-level ``NOTICE``. ``tests/test_vendor_attribution.py`` fails if a directory appears here
without both.

Vendoring rather than depending is a deliberate cost. The core ring of this SDK declares zero
required dependencies (``pyproject.toml``), because this package is installed into other people's
production images: every version constraint we add is a chance to conflict with something the
customer already pins, and a resolver conflict is how a telemetry SDK gets uninstalled. Two
components are worth the copy:

* ``wrapt`` — the only correct way to wrap a Python callable while preserving its identity,
  signature, descriptor behaviour and introspectability. Reimplementing it is a well-known trap.
* ``ddtrace_module`` — dd-trace-py's import-hook machinery. See its module docstring for why
  every odd-looking line in it is load-bearing.

Neither is imported at ``import nexus`` time. They are pulled in only when auto-instrumentation
is actually installed, which keeps the kill-switch and the base import cost honest.
"""
