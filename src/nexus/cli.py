"""``nexus-run`` — the zero-code launcher, analogous to ``ddtrace-run``.

    nexus-run python -m myservice
    nexus-run gunicorn -w 4 myapp:app

All it does is prepend ``nexus/bootstrap`` to ``PYTHONPATH`` and ``exec`` the command. That is the
entire mechanism, and its smallness is the feature:

* **``execvp``, not ``subprocess``.** The launcher replaces itself with the target, so there is no
  supervising process to lose signals, mangle exit codes, or sit between the orchestrator's
  ``SIGTERM`` and the application's handler. A wrapper that breaks graceful shutdown to add
  telemetry has made the system worse.
* **``PYTHONPATH`` is prepended, never replaced.** Applications legitimately set it; clobbering it
  turns "no telemetry" into "ImportError at startup".
* **The child inherits everything else.** No environment normalisation, no cwd change, no
  argument rewriting — every one of those is a way for the launcher to change program behaviour,
  which is not a trade a telemetry tool is entitled to make.

``nexus-run`` is the convenient form. The durable form is ``ENV PYTHONPATH`` in a Dockerfile, which
survives an entrypoint owned by someone else — an init system, a framework runner, a base image's
CMD. Both are documented, because in production the second is what usually works.
"""
from __future__ import annotations

import os
import sys


def _usage() -> int:
    sys.stderr.write(
        "usage: nexus-run <command> [args...]\n"
        "\n"
        "Runs <command> with the nexus SDK armed before the application imports.\n"
        "Equivalent, and preferable in a container image:\n"
        "    ENV PYTHONPATH=%s:$PYTHONPATH\n"
        "\n"
        "Environment:\n"
        "  NEXUS_ENABLED=0          off entirely: no hooks, no threads, near-zero import cost\n"
        "  NEXUS_SERVICE            service name (unified tagging); default 'unknown'\n"
        "  NEXUS_ENV                environment name, e.g. prod\n"
        "  NEXUS_VERSION            deployed version\n"
        "  NEXUS_COLLECTOR_HOST     collector host; default 127.0.0.1\n"
        "  NEXUS_COLLECTOR_PORT     collector port; default 8791\n"
        "  NEXUS_COLLECTOR_URL      full base URL; overrides host/port (sidecar, k8s service)\n"
        "  NEXUS_TIER               metadata_only (default) | redacted_preview | full\n"
        "                           no field is hashed except *_fingerprint;\n"
        "                           redacted_preview is truncated plaintext.\n"
        "                           ('hashed' is accepted as a legacy alias)\n"
        "  NEXUS_AUTO_INSTRUMENT=0  identity + explicit API only; no import patching\n"
        % _bootstrap_dir())
    return 2


def _bootstrap_dir() -> str:
    from .bootstrap import path
    return path()


def build_env(env: dict, bootstrap: str) -> dict:
    out = dict(env)
    existing = out.get("PYTHONPATH", "")
    parts = [p for p in existing.split(os.pathsep) if p]
    if bootstrap not in parts:
        parts.insert(0, bootstrap)
    out["PYTHONPATH"] = os.pathsep.join(parts)
    return out


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        return _usage()
    os.environ.update(build_env(os.environ, _bootstrap_dir()))
    try:
        os.execvp(args[0], args)
    except OSError as exc:
        sys.stderr.write(f"nexus-run: cannot execute {args[0]!r}: {exc}\n")
        return 127
    return 0    # unreachable: execvp does not return


if __name__ == "__main__":     # pragma: no cover
    raise SystemExit(main())
