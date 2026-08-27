"""A directory whose only job is to be on ``PYTHONPATH``.

CPython imports ``sitecustomize`` during interpreter startup if it can find one on the path. That
is the earliest user-controllable hook there is, and it is what makes zero-code instrumentation
possible: by the time an application's own ``import`` statements run, we are already installed.

Keeping it in a subpackage rather than shipping a top-level ``sitecustomize.py`` matters. A
top-level one would be importable by *anything* that has this package's parent on its path — we
would silently arm ourselves inside unrelated interpreters, including the customer's build tooling.
Here, the module is reachable only when someone deliberately puts *this directory* on the path,
which is what ``nexus-run`` does and what a Dockerfile ``ENV PYTHONPATH=…`` does.
"""
from __future__ import annotations

import os


def path() -> str:
    """Filesystem directory to prepend to ``PYTHONPATH``."""
    return os.path.dirname(os.path.abspath(__file__))
