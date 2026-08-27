"""Single source of the package version.

Kept in a module of its own, with no imports, because ``pyproject.toml`` reads it at build time
and the SDK stamps it onto self-telemetry at runtime. A version string that disagrees between the
wheel metadata and the events is a support ticket nobody can close.
"""

__version__ = "0.1.0"

# The event-contract version this SDK speaks. Distinct from ``__version__`` on purpose: a customer's
# production image does not upgrade on our schedule, so ingest must keep accepting an 18-month-old
# SDK. Bumping the package version must never silently bump the contract.
CONTRACT_VERSION = "1"
