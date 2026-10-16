# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""V4 HX control-plane core (offline-testable, stdlib only).

This package is a bounded, software-only core for the HX control plane contract in
runbooks/05_CONTROL_PLANE_AND_SCHEDULER.md. It is NOT a deployed service:
it never contacts remote hosts, starts models, or claims hardware readiness.

Layers:
- ``store``   : durable SQLite metadata (profiles, generations, nodes, jobs).
- ``manager`` : fail-closed lifecycle logic; adapter interface lives in ``adapter``.
- ``httpapi`` : loopback-only authenticated HTTP surface (contract "1" subset).
- ``cli``     : minimal client wrapper for humans/tests.

Importing this package has no side effects.
"""
__all__ = ['adapter', 'cli', 'config', 'errors', 'httpapi', 'manager', 'store']
