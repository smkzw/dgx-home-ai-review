# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Load the read-only V4 configuration (profiles.json, scheduler-policy.json).

Read-only consumer: this module never writes configuration and never invents
calibration values. A ``null`` calibration stays ``None`` (unknown), never 0.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any
PROFILE_NAME = re.compile('[a-z0-9][a-z0-9._-]{0,63}')
NODE_NAME = re.compile('[a-z0-9][a-z0-9._-]{0,63}')
LIFECYCLE_STATES = ('STOPPED', 'STARTING', 'READY', 'DRAINING', 'STOPPING', 'FAILED', 'QUARANTINED', 'RECONCILING')
ACTIVE_STATES = ('STARTING', 'READY', 'DRAINING', 'STOPPING', 'QUARANTINED', 'RECONCILING')
POLICY_DEFAULTS: dict[str, Any] = {'conflict_grace_seconds': 120, 'lease_ttl_seconds': 300, 'min_residency_seconds': 300, 'memory_samples_required': 3, 'sample_max_age_seconds': 10, 'unreachable_rank': 'QUARANTINED_keep_reservation', 'active_request_preemption': False, 'cloud_fallback': False, 'ordinary_clients': 'no lifecycle privileges'}

def repo_root(start: Path) -> Path:
    """Repository root that contains ``config/profiles.json``."""
    here = start.resolve()
    for candidate in (here, *here.parents):
        if (candidate / 'config' / 'profiles.json').is_file():
            return candidate
    return here

def load_json(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding='utf-8'))

def load_profiles(root: Path) -> dict[str, dict[str, Any]]:
    """Return profile definitions from ``<root>/config/profiles.json``."""
    return read_profiles_json(Path(root) / 'config' / 'profiles.json')

def read_profiles_json(path: Path) -> dict[str, dict[str, Any]]:
    """Validate and normalize a profiles JSON document (shipped or explicit).

    Explicit files are a *test/operator aid*: the fail-closed checks still run,
    so a profile only starts when it declares ``hardware_validated: true`` and
    real per-node calibration. Nulls are preserved, never replaced with 0.
    """
    data = load_json(path)
    profiles: dict[str, dict[str, Any]] = {}
    for name, raw in data.get('profiles', {}).items():
        if not PROFILE_NAME.fullmatch(name):
            raise ValueError(f'Invalid profile name in config: {name!r}')
        nodes = raw.get('nodes')
        if not isinstance(nodes, list) or not nodes or any((not NODE_NAME.fullmatch(n) for n in nodes)):
            raise ValueError(f'Invalid node list for profile {name!r}')
        if len(set(nodes)) != len(nodes):
            raise ValueError(f'Duplicate nodes for profile {name!r}')
        profiles[name] = {'name': name, 'nodes': list(nodes), 'source': raw.get('source'), 'role': raw.get('role'), 'min_start_available_gib': raw.get('min_start_available_gib'), 'runtime_floor_gib': raw.get('runtime_floor_gib'), 'hardware_validated': raw.get('hardware_validated') is True}
    if not profiles:
        raise ValueError(f'profiles document contains no profiles: {path}')
    return profiles

def load_policy(root: Path) -> dict[str, Any]:
    path = Path(root) / 'config' / 'scheduler-policy.json'
    policy = dict(POLICY_DEFAULTS)
    if path.is_file():
        policy.update(load_json(path))
    return policy
