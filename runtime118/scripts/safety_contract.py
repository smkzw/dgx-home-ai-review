# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure fail-closed validation helpers, NOT a running cluster scheduler."""
from __future__ import annotations
import math, re
from typing import Any

class SafetyError(ValueError):
    pass

def finite_number(x: Any, *, positive=False) -> float:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or (not math.isfinite(x)):
        raise SafetyError('Missing, nonnumeric or non-finite value')
    if x < 0 or (positive and x <= 0):
        raise SafetyError('Value out of range')
    return float(x)

def checked_sha(x: str, *, length=40) -> str:
    if not isinstance(x, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', x):
        raise SafetyError('An immutable full lowercase SHA is required')
    return x

def conflicts(left: dict, right: dict) -> bool:
    a, b = (left.get('nodes'), right.get('nodes'))
    if not a or not b or (not isinstance(a, list)) or (not isinstance(b, list)):
        raise SafetyError('Unknown resource set')
    return bool(set(a) & set(b))

def memory_ready(profile: dict, samples: dict, *, now: float, required_count=3, max_age=10.0) -> tuple[bool, str]:
    """Require per-node calibration and fresh strictly ordered observations.
    Input timestamps and `now` must use the same trusted monotonic clock domain.
    Does not release/reserve nodes or promise runtime headroom.
    """
    try:
        now = finite_number(now)
        max_age = finite_number(max_age, positive=True)
        if isinstance(required_count, bool) or not isinstance(required_count, int) or required_count < 1:
            raise SafetyError('Invalid sample count')
        if profile.get('hardware_validated') is not True:
            raise SafetyError('Profile not hardware-qualified')
        nodes = profile.get('nodes')
        needs = profile.get('min_start_available_gib')
        if not isinstance(nodes, list) or not nodes or len(nodes) != len(set(nodes)):
            raise SafetyError('Invalid nodes')
        if not isinstance(needs, dict) or set(needs) != set(nodes):
            raise SafetyError('Per-node memory calibration missing')
        for node in nodes:
            need = finite_number(needs[node], positive=True)
            seq = samples.get(node)
            if not isinstance(seq, list) or len(seq) < required_count:
                raise SafetyError('Insufficient memory samples')
            prev = -1.0
            for item in seq[-required_count:]:
                stamp = finite_number(item.get('timestamp'))
                free = finite_number(item.get('available_gib'))
                if stamp <= prev or stamp > now or now - stamp > max_age:
                    raise SafetyError('Stale, future or unordered sample')
                if item.get('reachable') is not True:
                    raise SafetyError('Node unreachable')
                if free < need:
                    raise SafetyError('Memory below calibrated start budget')
                prev = stamp
        return (True, 'fresh calibrated samples passed; resource ownership still requires manager transaction')
    except (SafetyError, TypeError, AttributeError, KeyError) as exc:
        return (False, str(exc))
