# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Budget arithmetic proposal only; no grant authority or production activation.
Caller must first verify genuine current pulse/source/nonce/full original SHA,
and measure parent_remaining from the same host monotonic absolute end.
"""
import math

class Refused(ValueError):
    pass

def finite(v):
    return type(v) in (float, int) and math.isfinite(v)

def bounded_remaining(*, parent_remaining, pulse_remaining, PC_phase_elapsed, A_bracket_elapsed, transport_reserve=12):
    vals = (parent_remaining, pulse_remaining, PC_phase_elapsed, A_bracket_elapsed, transport_reserve)
    if not all((finite(v) for v in vals)) or not 0 < parent_remaining <= 1800 or (not 0 < pulse_remaining <= 1800) or (not 0 <= PC_phase_elapsed <= 20) or (not 0 <= A_bracket_elapsed <= 90) or (transport_reserve != 12):
        raise Refused('strict_actual_local_budget_inputs')
    left = min(parent_remaining, pulse_remaining - PC_phase_elapsed - A_bracket_elapsed) - transport_reserve
    if left <= 0:
        raise Refused('original_parent_or_grant_window_expired_no_extension')
    return left

def reserve_budget(parent_remaining, *, preparation_reserve=90):
    if not finite(parent_remaining) or not 0 < parent_remaining <= 1800 or preparation_reserve != 90:
        raise Refused('parent_window_missing_or_expired')
    value = math.floor(parent_remaining - preparation_reserve)
    if value <= 0:
        raise Refused('insufficient_original_window_no_reserve')
    return value
