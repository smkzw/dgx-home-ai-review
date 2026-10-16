# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same-PC/sameboot deadline kernel. No authorization or clock acquisition here."""
import math

class ClockRefused(ValueError):
    pass

def number(value):
    return type(value) in (int, float) and math.isfinite(value)

def require(value, reason):
    if not value:
        raise ClockRefused(reason)

def check(begin, permit, boot, monotonic_now, wall_now):
    require(type(begin) is dict and type(permit) is dict, 'owner_clock_complete_objects')
    require(begin['PC_boot_id'] == boot == permit['PC_boot_id'], 'owner_clock_same_boot')
    sent = begin['PC_monotonic_sent']
    origin, end = (permit['PC_monotonic_origin'], permit['PC_deadline_monotonic'])
    seconds = permit['duration_seconds']
    require(all((number(v) for v in (sent, origin, end, monotonic_now, wall_now, begin['PC_sent_at'], permit['PC_issued_at']))), 'owner_clock_finite_original_domain')
    require(type(seconds) is int and 1 <= seconds <= 120 and (end == origin + seconds), 'owner_clock_original_permit_formula')
    require(origin <= sent <= monotonic_now < end, 'owner_clock_original_permit_monotonic')
    elapsed = monotonic_now - sent
    require(elapsed <= 30, 'owner_clock_original_BEGIN_whole30')
    wall_elapsed = wall_now - begin['PC_sent_at']
    require(0 <= wall_now - permit['PC_issued_at'] <= seconds and wall_elapsed >= 0 and (abs(wall_elapsed - elapsed) <= 5), 'owner_clock_wall_audit_drift')
    return {'PC_boot_id': boot, 'PC_monotonic_sent': sent, 'PC_monotonic_observed': monotonic_now, 'PC_monotonic_elapsed': elapsed, 'PC_wall_observed': wall_now, 'PC_whole30_remaining': 30 - elapsed, 'permit_deadline_monotonic': end}
