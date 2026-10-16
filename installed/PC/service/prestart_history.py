# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact completed NOT_LAUNCHED release history; never a new work permit.

An absent recovery root means pending. A present partial or unknown recovery
root refuses startup rather than releasing maintenance. Completed history is
consumed using its original event time, not the current wall clock.
"""
import math, re
from pathlib import Path
from contract import need, strict, sha, encode
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
import pc_recovery
from legacy_actor import held_actor

def originals(read=protected_read):
    p = pc_recovery.APPROVED_POLICY
    need(type(p) is dict, 'prestart_history_SOURCE_pending')
    for name, row in p['PC_Root97'].items():
        raw, f9 = read(Path(p['PC_Root_root']) / name, limit=2097152)
        need(sha(raw) == row['sha256'] and f9 == row['F9'], 'prestart_history_original_Root97')
    for name, row in p['PC_Root_originals'].items():
        raw, f9 = read(Path(p['PC_Root_root']) / name, limit=2097152)
        need(sha(raw) == row['sha256'] and f9 == row['F9'], 'prestart_history_original_dynamic_Root')
    expected = dict(p['actor'], files=p['actor_files'])
    return held_actor(Path(expected['path']), expected=expected)

def pending_originals(read=protected_read):
    decoded, packed = pc_recovery.packed_histories(read, Path(pc_recovery.APPROVED_ROOT))
    old = pc_recovery.history(decoded['PC'])
    need(originals(read) == old['actor'], 'prestart_history_pending_actor_original')
    return {'history': old, 'packed_originals': packed}

def consume_released(config, read=protected_read):
    import ffc2_history
    return ffc2_history.consume_released(config, read)
