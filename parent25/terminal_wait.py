# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Read-only bounded wait before sending any one-time terminal phase."""
import time, re
from plan import need

def wait(io, stage, end):
    unit = 'dgx-v4-image-segment-' + stage + '.service'
    while True:
        need(time.monotonic() < end, 'stage_cleanup_quiescence90_expired_sticky')
        v = io.cleanup_rpc('a', 'asset-observe', {'stage_operation': stage}, end)
        if v.get('pending') is True:
            need(set(v) == {'pending'}, 'stage_cleanup_known_pending_only')
            time.sleep(min(0.1, max(0, end - time.monotonic())))
            continue
        need(set(v) == {'pending', 'actual_unit_original'} and v['pending'] is False, 'stage_cleanup_positive_unit_original_required')
        u = dict((x.split('=', 1) for x in v['actual_unit_original'].splitlines()))
        need(u['Id'] == unit and u['LoadState'] == 'loaded' and (u['MainPID'] == '0') and (int(u['ExecMainPID']) > 1) and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] in ('0', '1')) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (u['ExecMainStatus'] == '0' and u['ActiveState'] == 'active' and (u['SubState'] == 'exited') or (u['ExecMainStatus'] == '1' and u['ActiveState'] == 'failed')), 'stage_cleanup_notfound_or_unknown_not_terminal')
        return v
