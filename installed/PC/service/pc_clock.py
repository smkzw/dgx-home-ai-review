# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed PC same-host clock component. Future publisher binds all None slots.
Root reader/writer are the existing protected functions, not arbitrary programs.
"""
import math
from plan import need, strict, encode
from root_io import sha
from receipt_codec import pack
import prelaunch_negative as negative
APPROVED_REVIEW = 'fb52ebe2e7c3f848322472e451fef05255dc045cd81c0aac0d0372d2000eab62'

def begin(request_raw, PC_sent_at, PC_monotonic, current):
    r = negative.checked_request(request_raw, current)
    need(APPROVED_REVIEW is not None and r['current'] == current and (current['review_sha256'] == APPROVED_REVIEW), 'not_launched_clock_current_SOURCE_pending')
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (PC_sent_at, PC_monotonic))), 'not_launched_real_PC_clock')
    return {'schema': 'stage-not-launched-PC-BEGIN/v1', 'request_sha256': sha(request_raw), 'request_nonce': r['nonce'], 'current': current, 'PC_boot_id': current['manager_identity']['boot_id'], 'PC_sent_at': PC_sent_at, 'PC_monotonic': PC_monotonic}

def finish(begin_raw, A_raw, A_history_raw, PC_received_at, PC_monotonic, current):
    b = strict(begin_raw)
    need(b['current'] == current, 'not_launched_finish_same_current')
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (PC_received_at, PC_monotonic))) and 0 <= PC_received_at - b['PC_sent_at'] <= 30 and (0 <= PC_monotonic - b['PC_monotonic'] <= 30), 'not_launched_no_extended_PC_whole30')
    a = strict(A_raw)
    negative.validate(a, A_history_raw, current)
    request = negative.original(a['request_original'])
    need(sha(request) == b['request_sha256'] and negative.checked_request(request, current)['nonce'] == b['request_nonce'], 'not_launched_finish_actual_same_request')
    compact = pack(A_raw)
    return ({'schema': 'stage-not-launched-PC-finish/v1', 'begin_sha256': sha(begin_raw), 'request_sha256': sha(request), 'A_proof_sha256': sha(encode(compact)), 'current': current, 'PC_boot_id': current['manager_identity']['boot_id'], 'PC_received_at': PC_received_at, 'PC_monotonic': PC_monotonic}, compact)
