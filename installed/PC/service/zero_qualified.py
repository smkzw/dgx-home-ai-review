# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""New explicit zero-launch Root certificate; same existing PC whole30 clocks."""
import math
from plan import need, strict, encode
from root_io import sha
from receipt_codec import unpack
import zero_negative as negative
import zero_scope
import not_launched_history as zero_history
APPROVED_REVIEW = None
APPROVED_ROOT = None
APPROVED_POLICY = None

def consume(qualified_raw, qualified_stat, A_history_raw, PC_history_raw, current, now):
    need(APPROVED_REVIEW is not None and APPROVED_ROOT is not None, 'not_launched_PC_final_SOURCE_pending')
    need(qualified_stat[2] == len(qualified_raw) and qualified_stat[3:7] == [0, 989, 33056, 1], 'not_launched_PC_Root_shared_original')
    v = strict(qualified_raw)
    need(set(v) == {'schema', 'review_sha256', 'begin', 'finish', 'A_proof', 'current'} and v['schema'] == 'stage-not-launched-PC-qualified/v1' and (v['review_sha256'] == APPROVED_REVIEW) and (v['current'] == current), 'not_launched_current_new_source_not_history')
    p = APPROVED_POLICY
    pc_raw, a_raw, s_raw = zero_history.histories()
    need(pc_raw == PC_history_raw and a_raw == A_history_raw, 'zero_launch_exact_history_arguments')
    h = zero_history.history(pc_raw, a_raw, s_raw)
    old = {'actor': h['PC'], 'deadline_monotonic': h['original_deadline'], 'stage_operation': h['stage_operation']}
    outer = strict(unpack(v['A_proof']))
    proof = zero_scope.validate(outer, A_history_raw, current)
    a = negative.validate(proof, A_history_raw, current)
    request = negative.original(proof['request_original'])
    r = negative.checked_request(request, current)
    begin = strict(negative.original(v['begin'], (0, 989, 33056, 1)))
    finish = strict(negative.original(v['finish'], (0, 989, 33056, 1)))
    need(set(begin) == {'schema', 'request_sha256', 'request_nonce', 'current', 'PC_boot_id', 'PC_sent_at', 'PC_monotonic'} and set(finish) == {'schema', 'begin_sha256', 'request_sha256', 'A_proof_sha256', 'current', 'PC_boot_id', 'PC_received_at', 'PC_monotonic'}, 'not_launched_full_PC_clock_originals')
    need(begin['schema'] == 'stage-not-launched-PC-BEGIN/v1' and finish['schema'] == 'stage-not-launched-PC-finish/v1' and (begin['request_sha256'] == finish['request_sha256'] == sha(request)) and (begin['request_nonce'] == r['nonce']) and (finish['begin_sha256'] == v['begin']['sha256']) and (finish['A_proof_sha256'] == sha(encode(v['A_proof']))), 'not_launched_PC_nonce_clock_chain')
    need(begin['current'] == finish['current'] == r['current'] == current and current['review_sha256'] == APPROVED_REVIEW and (len(current['source118']) == 118) and (begin['PC_boot_id'] == finish['PC_boot_id'] == current['manager_identity']['boot_id']), 'not_launched_current_full118_epoch')
    nums = (begin['PC_sent_at'], begin['PC_monotonic'], finish['PC_received_at'], finish['PC_monotonic'], now)
    need(all((type(x) in (int, float) and math.isfinite(x) for x in nums)) and 0 <= finish['PC_monotonic'] - begin['PC_monotonic'] <= 30 and (0 <= finish['PC_received_at'] - begin['PC_sent_at'] <= 30) and (0 <= now - finish['PC_received_at']) and (now - begin['PC_sent_at'] <= 30), 'not_launched_PC_single_domain_whole30')
    return dict(a, schema='fixed-image-not-launched-stage-terminal/v1', state=zero_history.STATE, proof_sha256=sha(qualified_raw), history_actor=old, plan_sha256=sha(encode(h['plan'])), history_refs={k: p[k] for k in ('PC_history_sha256', 'A_history_sha256', 'A_sources_sha256')}, aggregate_exit_status=None, context_initial_intent_cleanup=None, original_deadline_monotonic=old['deadline_monotonic'], work_deadline_extended=False)
