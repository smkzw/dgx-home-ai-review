# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Only unattempted aggregate-start failures may seek a typed no-launch close.
The actual collector still refuses context/worker/payload/unknown prior state.
This is a normal failure outcome, never a successful image-stage result.
"""
import base64
import json
import re
import time
import uuid
from emission import need, sha, encode, run_readonly, EPOCH, SOURCE_EPOCH
import late_rpc

def result(wrapper):
    need(type(wrapper) is dict and set(wrapper) == {'original_reply_raw_b64', 'original_reply_sha256', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed'}, 'actual_full_private_reply_wrapper')
    raw = base64.b64decode(wrapper['original_reply_raw_b64'], validate=True)
    need(sha(raw) == wrapper['original_reply_sha256'], 'actual_private_reply_original_SHA')
    body = json.loads(raw)
    need(set(body) == {'ok', 'result'} and body['ok'] is True, 'actual_listener_result_not_transport_rc')
    return body['result']

def source_policy(emitted, A_original):
    """Derive from actual complete source-origin, not future F9 or caller flags."""
    need(type(A_original) is dict and set(A_original) == {'raw_b64', 'sha256', 'F9'}, 'actual_A_origin_original')
    raw = base64.b64decode(A_original['raw_b64'], validate=True)
    f = A_original['F9']
    need(sha(raw) == A_original['sha256'] and f[2] == len(raw) and (f[3:7] == [0, 0, 33152, 1]), 'actual_A_origin_envelope_F9')
    v = json.loads(raw)
    graph = emitted.graph
    fixed = graph['readonly_scope']['slots']['APPROVED_A_ORIGIN']
    need(set(v) == {'schema', 'source_root', 'source_epoch', 'review_sha256', 'files', 'boot_original'} and v['schema'] == 'R12-A-source-held-original/v1' and (v['source_root'] == fixed['source_root']) and (v['source_epoch'] == SOURCE_EPOCH) and (v['review_sha256'] == graph['packet']['review_sha256']) and (set(v['files']) == set(fixed['source_pins'])), 'actual_full_A_source_domain')
    for name, row in v['files'].items():
        s = row['F9']
        need(set(row) == {'sha256', 'F9'} and row['sha256'] == fixed['source_pins'][name] and (len(s) == 9) and (s[2] == fixed['source_sizes'][name]) and (s[3:7] == [0, 0, 33152, 1]), 'actual_all_A_source_SHA_F9')
    boot = v['boot_original']
    b = base64.b64decode(boot['raw_b64'], validate=True)
    need(set(boot) == {'raw_b64', 'sha256', 'F9'} and sha(b) == boot['sha256'] and (len(b) == 37) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\n', b.decode()) and (boot['F9'][2] == 0) and (boot['F9'][3] == 0) and (boot['F9'][6] == 1), 'actual_A_kernel_boot_original')
    return {'source_root': fixed['source_root'], 'data_root': fixed['data_root'], 'sources': v['files'], 'index_sha256': fixed['index_sha256'], 'ready_worker_sha256': fixed['ready_worker_sha256'], 'boot_id': b.decode().strip()}

def close(once, emitted, RPC_original, A_original, stage, attempted, *, deadline, tag):
    """Called once by the original failed stage, before any terminal retry.
    `deadline` is the caller's original cleanup_end, never created or extended here.
    `attempted` includes all emitted phases, even if their reply was lost.
    """
    need(re.fullmatch('[0-9a-f]{32}', stage) is not None and stage != 'd8d0f06cc54a807f320d03813daf3b4b', 'new_stage_not_spent_old_stage')
    forbidden = {'asset-start', 'begin-asset-terminal-clock', 'asset-finalize', 'publish-asset-terminal', 'finish-asset-stage', 'finish-failed-asset-stage', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage'}
    need(not set(attempted).intersection(forbidden), 'no_retry_of_emitted_start_or_terminal')
    need(time.monotonic() < deadline, 'original_cleanup_budget_no_extension')

    def call(action):
        need(time.monotonic() < deadline, 'original_cleanup_budget_no_extension')
        attempted.add(action)
        code = late_rpc.command(emitted.graph, RPC_original, action, uuid.uuid4().hex, {'stage_operation': stage})
        return result(once.actual(tag + '-' + action, code, timeout=min(30, deadline - time.monotonic())))
    prepared = call('prepare-not-launched-asset-stage')
    need(set(prepared) == {'request', 'actor', 'clock_started', 'work_may_resume'} and prepared['clock_started'] is False and (prepared['work_may_resume'] is False), 'actual_internal_prepare_result')
    actor = prepared['actor']
    need(actor['stage_operation'] == prepared['request']['stage_operation'] == prepared['request']['nonce'] == stage and actor['schema'] == 'current-stage-prebind-actor/v2', 'actual_internal_stage_nonce_actor')
    plan = emitted.readonly_plan('current-stage-prebind', actor['current'], stage, encode(actor), current_policy=source_policy(emitted, A_original))
    run_readonly(once, emitted, plan, tag=tag + '-readonly', deadline=deadline)
    done = call('finish-not-launched-asset-stage')
    need(done['schema'] == 'current-stage-not-launched-completed/v1' and done['stage_operation'] == stage and (done['work_deadline_extended'] is done['image_imported'] is done['CPU_success'] is False) and (done['models_started'] == 0), 'typed_not_launched_failure_not_success')
    return done
