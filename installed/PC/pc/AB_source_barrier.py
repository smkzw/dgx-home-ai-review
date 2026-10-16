# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite authenticated SOURCE handoff after normal old EXIT0; no SSH here."""
import os, re, secrets, time
from pathlib import Path
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
REQUEST = PC_ROOT / 'AB-current-idle-source-request.json'
RESPONSE = PC_ROOT / 'AB-current-idle-source-handoff.json'

def await_source(native, p, before, end):
    need(native.holders() == [native.pid()] and native.stopped_mode and (time.monotonic() < end), 'old_EXIT0_and_owned_lease_before_AB_source')
    nonce = secrets.token_hex(16)
    issued = native.wall()
    deadline = min(end, time.monotonic() + 120)
    request = {'schema': 'AB-current-idle-source-request-R26-R6/v1', 'operation': EPOCH_OPERATION, 'request_nonce': nonce, 'review_sha256': APPROVED_REVIEW, 'installer_pid': native.pid(), 'installer_invocation_id': os.environ.get('INVOCATION_ID'), 'old_identity': before['manager_identity'], 'new_node_source_pins': strict(p['new_config_raw_utf8'])['node_source_pins'], 'issued_at': issued, 'timeout_seconds': 120, 'automatic_retry': False}
    need(re.fullmatch('[0-9a-f]{32}', request['installer_invocation_id']) is not None, 'actual_same_root_worker_invocation')
    native.current.io.fresh(REQUEST, encode(request), mode=288, gid=989)
    while not RESPONSE.exists():
        need(time.monotonic() < deadline and native.holders() == [native.pid()], 'bounded_source_handoff_timeout_hold_preserved')
        time.sleep(0.1)
    raw, st = protected_read(RESPONSE, limit=4194304)
    r = strict(raw)
    need(st[3:7] == [0, 989, 33056, 1] and r['schema'] == 'AB-current-idle-source-handoff-R26-R6/v1' and (r['request_sha256'] == sha(encode(request))) and (r['request_nonce'] == nonce) and (r['operation'] == EPOCH_OPERATION) and (r['review_sha256'] == APPROVED_REVIEW), 'exact_protected_parent_source_handoff')
    need(issued <= r['observed_at'] <= native.wall() and set(r['nodes']) == {'spark-a', 'spark-b'}, 'actual_source_handoff_timestamp_AB')
    for node, v in r['nodes'].items():
        receipt_raw = v['install_completed_utf8'].encode()
        receipt = strict(receipt_raw)
        need(sha(receipt_raw) == v['install_completed_sha256'] and v['install_completed_stat']['st_uid'] == 0 and (v['install_completed_stat']['st_nlink'] == 1), 'actual_singleleaf_install_root_original')
        need(receipt['schema'] == 'AB-current-idle-snapshot-wrapper-R26-R6-installed/v1' and receipt['node'] == node and (receipt['old_sha'] == strict(p['old_config_raw_utf8'])['node_source_pins'][node]['/opt/dgx-v4/runtime/node_adapter/node_wrapper.py']) and (receipt['new_sha'] == request['new_node_source_pins'][node]['/opt/dgx-v4/runtime/node_adapter/node_wrapper.py']) and (receipt['other8_exact_unchanged'] is True) and (receipt['guard_restarts'] == receipt['models_started_or_stopped'] == 0), 'exact_original_ef48_newreadonly_only_CAS')
        need(set(v['current9']) == set(request['new_node_source_pins'][node]), 'actual_complete_root9_after_CAS')
        for path, pin in request['new_node_source_pins'][node].items():
            item = v['current9'][path]
            need(item['sha256'] == pin and len(item['stat']) == 9 and (item['stat'][3] == 0) and (item['stat'][6] == 1) and (not item['stat'][5] & 18), 'postCAS_current_actual_source_F9')
        need(v['record_before'] == v['record_after'] and v['GuardPID_before'] == v['GuardPID_after'] and (v['Guard_session_before'] == v['Guard_session_after']), 'no_NodeDB_or_Guard_mutation')
    need(protected_read(RESPONSE, limit=4194304) == (raw, st) and native.holders() == [native.pid()] and (time.monotonic() < end), 'same_protected_actual_handoff_final')
    return {'sha256': sha(raw), 'stat': st, 'observed_at': r['observed_at'], 'new_node_source_pins': request['new_node_source_pins']}
