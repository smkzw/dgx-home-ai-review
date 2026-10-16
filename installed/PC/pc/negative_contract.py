# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite typed negative history; no admission permission or current hold release."""
import re, stat
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, fresh
from B_OWNER_RECOVERY_R25_WIRING.collector import validate_clear, NODES, fresh_node_stamp
OPERATION = '30f3c284a90b32bcd05e0380b381bfb7'
CLEANUP = '94e1deb60b61f87a4ee05d1c77a8d5aa'
CAP = 4194304
PRIVATE_NAMES = frozenset({'intent.json', 'reserved.json', 'pulse-1.json'})
RUN_NAMES = frozenset({'intent.json', 'negative-released.json', 'maintenance-released.json'})

def f9(meta, raw=None, *, owner=0, gid=None, mode=None):
    need(type(meta) is list and len(meta) == 9 and all((type(x) is int for x in meta)), 'exact_integer_F9')
    need(stat.S_ISREG(meta[5]) and meta[3] == owner and (meta[6] == 1) and (not meta[5] & 18) and (0 <= meta[2] <= CAP), 'fixed_F9_leaf')
    if raw is not None:
        need(type(raw) is bytes and meta[2] == len(raw), 'full_raw_F9_size')
    if gid is not None:
        need(meta[4] == gid, 'exact_F9_group')
    if mode is not None:
        need(stat.S_IMODE(meta[5]) == mode, 'exact_F9_mode')
    return meta

def whole_clear(proof, config, now, *, fenced=True):
    need(type(proof) is dict and set(proof['nodes']) == set(NODES) == set(config['node_source_pins']), 'exact_whole_AB')
    need(proof['scheduler']['operator_maintenance'] is fenced, 'actual_expected_scheduler_fence')
    if fenced:
        validate_clear(proof, proof, config, now)
    else:
        fresh(proof['observed_at'], now, 30)
        fresh(proof['finished_at'], now, 30)
        for node, item in proof['nodes'].items():
            s = item['reply']['snapshot']
            r = s['record']
            gpu = s['gpu']
            data = s['container']['data'] or {}
            need((r['profile'], r['owner'], r['generation'], r['container_id']) == ('glm-ab', 'dgx-hx-service', 10, config['container_ids'][node]) and r['state'] == 'CLEAR' and (r['released_at'] is not None) and (r['released_at'] <= r['updated_at']), 'actual_released_NodeRecord')
            need(gpu['complete'] is True and gpu['truncated'] is False and (gpu['empty'] is True) and (gpu['processes'] == gpu['containers'] == []), 'released_whole_empty_GPU')
            need(s['container']['exists'] is False or (s['container']['exists'] is True and data.get('running') is False and (data.get('status') in ('created', 'exited', 'dead'))), 'released_container_inactive_known')
            guard = strict(s['guard_status']['raw_utf8'])
            state = strict(s['guard_state']['raw_utf8'])
            fresh_node_stamp(item, guard['observed_at'], now, 30)
            need(guard['state'] == 'IDLE_HOLD_RETAINED' and guard['reason_code'] == 'idle_db_clear' and (state['clear_authorized'] is True) and (state['last_record'] == {k: r[k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'released_at', 'updated_at')}), 'released_Guard_accepts_same_record')
    need(proof['core_profile']['profile'] == 'glm-ab' and proof['core_profile']['state'] == 'STOPPED' and (proof['core_profile']['owner'] is None) and (proof['core_profile']['generation'] == 10), 'historical_gen10_STOPPED_not_future_hold_release')
    rows = {v['node']: v for v in proof['core_nodes']}
    need(set(NODES) <= set(rows), 'Core_AB_present')
    for n in NODES:
        r = rows[n]
        need(r['hold_profile'] == r['hold_owner'] == r['hold_generation'] == None and r['quarantined'] is False, 'historical_noholds')
    for r in proof['scheduler']['profiles'].values():
        need(type(r['active']) is int and type(r['queued']) is int and (r['active'] == r['queued'] == 0) and (r['uncertain'] is False) and (r['draining'] is False), 'whole_scheduler_idle')
    need(proof['rows']['active_jobs'] == proof['rows']['active_requests'] == [] and proof['rows']['historical_terminal_uncertain_count'] == 9 and (proof['rows']['historical_terminal_uncertain_sha256'] == config['historical_terminal_uncertain_sha256']), 'immutable_history9_idle')
    need(set(proof['PC_source_files']) == set(config['PC_source_pins']) and len(proof['PC_source_files']) == 118 and (proof['lease_dev_inode'] == config['lease_dev_inode'] == [2096, 69257]), 'current_epoch118_and_physical_lease')
    for path, pin in config['PC_source_pins'].items():
        v = proof['PC_source_files'][path]
        need(v['sha256'] == pin, 'proof_current_PC_source')
        f9(v['stat'])
    for n, item in proof['nodes'].items():
        s = item['reply']['snapshot']
        need(item['reply']['status'] == 'ok' and item['reply']['readonly'] is True and (s['root_uid'] == 0) and (s['guard_process_verified'] is True), 'actual_Root_AB_snapshot')
        need(set(s['sources']) == set(config['node_source_pins'][n]) and len(s['sources']) == 9, 'actual_complete_AB9')
        for path, pin in config['node_source_pins'][n].items():
            v = s['sources'][path]
            need(v['path'] == path and v['sha256'] == pin, 'historical_AB9_source')
            f9(v['stat'])
        need(sha(s['record_utf8'].encode()) == s['record_sha256'] and strict(s['record_utf8']) == s['record'], 'historical_transactional_record_bytes')
        for key in ('guard_state', 'guard_status'):
            v = s[key]
            need(sha(v['raw_utf8'].encode()) == v['sha256'], 'historical_Guard_raw')
            f9(v['stat'], v['raw_utf8'].encode())
    return proof

def completed(outcome, marker, config, review, prerequisites_sha):
    need(type(review) is str and re.fullmatch('[0-9a-f]{64}', review), 'approved_negative_review_required')
    need(outcome['schema'] == 'MiMo-CPU-negative-release-completed/v1' and marker['schema'] == 'MiMo-CPU-negative-maintenance-released/v1', 'typed_negative_callback')
    for v in (outcome, marker):
        need(v['state'] == 'NEGATIVE_RELEASED' and v['operation'] == OPERATION and (v['cleanup_operation'] == CLEANUP) and (v['source_review_sha256'] == review), 'exact_negative_once_identity')
    need(outcome['config_sha256'] == config['_config_sha256'] and outcome['old_prerequisites_sha256'] == prerequisites_sha, 'negative_current_source_and_oldfacts')
    need(outcome['whole_CPU_accepted'] is False and marker['CPU_success'] is False and (outcome['automatic_retry'] is False) and (outcome['engine_launches'] == outcome['reservation_replays'] == outcome['deadline_extensions'] == outcome['model_commands'] == 0), 'negative_never_CPU_success_or_replay')
    need(marker['negative_released_sha256'] == sha(encode(outcome)) and marker['operator_maintenance_observed'] is False and (marker['finished_at'] >= outcome['finished_at']), 'durable_negative_completed_marker')
    whole_clear(outcome['before'], config, outcome['finished_at'])
    whole_clear(outcome['after'], config, outcome['finished_at'])
    validate_clear(outcome['after'], outcome['before'], config, outcome['finished_at'])
    need(outcome['before']['rows'] == outcome['after']['rows'] and outcome['before']['PC_source_files'] == outcome['after']['PC_source_files'] and (outcome['before']['lease_dev_inode'] == outcome['after']['lease_dev_inode']), 'callback_rows_source_lease_stable')
    return outcome
