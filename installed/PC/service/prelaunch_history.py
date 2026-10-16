# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Read-only PRELAUNCH candidate. No installed API and no maintenance mutation.

A candidate is NOT a permit. New source/epoch integration still must qualify
its actual new PID and C16, then own the real shared lock. Defaults hard-deny.
"""
from pathlib import Path
from proc_lifetime import validate as validate_proc_lifetime
from old_failed_kernel import validate_failed_kernel
import base64, hashlib, json, math, re, stat
APPROVED_POLICY_SHA256 = 'a34013d0240718a6f188682c9da36dbcff88ba48f0d5ce8179da6fd821a4f0f4'
SCHEMA = 'registry-R26-FAILED_REGISTRY_QUIESCENT-candidate/v1'
APPROVED_FAILED_A_MIRROR = '/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3/failed-registry-A-originals.json'
APPROVED_FAILED_A_SHA = '45307dc39e5de33d6a9f632312eb65e78bd1ba13e44a8fe9dbe164fc02bb0005'

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):
    need(type(raw) is bytes and len(raw) <= 16 * 1024 ** 2, 'bounded_original_bytes')

    def pairs(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate_key')
            d[k] = v
        return d
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_json'))
    encode(v)
    return v

def identity(v):
    need(type(v) is dict and set(v) == {'pid', 'start_ticks', 'boot_id', 'invocation_id'} and (type(v['pid']) is int) and (v['pid'] > 1) and (type(v['start_ticks']) is str) and re.fullmatch('[1-9][0-9]*', v['start_ticks']) and (type(v['boot_id']) is str) and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', v['boot_id']) and (type(v['invocation_id']) is str) and re.fullmatch('[0-9a-f]{32}', v['invocation_id']), 'strict_actual_process_identity')
    return v

def original(item, *, uid, gid, mode):
    need(type(item) is dict and set(item) == {'raw_b64', 'sha256', 'F9'}, 'exact_raw_F9_envelope')
    raw = base64.b64decode(item['raw_b64'], validate=True)
    s = item['F9']
    need(base64.b64encode(raw).decode() == item['raw_b64'] and sha(raw) == item['sha256'], 'whole_original_SHA')
    need(type(s) is list and len(s) == 9 and all((type(x) is int for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[2] == len(raw)) and (s[3:7] == [uid, gid, stat.S_IFREG | mode, 1]) and (s[7] > 0) and (s[8] > 0), 'exact_original_full_F9')
    return strict(raw)

def policy(raw):
    need(APPROVED_POLICY_SHA256 is not None and sha(raw) == APPROVED_POLICY_SHA256, 'reviewed_failed_registry_policy_pending')
    p = strict(raw)
    identity(p['manager_identity'])
    need(p['schema'] == 'FAILED-REGISTRY-recovery-historical-policy/v1' and len(p['current_source118']) == 118 and (len(p['Root65']) == 77) and (len(p['A34']) == 34) and (p['operation'] == 'cec7372f18000da32e5060c7fa7e67f7') and (p['last_pulse_ordinal'] == 28), 'fixed_failed_registry_source_closure')
    return p

def partial(records, p):
    need(type(records) is dict, 'full_actual_registry_records_required')
    expected = {'intent.json', 'reserved.json'} | {'pulse-' + str(k) + '.json' for k in range(1, p['last_pulse_ordinal'] + 1)}
    need(set(records) == set(p['records']) == expected, 'all_actual_failed_registry_originals_no_terminal_or_gap')
    rows = {}
    refs = {}
    for name, item in records.items():
        need({k: item[k] for k in ('sha256', 'F9')} == {k: p['records'][name][k] for k in ('sha256', 'F9')}, 'failed_registry_exact_raw_F9_pin')
        rows[name] = original({k: item[k] for k in ('raw_b64', 'sha256', 'F9')}, uid=999, gid=989, mode=384)
        refs[name] = p['records'][name]
    i, r = (rows['intent.json'], rows['reserved.json'])
    need(i['schema'] == 'registry-new-CPU-once-intent/v1' and i['automatic_retry'] is False and (i['old_bf84_replayed'] is False) and (type(i['duration_seconds']) is int) and (i['duration_seconds'] == p['duration_seconds'] == 1698) and (i['budget'] == r['budget']) and (i['deadline_monotonic'] == r['deadline_monotonic'] == p['deadline_monotonic']), 'actual_original_deadline_never_extended')
    need(i['before_sha256'] == sha(encode(r['before'])) and i['issued_at'] <= r['observed_at'] and (r['before']['scheduler']['operator_maintenance'] is False) and (r['after']['scheduler']['operator_maintenance'] is True), 'actual_original_reservation_causal_fence')
    for row in rows.values():
        need(row['operation'] == p['operation'] and row['source_release_sha256'] == p['source_release_sha256'], 'original_operation_source_not_new_recovery')
    last = r['observed_at']
    remaining = i['duration_seconds']
    for k in range(1, p['last_pulse_ordinal'] + 1):
        v = rows['pulse-' + str(k) + '.json']
        need(v['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and type(v['ordinal']) is int and (v['ordinal'] == k) and (v['clear_reservation_original'] == r['after']) and (v['clear_reservation_sha256'] == sha(encode(r['after']))) and (v['budget'] == i['budget']) and (v['config_sha256'] == p['config_sha256']) and (v['manager_epoch_sha256'] == sha(encode(p['current_source118']))), 'complete_original_pulse_ordinal_source_binding')
        need(type(v['remaining_seconds']) in (int, float) and math.isfinite(v['remaining_seconds']) and (last <= v['observed_at']) and (0 < v['remaining_seconds'] < remaining), 'original_pulse_time_order_no_retime')
        last = v['observed_at']
        remaining = v['remaining_seconds']
    return {'records': refs, 'intent_sha256': records['intent.json']['sha256'], 'last_pulse_ordinal': p['last_pulse_ordinal'], 'old_deadline_monotonic': i['deadline_monotonic'], 'old_duration_seconds': i['duration_seconds'], 'finished': False}

def historical_entry(records, p, modules):
    need(set(records) == set(p['A_records']) == {'entry-qualified.json'}, 'exact_historical_A_entry')
    for n, item in records.items():
        need({k: item[k] for k in ('sha256', 'F9')} == p['A_records'][n], 'historical_entry_raw_F9_pin')
    body = original(records['entry-qualified.json'], uid=0, gid=0, mode=384)
    response = p['entry_response_original']
    need(body['schema'] == 'registry-R26-A-entry-qualified/v1' and body['operation'] == p['operation'] and (body['manager_identity'] == p['manager_identity']) and (body['current_PC_source118'] == p['current_source118']) and (body['PC_config_sha256'] == p['config_sha256']) and (type(body['models_started']) is int) and (body['models_started'] == 0), 'historical_real_A_entry_not_fresh_permission')
    need(response['entry_sha256'] == records['entry-qualified.json']['sha256'] and base64.b64decode(response['entry_raw_b64'], validate=True) == base64.b64decode(records['entry-qualified.json']['raw_b64'], validate=True), 'whole_original_entry_clock_not_republished')
    modules['observer'].positive(body['actual_readonly_scope'], body['actual_readonly_scope']['unit']['Id'], body['readonly_worker_sha256'], True)
    modules['entry_clock'].stop_check(response, body)
    return body

def sources(rows, expected):
    need(set(rows) == set(expected), 'complete_source_set')
    for name, pin in expected.items():
        actual = rows[name]
        s = actual['F9']
        need(actual == pin and type(s) is list and (len(s) == 9) and all((type(x) is int for x in s)) and (s[3] == 0) and (s[6] == 1) and stat.S_ISREG(s[5]) and (not s[5] & 18), 'current_same_source_SHA_and_fullF9')

def validate(observation, praw, config, now, modules, actual_records=None):
    p = policy(praw)
    need(type(now) in (int, float) and math.isfinite(now), 'finite_current_PC_now')
    need(set(observation) == {'schema', 'request_nonce', 'PC_started_at', 'PC_finished_at', 'PC_monotonic_elapsed', 'PC', 'A'} and observation['schema'] == 'registry-prelaunch-readonly-observation/v1', 'exact_readonly_observation')
    need(type(observation['request_nonce']) is str and re.fullmatch('[0-9a-f]{32}', observation['request_nonce']), 'new_readonly_nonce')
    start, end, elapsed = (observation[k] for k in ('PC_started_at', 'PC_finished_at', 'PC_monotonic_elapsed'))
    need(all((type(v) in (int, float) and math.isfinite(v) for v in (start, end, elapsed))) and 0 <= end - start <= 30 and (0 <= elapsed <= 30) and (abs(end - start - elapsed) <= config['max_clock_skew_seconds']) and (0 <= now - end) and (elapsed + now - end <= 30), 'whole_PC_current_readonly30_no_retime')
    pc, a = (observation['PC'], observation['A'])
    identity(pc['manager_identity'])
    identity(config['_manager_identity'])
    checked = partial(actual_records, p)
    need(pc['records'] == checked, 'physical_full_old_registry_consumed_not_hash_assertion')
    historical_entry(a['records'], p, modules)
    failed_A(a, p)
    live = p.get('live_current', p)
    need(config['_config_sha256'] == live['config_sha256'] and config['PC_source_pins'] == live['current_source118'] and (config['_manager_identity'] == live['manager_identity']), 'actual_live_old_owner_source')
    need(pc['manager_identity'] == live['manager_identity'] and pc['lease_full_F9'] == live['lease_full_F9'] and (pc['Cleaf'] == live['Cleaf']), 'actual_same_lease_Cleaf')
    sources(pc['Root65'], p['Root65'])
    sources(a['A34'], p['A34'])
    reply = strict(base64.b64decode(pc['status_raw_b64'], validate=True))
    need(reply['ok'] is True, 'original_private_status_positive')
    r = reply['result']
    need(r['schema'] == 'registry-R26-source-current-status/v1' and r['operation'] == p.get('live_operation', p['operation']) and (r['request_nonce'] == observation['request_nonce']) and (r['manager_pid'] == live['manager_identity']['pid']) and (r['source118'] == live['current_source118']) and (r['models_started'] == 0) and (start <= r['observed_at'] <= end), 'current_same_private_request_owner')
    reserved = original({k: actual_records['reserved.json'][k] for k in ('raw_b64', 'sha256', 'F9')}, uid=999, gid=989, mode=384)
    modules['live_idle'].validate_live_idle(r['current'], config, now, fenced=p.get('live_fenced', True))
    return {'schema': SCHEMA, 'state': 'FAILED_REGISTRY_QUIESCENT', 'CPU_success': False, 'image_imported': False, 'models_started': 0, 'operation': p['operation'], 'original_parent_cutoff': p['parent_cutoff'], 'old_manager_identity': p['manager_identity'], 'original_partial': checked, 'observation_sha256': sha(encode(observation)), 'requires_reviewed_new_epoch': True, 'native_eligible': False, 'unique_original_first_cause': 'unknown', 'observed_at': end}

def validate_failed_close(unit_raw, journal_raw, old_identity):
    from prelaunch_stop import classify, LOGGER_SHA
    return classify(unit_raw, journal_raw, old_identity, LOGGER_SHA)

def failed_A_originals(read):
    need(APPROVED_FAILED_A_MIRROR is not None and APPROVED_FAILED_A_SHA is not None, 'failed_A_historical_source_pending')
    raw, st = read(Path(APPROVED_FAILED_A_MIRROR), limit=2097152)
    need(sha(raw) == APPROVED_FAILED_A_SHA and st[3:7] == [0, 989, 33056, 1], 'failed_A_exact_Root_mirror_original')
    return strict(raw)

def failed_A(a, p):
    need(a['failed_file_refs'] == p['A_failed_records'] and a['cleanup_ref'] == p['A_cleanup'] and (a['A34'] == p['A34']), 'exact_immutable_failed_A_raw_F9_rechecked')
    saved = p['A_failed_unit']
    u = saved['unit']
    need(sha(saved['raw_utf8'].encode()) == saved['sha256'] and dict((x.split('=', 1) for x in saved['raw_utf8'].splitlines())) == u, 'historical_retained_failed_unit_fullraw')
    need(u['Id'] == p['aggregate_unit'] and u['ExecMainPID'] == '3235350' and (u['InvocationID'] == 'feb7f3e60256481b09f0674c64ea2e35') and (u['MainPID'] == '0') and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'failed') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '1'), 'actual_A_EXIT1_preserved_never_success')
    validate_proc_lifetime(a['process_scan'], Path(p['A_root']))
    need(set(a['no_engine_paths']) == {p['A_data'] + '/' + n for n in ('containerd.sock', 'containerd.toml', 'private-config-validated.json', 'returned-zero.json', 'initialized-registry.raw')} and all((v == {'exists': False, 'is_symlink': False} for v in a['no_engine_paths'].values())), 'actual_no_daemon_import_outputs')
    need(set(a['empty_private_dirs']) == {'containerd-data', 'containerd-exec', 'private-opt', 'private-overlay'} and all((v['entries'] == [] and v['stat'][3:6] == [0, 0, 16832] for v in a['empty_private_dirs'].values())), 'actual_private_daemon_storage_empty')
    need(a['old_worker_kernel']['PID_absence'] == {'path': '/proc/REDACTED_PID', 'errno': 2} and a['old_worker_kernel']['unit'] == p['aggregate_unit'] and (a['old_worker_kernel']['cgroup_state'] in ('absent', 'present-empty')), 'actual_new_kernel_dead_old_failed_worker')
    need(a['payload_entries'] == p['A_payload_entries'] and a['blob_metadata'] == p['A_blob_metadata'], 'partial_assets_preserved_not_whole_blob_count')
    validate_failed_kernel(a['old_worker_kernel'], p['aggregate_unit'], 3235350, saved['boot_id'], a['started_at'])
    return a

def consume_failed_A_history(read, p):
    saved = failed_A_originals(read)
    old = saved['terminal']
    cleanup = saved['cleanup']
    need(old['unit'] == p['A_failed_unit']['unit'] and old['unit_raw_utf8'] == p['A_failed_unit']['raw_utf8'] and (old['unit_raw_sha256'] == p['A_failed_unit']['sha256']) and (old['boot_id'] == p['A_failed_unit']['boot_id']), 'exact_old_A_failed_unit_source_original')
    for name, row in old['originals'].items():
        raw = base64.b64decode(row['raw_b64'], validate=True)
        need(sha(raw) == row['sha256'] and row['F9'][2] == len(raw) and (row['F9'][3:7] == [0, 0, 33152, 1]) and ({k: row[k] for k in ('sha256', 'F9')} == p['A_failed_records'][name]), 'whole_old_A_failure_raw_F9_not_count')
    failed = original(old['originals']['failed.json'], uid=0, gid=0, mode=384)
    need(failed['phase'] == 'registry.download' and failed['schema'] == 'registry-R26-A-owned-phase-failed-preserved/v1' and (failed['operation'] == p['operation']) and (failed['automatic_retry'] is False) and (failed['partial_preserved'] is True), 'actual_pre_daemon_failed_phase_unknown_first_RPC_cause')
    need({k: cleanup[k] for k in ('sha256', 'F9')} == p['A_cleanup'], 'full_owned_cleanup_original_reference')
    c = original({k: cleanup[k] for k in ('raw_b64', 'sha256', 'F9')}, uid=0, gid=0, mode=384)
    k = c['kernel_after_cleanup']
    need(c['all_owned_children_exited'] is True and c['force_kill'] == c['global_signals'] == 0 and (len(k['processes']) == 1) and (k['processes'][0]['pid'] == 3235350) and (k['processes'][0]['starttick'] == '33789440') and (k['processes'][0]['argv'] == ['/usr/bin/python3', '-I', '-B', p['A_root'] + '/root_worker.py']), 'actual_cleanup_only_original_supervisor_no_fake_success')
    need(old['fixed_cgroup_exists'] is old['old_worker_PID_exists'] is False and old['whole_cgroup_procs'] == [], 'actual_saved_terminal_PIDgone_fullCGempty')
    return {'old_state': 'FAILED_REGISTRY_PRESERVED', 'old_actual_EXIT1': True, 'CPU_success': False, 'image_imported': False, 'specific_first_RPC_cause': 'unknown', 'old_cleanup_sha256': cleanup['sha256']}
