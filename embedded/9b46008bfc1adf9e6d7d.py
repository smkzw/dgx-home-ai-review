# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure current-source checks; never an ARM/launch authority."""
import base64, hashlib, json, math, re
from pathlib import Path
HERE = Path(__file__).resolve().parent
A = json.loads((HERE / 'ANCHORS.json').read_bytes())

class Refused(ValueError):
    pass

def need(v, k):
    if not v:
        raise Refused(k)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def strict(raw):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_JSON')
            d[k] = v
        return d
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_JSON'))
    json.dumps(v, allow_nan=False)
    return v

def fresh(stamp, now, age=300):
    need(type(stamp) in (int, float) and math.isfinite(stamp) and (0 <= now - stamp <= age), 'fresh_original_stamp')

def pc(v, now):
    fresh(v['observed_at'], now)
    fresh(v['finished_at'], now)
    p = A['PC']
    need(v['PID'] == p['manager_identity']['pid'] and v['start_ticks'] == p['manager_identity']['start_ticks'] and (v['boot'] == p['manager_identity']['boot_id']) and (v['lease'] == p['lease_dev_inode']), 'current118_original_sole_lease')
    need(set(v['files']) == set(p['source_files']) and len(v['files']) == 118, 'current118_exact_namespace')
    need(v['files'] == {k: {'sha256': h, 'stat': p['source_metadata'][k]} for k, h in p['source_files'].items()}, 'current118_all_SHA_F9')
    rows = v['rows']
    fresh(rows['observed_at'], now)
    need(rows['active_jobs'] == rows['active_requests'] == [] and rows['historical_terminal_uncertain_count'] == 9 and (rows['historical_terminal_uncertain_sha256'] == p['history9_sha256']), 'current_idle_original_history9')
    for profile, g in [('image-turbo-c', 1), ('qwen-a-c', 8), ('glm-ab', 10)]:
        row = rows['profiles'][profile]
        need(row['state'] == 'STOPPED' and row['owner'] is None and (row['generation'] == g), 'current_released_generations')
    image = rows['profiles']['image-turbo-c']
    need(image['hardware_validated'] is False and image['min_start_available_gib'] is None and (image['runtime_floor_gib'] is None), 'C_uncalibrated_not_READY')
    for node in rows['nodes']:
        need(node['hold_profile'] is None and (not node['quarantine']), 'no_current_holds_QUAR')
    raw = base64.b64decode(v['rows_raw_b64'], validate=True)
    need(sha(raw) == v['rows_raw_sha256'] and strict(raw) == rows, 'rows_original_not_restamped')
    return {'source_count': 118, 'qualification': 'source_current_only', 'hardware_validated': False}

def commands(v):
    rows = strict(v['canonical_utf8'])
    expected = json.loads((HERE / 'old_three.json').read_bytes())
    need(len(rows['run']) == 1 and rows['run'][0]['id'] == A['old_run'] and (rows['run'][0]['phase'] == 'CLEANED_RELEASED') and (len(rows['commands']) == 3), 'original_firsttrial_three_only')
    actual = {r['key']: {**r, 'result': strict(r['result']) if type(r['result']) is str else r['result']} for r in rows['commands']}
    need(actual == {r['key']: r for r in expected}, 'original_three_FINISHED_exact_results_digests')
    need(sha(v['canonical_utf8'].encode()) == v['sha256'], 'command_history_original_SHA')

def inactive_historical_proof(value, status, state):
    expected = A['C']['inactive_historical_proof']
    need(type(value) is dict and set(value) == {'path', 'raw_b64', 'sha256', 'stat9'}, 'exact_historical_proof_fields')
    need(type(value['stat9']) is list and len(value['stat9']) == 9 and all((type(x) is int for x in value['stat9'])), 'historical_proof_F9_integer_types')
    raw = base64.b64decode(value['raw_b64'], validate=True)
    need(value['path'] == expected['path'] and raw == base64.b64decode(expected['raw_b64'], validate=True) and (sha(raw) == value['sha256'] == expected['sha256']) and (value['stat9'] == expected['stat9']), 'exact_one_Root_historical_proof_raw_F9')
    old = strict(raw)
    need(old == expected['parsed'], 'exact_historical_proof_parsed')
    need(old['run_id'] == A['old_run'] and old['guard_pid'] != status['guard_pid'] and (old['session_id'] != state['session_id']) and (old['observed_at'] < status['observed_at']), 'historical_not_current_guard_witness')
    need(status.get('schema') == 'dgx-v4-runtime-guard-v1' and state.get('schema') == 'dgx-v4-runtime-guard-state-v1' and (type(status['guard_pid']) is int) and (status['guard_pid'] > 1) and (type(state['session_id']) is str) and (re.fullmatch('[a-f0-9]{32}', state['session_id']) is not None) and (status['state'] == state['phase'] == 'IDLE_HOLD_RETAINED') and (status['reason_code'] == 'idle_db_clear') and all((status[k] is None for k in ('profile', 'owner', 'generation', 'container_id', 'image'))) and (state['arming_started_at'] is None) and (state['clear_authorized'] is True) and (state['tracked'] is state['terminal'] is None) and (state['retained_unknown'] is False), 'positive_current_unarmed_guard_only')
    return {'classification': 'exact_inactive_historical_proof', 'runtime_or_ARM_witness': False, 'raw_and_F9_retained': True}

def original_c(v, now):
    fresh(v['observed_at'], now)
    a = A['C']
    need(v['boot_id'] == a['boot_id'], 'C_original_boot')
    need(v['node_record'] == a['record'] and v['resource_lock'] == a['resource_lock'], 'C_prior_image1_CLEAR_not_qwen8_or_BOOT_inode')
    need(v['guard_pid'] == a['guard_pid'] and v['session_id'] == a['session_id'], 'original_unarmed_guard_epoch')
    status = v['status']
    state = v['guard_state']
    fresh(status['observed_at'], now, 10)
    need(status['guard_pid'] == v['guard_pid'] and status['state'] == 'IDLE_HOLD_RETAINED' and (state['phase'] == 'IDLE_HOLD_RETAINED') and (state['session_id'] == v['session_id']) and (state['clear_authorized'] is True) and (state['tracked'] is state['terminal'] is None) and (state['retained_unknown'] is False), 'actual_positive_CLEAR_guard')
    need(state['last_record'] == {k: v['node_record'].get(k) for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'updated_at', 'released_at')}, 'guard_observed_exact_prior_record')
    need(v['NODE_permit_absent'] is v['approval_absent'] is True, 'old_NODE_authority_absent')
    inactive_historical_proof(v['historical_inactive_proof'], status, state)
    need(set(v['source_files']) == set(a['source19']) and all((v['source_files'][k]['sha256'] == h for k, h in a['source19'].items())), 'actual_C_source19_SHA')
    for path, row in a['changed'].items():
        need(v['root_changed'][path] == row, 'C_success_three_leaf_fullstat')
    controls = json.loads((HERE / 'Root_C_pins.json').read_bytes())['control_files']
    need(set(v['control_files']) == set(controls) and all((v['control_files'][k]['sha256'] == h for k, h in controls.items())), 'five_controls_unchanged')
    for path, row in {**v['source_files'], **v['control_files'], **v['root_changed']}.items():
        st = row['stat']
        need(st['st_uid'] == st['st_gid'] == 0 and st['st_nlink'] == 1 and (st['st_mode'] & 61440 == 32768) and (not st['st_mode'] & 18), 'Root_current_leaf_protection')
    for name, h in [('repair', a['completion_sha256']), ('old_D', a['old_D_failed_sha256']), ('R1B', a['R1B_failed_sha256'])]:
        item = v['historical_root_originals'][name]
        need(sha(base64.b64decode(item['raw_b64'], validate=True)) == item['sha256'] == h, 'original_failures_not_relabelled')
    need(v['input_receipt_sha256'] == '441ebb261880f6de7dbfd96acce7e3cd370a57ef2f13d4696d18a517c4afabf6', 'original_fullSHA_input_receipt')
    stamps = []
    nonces = set()
    for r in v['preflights']:
        raw = base64.b64decode(r['raw_b64'], validate=True)
        request_raw = base64.b64decode(r['request_raw_b64'], validate=True)
        request = strict(request_raw)
        need(sha(raw) == r['sha256'] and strict(raw) == r['reply'] and (sha(request_raw) == r['request_sha256']) and (set(request) == {'schema', 'request_id', 'action', 'node', 'profile', 'owner', 'generation'}) and (request['schema'] == 'dgx-v4-node-v1') and (re.fullmatch('[a-f0-9]{32}', request['request_id']) is not None) and (request['action'] == 'preflight') and (request['node'] == 'spark-c') and (request['profile'] == 'qwen-a-c') and (request['owner'] == 'dgx-hx-service') and (request['generation'] == v['node_record']['generation']) and all((r['reply'].get(k) == x for k, x in request.items())), 'original_preflight_request_reply_raw_SHA_nonce')
        fresh(r['reply']['observed_at'], now, 10)
        need(r['sent_at'] <= r['reply']['observed_at'] <= r['received_at'], 'issued_remote_time_actual')
        need(request['request_id'] not in nonces, 'three_distinct_preflight_nonces')
        nonces.add(request['request_id'])
        reply = r['reply']
        gpu = reply['gpu']
        m = reply['memory']
        need(reply['clear'] is True and gpu['enumeration'] == 'complete' and (gpu['truncated'] is False) and (gpu['empty'] is True) and (gpu['processes'] == gpu['containers'] == []) and (gpu['process_count'] == gpu['gpu_container_count'] == 0), 'actual_complete_GPUempty')
        need(m['source'] == 'proc_meminfo' and m['mem_total_bytes'] == v['host_facts']['total_bytes'] and (type(m['mem_available_bytes']) is int) and (112 * 2 ** 30 <= m['mem_available_bytes'] <= m['mem_total_bytes']), 'three112GiB_policy_not_calibration')
        stamps.append(reply['observed_at'])
    need(len(stamps) == 3 and all((b - a >= 2 for a, b in zip(stamps, stamps[1:]))), 'three_fresh_spaced_samples')
    return {'next_image_generation': 2, 'threshold_calibration_required': True, 'hardware_validated': False, 'ARM_accepted': False}

def arm():
    raise Refused('new_Samples_source_epoch_current_proof_and_finite_ARM_loader_pending')

def record_policy(record, now):
    need(type(record) is dict and record['state'] == 'CLEAR' and (record['profile'] in ('qwen-a-c', 'image-turbo-c')) and (record['owner'] == 'dgx-hx-service') and (type(record['generation']) is int) and (record['generation'] > 0) and (type(record['container_id']) is str) and (re.fullmatch('[a-f0-9]{64}', record['container_id']) is not None) and (record.get('quarantine_reason') is None), 'current_known_C_released_identity')
    need(all((type(record[k]) in (int, float) and math.isfinite(record[k]) for k in ('released_at', 'updated_at'))) and 0 < record['released_at'] <= record['updated_at'] <= now, 'current_real_release_not_future_or_unknown')
    return record

def c(v, now):
    record_policy(v['node_record'], now)
    record = v['node_record_original']
    raw_record = record['canonical_utf8'].encode()
    st = record['stat9']
    need(sha(raw_record) == record['sha256'] and strict(raw_record) == v['node_record'] and (record['path'] == '/var/lib/dgx-v4/node-fence/state.sqlite3') and (len(st) == 9) and all((type(x) is int for x in st)) and (st[3:5] == [0, 0]) and (st[6] == 1) and (st[5] & 61440 == 32768) and (not st[5] & 18), 'actual_current_Node_SQL_raw_F9')
    for item in v['historical_root_originals'].values():
        body = base64.b64decode(item['raw_b64'], validate=True)
        st = item['stat']
        need(set(st) == {'st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns'} and all((type(x) is int for x in st.values())), 'whole_historical_Root_F9')
        need(st['st_size'] == len(body) and st['st_uid'] == st['st_gid'] == 0 and (st['st_nlink'] == 1) and (st['st_mode'] & 61440 == 32768) and (not st['st_mode'] & 18), 'historical_Root_original_F9_preserved')
    proc = v['current_guard_process']
    need(proc['pid'] == v['guard_pid'] and proc['boot_id'] == v['boot_id'], 'current_guard_process_boot_pid')
    originals = proc['originals']
    need(set(originals) == {'cmdline', 'status', 'stat'}, 'whole_current_guard_process_originals')
    raw = {}
    for name, item in originals.items():
        body = base64.b64decode(item['raw_b64'], validate=True)
        need(sha(body) == item['sha256'] and item['path'] == '/proc/' + str(proc['pid']) + '/' + name and (type(item['stat9']) is list) and (len(item['stat9']) == 9) and all((type(x) is int for x in item['stat9'])) and (item['stat9'][3:5] == [0, 0]) and (item['stat9'][6] == 1) and (not item['stat9'][5] & 18), 'current_Root_proc_original_raw_F9')
        raw[name] = body
    need(raw['cmdline'].split(b'\x00')[:-1] == [b'/usr/bin/python3', b'-I', b'/opt/dgx-v4/bin/node-guard-bootstrap.py', b'--serve'], 'current_fixed_guard_argv')
    status_text = raw['status'].decode()
    uids = re.search('^Uid:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*$', status_text, re.M)
    need(uids is not None and all((x == '0' for x in uids.groups())) and (re.search('^CapEff:\\s+[0-9a-f]+\\s*$', status_text, re.M) is not None), 'current_guard_UID_cap_original')
    need(int(raw['stat'].split(b' ', 1)[0]) == proc['pid'] and raw['stat'].rsplit(b')', 1)[1].split()[19].decode() == proc['start_ticks'], 'current_guard_proc_start_ticks')
    guards = v['current_guard_originals']
    need(set(guards) == {'status', 'state'}, 'whole_current_guard_originals')
    for name, key in (('status', 'status'), ('state', 'guard_state')):
        item = guards[name]
        need(item['path'] == ('/var/lib/dgx-v4/node-runtime-guard/status.json' if name == 'status' else '/var/lib/dgx-v4/node-runtime-guard/guard-state.json'), 'exact_current_Guard_Root_paths')
        body = base64.b64decode(item['raw_b64'], validate=True)
        need(sha(body) == item['sha256'] and strict(body) == v[key] and (item['stat']['st_size'] == len(body)) and (item['stat']['st_uid'] == item['stat']['st_gid'] == 0) and (item['stat']['st_nlink'] == 1) and (item['stat']['st_mode'] & 61440 == 32768) and (not item['stat']['st_mode'] & 18), 'current_Guard_raw_F9_not_self_declared')
    global A
    previous = A
    A = {**A, 'C': {**A['C'], 'record': v['node_record'], 'guard_pid': v['guard_pid'], 'session_id': v['session_id'], 'boot_id': v['boot_id']}}
    try:
        result = original_c(v, now)
    finally:
        A = previous
    return dict(result, next_image_generation=v['node_record']['generation'] + 1)
