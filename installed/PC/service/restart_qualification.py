# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Independent readonly new-PID qualification, never an epoch/install success."""
import math, re, time
from pathlib import Path
from contract import *
from ancestor import root
from managed_scope import positive
from live_idle import validate_live_idle
APPROVED_RENEWAL_WORKER_SHA = '223684c9e4c15522bbe8098c958b8c60294afa74947a286a87e41e31250f97c9'
APPROVED_C_RENEWAL_CONSUMER_SHA = '0a81bec37a7eb8bcccefa6efb65cc6327f897b6fd2dcf6bc80b4fd672ecf0b10'

def paths(identity):
    inv = identity['invocation_id']
    need(type(inv) is str and re.fullmatch('[0-9a-f]{32}', inv), 'actual_current_invocation_root')
    parent = PC_ROOT / 'runtime-qualifications' / inv
    return (parent, parent / 'qualified.json', parent / 'completed.json')

def consume(read, config, identity, now, installation):
    need(APPROVED_RENEWAL_WORKER_SHA is not None and APPROVED_C_RENEWAL_CONSUMER_SHA is not None, 'current_PID_readonly_qualification_pending')
    parent, receipt, done = paths(identity)
    raw, st = root(read, receipt)
    dr, ds = root(read, done)
    r, d = (strict(raw), strict(dr))
    need(r['schema'] == 'registry-R26-R6-runtime-source-qualified/v1' and d['schema'] == 'registry-R26-R6-runtime-qualified-completed/v1' and (d['receipt_sha256'] == sha(raw)), 'typed_runtime_qualification')
    need(r['operation'] == EPOCH_OPERATION and r['review_sha256'] == APPROVED_REVIEW and (r['initial_installation_sha256'] == installation['source_qualified_sha256']) and (r['current']['manager_identity'] == d['manager_identity'] == identity) and (r['current']['current_source118'] == config['PC_source_pins']) and (r['current']['config_sha256'] == config['_config_sha256']), 'historical_installation_distinct_current_PID_source')
    positive(r['actual_readonly_scope'], r['returned_original'], APPROVED_RENEWAL_WORKER_SHA, unit='dgx-v4-mimo-source-renewal-entryclock-r1-' + identity['invocation_id'] + '.service', runtime_seconds=120)
    need(r['returned_original']['result']['body_sha256'] == r['provisional_sha256'], 'actual_readonly_output_not_static_bool')
    indexraw, indexstat = read(PC_ROOT / 'epoch-index.json')
    index = strict(indexraw)
    need(set(r['source_originals']) == set(index['files']) and index['review_sha256'] == APPROVED_REVIEW, 'renewal_complete_exact_final_source_set')
    for name, v in r['source_originals'].items():
        body, meta = read(PC_ROOT / name, limit=2097152)
        need(sha(body) == v['sha256'] and meta == v['stat'], 'renewal_complete_source_F9')
    need(r['C_renewal']['consumer_source_sha256'] == APPROVED_C_RENEWAL_CONSUMER_SHA and r['C_renewal']['manager_identity'] == identity and (r['C_renewal']['source_review_sha256'] == APPROVED_REVIEW) and (r['C_renewal']['Root_scope_EXIT0'] is True), 'actual_same_PID_new_C_renewal_source')
    for path, item in r['C_renewal']['originals'].items():
        body, meta = read(Path(path), limit=4194304)
        need(sha(body) == item['sha256'] and meta == item['stat'], 'C_renewal_originals_immutable')
    observations = r['command_history_observations']
    need(type(observations) is dict and set(observations) == {'before', 'after'} and (observations['after'] == r['current']['commands']), 'commands_preserved_complete_capture_chain')
    command_history_stable(observations['before'], observations['after'], r['observed_at'])
    command_history_stable(observations['after'], r['command_history_final_observation'], d['observed_at'])
    stamps = (observations['before']['observed_at'], r['command_history_before_capture_observed_at'], observations['after']['observed_at'], r['current']['observed_at'], r['observed_at'], r['actual_readonly_scope']['observed_at'], r['command_history_final_observation']['observed_at'], r['command_history_final_capture_observed_at'], d['observed_at'], now)
    need(all((type(x) in (int, float) and math.isfinite(x) for x in stamps)) and all((a <= b for a, b in zip(stamps, stamps[1:]))), 'complete_commands_three_observations_time_chain')
    need(r['models_started'] == r['normal_stop_calls'] == r['normal_start_calls'] == r['CAS_calls'] == 0 and r['operator_maintenance_observed'] is True and (r['automatic_retry'] is False) and (r['observed_at'] <= d['observed_at'] <= now), 'readonly_current_source_never_model_or_installation_success')
    return {'source_qualified_sha256': sha(raw), 'historical_installation_sha256': installation['source_qualified_sha256'], 'historical_only': True, 'Core_generations': {p: v['generation'] for p, v in r['current']['rows_original']['rows']['profiles'].items()}}

def command_history_stable(before, after, now):
    """Keep complete captures; compare only immutable DB content/F9, not clocks."""
    keys = {'canonical_utf8', 'sha256', 'original_file_stat', 'observed_at'}
    stat_keys = {'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'}
    need(type(now) in (int, float) and math.isfinite(now), 'commands_actual_local_time')
    for row in (before, after):
        need(type(row) is dict and set(row) == keys and (type(row['canonical_utf8']) is str) and (type(row['sha256']) is str), 'commands_complete_original_schema')
        raw = row['canonical_utf8'].encode()
        need(sha(raw) == row['sha256'], 'commands_canonical_original_SHA')
        meta = row['original_file_stat']
        need(type(meta) is dict and set(meta) == stat_keys and all((type(v) is int for v in meta.values())) and (meta['st_dev'] > 0) and (meta['st_ino'] > 0) and (meta['st_size'] >= 0) and (meta['st_uid'] == 999) and (meta['st_gid'] == 989) and (meta['st_mode'] == 33152) and (meta['st_nlink'] == 1) and (meta['st_mtime_ns'] >= 0) and (meta['st_ctime_ns'] >= 0), 'commands_exact_original_file_stat')
        stamp = row['observed_at']
        need(type(stamp) in (int, float) and math.isfinite(stamp) and (0 < stamp <= now), 'commands_original_observation_nonfuture')
    need(before['observed_at'] <= after['observed_at'], 'commands_actual_observation_order')
    need(all((before[k] == after[k] for k in ('canonical_utf8', 'sha256', 'original_file_stat'))), 'commands_original_bytes_SHA_F9_unchanged')
    return True

def provisional(native, config, identity, installation, C_consumer, read):
    """Invoked in a new finite Root readonly worker, never in service UID999."""
    need(native.root_uid() == 0 and native.scope_identity()['unit'] == 'dgx-v4-mimo-source-renewal-entryclock-r1-' + identity['invocation_id'] + '.service', 'fixed_current_Root_readonly_scope')
    before = native.capture_current(time.monotonic() + 60)
    need(before['manager_identity'] == identity and before['current_source118'] == config['PC_source_pins'] and (before['config_sha256'] == config['_config_sha256']), 'actual_new_current_readonly')
    status = native.current_idle_status()
    proof = status['current']
    baseline = validate_live_idle(proof, config, native.wall(), fenced=True)
    C = C_consumer(read, config, identity, native.wall())
    after = native.capture_current(time.monotonic() + 60)
    command_history_stable(before['commands'], after['commands'], native.wall())
    capture_stamps = (before['commands']['observed_at'], before['observed_at'], after['commands']['observed_at'], after['observed_at'], native.wall())
    need(all((type(x) in (int, float) and math.isfinite(x) for x in capture_stamps)) and all((a <= b for a, b in zip(capture_stamps, capture_stamps[1:]))), 'commands_original_capture_time_order')
    need(all((before[k] == after[k] for k in ('manager_identity', 'source_files', 'config_sha256', 'config_stat', 'Cleaf', 'lease_full_F9', 'socket'))), 'current_identity_source_lease_history_stable')
    need(before['rows_original']['rows']['requests'] == after['rows_original']['rows']['requests'] and before['rows_original']['rows']['profiles'] == after['rows_original']['rows']['profiles'] and (before['rows_original']['rows']['historical_terminal_uncertain_sha256'] == after['rows_original']['rows']['historical_terminal_uncertain_sha256']), 'current_rows_unchanged_during_qualification')
    return {'schema': 'registry-R26-R6-runtime-source-provisional/v1', 'operation': EPOCH_OPERATION, 'review_sha256': APPROVED_REVIEW, 'initial_installation_sha256': installation['source_qualified_sha256'], 'current': after, 'command_history_before_capture_observed_at': before['observed_at'], 'command_history_observations': {'before': before['commands'], 'after': after['commands']}, 'baseline': baseline, 'live_status_original': status, 'C_renewal': C, 'operator_maintenance_observed': True, 'models_started': 0, 'normal_stop_calls': 0, 'normal_start_calls': 0, 'CAS_calls': 0, 'automatic_retry': False, 'observed_at': native.wall()}

def finalize(native, scope, returned, installation, read):
    need(APPROVED_RENEWAL_WORKER_SHA is not None, 'renewal_worker_source_pending')
    identity = returned['result']['manager_identity']
    parent, receipt, done = paths(identity)
    positive(scope, returned, APPROVED_RENEWAL_WORKER_SHA, unit='dgx-v4-mimo-source-renewal-entryclock-r1-' + identity['invocation_id'] + '.service', runtime_seconds=120)
    raw, meta = read(parent / 'provisional.json', limit=4194304)
    p = strict(raw)
    need(sha(raw) == returned['result']['body_sha256'] and p['current']['manager_identity'] == identity and (p['initial_installation_sha256'] == installation['source_qualified_sha256']), 'actual_provisional_raw_source_current')
    actual = native.capture_current(time.monotonic() + 60)
    need(all((actual[k] == p['current'][k] for k in ('manager_identity', 'source_files', 'config_sha256', 'config_stat', 'Cleaf', 'lease_full_F9', 'socket'))) and actual['rows_original']['rows']['requests'] == p['current']['rows_original']['rows']['requests'] and (actual['rows_original']['rows']['profiles'] == p['current']['rows_original']['rows']['profiles']) and (actual['rows_original']['rows']['historical_terminal_uncertain_sha256'] == p['current']['rows_original']['rows']['historical_terminal_uncertain_sha256']), 'fresh_current_same_after_retained_EXIT0')
    command_history_stable(p['current']['commands'], actual['commands'], native.wall())
    final_stamps = (scope['observed_at'], actual['commands']['observed_at'], actual['observed_at'], native.wall())
    need(all((type(x) in (int, float) and math.isfinite(x) for x in final_stamps)) and all((a <= b for a, b in zip(final_stamps, final_stamps[1:]))), 'commands_final_current_after_actual_retained_scope')
    body = dict(p, schema='registry-R26-R6-runtime-source-qualified/v1', actual_readonly_scope=scope, returned_original=returned, provisional_sha256=sha(raw), source_originals=native.source_originals(), command_history_final_observation=actual['commands'], command_history_final_capture_observed_at=actual['observed_at'])
    native.exclusive(receipt, encode(body), mode=288, gid=989)
    native.exclusive(done, encode({'schema': 'registry-R26-R6-runtime-qualified-completed/v1', 'receipt_sha256': sha(encode(body)), 'manager_identity': identity, 'observed_at': native.wall()}), mode=288, gid=989)
    return body
