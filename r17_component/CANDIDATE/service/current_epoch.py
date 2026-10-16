# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""NEW epoch qualification consumer; OLD R4 ancestor never relabelled current."""
from contract import *
from ancestor import root
from managed_scope import positive
from restart_qualification import consume as renew
APPROVED_QUALIFIER_SHA = '217a5cb2fd3970678f98da5feaa934aa53d249ec372a2db946914b4d75df0a1e'
APPROVED_EPOCH_WORKER_SHA = '9dfad7bd5c531ce5ddc05b57383f43c4b282a05a954cf975df190eb06a487350'
APPROVED_PHASE_GATE_SHA = 'b0851a274412b2cad18c23980868beade79ae18a34168b23e305bb305a671533'
RECEIPT = PC_ROOT / 'current-source-qualified.json'
DONE = PC_ROOT / 'current-qualification-completed.json'

def consume_initial(read, config, identity, now, *, phase_verify=None):
    need(APPROVED_QUALIFIER_SHA is not None and APPROVED_EPOCH_WORKER_SHA is not None, 'actual_new_epoch_source_qualification_pending')
    raw, st = root(read, RECEIPT)
    done, ds = root(read, DONE)
    r, c = (strict(raw), strict(done))
    need(r['schema'] == 'registry-R26-current118-source-qualified/v1' and c['schema'] == 'registry-R26-current118-qualified-completed/v1' and (r['qualifier_sha256'] == c['qualifier_sha256'] == APPROVED_QUALIFIER_SHA) and (c['receipt_sha256'] == sha(raw)) and (r['operation'] == EPOCH_OPERATION) and (r['grant_operation'] == OPERATION), 'independent_new_qualified_source_not_old_scope')
    need(r['current']['manager_identity'] == c['manager_identity'] == identity and r['current']['current_source118'] == config['PC_source_pins'] and (r['current']['config_sha256'] == config['_config_sha256']) and (len(config['PC_source_pins']) == 118) and (r['current']['lease_dev_inode'] == LEASE), 'new_PID_current118_config_original_physicallease')
    positive(r['actual_installer_scope'], r['returned_original'], APPROVED_EPOCH_WORKER_SHA)
    for name, pin in (('worker.py', APPROVED_EPOCH_WORKER_SHA), ('loader.py', r['scope_sources']['loader.py']['sha256'])):
        source, ss = read(PC_ROOT / 'epoch-scope' / name)
        need(sha(source) == pin and ss == r['scope_sources'][name]['stat'], 'actual_scope_worker_loader_source_fullF9')
    installed, ist = root(read, PC_ROOT / 'current-installed-original.json')
    need(sha(installed) == r['installed_original']['sha256'] == r['installed_mirror']['sha256'] and ist == r['installed_mirror']['stat'] and (r['installed_original']['stat'][3:7] == [0, 0, 33152, 1]), 'same_original_installed_raw_and_distinct_actual_mirror_F9')
    v = strict(installed)
    stable = ('manager_identity', 'current_source118', 'source_files', 'config_sha256', 'config_stat', 'Cleaf', 'lease_full_F9', 'socket')
    need(all((v['current'][k] == r['current'][k] for k in stable)) and v['current']['rows_original']['rows']['requests'] == r['current']['rows_original']['rows']['requests'] and (v['current']['commands']['canonical_utf8'] == r['current']['commands']['canonical_utf8']) and (v['current']['commands']['original_file_stat'] == r['current']['commands']['original_file_stat']) and (v['normal_stop_calls'] == v['normal_start_calls'] == 1) and (v['CAS_calls'] == 2) and (v['socket_unlink_calls'] in (0, 1)) and (v['other117_metadata_unchanged'] is True) and (v['all_old_failures_preserved'] is True) and (v['models_started'] == 0), 'finite_exact_oldstop_newstart_no_model_success')
    gate_raw, gate_F9 = root(read, PC_ROOT / 'pc/r11-gate/gate_loader.py')
    need(APPROVED_PHASE_GATE_SHA is not None and sha(gate_raw) == APPROVED_PHASE_GATE_SHA, 'phase_history_service_actual_gate_pin')
    import types
    phase_gate = types.ModuleType('R11_service_phase_history_gate')
    phase_gate.__file__ = str(PC_ROOT / 'pc/r11-gate/gate_loader.py')
    exec(compile(gate_raw, phase_gate.__file__, 'exec'), phase_gate.__dict__)
    phase_gate.verify_installed_history(v) if phase_verify is None else phase_verify(v)
    need(v['before']['manager_identity']['pid'] != identity['pid'] and v['before']['manager_identity']['boot_id'] == identity['boot_id'] and (r['observed_at'] <= c['observed_at'] <= now), 'newsource_history_original_times_sameboot_distinctPID')
    return {'Core_generations': {k: v['current']['rows_original']['rows']['profiles'][k]['generation'] for k in ('glm-ab', 'qwen-a-c', 'image-turbo-c')}, 'source_qualified_sha256': sha(raw), 'historical_only': True}

def consume_installation(read, config, now):
    raw, st = root(read, RECEIPT)
    r = strict(raw)
    initial = r['current']['manager_identity']
    value = consume_initial(read, config, initial, now)
    return dict(value, initial_identity=initial, historical_only=True)

def consume(read, config, identity, now, *, prepared=None):
    installation = consume_installation(read, config, now) if prepared is None else prepared.installation(read, config)
    if identity == installation['initial_identity']:
        value = installation
    else:
        value = renew(read, config, identity, now, installation)
    current_owner(read, identity, prepared)
    return value

def current_owner(read, identity, prepared=None):
    raw, meta = root(read, PC_ROOT / 'pc/r11-gate/gate_loader.py')
    need(sha(raw) == APPROVED_PHASE_GATE_SHA, 'R17_current_owner_exact_gate_source')
    from asset_stage import identity as actual_identity
    if prepared is not None:
        return prepared.current_owner(read, identity, actual_identity)
    import types
    gate = types.ModuleType('R17_private_current_owner_gate')
    gate.__file__ = str(PC_ROOT / 'pc/r11-gate/gate_loader.py')
    exec(compile(raw, gate.__file__, 'exec'), gate.__dict__)
    from asset_stage import identity as actual_identity
    return gate.verify_current_owner(identity, actual_identity=actual_identity)
