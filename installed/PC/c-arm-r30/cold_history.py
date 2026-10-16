# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact old C3 history plus genuine future current source and C30; no ARM."""
import time, types, sys
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, protected_read
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30')
PERMIT = Path('/etc/dgx-home-ai/g8-c-firsttrial.json')
RUN = 'f3bd52707da7bf959664ff9e6af44fd8'
APPROVED_INPUT_PINS = None
APPROVED_CURRENT_C_CONSUMER = '6ecc4b1eb2bbc0f6c94c0f1279e0f7e2f6f5f881950d541076006a5d0b975e48'
APPROVED_SOURCE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'

def source(name):
    need(APPROVED_INPUT_PINS is not None and name in APPROVED_INPUT_PINS, 'fixed_legacy_source_pending')
    raw, st = protected_read(ROOT / name, limit=4194304)
    need(sha(raw) == APPROVED_INPUT_PINS[name], 'fixed_legacy_source_SHA')
    return (raw, st)

def load_stopped_nodes():
    """Load the exact two protected sources; restore ambient import state."""
    contract, _ = source('negative_contract.py')
    support, _ = source('stopped_nodes.py')
    name = 'negative_contract'
    missing = object()
    previous = sys.modules.get(name, missing)
    try:
        c = types.ModuleType(name)
        c.__file__ = str(ROOT / 'negative_contract.py')
        sys.modules[name] = c
        exec(compile(contract, c.__file__, 'exec'), c.__dict__)
        m = types.ModuleType('fixed_R6_current_AB_validator')
        m.__file__ = str(ROOT / 'stopped_nodes.py')
        exec(compile(support, m.__file__, 'exec'), m.__dict__)
        return m
    finally:
        if previous is missing:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous

def history(document, history_value, permit_raw, permit_stat):
    """Pure exact old bytes + WHOLE Ledger FINISHED predicate at original time."""
    expected = strict(source('inputs/legacy-permit.json')[0])['legacy_C_permit']
    need(permit_raw == expected['raw_utf8'].encode() and sha(permit_raw) == expected['sha256'] and (permit_stat == expected['stat']), 'one_exact_historical_HX_permit_raw_F9')
    v = strict(permit_raw)
    need(document.value == v and document.sha256 == expected['sha256'], 'actual_loaded_document_not_replaced')
    need((v['run_id'], v['generation'], v['manager_pid'], v['profile'], v['node'], v['owner']) == (RUN, 1, 165691, 'image-turbo-c', 'spark-c', 'dgx-hx-service') and type(v['generation']) is int and (v['lease_dev_inode'] == [2096, 69257]), 'only_old_C3_gen1_not_new_C_authority')
    original = strict(source('inputs/legacy-C3.json')[0])['snapshot']['commands']
    need(all((history_value[k] == original[k] for k in ('canonical_utf8', 'sha256', 'original_file_stat'))) and sha(history_value['canonical_utf8'].encode()) == history_value['sha256'], 'whole_original_C3_raw_F9_not_new_empty_ledger')
    rows = strict(history_value['canonical_utf8'])
    run = rows['run']
    commands = rows['commands']
    need(len(run) == 1 and len(commands) == 3 and (len({r['key'] for r in commands}) == 3), 'exact_one_run_three_commands')
    from G7_INTEGRATION_CANDIDATE_R2.durable import digest
    identity = digest({'run': RUN, 'permit': document.sha256, 'generation': 1, 'owner': 'dgx-hx-service'})
    need(run[0]['id'] == RUN and run[0]['identity'] == identity and (run[0]['generation'] == 1) and (run[0]['attempted'] == 1) and (run[0]['phase'] == 'CLEANED_RELEASED'), 'historical_identity_and_cleaned_released')
    byaction = {}
    for row in commands:
        need(row['state'] == 'FINISHED' and row['owner'] == 'Mac-Codex-V4' and (row['action'] not in byaction), 'whole_FINISHED_unique_actions')
        byaction[row['action']] = strict(row['result']) if type(row['result']) is str else row['result']
    need(set(byaction) == {'start', 'stop', 'cleanup'}, 'exact_original_three_actions')
    need(byaction['start']['run_id'] == RUN and byaction['start']['generation'] == 1 and (byaction['start']['permit_sha256'] == document.sha256), 'same_historical_start')
    need(byaction['stop']['confirmed'] is True and byaction['stop']['stopped'] is True and (byaction['stop']['confirmation']['stopped'] is True) and (byaction['stop']['generation'] == 1), 'positive_historical_stop_not_ACK')
    need(byaction['cleanup']['cleaned'] is byaction['cleanup']['core_released'] is byaction['cleanup']['scheduler_released'] is True and byaction['cleanup']['generation'] == 1, 'positive_historical_cleanup')
    return {'classification': 'exact_C3_gen1_historical_permit', 'run_id': RUN, 'permit_sha256': sha(permit_raw), 'permit_stat': permit_stat, 'C3_sha256': history_value['sha256'], 'C3_stat': history_value['original_file_stat'], 'ARM_authority': False}

def consume_current_C(config, now):
    need(APPROVED_CURRENT_C_CONSUMER is not None and APPROVED_SOURCE_REVIEW is not None, 'actual_fresh_C_before_start_pending')
    raw, st = protected_read(ROOT / 'current_C_consumer.py', limit=2097152)
    need(sha(raw) == APPROVED_CURRENT_C_CONSUMER, 'fixed_current_C_consumer_source')
    m = types.ModuleType('held_R6_current_C_consumer')
    m.__file__ = str(ROOT / 'current_C_consumer.py')
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m.consume(protected_read, config, now)

def classify(runtime, lease, operator, document, historical_consumer, live_idle_consumer, installation_consumer):
    """Ctor only: historical negative is not this future epoch qualification."""
    need(runtime is operator.runtime and runtime.server.scheduler is operator.scheduler and (operator.scheduler.manager is runtime.manager) and (operator.lease is lease), 'one_actual_runtime_and_original_lease')
    first = runtime.c_firsttrial
    need(first is runtime.server.c_firsttrial and first.runtime is runtime and (first.lease is lease), 'original_C_controller_same_runtime')
    need(first.document is first.token is first.cid is first.thread is first.samples is None and (not first.admitted) and (first.error is first.stop_result is None) and (not first.stop_event.is_set()), 'no_active_or_unknown_C_trial')
    raw, st = protected_read(PERMIT, limit=65536)
    from B_OWNER_RECOVERY_R25_WIRING.collector import history_and_work
    rows = history_and_work(runtime)
    code, _ = source('inputs/old_installer_helpers.py')
    helper_module = types.ModuleType('fixed_C3_original_reader')
    helper_module.__file__ = str(ROOT / 'inputs/old_installer_helpers.py')
    exec(compile(code, helper_module.__file__, 'exec'), helper_module.__dict__)
    commands = helper_module.read_command_history()
    old = history(document, commands, raw, st)
    historical = historical_consumer(runtime.manager._now())
    helper = operator.negative_cpu_release
    need(helper.runtime is runtime and helper.lease is lease and (helper.scheduler is operator.scheduler) and (helper.original == historical), 'actual_typed_negative_archive_not_config_bool')
    need(historical['state'] == 'NEGATIVE_RELEASED' and historical['CPU_success'] is False and (historical['historical_only'] is True) and (historical['requires_caller_fresh_current_idle'] is True), 'negative_ancestor_not_new_CPU_authority')
    bridge = operator.cpu_bridge
    need(bridge.runtime is runtime and bridge.lease is lease and (bridge.active is False) and (bridge.deadline is None), 'no_bf84_resume_or_deadline_extension')
    local_source = operator.collector.source_and_lease()
    need(rows['active_requests'] == rows['active_jobs'] == [] and rows['historical_terminal_uncertain_count'] == 9 and (rows['historical_terminal_uncertain_sha256'] == operator.config['historical_terminal_uncertain_sha256']), 'whole_current_requests_history9')
    now = runtime.manager._now()
    qualification = ROOT.parent / 'current-source-qualified.json'
    completed = ROOT.parent / 'current-qualification-completed.json'
    present = qualification.exists() or qualification.is_symlink()
    done = completed.exists() or completed.is_symlink()
    need(present == done, 'partial_installation_history_no_C30_fallback')
    warm = present
    installation = installation_consumer(operator.config, now) if warm else None
    if warm:
        need(installation['historical_only'] is True and type(installation['initial_identity']) is dict and (len(installation['source_qualified_sha256']) == 64), 'complete_historical_installation_not_current_PID_authority')
        current = None
        original_raw = None
        live = None
    else:
        original_raw, _ = protected_read(ROOT / 'startup-AB-original.json', limit=2097152)
        original = strict(original_raw)
        need(sha(original['raw_utf8'].encode()) == original['sha256'] and strict(original['raw_utf8']) == original['nodes'] and (original['source_review_sha256'] == APPROVED_SOURCE_REVIEW) and (original['target_config_sha256'] == operator.config['_config_sha256']), 'actual_current_AB_original_not_old_epoch')
        current = consume_current_C(operator.config, now)
    with operator.scheduler._lock:
        operator.scheduler.continue_operator_maintenance()
        need(operator.c_arm_gate is None and operator.scheduler._operator_maintenance is True and (runtime.manager._now() - now <= 1), 'constructor_pending_only_bounded_local_handoff')
        scheduler = operator.scheduler
        need(not (scheduler._operator_tick_inflight or scheduler._operator_public_inflight or scheduler._operator_creative_pulse_inflight or (scheduler._creative is not None) or scheduler._infos or any(scheduler._queues.values()) or any(scheduler._active.values()) or scheduler._uncertain or scheduler._ensuring or scheduler._dispatch_checks or scheduler._draining), 'cold_pending_actual_all_work_counters_zero')
        core = {}
        for name in ('glm-ab', 'qwen-a-c', 'image-turbo-c'):
            row = runtime.control_store.profile_view(name)
            need(row['state'] == 'STOPPED' and row['owner'] is None and (type(row['generation']) is int) and (row['generation'] > 0), 'current_Core_positive_idle_no_history_substitution')
            core[name] = row['generation']
        if not warm:
            live = live_idle_consumer(original['nodes'], operator.config, now, fenced=True)
            need(live['Core_generations'] == core, 'cold_start_current_Core_and_genuine_AB_match')
        for row in runtime.control_store.nodes_view():
            need(row['hold_profile'] is row['hold_owner'] is row['hold_generation'] is None and row['quarantined'] is False, 'current_all_nodes_nohold_noquarantine')
    need(protected_read(PERMIT, limit=65536) == (raw, st), 'legacy_permit_fullF9_after_classify')
    return dict(old, current_C=current, current_AB_sha256=sha(original_raw) if original_raw is not None else None, current_source_and_lease=local_source, negative_ancestor=historical, operator_maintenance_retained=True, installation_history=installation, current_resource_pending=True, restart_standby=warm)
