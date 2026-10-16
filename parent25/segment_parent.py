# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import terminal_wait
'Finite explicit stage pipeline. Future actual binding stays None.'
import base64, time, uuid
from pathlib import Path
APPROVED_STAGE = None

def terminal_finish_action(published):
    from plan import need
    need(type(published) is dict and set(published) == {'state', 'sha256', 'image_imported', 'models_started'}, 'complete_PC_validated_terminal_publication')
    need(published['image_imported'] is False and type(published['models_started']) is int and (published['models_started'] == 0) and (type(published['sha256']) is str) and (len(published['sha256']) == 64) and all((c in '0123456789abcdef' for c in published['sha256'])), 'exact_PC_validated_terminal_origin')
    need(published['state'] in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT'), 'known_published_terminal_state_no_guess')
    return 'finish-asset-stage' if published['state'] == 'ASSET_STAGE_COMPLETED' else 'finish-failed-asset-stage'

def terminal_finish_result(original, stage, state):
    import base64, math
    from plan import need, strict
    from root_io import sha
    need(type(original) is dict and set(original) == {'original_reply_raw_b64', 'original_reply_sha256', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed'}, 'complete_actual_Root_finish_frame')
    raw = base64.b64decode(original['original_reply_raw_b64'], validate=True)
    need(0 < len(raw) <= 1048576 and raw.count(b'\n') == 1 and raw.endswith(b'\n') and (sha(raw) == original['original_reply_sha256']), 'actual_finish_original_frame_SHA')
    for name in ('PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed'):
        need(type(original[name]) in (int, float) and math.isfinite(original[name]), 'actual_finish_clock_fields')
    need(0 <= original['PC_monotonic_elapsed'] <= 90, 'actual_finish_unchanged_private_roundtrip_cap')
    reply = strict(raw)
    need(type(reply) is dict and set(reply) == {'ok', 'result'} and (reply['ok'] is True) and (type(reply['result']) is dict), 'actual_finish_Root_ok_result')
    result = reply['result']
    need(result['schema'] == 'fixed-image-finite-stage-completed/v1' and result['stage_operation'] == stage and (result['state'] == state) and (state in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT')) and (result['image_imported'] is result['CPU_success'] is result['work_deadline_extended'] is False) and (type(result['models_started']) is int) and (result['models_started'] == 0), 'same_actual_finished_stage_result')
    return result

def run(io, window, context, work):
    from plan import need, encode, strict, OPERATION
    from root_io import fresh, sha
    need(APPROVED_STAGE is not None and (not Path(work).exists()), 'actual_finite_stage_binding_None')
    root = Path(work)
    root.mkdir(mode=448)
    stage = APPROVED_STAGE['stage_operation']
    reserved = False
    attempted = set()
    remaining = window.check()
    need(remaining > 120, 'stage_plan_original_parent_budget')
    duration = min(APPROVED_STAGE['maximum_seconds'], int(remaining) - 90)
    intent = window.path.read_bytes()
    stage_plan = {'schema': 'fixed-image-finite-asset-stage-plan/v1', 'operation_family': OPERATION, 'stage_operation': stage, 'review_sha256': context['source_release_sha256'], 'manager_identity': context['manager_identity'], 'config_sha256': context['PC_config_sha256'], 'source118_sha256': sha(encode(context['current_PC_source118'])), 'ranges': APPROVED_STAGE['ranges'], 'duration_seconds': duration, 'parent_intent_original': {'raw_b64': base64.b64encode(intent).decode(), 'sha256': window.pin, 'F9': window.stat}, 'created_at': None, 'PC_plan_monotonic': None, 'PC_plan_deadline_monotonic': None, 'automatic_retry': False}

    def call(node, action, payload):
        window.check()
        attempted.add(action)
        v = io.rpc(node, action, payload, min(io.end, window.end))
        fresh(root / (action + '-' + uuid.uuid4().hex + '.json'), encode(v))
        return v
    try:
        actual = call('pc', 'source-context', {})
        entry_context = {'operation': OPERATION, 'review_sha256': context['source_release_sha256'], 'current_PC_source118': context['current_PC_source118'], 'manager_identity': context['manager_identity'], 'PC_config_sha256': context['PC_config_sha256'], 'tools': context['tools'], 'PC_qualification_original': actual, 'PC_root_rpc_source_sha256': actual['RPC_source_sha256'], 'NVMe_device': context['NVMe_device'], 'NVMe_major_minor': context['NVMe_major_minor']}
        p = call('pc', 'publish-asset-plan', stage_plan)
        clock = call('pc', 'begin-asset-entry-clock', {'stage_operation': stage})
        prepared = {'stage_operation': stage, 'plan_raw_b64': base64.b64encode(encode(p['plan'])).decode(), 'plan_sha256': p['plan_ref']['sha256'], 'entry_context': entry_context, 'clock_request': clock}
        call('a', 'asset-prepare', prepared)
        call('a', 'asset-ready-start', {'stage_operation': stage})
        while True:
            v = call('a', 'asset-ready-observe', {'stage_operation': stage})
            if not v.get('pending'):
                break
            need(window.check() > 0, 'stage_readiness_budget')
            time.sleep(0.1)
        response = call('a', 'asset-ready-finalize', {'stage_operation': stage})
        call('pc', 'publish-asset-entry-clock', response)
        call('pc', 'reserve-asset-stage', {'stage_operation': stage})
        reserved = True
        need(io.stage_operation == stage, 'fixed_stage_parent_IO_binding')
        io.bind_context(dict(context, owned_aggregate_unit='dgx-v4-image-segment-' + stage + '.service', owned_aggregate_cgroup='/system.slice/dgx-v4-image-segment-' + stage + '.service'), None, min(io.end, window.end))
        call('a', 'asset-start', {'stage_operation': stage})
        while True:
            observed = call('a', 'asset-observe', {'stage_operation': stage})
            if not observed.get('pending'):
                break
            io.metadata_step(min(io.end, window.end))
            time.sleep(0.1)
        terminal_clock = call('pc', 'begin-asset-terminal-clock', {'stage_operation': stage})
        terminal = call('a', 'asset-finalize', {'stage_operation': stage, 'terminal_clock': terminal_clock})
        published = call('pc', 'publish-asset-terminal', terminal)
        action = terminal_finish_action(published)
        done = call('pc', action, {'stage_operation': stage})
        terminal_finish_result(done, stage, published['state'])
        if published['state'] == 'FAILED_REGISTRY_QUIESCENT':
            fresh(root / 'failed-released.json', encode(done))
            need(False, 'asset_stage_failed_preserved_released')
        fresh(root / 'completed.json', encode(done))
        return done
    except BaseException as e:
        from safe_error import original_safe_error
        fresh(root / 'failed.json', encode(original_safe_error('finish-failed-asset-stage', e)))
        if reserved and 'asset-start' not in attempted and (not attempted.intersection({'begin-asset-terminal-clock', 'asset-finalize', 'publish-asset-terminal', 'finish-asset-stage', 'finish-failed-asset-stage', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage'})):
            try:
                cleanup_end = time.monotonic() + 90
                io.close_not_launched(stage, attempted, cleanup_end)
            except BaseException as cleanup_error:
                fresh(root / 'cleanup-failed.json', encode(original_safe_error('finish-failed-asset-stage', cleanup_error)))
        elif reserved and (not attempted.intersection({'begin-asset-terminal-clock', 'asset-finalize', 'publish-asset-terminal', 'finish-asset-stage'})):
            try:
                cleanup_end = time.monotonic() + 90
                terminal_wait.wait(io, stage, cleanup_end)
                attempted.add('begin-asset-terminal-clock')
                clock = io.cleanup_rpc('pc', 'begin-asset-terminal-clock', {'stage_operation': stage}, cleanup_end)
                attempted.add('asset-finalize')
                v = io.cleanup_rpc('a', 'asset-finalize', {'stage_operation': stage, 'terminal_clock': clock}, cleanup_end)
                attempted.add('publish-asset-terminal')
                published = io.cleanup_rpc('pc', 'publish-asset-terminal', v, cleanup_end)
                action = terminal_finish_action(published)
                attempted.add(action)
                done = io.cleanup_rpc('pc', action, {'stage_operation': stage}, cleanup_end)
                terminal_finish_result(done, stage, published['state'])
                fresh(root / 'cleanup-released.json', encode(done))
            except BaseException as cleanup_error:
                fresh(root / 'cleanup-failed.json', encode(original_safe_error('finish-failed-asset-stage', cleanup_error)))
        fresh(root / 'attempted-terminal-phases.json', encode({'attempted': sorted(attempted.intersection({'begin-asset-terminal-clock', 'asset-finalize', 'publish-asset-terminal', 'finish-asset-stage', 'finish-failed-asset-stage', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage'})), 'replay_permitted': False}))
        raise
