# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def owner_history(stages, stage, rows):
    if owner_strict(rows['completed.json']).get('schema') == 'fixed-image-finite-stage-owner-recovered/v2':
        return owner_committed_history_v2(stages, stage, rows)
    p = owner_policy()
    owner_need(stage == p['stage'], 'owner_history_exact_stage')
    c = owner_strict(rows['completed.json'])
    f = owner_strict(rows['fence-released.json'])
    owner_need(set(c) == {'schema', 'stage_operation', 'state', 'terminal_sha256', 'current', 'original_deadline_monotonic', 'work_deadline_extended', 'image_imported', 'CPU_success', 'models_started', 'finished_at', 'owner_recovery'} and c['schema'] == 'fixed-image-finite-stage-owner-recovered/v1', 'owner_complete_recovery_schema')
    actual, actual_stats = owner_actor_snapshot(stages, stage)
    owner_need(actual == rows, 'owner_recovered_actual_actor_bytes_before')
    original = {n: raw for n, raw in rows.items() if n not in ('terminal.json', 'completed.json', 'fence-released.json')}
    stats = {n: actual_stats[n] for n in original}
    pend = owner_pending(stages.read, original, stats, p)
    owner_need(rows['terminal.json'] == owner_encode(pend['original_terminal']) and c['terminal_sha256'] == owner_sha(rows['terminal.json']) and (c['state'] == owner_FAILED) and (c['stage_operation'] == stage) and (c['original_deadline_monotonic'] == pend['original_deadline_monotonic']) and (c['work_deadline_extended'] is c['image_imported'] is c['CPU_success'] is False) and (type(c['models_started']) is int) and (c['models_started'] == 0) and (f['stage_operation'] == stage) and (f['completed_sha256'] == owner_sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (c['finished_at'] <= f['observed_at']), 'owner_recovered_failed_complete_fence_not_success')
    result = owner_fresh(stages.read, p, stages.g, pend, None, c['owner_recovery']['observed_at'], historical=True, event=c['owner_recovery'])
    owner_need(result['observed_at'] <= c['finished_at'], 'owner_event_precedes_actual_finish')
    a = c['owner_recovery']['new_current']['manager_identity']['invocation_id']
    root = owner_Path(p['activation_root']) / a
    source_records, source_stats = owner_activation_records(root)
    owner_need(set(source_records) == {'intent.json', 'completed.json', 'fence-released.json'}, 'owner_complete_source_activation_entries')
    ir, dr, fr = (source_records[n] for n in ('intent.json', 'completed.json', 'fence-released.json'))
    intent, done, mark = map(owner_strict, (ir, dr, fr))
    owner_need(intent['owner_recovery'] == result and done['owner_recovery'] == result and (done['state'] == 'SOURCE_EPOCH_READY') and (mark['completed_sha256'] == owner_sha(dr)) and (mark['operator_maintenance_observed'] is False) and (done['observed_at'] <= mark['observed_at']), 'owner_complete_source_activation_fence_chain')
    source_last, source_last_stats = owner_activation_records(root)
    owner_need(source_last == source_records and source_last_stats == source_stats, 'owner_source_activation_fullF9_after_history')
    last, last_stats = owner_actor_snapshot(stages, stage)
    owner_need(last == actual and last_stats == actual_stats, 'owner_recovered_actor_fullF9_after_history')
    stages.used.extend(pend['ranges'])
    return pend['original_terminal']
