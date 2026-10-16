# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Old owner cold classification; distinct new-source maintenance stays held."""

def owner_converged_cold(stages):
    p = owner_policy()
    stage = p['stage']
    rows, stats = owner_actor_snapshot(stages, stage)
    projections = {'terminal.json', 'completed.json', 'fence-released.json'}
    original = set(p['old_records'])
    owner_need(original <= set(rows) <= original | projections, 'owner_decision_cold_exact_old_plus_projection_names')
    base = {n: rows[n] for n in original}
    base_stats = {n: stats[n] for n in original}
    pending = owner_pending(stages.read, base, base_stats, p)
    recovery = stages.g.prelaunch_recovery
    with stages.g.s._lock:
        try:
            authority = recovery.owner_decision_cold(stages)
        except (owner_Refused, owner_journal_module.DecisionRefused, owner_projection_module.ProjectionRefused, OSError, ValueError, KeyError, TypeError):
            stages.g.s.restore_operator_block()
            authority = {'state': 'UNKNOWN_HELD', 'reason_code': 'owner_cold_history_or_projection_unverified'}
        except BaseException:
            stages.g.s.restore_operator_block()
            raise
        owner_need(type(authority) is dict and authority['state'] in ('ABSENT', 'PREPARED', 'UNKNOWN_HELD', 'EXPIRED', 'ABORTED', 'FINISH_WITNESS_PRESENT', 'COMMITTED'), 'owner_decision_cold_known_state')
        if authority['state'] == 'ABSENT' and (projections <= set(rows) or not projections & set(rows)):
            return False
        if authority['state'] == 'COMMITTED':
            owner_need(authority['historical_only'] is True and authority['pending'] == pending and (authority['physical_finish_calls'] == 0) and (authority['current_source_activation_required'] is True), 'owner_cold_complete_historical_not_new_source_release')
            stages.used.extend(pending['ranges'])
            stages.failed_owner_pending = None
            stages.owner_committed_history = authority
            stages.owner_decision_diagnostic = {k: authority[k] for k in ('state', 'historical_only', 'decision_ref', 'projections', 'current_source_activation_required')}
            return True
        last, last_stats = owner_actor_snapshot(stages, stage)
        owner_need(last == rows and last_stats == stats, 'owner_decision_cold_actual_actor_fullF9_after')
        stages.failed_owner_pending = pending
        stages.used.extend(pending['ranges'])
        stages.closed = True
        stages.g.s.restore_operator_block()
        stages.owner_decision_diagnostic = {'state': authority['state'], 'projections': {n: {'sha256': owner_sha(rows[n]), 'F9': stats[n]} for n in sorted(projections & set(rows))}, 'physical_release_authorized': False, 'work_may_resume': False, 'current_source_activation_required': True}
        return True
