# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fresh AB9/CLEAR proof while the original PC process is dead, not new Manager."""
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict
from B_OWNER_RECOVERY_R25_WIRING.collector import NODES, validate_snapshot_clock, fresh_node_stamp
from negative_contract import f9

def validate_nodes(nodes, config, now):
    need(set(nodes) == set(NODES) == set(config['node_source_pins']), 'actual_stopped_AB_complete')
    for node, item in nodes.items():
        validate_snapshot_clock(item, now, 30)
        reply = item['reply']
        snap = reply['snapshot']
        r = snap['record']
        g = snap['gpu']
        c = snap['container']
        data = c['data'] or {}
        need(reply['status'] == 'ok' and reply['readonly'] is True and (item['transport'].get('reason') is None) and (snap['root_uid'] == 0) and (snap['guard_process_verified'] is True), 'actual_stopped_Root_channel_positive')
        need((r['profile'], r['owner'], r['generation'], r['container_id']) == ('glm-ab', 'dgx-hx-service', 10, config['container_ids'][node]) and r['state'] == 'CLEAR' and (r['released_at'] is not None) and (r['released_at'] <= r['updated_at']), 'stopped_sameowner_gen10_positive_CLEAR')
        need(g['complete'] is True and g['truncated'] is False and (g['empty'] is True) and (g['processes'] == g['containers'] == []), 'current_stopped_AB_GPUempty')
        need(c['exists'] is False or (c['exists'] is True and data.get('running') is False and (data.get('status') in ('created', 'exited', 'dead'))), 'stopped_AB_inactive_container_known')
        need(set(snap['sources']) == set(config['node_source_pins'][node]) and len(snap['sources']) == 9, 'stopped_actual_AB9_source_complete')
        for p, pin in config['node_source_pins'][node].items():
            v = snap['sources'][p]
            need(v['path'] == p and v['sha256'] == pin, 'stopped_exact_AB9_source')
            f9(v['stat'])
        need(sha(snap['record_utf8'].encode()) == snap['record_sha256'] and strict(snap['record_utf8']) == r, 'stopped_current_record_fullraw')
        guard = strict(snap['guard_status']['raw_utf8'])
        state = strict(snap['guard_state']['raw_utf8'])
        fresh_node_stamp(item, guard['observed_at'], now, 30)
        need(guard['state'] == state['phase'] == 'IDLE_HOLD_RETAINED' and guard['reason_code'] == 'idle_db_clear' and (state['clear_authorized'] is True) and (state['tracked'] is state['terminal'] is None) and (state['retained_unknown'] is False) and (state['last_record'] == {k: r[k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'released_at', 'updated_at')}), 'stopped_actual_Guard_accepts_CLEAR')
        for key in ('guard_state', 'guard_status'):
            v = snap[key]
            need(sha(v['raw_utf8'].encode()) == v['sha256'], 'stopped_Guard_raw_SHA')
            f9(v['stat'], v['raw_utf8'].encode())
    return nodes
