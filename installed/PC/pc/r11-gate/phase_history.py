# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Consume the original two qualified phase records, never refresh their clock."""
import math
from pathlib import Path
from plan import need, strict, encode
from root_io import sha
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
import pc_gate as gate
import prelaunch_negative as negative
import scope_receipt as receipt
import prelaunch_stop as stopped
SCHEMA = 'R11-PC-phase-qualified/v1'

def rootleaf(path):
    raw, f = protected_read(path, limit=2097152)
    need(f[3:7] == [0, 989, 33056, 1], 'phase_history_Root_readonly_F9')
    return (raw, f)

def consume(installed, phase):
    need(phase in ('before-stop', 'after-stop'), 'phase_history_exact_phase')
    reference = installed['noengine_before' if phase == 'before-stop' else 'noengine_after_stop']
    path = gate.root(phase) / 'qualified.json'
    need(set(reference) == {'phase', 'state', 'aggregate_exit_status', 'qualified_ref'} and reference['phase'] == phase and (reference['state'] == 'NOT_LAUNCHED_QUIESCENT') and (reference['aggregate_exit_status'] is None), 'phase_history_exact_not_launched_not_EXIT0')
    ref = reference['qualified_ref']
    raw, f = rootleaf(path)
    need(set(ref) == {'path', 'sha256', 'stat'} and ref['path'] == str(path) and (sha(raw) == ref['sha256']) and (f == ref['stat']), 'phase_history_original_ref_exact_SHA_F9')
    q = strict(raw)
    need(set(q) == {'schema', 'phase', 'current', 'begin', 'finish', 'context_ref', 'A_scope', 'result'} and q['schema'] == SCHEMA and (q['phase'] == phase), 'phase_history_complete_schema')
    begin_raw, bf = rootleaf(path.parent / 'begin.json')
    finish_raw, ef = rootleaf(path.parent / 'finish.json')
    context_raw, cf = rootleaf(path.parent / 'context.json')
    request_raw, rf = rootleaf(path.parent / 'request.json')
    need(q['begin'] == gate.row(begin_raw, bf) and q['finish'] == gate.row(finish_raw, ef) and (q['context_ref'] == {'path': str(path.parent / 'context.json'), 'sha256': sha(context_raw), 'F9': cf}), 'phase_history_all_originals_bound')
    begin, finish, context = (strict(begin_raw), strict(finish_raw), strict(context_raw))
    before = installed['before']
    current = {'review_sha256': installed['review_sha256'], 'config_sha256': before['config_sha256'], 'manager_identity': before['manager_identity'], 'source118': before['current_source118']}
    need(set(begin) == {'schema', 'phase', 'request_sha256', 'request_nonce', 'context_sha256', 'current', 'PC_sent_at', 'PC_monotonic', 'PC_boot_id'} and begin['schema'] == 'R11-PC-phase-BEGIN/v1' and (begin['phase'] == phase) and (begin['current'] == q['current'] == current) and (begin['PC_boot_id'] == before['manager_identity']['boot_id']) and (begin['request_sha256'] == sha(request_raw)) and (begin['context_sha256'] == sha(context_raw)), 'phase_history_true_original_BEGIN')
    request = strict(request_raw)
    need(request['PC_context_sha256'] == sha(context_raw) and request['nonce'] == begin['request_nonce'], 'phase_history_request_context_nonce')
    need(set(finish) == {'schema', 'phase', 'begin_sha256', 'request_sha256', 'context_sha256', 'A_compact_sha256', 'PC_received_at', 'PC_monotonic', 'current'} and finish['schema'] == 'R11-PC-phase-finish/v1' and (finish['phase'] == phase) and (finish['begin_sha256'] == sha(begin_raw)) and (finish['request_sha256'] == sha(request_raw)) and (finish['context_sha256'] == sha(context_raw)) and (finish['A_compact_sha256'] == sha(encode(q['A_scope']))) and (finish['current'] == current), 'phase_history_true_original_finish')
    nums = (begin['PC_sent_at'], begin['PC_monotonic'], finish['PC_received_at'], finish['PC_monotonic'])
    need(all((type(x) in (int, float) and math.isfinite(x) for x in nums)) and 0 <= finish['PC_received_at'] - begin['PC_sent_at'] <= 30 and (0 <= finish['PC_monotonic'] - begin['PC_monotonic'] <= 30), 'phase_history_whole30_at_original_event_times')
    packed, _ = gate.recovery.packed_histories(protected_read, Path(gate.APPROVED_ROOT))
    trusted = receipt.validate(strict(gate.unpack(q['A_scope'])), request_raw, current, gate.APPROVED_PHASES[phase]['worker_sha256'], packed['A'], phase)
    need(q['result'] == {k: v for k, v in trusted.items() if k not in ('proof', 'request')}, 'phase_history_true_typed_scope_consumer_result')
    snapshot = context['snapshot']
    need(context['owner_state'] == ('LIVE' if phase == 'before-stop' else 'STOPPED'), 'phase_history_exact_owner_phase')
    for key in ('current_source118', 'config_sha256', 'config_stat', 'source_files', 'lease_full_F9', 'Cleaf'):
        need(snapshot[key] == before[key], 'phase_history_preserved_before_' + key)
    need(snapshot['commands']['canonical_utf8'] == before['commands']['canonical_utf8'] and snapshot['commands']['original_file_stat'] == before['commands']['original_file_stat'] and (snapshot['rows_original']['rows']['requests'] == before['rows_original']['rows']['requests']), 'phase_history_C3_requests_same_before')
    if phase == 'before-stop':
        need(snapshot['manager_identity'] == before['manager_identity'], 'phase_history_true_before_live_owner')
        status = strict(context['private_status_original']['reply_raw_utf8'].encode())
        need(status['ok'] is True and status['result']['manager_pid'] == before['manager_identity']['pid'] and (status['result']['current']['scheduler']['operator_maintenance'] is True), 'phase_history_before_original_held_maintenance')
    else:
        need(snapshot.get('manager_identity') in (None, {}) and context['prior_stopped_original'] == installed['old_shutdown_original'], 'phase_history_after_true_stopped_original')
        s = context['prior_stopped_original']
        need(sha(s['raw_utf8'].encode()) == s['sha256'] and sha(s['journal_raw_utf8'].encode()) == s['journal_sha256'] and (stopped.classify(s['raw_utf8'].encode(), s['journal_raw_utf8'].encode(), before['manager_identity'], s['composition_sha256']) == s['classification']) and (s['classification']['state'] == 'OLD_OWNER_FAILED_SHUTDOWN_PRESERVED_NO_ENGINE') and (s['classification']['actual_exit_code'] == 2), 'phase_history_strict_normalstop_classification')
        kernel = context['fresh_kernel_original']
        need(kernel['old_PID_absent'] is True and kernel['owned_cgroup_processes'] == kernel['kernel_socket_owners'] == [] and (context['lease_holders'] == [context['owned_installer_pid']]) and (type(context['owned_installer_pid']) is int) and (context['owned_installer_pid'] > 1), 'phase_history_fresh_afterstop_original_kernel')
    holder = installed['current']['manager_identity']['pid']
    gate.actor_parent(holder)
    return {'phase': phase, 'qualified_sha256': sha(raw), 'historical_only': True, 'aggregate_exit_status': None}
