# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Truthful generic-logger Code2 classification; kernel/no-engine are separate."""
import json
from contract import need, sha, strict
LOGGER_SHA = '6a9f8403e77c4daaa458ebc7f3ecda6378e5a9d3c298fad386d966362d6fdee8'

def classify(unit_raw, journal_raw, identity, composition_sha):
    need(type(unit_raw) is bytes and type(journal_raw) is bytes and (0 < len(unit_raw) <= 65536) and (0 < len(journal_raw) <= 1048576) and (composition_sha == LOGGER_SHA), 'pinned_actual_generic_shutdown_logger')
    lines = unit_raw.decode().splitlines()
    need(len(lines) == len({x.split('=', 1)[0] for x in lines}), 'unique_actual_unit_fields')
    u = dict((x.split('=', 1) for x in lines))
    need(u['MainPID'] == '0' and u['ExecMainPID'] == str(identity['pid']) and (u['InvocationID'] == identity['invocation_id']) and (u['NRestarts'] == '0') and (u['ControlGroup'] == ''), 'same_stopped_old_owner_invocation')
    if u['ActiveState'] == 'inactive' and u['Result'] == 'success' and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0'):
        return {'state': 'OLD_OWNER_REAL_EXIT0', 'actual_exit_code': 0, 'specific_shutdown_cause': 'actual_EXIT0', 'unit_raw_sha256': sha(unit_raw), 'journal_raw_sha256': sha(journal_raw)}
    need(u['ActiveState'] == 'failed' and u['Result'] == 'exit-code' and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '2'), 'actual_Code1Status2_not_timeout_signal_or_fabricated_EXIT0')
    required = [{'ok': False, 'reason_code': 'composition_shutdown_failed', 'error': 'CompositionError'}, {'ok': False, 'reason_code': 'composition_shutdown_incomplete', 'ownership_retained': True}]
    found = []
    for line in journal_raw.splitlines():
        row = strict(line)
        need(type(row) is dict, 'journal_original_JSON_rows')
        message = row.get('MESSAGE')
        need(type(message) is str, 'journal_original_message')
        try:
            value = strict(message)
        except (ValueError, TypeError):
            continue
        if type(value) is dict and str(value.get('reason_code', '')).startswith('composition_shutdown_'):
            need(row.get('_PID') == str(identity['pid']) and row.get('_SYSTEMD_INVOCATION_ID') == identity['invocation_id'] and (row.get('_BOOT_ID') == identity['boot_id'].replace('-', '')) and (value in required), 'same_original_generic_logger_not_unknown_shutdown_pattern')
            found.append(value)
    need(found == required, 'exact_two_ordered_generic_shutdown_originals')
    return {'state': 'OLD_OWNER_FAILED_SHUTDOWN_PRESERVED_NO_ENGINE', 'actual_exit_code': 2, 'actual_result': 'exit-code', 'specific_shutdown_cause': 'unknown_specific_shutdown_failure', 'unit_raw_sha256': sha(unit_raw), 'journal_raw_sha256': sha(journal_raw), 'CPU_success': False, 'image_imported': False, 'requires_positive_deadPID_CG_freelease_history_AB_Aabsence': True}

def stopped(proof):
    original = proof['stopped_unit_original']
    need(sha(original['raw_utf8'].encode()) == original['sha256'] and original['unit'] == dict((x.split('=', 1) for x in original['raw_utf8'].splitlines())), 'unaltered_stopped_unit_original')
    result = classify(original['raw_utf8'].encode(), original['journal_raw_utf8'].encode(), proof['old_identity'], original['composition_sha256'])
    need(result == original['classification'], 'exact_typed_shutdown_classification_not_bool')
    need(proof['old_PID_absent'] is True and proof['other_Manager_PIDs'] == [] and (proof['lease_holders'] == [proof['owned_installer_pid']]) and (proof['owned_cgroup_processes'] == []) and (proof['kernel_socket_owners'] == []), 'independent_current_kernel_death_emptyCG_ownedlease')
    return result
