# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite normal old sole stop1/explicit CAS set/new sole start1. Never invoked at import.
The algorithm uses RootNative, an existing IO/helper/reader closure. CPU fixtures
inject observations and systemd results; they do not qualify native hardware.
"""
import time
import source_delta
from contract import APPROVED_SOURCE_DELTA, need, sha, encode, strict, STATE, CONFIG, WIRE, UNIT, SOCKET, EPOCH_OPERATION, fixed_packet, source_reason
APPROVED_PACKET_SHA = None
WORKER_DEADLINE = 840

def idle(snapshot):
    rows = snapshot['rows_original']['rows']
    need(rows['active_jobs'] == rows['active_requests'] == [] and rows['historical_terminal_uncertain_count'] == 9, 'actual_wholeidle_history9')
    for name in ('glm-ab', 'qwen-a-c', 'image-turbo-c'):
        p = rows['profiles'][name]
        need(p['state'] == 'STOPPED' and p['owner'] is None and (type(p['generation']) is int) and (p['generation'] > 0), 'all_current_profiles_STOPPED_no_gen_invention')
    for n in rows['nodes']:
        need(n['hold_profile'] is n['hold_owner'] is n['hold_generation'] is None and n['quarantine'] == 0, 'all_current_Core_nodes_nohold_noQUAR')
    return snapshot

def unchanged(before, after, *, newmap=None, new_config_sha=None, delta=None):
    need(before['rows_original']['rows']['requests'] == after['rows_original']['rows']['requests'] and before['rows_original']['rows']['historical_terminal_uncertain_sha256'] == after['rows_original']['rows']['historical_terminal_uncertain_sha256'] and (before['commands']['canonical_utf8'] == after['commands']['canonical_utf8']) and (before['commands']['original_file_stat'] == after['commands']['original_file_stat']) and (before['Cleaf'] == after['Cleaf']) and (before['lease_full_F9'] == after['lease_full_F9']), 'exact_history_C3_Cleaf_original_lock')
    if newmap is None:
        need(before['source_files'] == after['source_files'] and before['config_sha256'] == after['config_sha256'] and (before['config_stat'] == after['config_stat']), 'before_CAS_full118_config_F9')
    else:
        need(after['current_source118'] == newmap and after['config_sha256'] == new_config_sha, 'new_current118_config_not_prior_epoch')
        source_delta.transition(before, after, delta)
    idle(after)

def transaction(native, packet_raw, clock=time.monotonic):
    need(APPROVED_PACKET_SHA is not None and sha(packet_raw) == APPROVED_PACKET_SHA, 'actual_packet_review_literal_pending')
    p = strict(packet_raw)
    newcfg = fixed_packet(p)
    end = clock() + WORKER_DEADLINE
    stops = starts = unlinks = 0
    committed = []
    lease = None
    created = False

    def check():
        need(clock() < end, 'whole_installer_absolute_deadline')

    def record(name, value):
        native.record(name, value)

    def command(argv, seconds):
        check()
        remaining = min(seconds, end - clock())
        need(remaining > 0, 'no_command_after_absolute_deadline')
        r = native.command(argv, remaining)
        record(name='command-' + str(native.command_count), value={'argv': argv, 'rc': r.returncode, 'stdout_raw_utf8': r.stdout.decode(), 'stderr_raw_utf8': r.stderr.decode(), 'observed_at': native.wall()})
        return r
    try:
        check()
        native.fixed_Root_identity()
        native.namespace_absent()
        ancestor = native.historical_ancestor(p)
        need(ancestor['state'] == 'NEGATIVE_RELEASED' and ancestor['CPU_success'] is False and (ancestor['ancestor_sha256'] == p['historical_ancestor_sha256']) and (ancestor['old_source118'] == p['historical_oldmap']), 'actual_R4_oldcfg_oldPID_old118_complete_ancestor')
        before = idle(native.capture(end, old=True))
        need(before['manager_identity'] == p['old_identity'] and before['current_source118'] == p['oldmap'] and (before['config_sha256'] == sha(p['old_config_raw_utf8'].encode())), 'old_current_actual_identity_before_stop')
        native.current_unarmed_idle(end)
        native.sealed_helpers(p)
        native.normal_unit_policy()
        native.await_prelaunch_before(p, before, end)
        prestart = native.prestart_helper_probe(p, end)
        native.create_state()
        created = True
        record('UID999-pure-cold-prestart', prestart)
        native.original_before = before
        record('intent', {'operation': EPOCH_OPERATION, 'packet_sha256': sha(packet_raw), 'ancestor': ancestor, 'before': before, 'normal_stop_calls_planned': 1, 'normal_start_calls_planned': 1, 'automatic_retry': False, 'automatic_rollback': False})
        native.backup_originals(p, before)
        later = idle(native.capture(end, old=True))
        unchanged(before, later)
        need(later['manager_identity'] == before['manager_identity'], 'same_live_old_epoch_before_stop')
        native.current_unarmed_idle(end)
        record('stop-intent', {'old_identity': before['manager_identity'], 'observed_at': native.wall()})
        stops = 1
        r = command(['/usr/bin/systemctl', 'stop', UNIT], 160)
        need(type(r.returncode) is int and r.returncode in (0, 1), 'bounded_normal_TERM_command_no_force_or_retry')
        stopped = native.stopped(before, end)
        native.no_other_manager()
        lease = native.lease()
        need(native.holders() == [native.pid()] and native.lock_F9() == before['lease_full_F9'], 'exact_original_lease_held_installer_only')
        record('current-AB-source-policy', {'AB_mutations': 0, 'node_source_pins': newcfg['node_source_pins']})
        dead = idle(native.capture_stopped(end))
        unchanged(before, dead)
        native.current_unarmed_idle(end)
        record('stopped', {'old_unit': stopped, 'current': dead, 'stop_calls': 1})
        native.await_prelaunch_after_stop(p, before, end)
        if before['socket'] is not None:
            native.dead_socket(before['socket'])
            record('socket-unlink-intent', before['socket'])
            native.unlink_socket(before['socket'])
            unlinks = 1
            record('socket-unlinked', {'calls': 1})
        else:
            record('socket-original-absent', {'calls': 0})
        for path, raw, row in source_delta.targets(p, APPROVED_SOURCE_DELTA):
            oldpin = row['old_sha256']
            check()
            native.verify_before_CAS(path, oldpin, before)
            record('CAS-' + str(len(committed) + 1) + '-intent', {'path': str(path), 'old_sha256': oldpin, 'new_sha256': sha(raw)})
            native.CAS(path, raw)
            committed.append(str(path))
            record('CAS-' + str(len(committed)) + '-completed', {'path': str(path), 'new_sha256': sha(raw)})
        native.sealed_helpers(p)
        native.verify_new_stopped(p, before, end)
        cfg = native.check_config(sha(p['new_config_raw_utf8'].encode()), newcfg['operation'], end)
        record('UID999-load_config', cfg)
        r = command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', str(native.BOOT), '--check'], 40)
        need(r.returncode == 0 and (not r.stderr) and (strict(r.stdout).get('ok') is True), 'actual_UID999_BOOTcheck_after_CAS_before_start')
        record('actual-C9-before-original-start', native.await_C9(p, before, end))
        native.verify_new_stopped(p, before, end)
        need(native.holders() == [native.pid()], 'own_original_lease_before_start')
        record('start-intent', {'new_config_sha256': sha(p['new_config_raw_utf8'].encode()), 'observed_at': native.wall()})
        native.release(lease)
        lease = None
        starts = 1
        r = command(['/usr/bin/systemctl', 'start', UNIT], 40)
        need(r.returncode == 0 and (not r.stderr), 'normal_start_failed_no_retry')
        now = native.wait_current(before, p, min(end, clock() + 40))
        unchanged(before, now, newmap=p['newmap'], new_config_sha=sha(p['new_config_raw_utf8'].encode()), delta=p['source_delta'])
        need(now['manager_identity']['pid'] != before['manager_identity']['pid'] and now['manager_identity']['boot_id'] == before['manager_identity']['boot_id'], 'new_sole_sameboot_not_pre_filled_PID')
        native.current_unarmed_idle(end)
        native.sealed_helpers(p)
        result = {'schema': source_delta.INSTALLED, 'operation': EPOCH_OPERATION, 'grant_operation': p['grant_operation'], 'review_sha256': p['review_sha256'], 'ancestor': ancestor, 'before': before, 'current': now, 'old_shutdown_original': stopped, 'noengine_before': native.prelaunch_before, 'noengine_after_stop': native.prelaunch_after_stop, 'normal_stop_calls': 1, 'normal_start_calls': 1, 'CAS_calls': len(native.cas_originals), 'socket_unlink_calls': unlinks, 'source_delta': p['source_delta'], 'cas_originals': native.cas_originals, 'unchanged_source_count': 118 - len(p['source_delta']['sources']), 'all_old_failures_preserved': True, 'models_started': 0, 'actual_retained_EXIT0_pending': True, 'observed_at': native.wall()}
        source_delta.verify_installed(result, APPROVED_SOURCE_DELTA)
        record('installed-unqualified', result)
        return result
    except BaseException as error:
        if created:
            record('failed', {'error_type': type(error).__name__, 'reason_code': 'finite_registry_epoch_failed', 'source_reason_code': source_reason(error), 'normal_stop_calls': stops, 'normal_start_calls': starts, 'socket_unlink_calls': unlinks, 'committed': committed, 'CAS_attempted': sorted(getattr(native, 'cas_started', set())), 'cas_originals': getattr(native, 'cas_originals', []), 'partial_preserved': True, 'automatic_retry': False, 'automatic_rollback': False, 'models_started': 0})
        raise
    finally:
        if lease is not None:
            native.release(lease)
