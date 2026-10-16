# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One fixed bind-before-launch owner recovery. No old actor or deadline rewrite.
Held-loaded by the existing Runtime; no caller proof, identity or callback slots.
"""
import os, stat
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read, exclusive
import not_launched_history as history
import zero_qualified
import late_scope_context
APPROVED_ACTOR_F9 = None
OLD_ACTOR_ROOT = None
OLD_STAGE = 'd8d0f06cc54a807f320d03813daf3b4b'
RECOVERY_ROOT = None
QUALIFIED_ROOT = '/opt/dgx-v4/hx/mimo-registry-native-r26-asset-protocol-r12'
APPROVED_REVIEW = '212c3637d398da75f62327b2840e3757b50242167d77b26654f034ad73e2b34a'

def originals(stages):
    pc, a, s = history.histories()
    h = history.history(pc, a, s)
    rows = stages._zero_actor_reader()
    need(set(rows) == set(h['PC']['files']) and all((rows[n] == history.row(v, [999, 989, 33152, 1]) for n, v in h['PC']['files'].items())), 'zero_launch_actual_held_actor3_unchanged')
    return (h, rows)

def runtime_identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def current(g, identity):
    g.same()
    g.current_epoch()
    need(g.config['review_sha256'] == APPROVED_REVIEW and identity == runtime_identity(), 'zero_launch_internal_Runtime_identity')
    return {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'manager_identity': identity, 'source118': g.config['PC_source_pins']}

def proof(stages, identity, now):
    need(QUALIFIED_ROOT is not None and APPROVED_REVIEW is not None, 'zero_launch_qualified_SOURCE_None')
    g = stages.g
    c = current(g, identity)
    raw, st = protected_read(Path(QUALIFIED_ROOT) / 'not-launched-qualified.json', limit=2097152)
    pc, a, _ = history.histories()
    t = late_scope_context.consume('historical-fixed', g, raw, st, None, now)
    h, rows = originals(stages)
    history.actor_match(t, h['plan'], rows)
    return (t, (raw, st))

def completed_history(stages):
    """Warm validation uses the original event time, never a refreshed permit."""
    root = Path(RECOVERY_ROOT) / history.APPROVED_POLICY['stage']
    names = sorted((x.name for x in root.iterdir()))
    need(names == ['completed.json', 'fence-released.json', 'intent.json', 'terminal.json'], 'zero_launch_recovery_exact_four_records')
    rows = stages._zero_records_reader(root)
    i, t, c, f = (strict(rows[n]) for n in ('intent.json', 'terminal.json', 'completed.json', 'fence-released.json'))
    need(i['stage_operation'] == t['stage_operation'] == c['stage_operation'] == f['stage_operation'] == history.APPROVED_POLICY['stage'] and i['state'] == t['state'] == c['state'] == history.STATE and (c['intent_sha256'] == sha(rows['intent.json'])) and (c['terminal_sha256'] == sha(rows['terminal.json'])) and (f['completed_sha256'] == sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (i['observed_at'] <= c['observed_at'] <= f['observed_at']), 'zero_launch_immutable_completed_causal_chain')
    raw, st = protected_read(Path(QUALIFIED_ROOT) / 'not-launched-qualified.json', limit=2097152)
    v = strict(raw)
    pc, a, _ = history.histories()
    check = late_scope_context.consume_history('historical-fixed', stages.g, raw, st, None, i['observed_at'])
    need(check == t and i['proof_sha256'] == sha(raw) and (i['qualified_F9'] == st) and (i['current'] == v['current']) and (v['current']['config_sha256'] == stages.g.config['_config_sha256']) and (v['current']['source118'] == stages.g.config['PC_source_pins']), 'zero_launch_historical_proof_event_time_not_future_authority')
    h, actor = originals(stages)
    history.actor_match(t, h['plan'], actor)
    need(c['protected_ranges'] == [] and c['GET'] == 0 and (c['aggregate_exit_status'] is None), 'zero_launch_range_release_only_no_launch')
    return c

def initialise(stages, actor_reader, records_reader):
    """Integrator passes only held source-bound FD readers, never request JSON.
 Existing stage_originals(root,stage) is the exact service999 actor reader.
 """
    need(RECOVERY_ROOT is not None and QUALIFIED_ROOT is not None, 'zero_launch_recovery_SOURCE_None')
    stages._zero_actor_reader = actor_reader
    stages._zero_records_reader = records_reader
    h, _ = originals(stages)
    stages.zero_spent = {h['stage_operation']}
    folder = Path(RECOVERY_ROOT) / h['stage_operation']
    if folder.exists():
        completed_history(stages)
        stages.zero_pending = None
    else:
        need(not any((a['digest'] == b['digest'] and max(a['start'], b['start']) < min(a['start'] + a['count'], b['start'] + b['count']) for a in stages.used for b in h['plan']['ranges'])), 'zero_launch_pending_no_foreign_overlap')
        stages.used.extend(h['plan']['ranges'])
        stages.zero_pending = h
        stages.closed = True
        stages.g.s.restore_operator_block()

def activate(recovery, body):
    """Only RegistryGrant.activate_source -> actual Recovery.release under g.lock.
 One source qualification and one scheduler finish; no second stage action.
 """
    g = recovery.g
    stages = g.asset_stages
    h = stages.zero_pending
    need(g.lock.locked() and g.prelaunch_recovery is recovery, 'zero_launch_existing_activation_private_lock')
    source, prior, legacy = recovery.zero_source_context(body)
    now = g.runtime.manager._now()
    identity = runtime_identity()
    t, original = proof(stages, identity, now)
    root = Path(RECOVERY_ROOT)
    target = root / h['stage_operation']
    with g.facade._lifecycle_lock:
        g.live_baseline = None
        fresh = g.current('zero-launch-source-activation-current', fenced=True)
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            g.same()
            g.current_epoch()
            recovery.zero_recheck_source(source, prior, legacy)
            again, held = proof(stages, identity, g.runtime.manager._now())
            need(again == t and held == original, 'zero_launch_final_real_now_same_whole30')
            need(os.getuid() == os.geteuid() == 999 and (not target.exists()) and (not recovery.root.exists()), 'zero_launch_service999_once_not_retry')
            if not root.exists():
                root.mkdir(mode=448)
                os.chmod(root, 448)
            z = root.lstat()
            need(stat.S_ISDIR(z.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (999, 989, 448), 'zero_launch_private_recovery_parent')
            target.mkdir(mode=448)
            if not recovery.root.parent.exists():
                recovery.root.parent.mkdir(mode=448)
                os.chmod(recovery.root.parent, 448)
            recovery.root.mkdir(mode=448)
            os.chmod(recovery.root, 448)
            i = {'schema': 'fixed-image-zero-launch-recovery-intent/v1', 'stage_operation': h['stage_operation'], 'state': history.STATE, 'proof_sha256': sha(original[0]), 'qualified_F9': original[1], 'current': strict(original[0])['current'], 'observed_at': g.runtime.manager._now(), 'original_deadline_monotonic': h['original_deadline'], 'work_deadline_extended': False}
            exclusive(target / 'intent.json', i)
            try:
                activation_intent = {'schema': 'asset-source-zero-launch-activation-intent/v1', 'operation': body['operation'], 'current_identity': identity, 'qualification': source, 'previous_released_history': prior, 'legacy_original': legacy, 'current': fresh, 'request': body, 'zero_intent_sha256': sha(encode(i)), 'automatic_retry': False, 'observed_at': g.runtime.manager._now()}
                exclusive(recovery.root / 'intent.json', activation_intent)
                exclusive(target / 'terminal.json', t)
                c = {'schema': 'fixed-image-zero-launch-completed/v1', 'stage_operation': h['stage_operation'], 'state': history.STATE, 'intent_sha256': sha(encode(i)), 'terminal_sha256': sha(encode(t)), 'protected_ranges': [], 'GET': 0, 'aggregate_exit_status': None, 'observed_at': g.runtime.manager._now(), 'original_deadline_monotonic': h['original_deadline'], 'work_deadline_extended': False}
                exclusive(target / 'completed.json', c)
                activation = {'schema': 'asset-source-zero-launch-activation-completed/v1', 'state': 'SOURCE_EPOCH_READY', 'operation': body['operation'], 'current_identity': identity, 'source118': g.config['PC_source_pins'], 'qualification': source, 'zero_completed_sha256': sha(encode(c)), 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'observed_at': g.runtime.manager._now()}
                exclusive(recovery.root / 'completed.json', activation)
                recovery.zero_recheck_source(source, prior, legacy)
                proof(stages, identity, g.runtime.manager._now())
                g.s.finish_operator_maintenance()
                stamp = g.runtime.manager._now()
                exclusive(target / 'fence-released.json', {'stage_operation': h['stage_operation'], 'completed_sha256': sha(encode(c)), 'operator_maintenance_observed': False, 'observed_at': stamp})
                exclusive(recovery.root / 'fence-released.json', {'completed_sha256': sha(encode(activation)), 'operator_maintenance_observed': False, 'observed_at': stamp})
                stages.used = history.remaining_protected(stages.used, h['plan']['ranges'], t)
                stages.zero_pending = None
                stages.closed = False
                stages.legacy_pending = False
                g.operator.negative_cpu_release.pending = False
                recovery.released = True
                g.live_baseline = None
            except BaseException:
                g.s.restore_operator_block()
                raise
    return {'source_epoch_activated': True, 'operation': body['operation'], 'state': 'SOURCE_EPOCH_READY', 'prior_stage_state': history.STATE, 'prior_stage_historical_only': False, 'prior_stage_failure_released': True, 'old_failure_preserved': True, 'image_imported': False, 'models_started': 0, 'zero_completion': c}
