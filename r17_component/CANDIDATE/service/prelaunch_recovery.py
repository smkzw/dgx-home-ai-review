# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Qualified new source activation and one exact old prepayload failure release.
The old stage remains failed and its deadline remains expired. No work replay.
"""
import os, re
from pathlib import Path
from contract import *
OPERATION = EPOCH_OPERATION
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, exclusive
from current_epoch import consume as current
from recovered_history import consume as recovered
import legacy_stage
import pc_recovery
import prestart_history
import zero_recovery
import retired_family
APPROVED_POLICY_SHA = 'a34013d0240718a6f188682c9da36dbcff88ba48f0d5ce8179da6fd821a4f0f4'
APPROVED_QUALIFIER_SHA = '217a5cb2fd3970678f98da5feaa934aa53d249ec372a2db946914b4d75df0a1e'
ROOT = OPERATOR / ('asset-source-activation-' + OPERATION)

def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def consume(read, config, owner, now):
    h = recovered(now)
    q = current(read, config, owner, now)
    return {'state': 'SOURCE_EPOCH_READY', 'CPU_success': False, 'image_imported': False, 'historical_recovery': h, 'current_source': q, 'historical_only': True, 'requires_caller_fresh_current_idle': True}

class Recovery:

    def __init__(self, grant):
        self.g = grant
        self.s = grant.s
        self.released = False
        inv = os.environ.get('INVOCATION_ID', '')
        need(re.fullmatch('[0-9a-f]{32}', inv), 'actual_new_current_invocation')
        self.root = ROOT / inv
        if self.root.exists():
            self.s.restore_operator_block()

    def zero_source_context(self, body):
        g = self.g
        stages = g.asset_stages
        history = g.operator.negative_cpu_release
        need(g.prelaunch_recovery is self and history.pending and (not self.released) and (not g.active) and (g.deadline is None) and (stages.active is None) and (stages.zero_pending is not None) and stages.closed and (not stages.legacy_pending), 'zero_launch_actual_source_pending_only')
        need(set(body) == {'action', 'operation', 'request_nonce'} and body['action'] == 'activate-registry-source' and (body['operation'] == OPERATION) and (type(body['request_nonce']) is str) and re.fullmatch('[0-9a-f]{32}', body['request_nonce']), 'zero_launch_original_activation_Rootpeer_ABI')
        need(not self.root.exists(), 'new_PID_source_activation_once_no_duplicate_mkdir')
        source = consume(protected_read, g.config, identity(), g.runtime.manager._now())
        prior = stages.prestart_released
        need(prior == prestart_history.consume_released(g.config, protected_read), 'prestart_completed_history_still_original')
        need(prior and prior['historical_only'] is True, 'zero_launch_previous_ffc2_history_only_not_release')
        return (source, prior, legacy_stage.originals())

    def zero_recheck_source(self, source, prior, legacy):
        g = self.g
        need(consume(protected_read, g.config, identity(), g.runtime.manager._now()) == source, 'zero_launch_source_qualification_unchanged')
        need(prestart_history.consume_released(g.config, protected_read) == prior and legacy_stage.originals() == legacy, 'zero_launch_original_completed_histories_stable')

    def release(self, body):
        g = self.g
        history = g.operator.negative_cpu_release
        stages = g.asset_stages
        if stages.failed_owner_pending is not None:
            import history_reader
            return history_reader.owner_activate(self, body)
        if stages.zero_pending is not None:
            return zero_recovery.activate(self, body)
        need(history.pending and (not self.released) and (not g.active) and (g.deadline is None) and (not stages.closed) and (stages.active is None), 'source_activation_cannot_release_unknown_stage_hold')
        need(not self.root.exists(), 'new_PID_source_activation_once_no_duplicate_mkdir')
        source = consume(protected_read, g.config, identity(), g.runtime.manager._now())
        if stages.legacy_pending:
            completed = pc_recovery.release(stages, protected_read, identity(), g.runtime.manager._now())
            self.released = True
            return {'source_epoch_activated': True, 'operation': OPERATION, 'state': 'SOURCE_EPOCH_READY', 'prior_stage_state': completed['state'], 'prior_stage_historical_only': FIRST_ACTIVATION_HISTORICAL_ONLY, 'prior_stage_failure_released': FIRST_ACTIVATION_RELEASED, 'old_failure_preserved': True, 'image_imported': False, 'models_started': 0}
        retired = retired_family.consume(g, protected_read)
        need(retired == stages.retired_family and retired['historical_only'] is True and (retired['accepted_bytes'] == 0), 'R13_complete_retired_history_before_new_activation')
        prior = stages.prestart_released
        need(prior == prestart_history.consume_released(g.config, protected_read), 'prestart_completed_history_still_original')
        need(prior and prior['historical_only'] is True and (not stages.legacy_pending), 'R9_actual_released_history_not_new_negative')
        negative = prior
        legacy = legacy_stage.originals()
        with g.facade._lifecycle_lock:
            g.live_baseline = None
            proof = g.current('asset-source-activation-current', fenced=True)
            with g.s._lock:
                g.counters_locked()
                g.s.continue_operator_maintenance()
                g.same()
                g.current_epoch()
                need(legacy_stage.originals() == legacy, 'legacy_actor_originals_unchanged_before_normal_release')
                need(prestart_history.consume_released(g.config, protected_read) == prior, 'prestart_immutable_completion_not_raced')
                need(retired_family.consume(g, protected_read) == retired, 'R13_retired_history_not_raced_at_single_activation')
                if not ROOT.exists():
                    ROOT.mkdir(mode=448)
                    os.chmod(ROOT, 448)
                self.root.mkdir(mode=448)
                os.chmod(self.root, 448)
                activation_intent = {'schema': 'asset-source-current-activation-intent/v2', 'operation': OPERATION, 'current_identity': identity(), 'qualification': source, 'retired_family': retired, 'negative': negative, 'legacy_original': legacy, 'current': proof, 'request': body, 'automatic_retry': False, 'observed_at': g.runtime.manager._now()}
                exclusive(self.root / 'intent.json', activation_intent)
                try:
                    activation = {'schema': 'asset-source-current-activation-completed/v2', 'state': 'SOURCE_EPOCH_READY', 'operation': OPERATION, 'current_identity': identity(), 'source118': g.config['PC_source_pins'], 'qualification': source, 'retired_family': retired, 'negative_prior_stage': negative, 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'observed_at': g.runtime.manager._now()}
                    exclusive(self.root / 'completed.json', activation)
                    g.s.finish_operator_maintenance()
                    exclusive(self.root / 'fence-released.json', {'completed_sha256': sha(encode(activation)), 'operator_maintenance_observed': False, 'observed_at': g.runtime.manager._now()})
                    stages.legacy_pending = False
                    history.pending = False
                    self.released = True
                except BaseException:
                    g.s.restore_operator_block()
                    raise
        return {'source_epoch_activated': True, 'operation': OPERATION, 'state': 'SOURCE_EPOCH_READY', 'prior_stage_state': 'FAILED_REGISTRY_QUIESCENT', 'prior_stage_historical_only': True, 'prior_stage_failure_released': False, 'old_failure_preserved': True, 'image_imported': False, 'models_started': 0}

    def owner_source_context(self, body):
        g = self.g
        stages = g.asset_stages
        history = g.operator.negative_cpu_release
        need(g.prelaunch_recovery is self and history.pending and (not self.released) and (not g.active) and (g.deadline is None) and (stages.active is None) and (stages.failed_owner_pending is not None) and stages.closed and (not stages.legacy_pending), 'owner_new_source_pending_exact_state')
        need(set(body) == {'action', 'operation', 'request_nonce'} and body['action'] == 'activate-registry-source' and (body['operation'] == OPERATION) and (type(body['request_nonce']) is str) and re.fullmatch('[0-9a-f]{32}', body['request_nonce']), 'owner_new_activation_Rootpeer_ABI')
        need(not self.root.exists(), 'owner_source_activation_once_not_old_request_replay')
        source = consume(protected_read, g.config, identity(), g.runtime.manager._now())
        prior = stages.prestart_released
        need(prior == prestart_history.consume_released(g.config, protected_read) and prior and (prior['historical_only'] is True), 'owner_original_prior_released_history_only')
        return (source, prior, legacy_stage.originals())

    def owner_recheck_source(self, source, prior, legacy):
        g = self.g
        need(consume(protected_read, g.config, identity(), g.runtime.manager._now()) == source, 'owner_new_source_qualification_stable')
        need(prestart_history.consume_released(g.config, protected_read) == prior and legacy_stage.originals() == legacy, 'owner_prior_full_history_stable')

    def owner_create_root(self):
        need(os.getuid() == os.geteuid() == 999 and (not self.root.exists()), 'owner_service_once_activation_directory')
        if not ROOT.exists():
            ROOT.mkdir(mode=448)
            os.chmod(ROOT, 448)
        self.root.mkdir(mode=448)
        os.chmod(self.root, 448)

    def owner_decision_cold(self, stages):
        import history_reader
        return history_reader.owner_restore_decision_cold(self, stages)
