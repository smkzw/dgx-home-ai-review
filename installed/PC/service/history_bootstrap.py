# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""No bf84 retry or second Bridge: fully qualified R4 history at sole startup."""
import os
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, protected_read, sha, strict, exclusive
from ancestor import consume
from contract import PC_ROOT, OPERATOR, EPOCH_OPERATION
APPROVED_OLD_CONFIG_SHA = '2939e9ccdb2bf7824c5aa0131c2361dadf958d7e3961223f0a5f00fb06b62ac2'
APPROVED_OLD_IDENTITY = {'boot_id': 'redacted-2606f3e07a03', 'invocation_id': '00e0dc737d47d6039a7edd3ed288fa34', 'pid': 833356, 'start_ticks': '14311588'}
APPROVED_NEW_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
OLD_CONFIG = Path('/opt/dgx-v4/hx/mimo-registry-native-r26/historical/raw/old-config')

def historical(now):
    need(APPROVED_OLD_CONFIG_SHA is not None and APPROVED_OLD_IDENTITY is not None, 'actual_R4_history_pending')
    raw, st = protected_read(OLD_CONFIG)
    need(sha(raw) == APPROVED_OLD_CONFIG_SHA and st[3:7] == [0, 989, 33056, 1], 'actual_qualified_old_config_readable_Root_original')
    return consume(protected_read, raw, APPROVED_OLD_IDENTITY, now)

class HistoricalNegative:

    def __init__(self, runtime, lease, c, bridge):
        self.runtime, self.lease, self.bridge = (runtime, lease, bridge)
        self.scheduler = runtime.server.scheduler
        need(runtime is bridge.runtime and lease is bridge.lease and (self.scheduler is bridge.scheduler) and (c['review_sha256'] == APPROVED_NEW_REVIEW) and (bridge.active is False) and (bridge.deadline is None), 'one_sole_factory_no_old_reserve_resume')
        self.original = historical(runtime.manager._now())
        inv = os.environ.get('INVOCATION_ID', '')
        need(__import__('re').fullmatch('[0-9a-f]{32}', inv), 'actual_restart_invocation')
        self.root = OPERATOR / ('registry-source-r26-r8-' + inv)
        self.pending = True
        with self.scheduler._lock:
            s = self.scheduler
            need(not (s._operator_tick_inflight or s._operator_public_inflight or s._operator_creative_pulse_inflight or (s._creative is not None) or s._infos or any(s._queues.values()) or any(s._active.values()) or s._uncertain or s._ensuring or s._dispatch_checks or s._draining), 'sole_factory_before_serving_all_counters_empty')
            for name in ('glm-ab', 'qwen-a-c', 'image-turbo-c'):
                row = runtime.control_store.profile_view(name)
                need(row['state'] == 'STOPPED' and row['owner'] is None and (type(row['generation']) is int) and (row['generation'] > 0), 'actual_store_nohold_not_history_bool')
            for row in runtime.control_store.nodes_view():
                need(row['hold_profile'] is row['hold_owner'] is row['hold_generation'] is None and row['quarantined'] is False, 'actual_store_nodes_not_released_by_bootstrap')
            need(s._operator_maintenance is True, 'only_original_Bridge_historical_block')
            s.continue_operator_maintenance()
            s.finish_operator_maintenance()
            s.begin_operator_maintenance()
            if not self.root.exists():
                self.root.mkdir(mode=448)
                exclusive(self.root / 'pending.json', {'schema': 'registry-R26-source-pending/v1', 'operation': EPOCH_OPERATION, 'new_config_sha256': c['_config_sha256'], 'manager_pid': os.getpid(), 'ancestor_sha256': self.original['ancestor_sha256'], 'observed_at': runtime.manager._now()})
        self.consumed = True

    def release(self, *args):
        raise RuntimeError('original_bf84_negative_once_consumed_no_replay')

    def status(self, body, uid):
        need(type(uid) is int and uid == 0 and (body['action'] == 'status-negative-mimo-metadata'), 'Root_historical_readonly_only')
        return {'schema': 'registry-R26-old-negative-history-only/v1', 'state': 'NEGATIVE_RELEASED', 'CPU_success': False, 'historical_only': True, 'manager_identity': self.original['old_manager_identity'], 'receipt_sha256': self.original['receipt_sha256'], 'observed_at': self.runtime.manager._now()}
