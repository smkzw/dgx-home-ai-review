# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Sequential fixed-image stage lifecycle on the existing sole Runtime locks."""
import os, re, time, threading, math, stat
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read, exclusive, HeldParent, metadata, directory_identity
from contract import PC_ROOT, OPERATION, OPERATOR
from asset_segments import exact_ranges, APPROVED_LEGACY_REFS
import legacy_stage
import zero_recovery
import current_prebind
import empty_range_repair
import retired_family
import history_reader as epoch_asset_history_bridge
import prestart_history
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
PLAN_ROOT = PC_ROOT / 'asset-plans'
STATE_ROOT = OPERATOR / 'fixed-image-asset-stages-role-context-r14'
ACTIONS = frozenset(('reserve-asset-stage', 'pulse-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage'))
ACTIONS = ACTIONS | frozenset((current_prebind.PREPARE, current_prebind.FINISH, empty_range_repair.PREPARE))
BUDGET = {'CPU': 1, 'memory_bytes': 4294967296, 'swap_bytes': 0, 'tasks': 256, 'io_read_bytes_per_second': 62914560, 'io_write_bytes_per_second': 62914560}

def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def plan(read, stage, config, current, now):
    need(APPROVED_REVIEW is not None and type(stage) is str and re.fullmatch('[0-9a-f]{32}', stage) and (stage != OPERATION), 'unique_finite_stage_operation')
    raw, st = read(PLAN_ROOT / (stage + '.json'), limit=2097152)
    p = strict(raw)
    need(st[3:7] == [0, 989, 33056, 1] and type(p) is dict and (set(p) == {'schema', 'operation_family', 'stage_operation', 'review_sha256', 'manager_identity', 'config_sha256', 'source118_sha256', 'ranges', 'duration_seconds', 'parent_intent_original', 'created_at', 'PC_plan_monotonic', 'PC_plan_deadline_monotonic', 'automatic_retry'}), 'Root_protected_stage_plan_exact_schema')
    need(p['schema'] == 'fixed-image-finite-asset-stage-plan/v1' and p['operation_family'] == OPERATION and (p['stage_operation'] == stage) and (p['review_sha256'] == APPROVED_REVIEW) and (p['manager_identity'] == current) and (p['config_sha256'] == config['_config_sha256']) and (p['source118_sha256'] == sha(encode(config['PC_source_pins']))) and (p['automatic_retry'] is False), 'stage_plan_current_runtime_not_historical_permit')
    need(type(p['duration_seconds']) is int and 1 <= p['duration_seconds'] <= 1800 and (type(p['created_at']) in (int, float)) and math.isfinite(p['created_at']) and (0 <= now - p['created_at'] <= 90), 'finite_plan_duration_and_local_publication_age')
    exact_ranges(p['ranges'])
    ref = p['parent_intent_original']
    need(type(ref) is dict and set(ref) == {'raw_b64', 'sha256', 'F9'}, 'actual_parent_intent_original')
    rawparent = __import__('base64').b64decode(ref['raw_b64'], validate=True)
    v = strict(rawparent)
    s = ref['F9']
    need(sha(rawparent) == ref['sha256'] and type(s) is list and (len(s) == 9) and (s[2] == len(rawparent)) and (s[3:7] == [501, 20, 33152, 1]) and (v['operation'] == OPERATION) and (v['current_context']['stage_operation'] == stage) and (v['current_context']['review_sha256'] == APPROVED_REVIEW) and (v['current_context']['config_sha256'] == config['_config_sha256']) and (v['current_context']['manager_identity'] == current) and (v['automatic_retry'] is False) and (type(v['whole_seconds']) is int) and (0 < v['whole_seconds'] <= 1800) and (v['deadline_monotonic'] - v['monotonic_origin'] == v['deadline_wall'] - v['issued_at'] == v['whole_seconds']), 'paired_original_parent_window_bound_not_bool')
    need(all((type(p[k]) in (int, float) and math.isfinite(p[k]) for k in ('PC_plan_monotonic', 'PC_plan_deadline_monotonic'))) and p['PC_plan_deadline_monotonic'] - p['PC_plan_monotonic'] == p['duration_seconds'] and (0 <= time.monotonic() - p['PC_plan_monotonic'] <= 90) and (time.monotonic() < p['PC_plan_deadline_monotonic']), 'original_PC_stage_plan_deadline_no_rebase')
    return (p, {'path': str(PLAN_ROOT / (stage + '.json')), 'sha256': sha(raw), 'F9': st})

def stage_originals(root, stage):
    need(re.fullmatch('[0-9a-f]{32}', stage), 'fixed_stage_history_name')
    allowed = {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'}
    with HeldParent(root, legacy=True) as chain:
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        sub = None
        try:
            rd = directory_identity(os.fstat(fd))
            need(rd[2:] == (999, 989, 16832), 'stage_root_service_identity')
            sub = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            sd = directory_identity(os.fstat(sub))
            need(sd[2:] == (999, 989, 16832), 'stage_directory_service_identity')
            names = sorted(os.listdir(sub))
            rows = {}
            for name in names:
                need(name in allowed or re.fullmatch('pulse-[1-9][0-9]{0,3}.json', name), 'stage_exact_original_leaf')
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sub)
                try:
                    before = metadata(os.fstat(leaf))
                    need(before[3:7] == [999, 989, 33152, 1] and 0 <= before[2] <= 4194304, 'stage_original_service_fullF9')
                    raw = os.pread(leaf, before[2] + 1, 0)
                    need(len(raw) == before[2] and before == metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=sub, follow_symlinks=False)), 'stage_original_held_named_F9')
                    rows[name] = raw
                finally:
                    os.close(leaf)
            need(names == sorted(os.listdir(sub)) and sd == directory_identity(os.fstat(sub)) == directory_identity(os.stat(stage, dir_fd=fd, follow_symlinks=False)) and (rd == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf())), 'stage_original_directory_identity_and_entries')
            chain.recheck()
            return rows
        finally:
            if sub is not None:
                os.close(sub)
            os.close(fd)

def zero_actor_records():
    root = Path(zero_recovery.OLD_ACTOR_ROOT)
    with HeldParent(root, legacy=True) as chain:
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            before = directory_identity(os.fstat(fd))
            need(before[2:] == (999, 989, 16832) and sorted(os.listdir(fd)) == [zero_recovery.OLD_STAGE], 'zero_launch_no_foreign_pending_namespace')
            pins = zero_recovery.APPROVED_ACTOR_F9
            need(type(pins) is dict and set(pins) == {'intent.json', 'reserved.json', 'pulse-1.json'}, 'zero_launch_pinned_old_actor_F9_None')
            sub = os.open(zero_recovery.OLD_STAGE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                need(all((metadata(os.stat(n, dir_fd=sub, follow_symlinks=False)) == f for n, f in pins.items())), 'zero_launch_old_actor_original_F9_before')
                rows = stage_originals(root, zero_recovery.OLD_STAGE)
                need(all((metadata(os.stat(n, dir_fd=sub, follow_symlinks=False)) == f for n, f in pins.items())), 'zero_launch_old_actor_original_F9_after')
            finally:
                os.close(sub)
            need(sorted(os.listdir(fd)) == [zero_recovery.OLD_STAGE] and before == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf()), 'zero_launch_parent_directory_stable')
            chain.recheck()
            return rows
        finally:
            os.close(fd)

class Stages:

    def __init__(self, grant, terminal, read=protected_read, root=STATE_ROOT):
        self.used = []
        self.empty_repair_grants = set()
        self.failed_owner_pending = None
        self.g, self.terminal, self.read, self.root = (grant, terminal, read, root)
        self.active = None
        self.closed = False
        self.legacy_originals = legacy_stage.originals(read)
        self.legacy_prior_release = legacy_stage.prior_released(grant.config)
        self.prestart_released = prestart_history.consume_released(grant.config, read)
        self.legacy_pending = self.prestart_released is None
        self.pending_stage_history = prestart_history.pending_originals(read)['history'] if self.legacy_pending else None
        if self.legacy_pending:
            self.g.s.restore_operator_block()
        self.epoch_asset_history = epoch_asset_history_bridge.load(grant.config)
        self.epoch_asset_history.require_complete_old_set([x.name for x in root.iterdir()] if root.exists() else [], root)
        if root.exists():
            need(root.is_dir() and (not root.is_symlink()), 'actual_stage_history_directory')
            need(len(list(root.iterdir())) <= 4096, 'bounded_stage_history_namespaces')
            for sub in sorted(root.iterdir()):
                need(sub.is_dir() and re.fullmatch('[0-9a-f]{32}', sub.name), 'fixed_stage_history_namespace')
                entries = {p.name for p in sub.iterdir()}
                done = sub / 'fence-released.json'
                if not {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'} <= entries:
                    if sub.name == epoch_asset_history_bridge.owner_policy()['stage']:
                        epoch_asset_history_bridge.owner_initialise(self)
                        continue
                    self.g.s.restore_operator_block()
                    self.closed = True
                    continue
                data = stage_originals(root, sub.name)
                need(all((n in {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'} or re.fullmatch('pulse-[1-9][0-9]*.json', n) for n in entries)), 'stage_history_exact_entries')
                if sub.name == epoch_asset_history_bridge.owner_policy()['stage']:
                    epoch_asset_history_bridge.owner_history(self, sub.name, data)
                    continue
                if sub.name in epoch_asset_history_bridge.owner_policy()['old_completed']:
                    epoch_asset_history_bridge.owner_completed_history(self, sub.name, data)
                    continue
                if current_prebind.is_record(data):
                    current_prebind.historical(self, sub.name, data)
                    continue
                empty_range_repair.history(self, sub.name, data, self.empty_repair_grants)
                self.used.extend(strict(data['intent.json'])['plan']['ranges'])
                i, c, m = (strict(data[n]) for n in ('intent.json', 'completed.json', 'fence-released.json'))
                t = self.epoch_asset_history.consume(sub.name, data, {n: metadata((sub / n).lstat()) for n in data}) if self.epoch_asset_history.has(sub.name) else self.terminal(sub.name, historical=True)
                need(encode(t) == data['terminal.json'] and c['terminal_sha256'] == sha(data['terminal.json']) and (m['completed_sha256'] == sha(data['completed.json'])) and (m['operator_maintenance_observed'] is False) and (c['stage_operation'] == i['stage_operation'] == sub.name) and (c['state'] in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT')) and (c['image_imported'] is False), 'historical_completed_stage_not_future_current_qualification')
        self.retired_family = retired_family.consume(grant, read)
        self.zero_spent = {'d8d0f06cc54a807f320d03813daf3b4b', '0177b4f7d21426f8ab8b6c3142b347c9'}
        self.zero_pending = None

    def command(self, body, uid):
        action = body.get('action')
        need(uid == 0 and type(uid) is int and (type(body) is dict) and (set(body) == {'action', 'operation', 'stage_operation', 'request_nonce'}) and (action in ACTIONS) and (body['operation'] == OPERATION) and re.fullmatch('[0-9a-f]{32}', body['request_nonce']) and re.fullmatch('[0-9a-f]{32}', body['stage_operation']), 'fixed_stage_Rootpeer_command')
        g = self.g
        need(g.lock.acquire(False), 'same_private_operation_lock')
        try:
            g.same()
            if action == 'status-asset-stage':
                pending = self.pending_stage_history if self.legacy_pending else None
                owner = self.failed_owner_pending
                return {'stage_operation': body['stage_operation'], 'active': self.active is not None or self.legacy_pending or owner is not None, 'sticky': self.closed or self.legacy_pending, 'legacy_failure_pending': self.legacy_pending, 'models_started': 0, 'maintenance_held': g.s._operator_maintenance, 'release_required': self.legacy_pending or self.active is not None or self.closed, 'active_stage_operation': self.active['stage_operation'] if self.active is not None else pending['stage_operation'] if pending is not None else owner['stage_operation'] if owner is not None else None, 'original_deadline_monotonic': self.active['deadline'] if self.active is not None else pending['deadline_monotonic'] if pending is not None else owner['original_deadline_monotonic'] if owner is not None else None, 'old_actor_sha256': sha(encode(pending['actor'])) if pending is not None else None, 'next_legal_action': 'activate-registry-source_with_fresh_failed_owner_terminal_qualification' if owner is not None else 'activate-registry-source_with_fresh_NOT_LAUNCHED_qualified' if self.legacy_pending else 'finish_matching_stage_with_actual_terminal' if self.active is not None else 'inspect_unresolved_history' if self.closed else 'new_disjoint_stage'}
            need(self.failed_owner_pending is None, 'owner_pending_only_new_source_activation_no_asset_action')
            if action == 'finish-failed-asset-stage' and self.zero_pending is not None:
                need(False, 'zero_launch_release_only_via_source_activation')
            if action == empty_range_repair.PREPARE:
                return empty_range_repair.prepare(self, body)
            if action == 'reserve-asset-stage':
                return self.reserve(body)
            need(self.active is not None and self.active['stage_operation'] == body['stage_operation'], 'same_existing_stage_not_new_window')
            if action == current_prebind.PREPARE:
                return current_prebind.prepare(self, body)
            if action == current_prebind.FINISH:
                return self.finish(body, True)
            if action in ('finish-asset-stage', 'finish-failed-asset-stage'):
                return self.finish(body, action == 'finish-failed-asset-stage')
            need(not self.closed and g.clock() < self.active['deadline'], 'stage_work_expired_sticky')
            return self.pulse(body)
        except BaseException:
            if self.active is not None:
                g.s.restore_operator_block()
                self.closed = True
            raise
        finally:
            g.lock.release()

    def reserve(self, b):
        need(b['stage_operation'] not in self.zero_spent, 'zero_launch_old_operation_remains_spent')
        g = self.g
        need(self.active is None and (not self.closed) and (not self.legacy_pending) and (not g.active) and (not g.closed) and (not g.operator.negative_cpu_release.pending), 'single_sole_maintenance_operation')
        current = g.current_epoch()
        p, ref = plan(self.read, b['stage_operation'], g.config, identity(), g.runtime.manager._now())
        folder = self.root / b['stage_operation']
        need(not folder.exists(), 'new_finite_stage_not_replay')
        if not self.root.exists() or not list(self.root.iterdir()):
            need(b['stage_operation'] == 'b7a518bbefa903b6c43c44b9a2f6f6cf' and p['ranges'] == [{'count': 462849, 'digest': '2ed23d91404d4701b704d1bde211c59a2a564a31c315f05871a6e9403bc19945', 'start': 6291456}], 'R13_first_independent_suffix_only_not_blind_retry')
        repair = empty_range_repair.admit(self, b['stage_operation'], p, ref, identity(), g.runtime.manager._now())
        protected = list(self.used)
        legacy_protected = [{'digest': r['digest'], 'start': r['start'], 'count': r['count']} for r in APPROVED_LEGACY_REFS]
        need(all((all((empty_range_repair.permitted(repair, a, z) for z in protected)) and all((not empty_range_repair.overlap(a, z) for z in legacy_protected)) for a in p['ranges'])), 'disjoint_all_completed_and_preserved_intervals_or_exact_typed_empty_grant')
        ready = self.terminal(b['stage_operation'], readiness=True)
        need(ready['state'] == 'ASSET_STAGE_READY' and ready['stage_operation'] == b['stage_operation'] and (ready['plan_sha256'] == ref['sha256']), 'fresh_stage_source_resource_readiness')
        with g.facade._lifecycle_lock:
            g.live_baseline = None
            before = g.current('asset-stage-before', fenced=False)
            with g.s._lock:
                g.counters_locked()
                need(not g.s._operator_maintenance, 'stage_no_old_or_foreign_hold')
                if not self.root.exists():
                    self.root.mkdir(mode=448)
                    os.chmod(self.root, 448)
                repair = empty_range_repair.recheck(self, repair)
                folder.mkdir(mode=448)
                os.chmod(folder, 448)
                deadline = p['PC_plan_deadline_monotonic']
                self.active = {'stage_operation': b['stage_operation'], 'root': folder, 'plan': p, 'plan_ref': ref, 'deadline': deadline, 'ordinal': 0, 'reserved': None, 'runtime_seconds': max(1, int(deadline - g.clock()))}
                self.used.extend(p['ranges'])
                exclusive(folder / 'intent.json', {'schema': 'fixed-image-finite-stage-intent/v1', 'operation_family': OPERATION, 'stage_operation': b['stage_operation'], 'plan': p, 'plan_ref': ref, 'source_release_sha256': APPROVED_REVIEW, 'duration_seconds': p['duration_seconds'], 'deadline_monotonic': deadline, 'current_qualification': current, 'before': before, 'request': b, 'empty_repair': repair, 'automatic_retry': False, 'issued_at': g.runtime.manager._now()})
                g.s.begin_operator_maintenance()
            after = g.current('asset-stage-reserved', fenced=True)
            with g.s._lock:
                g.counters_locked()
                g.s.continue_operator_maintenance()
                need(g.clock() < deadline, 'stage_prepare_consumes_original_window')
                v = {'stage_operation': b['stage_operation'], 'plan_ref': ref, 'deadline_monotonic': deadline, 'budget': dict(BUDGET, runtime_seconds=self.active['runtime_seconds']), 'after': after, 'observed_at': g.runtime.manager._now()}
                self.active['reserved'] = v
                exclusive(folder / 'reserved.json', v)
                return v

    def pulse(self, b):
        g = self.g
        a = self.active
        proof = g.current('asset-stage-pulse', fenced=True)
        source = g.collector.source_and_lease()
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            g.same()
            need(g.clock() < a['deadline'], 'stage_original_deadline')
            a['ordinal'] += 1
            p = {'schema': 'sole-Manager-private-CPU-reservation-pulse/v1', 'operation': OPERATION, 'source_release_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'ordinal': a['ordinal'], 'request_nonce': b['request_nonce'], 'manager_epoch_sha256': sha(encode(g.config['PC_source_pins'])), 'budget': dict(BUDGET, runtime_seconds=a['runtime_seconds']), 'remaining_seconds': a['deadline'] - g.clock(), 'manager_source': source, 'clear_reservation_original': a['reserved'], 'clear_reservation_sha256': sha(encode(a['reserved'])), 'observed_at': g.runtime.manager._now()}
            exclusive(a['root'] / ('pulse-' + str(a['ordinal']) + '.json'), p)
            return p

    def finish(self, b, failed):
        if b['action'] == current_prebind.FINISH:
            return current_prebind.finish(self, b)
        g = self.g
        a = self.active
        t = self.terminal(b['stage_operation'])
        state = 'FAILED_REGISTRY_QUIESCENT' if failed else 'ASSET_STAGE_COMPLETED'
        need(t['state'] == state and t['stage_operation'] == a['stage_operation'] and (t['plan_sha256'] == a['plan_ref']['sha256']) and (t['image_imported'] is False) and (t['models_started'] == 0), 'actual_stage_terminal_state_no_import_success')
        rows = stage_originals(self.root, a['stage_operation'])
        pulses = {n for n in rows if re.fullmatch('pulse-[1-9][0-9]*.json', n)}
        need(set(rows) == {'intent.json', 'reserved.json'} | pulses and sorted((int(n[6:-5]) for n in pulses)) == list(range(1, a['ordinal'] + 1)), 'stage_exact_original_records_before_finish')
        intent = strict(rows['intent.json'])
        reserved = strict(rows['reserved.json'])
        need(intent['plan'] == a['plan'] and intent['plan_ref'] == a['plan_ref'] and (intent['deadline_monotonic'] == a['deadline']) and (reserved == a['reserved']) and (reserved['deadline_monotonic'] == a['deadline']), 'stage_original_deadline_reservation_not_rebased')
        context = strict(__import__('base64').b64decode(t['context_original']['raw_b64'], validate=True))
        first = context['initial_pulse_original']
        original = __import__('base64').b64decode(first['original_raw_b64'], validate=True)
        pulse = strict(original)
        need(sha(original) == first['original_sha256'] and pulse['clear_reservation_original'] == reserved and (pulse['clear_reservation_sha256'] == sha(encode(reserved))) and ('pulse-' + str(pulse['ordinal']) + '.json' in rows) and (rows['pulse-' + str(pulse['ordinal']) + '.json'] == original), 'stage_terminal_context_actual_owned_pulse')
        with g.facade._lifecycle_lock:
            g.current_epoch()
            proof = g.current('asset-stage-after-terminal', fenced=True)
            with g.s._lock:
                g.counters_locked()
                g.s.continue_operator_maintenance()
                g.same()
                exclusive(a['root'] / 'terminal.json', t)
                d = {'schema': 'fixed-image-finite-stage-completed/v1', 'stage_operation': a['stage_operation'], 'state': state, 'terminal_sha256': sha(encode(t)), 'current': proof, 'original_deadline_monotonic': a['deadline'], 'work_deadline_extended': False, 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'finished_at': g.runtime.manager._now()}
                exclusive(a['root'] / 'completed.json', d)
                try:
                    g.s.finish_operator_maintenance()
                    exclusive(a['root'] / 'fence-released.json', {'stage_operation': a['stage_operation'], 'completed_sha256': sha(encode(d)), 'operator_maintenance_observed': False, 'observed_at': g.runtime.manager._now()})
                except BaseException:
                    g.s.restore_operator_block()
                    raise
                self.active = None
                self.closed = False
                g.live_baseline = None
                return d
