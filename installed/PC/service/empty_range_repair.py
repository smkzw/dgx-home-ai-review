# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit finite same-family repair of exactly proven empty failed intervals.

The used list and failed actors are never removed or rewritten. A new protected
Root contract, private actor and fresh typed receipt are required per new op.
This module does not create a work window, retry, release, or modify SQL.
"""
import base64, math, os, re, stat
import history_reader
from pathlib import Path
from contract import PC_ROOT, OPERATION, OPERATOR, APPROVED_REVIEW
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read, exclusive, HeldParent, directory_identity, metadata
from receipt_codec import pack, unpack
PREPARE = 'prepare-empty-asset-range-repair'
CONTRACT_ROOT = PC_ROOT / 'asset-empty-repair-contracts'
QUALIFIED_ROOT = PC_ROOT / 'asset-empty-repairs'
REQUEST_ROOT = OPERATOR / ('asset-empty-repair-' + OPERATION)
STATE = 'FAILED_EMPTY_RANGE_QUIESCENT'

def overlap(a, b):
    return a['digest'] == b['digest'] and max(a['start'], b['start']) < min(a['start'] + a['count'], b['start'] + b['count'])

def contract(stages, stage, plan, plan_ref, owner, now):
    raw, s = stages.read(CONTRACT_ROOT / (stage + '.json'), limit=2097152)
    v = strict(raw)
    need(s[3:7] == [0, 989, 33056, 1] and set(v) == {'schema', 'operation', 'stage_operation', 'source_review', 'config_sha256', 'source118', 'manager_identity', 'plan_sha256', 'ranges', 'prior_stages', 'created_at', 'PC_monotonic_origin', 'PC_deadline_monotonic', 'duration_seconds', 'automatic_retry'} and (v['schema'] == 'explicit-finite-failed-empty-range-repair/v1') and (v['operation'] == OPERATION) and (v['stage_operation'] == stage) and (v['source_review'] == APPROVED_REVIEW) and (v['config_sha256'] == stages.g.config['_config_sha256']) and (v['source118'] == stages.g.config['PC_source_pins']) and (v['manager_identity'] == owner) and (v['plan_sha256'] == plan_ref['sha256']) and (v['ranges'] == plan['ranges']) and (v['automatic_retry'] is False), 'empty_repair_explicit_finite_Root_contract_not_bool')
    need(len(v['ranges']) == 1 and type(v['prior_stages']) is list and (0 < len(v['prior_stages']) <= 32) and (v['prior_stages'] == sorted(set(v['prior_stages']))) and (stage not in v['prior_stages']) and all((type(x) is str and re.fullmatch('[0-9a-f]{32}', x) for x in v['prior_stages'])), 'empty_repair_one_exact_interval_all_ancestors_bound')
    need(all((type(v[k]) in (int, float) and math.isfinite(v[k]) for k in ('created_at', 'PC_monotonic_origin', 'PC_deadline_monotonic'))) and 0 <= now - v['created_at'] <= 90 and (v['PC_monotonic_origin'] == plan['PC_plan_monotonic']) and (v['PC_deadline_monotonic'] == plan['PC_plan_deadline_monotonic']) and (type(v['duration_seconds']) is int) and (v['duration_seconds'] == plan['duration_seconds'] <= 1800), 'empty_repair_original_new_plan_window_no_old_deadline_rebase')
    return (v, {'path': str(CONTRACT_ROOT / (stage + '.json')), 'sha256': sha(raw), 'F9': s})

def ancestors(stages, ranges, prior_stages):
    from asset_stage import stage_originals
    import current_prebind
    history = history_reader.load(stages.g.config)
    found = {}
    if stages.root.exists():
        for path in sorted(stages.root.iterdir()):
            first = {n.name: metadata(n.lstat()) for n in path.iterdir()}
            rows = stage_originals(stages.root, path.name)
            last = {n.name: metadata(n.lstat()) for n in path.iterdir()}
            need(first == last and set(rows) == set(first), 'empty_repair_original_actor_fullF9_before_after')
            if current_prebind.is_record(rows):
                current_prebind.historical(stages, path.name, rows)
                continue
            intent = strict(rows['intent.json'])
            if not any((overlap(r, p) for r in ranges for p in intent['plan']['ranges'])):
                continue
            need(intent['plan']['ranges'] == ranges, 'empty_repair_no_successful_or_partial_interval_overlap')
            need({'terminal.json', 'completed.json', 'fence-released.json'} <= set(rows), 'empty_repair_no_unfinished_ancestor')
            historical = history.has(path.name)
            if historical:
                t = history.consume(path.name, rows, first)
                need(intent['plan']['ranges'] == ranges, 'old_domain_exact_spent_interval')
            else:
                t = stages.terminal(path.name, historical=True)
            c = strict(rows['completed.json'])
            f = strict(rows['fence-released.json'])
            need(encode(t) == rows['terminal.json'] and t['state'] == c['state'] == 'FAILED_REGISTRY_QUIESCENT' and (t['operation_family'] == OPERATION) and (t['source118'] == stages.g.config['PC_source_pins'] and t['config_sha256'] == stages.g.config['_config_sha256'] or (historical and history.result['historical_only'] is True)) and (t['image_imported'] is False) and (c['terminal_sha256'] == sha(rows['terminal.json'])) and (f['completed_sha256'] == sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False), 'empty_repair_real_failed_completed_fence_not_success')
            found[path.name] = {'original_refs': {n: {'path': str(path / n), 'sha256': sha(raw), 'F9': first[n]} for n, raw in rows.items()}, 'terminal_sha256': sha(rows['terminal.json']), 'completed_sha256': sha(rows['completed.json']), 'fence_sha256': sha(rows['fence-released.json']), 'ranges': intent['plan']['ranges'], 'manager_identity': t['manager_identity'], 'failed_pid': int(t['scope']['unit']['ExecMainPID']), 'A_boot_id': t['scope']['boot_id'], 'unit': t['scope']['unit']['Id'], 'source_index_sha256': t['source_index_sha256']}
    need(sorted(found) == prior_stages, 'empty_repair_no_omitted_overlapping_used_ancestor')
    return found

def private_dir(stage):
    need(type(stage) is str and re.fullmatch('[0-9a-f]{32}', stage), 'empty_repair_stage_name')
    with HeldParent(REQUEST_ROOT, legacy=True) as chain:
        try:
            fd = os.open(REQUEST_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        except FileNotFoundError as error:
            need(error.errno == 2, 'empty_repair_positive_missing_private_base')
            os.mkdir(REQUEST_ROOT.name, 448, dir_fd=chain.parent_fd)
            os.fsync(chain.parent_fd)
            fd = os.open(REQUEST_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
            os.fchmod(fd, 448)
        try:
            before = directory_identity(os.fstat(fd))
            need(before[2:] == (999, 989, 16832), 'empty_repair_service_private_base')
            os.mkdir(stage, 448, dir_fd=fd)
            sub = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fchmod(sub, 448)
                need(directory_identity(os.fstat(sub))[2:] == (999, 989, 16832), 'empty_repair_new_private_stage')
            finally:
                os.close(sub)
            os.fsync(fd)
            need(before == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf()), 'empty_repair_private_base_held_named_after')
            chain.recheck()
        finally:
            os.close(fd)
    return REQUEST_ROOT / stage

def prepare(stages, body):
    from asset_stage import identity, plan
    g = stages.g
    need(g.lock.locked() and stages.active is None and (not stages.closed) and (not stages.legacy_pending) and (not g.active) and (not g.closed) and (not g.operator.negative_cpu_release.pending), 'empty_repair_only_idle_activated_same_Runtime')
    need(body['action'] == PREPARE, 'empty_repair_exact_prepare_action')
    owner = identity()
    now = g.runtime.manager._now()
    g.same()
    q = g.current_epoch()
    p, pr = plan(stages.read, body['stage_operation'], g.config, owner, now)
    v, ref = contract(stages, body['stage_operation'], p, pr, owner, now)
    originals = ancestors(stages, p['ranges'], v['prior_stages'])
    with g.facade._lifecycle_lock:
        g.live_baseline = None
        current = g.current('empty-range-repair-prepare', fenced=False)
        with g.s._lock:
            g.counters_locked()
            g.same()
            need(not g.s._operator_maintenance, 'empty_repair_no_foreign_hold')
            from late_scope_context import current_policy
            source = current_policy(g)
            actor = {'schema': 'same-Runtime-failed-empty-range-repair-actor/v1', 'operation': OPERATION, 'stage_operation': body['stage_operation'], 'current': {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'source118': g.config['PC_source_pins'], 'manager_identity': owner}, 'contract_original': ref, 'contract': v, 'plan_original': pr, 'plan': p, 'failed_ancestors': originals, 'A_source': source, 'known_stage_operations': sorted((x.name for x in stages.root.iterdir())), 'qualification': q, 'fresh_current': current, 'request': body, 'observed_at': g.runtime.manager._now(), 'automatic_retry': False}
            raw = encode(actor)
            need(len(raw) <= 2097152, 'empty_repair_complete_actor_singleleaf_cap')
            target = private_dir(body['stage_operation'])
            exclusive(target / 'request.json', actor)
            result = {'schema': 'same-Runtime-empty-repair-prepared/v1', 'stage_operation': body['stage_operation'], 'actor': pack(raw), 'actor_sha256': sha(raw), 'new_work_started': False, 'maintenance_held': False}
            need(len(encode({'ok': True, 'result': result})) <= 1048576, 'empty_repair_private_reply_original_cap')
            return result

def actor(stages, stage):
    path = REQUEST_ROOT / stage
    with HeldParent(REQUEST_ROOT, legacy=True) as chain:
        fd = os.open(REQUEST_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        sub = None
        try:
            parent = directory_identity(os.fstat(fd))
            need(parent[2:] == (999, 989, 16832), 'empty_repair_actual_private_parent')
            sub = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            before = directory_identity(os.fstat(sub))
            need(before[2:] == (999, 989, 16832) and set(os.listdir(sub)) in ({'request.json'}, {'request.json', 'reserve-attempt.json'}), 'empty_repair_private_actor_only_original')
            entries = sorted(os.listdir(sub))
            leaf = os.open('request.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sub)
            try:
                s = metadata(os.fstat(leaf))
                need(s[3:7] == [999, 989, 33152, 1] and 0 < s[2] <= 4194304, 'empty_repair_private_actor_origin')
                raw = os.pread(leaf, s[2] + 1, 0)
                need(s[2] == len(raw) and s == metadata(os.fstat(leaf)) == metadata(os.stat('request.json', dir_fd=sub, follow_symlinks=False)), 'empty_repair_private_actor_held_fullF9')
            finally:
                os.close(leaf)
            need(before == directory_identity(os.fstat(sub)) == directory_identity(os.stat(stage, dir_fd=fd, follow_symlinks=False)) and sorted(os.listdir(sub)) == entries and (parent == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf())), 'empty_repair_private_actor_directory_stability')
            chain.recheck()
        finally:
            if sub is not None:
                os.close(sub)
            os.close(fd)
    v = strict(raw)
    need(v['schema'] == 'same-Runtime-failed-empty-range-repair-actor/v1' and v['stage_operation'] == stage and (v['operation'] == OPERATION), 'empty_repair_internal_owned_stage_actor')
    return (raw, s, v)

def qualified(stages, stage, now, *, historical=False, event_actor=None):
    from late_scope_context import consume, consume_history
    g = stages.g
    if historical:
        need(type(event_actor) is dict and event_actor['stage_operation'] == stage, 'empty_repair_history_complete_intent_context')
        raw, s, v = actor(stages, stage)
        need(v == event_actor, 'empty_repair_event_actor_unchanged')
    else:
        need(g.lock.locked() and stages.active is None, 'empty_repair_current_before_reserve_only')
        raw, s, v = actor(stages, stage)
    path = QUALIFIED_ROOT / stage / 'qualified.json'
    proof, ps = stages.read(path, limit=4194304)
    need(ps[3:7] == [0, 989, 33056, 1], 'empty_repair_qualified_Root_origin')
    result = (consume_history if historical else consume)('failed-empty-range-repair', g, proof, ps, raw, now)
    need(result['state'] == STATE and result['stage_operation'] == stage and (result['ranges'] == v['plan']['ranges']) and (result['failed_ancestor_refs'] == {n: {k: r[k] for k in ('terminal_sha256', 'completed_sha256', 'fence_sha256')} for n, r in v['failed_ancestors'].items()}) and (result['accepted_bytes'] == 0) and (result['work_may_resume'] is False), 'empty_repair_actual_typed_proof_not_zero_bool')
    return {'schema': 'explicit-empty-repair-grant-consumed/v1', 'stage_operation': stage, 'actor_original': {'path': str(REQUEST_ROOT / stage / 'request.json'), 'sha256': sha(raw), 'F9': s}, 'qualified_original': {'path': str(path), 'sha256': sha(proof), 'F9': ps}, 'contract_original': v['contract_original'], 'plan_original': v['plan_original'], 'result': result, 'observed_at': now}

def admit(stages, stage, p, ref, owner, now):
    if not any((overlap(r, z) for r in p['ranges'] for z in stages.used)):
        return None
    value = qualified(stages, stage, now)
    raw, s, v = actor(stages, stage)
    contract(stages, stage, p, ref, owner, now)
    need(v['current'] == {'review_sha256': APPROVED_REVIEW, 'config_sha256': stages.g.config['_config_sha256'], 'source118': stages.g.config['PC_source_pins'], 'manager_identity': owner} and v['plan'] == p and (v['plan_original'] == ref), 'empty_repair_new_exact_plan_source_current')
    need(ancestors(stages, p['ranges'], v['contract']['prior_stages']) == v['failed_ancestors'], 'empty_repair_all_original_failed_ancestors_still_exact')
    attempt = {'schema': 'explicit-empty-repair-single-reserve-attempt/v1', 'stage_operation': stage, 'actor_sha256': sha(raw), 'plan_original': ref, 'qualified_original': value['qualified_original'], 'observed_at': stages.g.runtime.manager._now(), 'automatic_retry': False}
    exclusive(REQUEST_ROOT / stage / 'reserve-attempt.json', attempt)
    value['reserve_attempt'] = reserve_attempt(stages, stage, value)
    return value

def reserve_attempt(stages, stage, grant):
    folder = REQUEST_ROOT / stage
    with HeldParent(REQUEST_ROOT, legacy=True) as chain:
        root = os.open(REQUEST_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        fd = None
        try:
            parent = directory_identity(os.fstat(root))
            need(parent[2:] == (999, 989, 16832), 'empty_repair_attempt_private_base')
            fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            before = directory_identity(os.fstat(fd))
            need(before[2:] == (999, 989, 16832) and sorted(os.listdir(fd)) == ['request.json', 'reserve-attempt.json'], 'empty_repair_attempt_exact_private_tree')
            leaf = os.open('reserve-attempt.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                st = metadata(os.fstat(leaf))
                need(st[3:7] == [999, 989, 33152, 1] and 0 < st[2] <= 2097152, 'empty_repair_attempt_real_private_origin')
                raw = os.pread(leaf, st[2] + 1, 0)
                need(len(raw) == st[2] and st == metadata(os.fstat(leaf)) == metadata(os.stat('reserve-attempt.json', dir_fd=fd, follow_symlinks=False)), 'empty_repair_attempt_held_named_original')
            finally:
                os.close(leaf)
            need(before == directory_identity(os.fstat(fd)) == directory_identity(os.stat(stage, dir_fd=root, follow_symlinks=False)) and sorted(os.listdir(fd)) == ['request.json', 'reserve-attempt.json'] and (parent == directory_identity(os.fstat(root)) == directory_identity(chain.named_leaf())), 'empty_repair_attempt_directory_stable')
            chain.recheck()
        finally:
            if fd is not None:
                os.close(fd)
            os.close(root)
    v = strict(raw)
    need(set(v) == {'schema', 'stage_operation', 'actor_sha256', 'plan_original', 'qualified_original', 'observed_at', 'automatic_retry'} and v['schema'] == 'explicit-empty-repair-single-reserve-attempt/v1' and (v['stage_operation'] == stage) and (v['actor_sha256'] == grant['actor_original']['sha256']) and (v['plan_original'] == grant['plan_original']) and (v['qualified_original'] == grant['qualified_original']) and (v['automatic_retry'] is False) and (type(v['observed_at']) in (int, float)) and math.isfinite(v['observed_at']), 'empty_repair_exact_once_attempt_not_second_work_authority')
    return {'path': str(folder / 'reserve-attempt.json'), 'sha256': sha(raw), 'F9': st}

def permitted(repair, r, z):
    if not overlap(r, z):
        return True
    if repair is None:
        return False
    return r == z and r in repair['result']['ranges']

def recheck(stages, repair):
    if repair is None:
        return None
    checked = qualified(stages, repair['stage_operation'], stages.g.runtime.manager._now())
    checked['reserve_attempt'] = reserve_attempt(stages, repair['stage_operation'], checked)
    need({k: v for k, v in checked.items() if k != 'observed_at'} == {k: v for k, v in repair.items() if k != 'observed_at'}, 'empty_repair_same_original_reconsumed_after_fresh_current')
    return checked

def history(stages, stage, rows, seen):
    intent = strict(rows['intent.json'])
    repair = intent.get('empty_repair')
    if repair is None:
        return
    need(stage == repair['stage_operation'] and repair['schema'] == 'explicit-empty-repair-grant-consumed/v1' and (repair['plan_original'] == intent['plan_ref']) and (repair['observed_at'] <= intent['issued_at']), 'empty_repair_historical_intent_refs_not_new_permission')
    grant = repair['qualified_original']['sha256']
    need(grant not in seen, 'empty_repair_one_grant_one_new_operation')
    raw, s, v = actor(stages, stage)
    value = qualified(stages, stage, repair['observed_at'], historical=True, event_actor=v)
    value['reserve_attempt'] = reserve_attempt(stages, stage, value)
    need(value == repair, 'empty_repair_full_original_event_consumer_no_clock_refresh')
    seen.add(grant)

def publish_contract(config, current, value):
    """Root-only once data publisher, after the ordinary new finite plan exists.
 This writes no service actor/fence and starts no work. The service prepare
 re-consumes every failed ancestor and requires a fresh independent proof.
 """
    from asset_stage import plan as stage_plan
    from segment_clock import directory
    need(os.getuid() == os.geteuid() == 0 and type(value) is dict and (set(value) == {'stage_operation', 'prior_stages'}), 'empty_repair_Root_once_contract_publication')
    stage = value['stage_operation']
    now = __import__('time').time()
    p, ref = stage_plan(protected_read, stage, config, current, now)
    previous = value['prior_stages']
    need(type(previous) is list and 0 < len(previous) <= 32 and (previous == sorted(set(previous))) and (stage not in previous) and all((type(n) is str and re.fullmatch('[0-9a-f]{32}', n) for n in previous)), 'empty_repair_Root_explicit_all_prior_operations')
    v = {'schema': 'explicit-finite-failed-empty-range-repair/v1', 'operation': OPERATION, 'stage_operation': stage, 'source_review': APPROVED_REVIEW, 'config_sha256': config['_config_sha256'], 'source118': config['PC_source_pins'], 'manager_identity': current, 'plan_sha256': ref['sha256'], 'ranges': p['ranges'], 'prior_stages': previous, 'created_at': now, 'PC_monotonic_origin': p['PC_plan_monotonic'], 'PC_deadline_monotonic': p['PC_plan_deadline_monotonic'], 'duration_seconds': p['duration_seconds'], 'automatic_retry': False}
    if not CONTRACT_ROOT.exists():
        directory(CONTRACT_ROOT, True)
    else:
        directory(CONTRACT_ROOT)
    path = CONTRACT_ROOT / (stage + '.json')
    raw = encode(v)
    from root_io import fresh
    fresh(path, raw, mode=288)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchown(fd, 0, 989)
        os.fchmod(fd, 288)
        os.fsync(fd)
    finally:
        os.close(fd)
    body, st = protected_read(path, limit=2097152)
    need(body == raw and st[3:7] == [0, 989, 33056, 1], 'empty_repair_contract_full_readback')
    return {'schema': 'explicit-empty-repair-contract-published/v1', 'path': str(path), 'sha256': sha(raw), 'F9': st, 'stage_operation': stage, 'new_work_started': False}
