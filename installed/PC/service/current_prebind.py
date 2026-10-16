# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same Stages.active, sole grant lock, lifecycle lock and scheduler fence.
No Runtime/Manager/Adapter construction. New SOURCE roots default None.
"""
import base64, os, re, stat, types
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read, exclusive, HeldParent, metadata, directory_identity
import current_negative as negative
from contract import OPERATION
import known_prior_assets
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
REQUEST_ROOT = None
QUALIFIED_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16/current-prebind-readonly'
APPROVED_NONCE_POLICY = 'active-stage-operation/v1'
APPROVED_LATE_CONTEXT_PATH = '/opt/dgx-v4/hx/mimo-registry-r16/service/late_scope_context.py'
APPROVED_LATE_CONTEXT_SHA = '0e829a61212ac1089a9eb75377492ca719304c423f7cc99f92610ca45094eb92'
PREPARE = 'prepare-not-launched-asset-stage'
FINISH = 'finish-not-launched-asset-stage'

def current(g):
    from asset_stage import identity
    g.same()
    g.current_epoch()
    need(APPROVED_REVIEW is not None and g.config['review_sha256'] == APPROVED_REVIEW, 'current_prebind_same_review')
    return {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'manager_identity': identity(), 'source118': g.config['PC_source_pins']}

def source():
    need(REQUEST_ROOT is not None and QUALIFIED_ROOT is not None and (APPROVED_NONCE_POLICY == 'active-stage-operation/v1'), 'current_prebind_roots_nonce_SOURCE_None')

def actor_records(stages, stage):
    from asset_stage import stage_originals
    rows = stage_originals(stages.root, stage)
    out = {}
    root = stages.root
    with HeldParent(root, legacy=True) as chain:
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        sub = None
        try:
            sd = directory_identity(os.fstat(fd))
            sub = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            before = directory_identity(os.fstat(sub))
            names = sorted(os.listdir(sub))
            need(names == sorted(rows), 'current_actor_exact_entries')
            for name, raw in rows.items():
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sub)
                try:
                    s = metadata(os.fstat(leaf))
                    need(s[3:7] == [999, 989, 33152, 1] and len(raw) == s[2] <= 2097152 and (os.pread(leaf, len(raw) + 1, 0) == raw) and (s == metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=sub, follow_symlinks=False))), 'current_actor_held_raw_F9')
                    out[name] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}
                finally:
                    os.close(leaf)
            need(names == sorted(os.listdir(sub)) and before == directory_identity(os.fstat(sub)) == directory_identity(os.stat(stage, dir_fd=fd, follow_symlinks=False)) and (sd == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf())), 'current_actor_directory_unchanged')
            chain.recheck()
        finally:
            if sub is not None:
                os.close(sub)
            os.close(fd)
    need(stage_originals(root, stage) == rows, 'current_actor_recheck_original_rows')
    return out

def snapshot(stages):
    source()
    need(os.getuid() == os.geteuid() == 999, 'current_prebind_existing_service999')
    g = stages.g
    a = stages.active
    need(g.lock.locked() and a is not None and (a['reserved'] is not None) and (a['ordinal'] >= 1), 'current_prebind_actual_active_reserved_actor')
    c = current(g)
    records = actor_records(stages, a['stage_operation'])
    from asset_stage import PLAN_ROOT
    raw, st = stages.read(PLAN_ROOT / (a['stage_operation'] + '.json'), limit=2097152)
    need(st[3:7] == [0, 989, 33056, 1] and st == a['plan_ref']['F9'] and (sha(raw) == a['plan_ref']['sha256']) and (strict(raw) == a['plan']), 'current_prebind_actual_held_plan')
    v = {'schema': 'current-stage-prebind-actor/v2', 'stage_operation': a['stage_operation'], 'current': c, 'plan_original': {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': st}, 'records': records, 'ordinal': a['ordinal'], 'original_deadline_monotonic': a['deadline'], 'known_prior_assets': known_prior_assets.service_snapshot(stages, c)}
    _late().actor_validator(g).actor(encode(v), c)
    need(strict(negative.original(records['reserved.json'], (999, 989, 33152, 1))) == a['reserved'], 'current_prebind_active_reserved_equal_original')
    return v

def private_dir(path):
    path = Path(path)
    base = Path(REQUEST_ROOT)
    need(path.parent == base and re.fullmatch('[0-9a-f]{32}', path.name), 'current_prebind_fixed_request_directory')
    with HeldParent(base, legacy=True) as chain:
        need(os.getuid() == os.geteuid() == 999 and base.name == 'asset-prebind-requests-' + OPERATION and (str(base.parent) == '/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d'), 'current_prebind_fixed_service_request_root')
        try:
            root = os.open(base.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        except FileNotFoundError as error:
            need(error.errno == 2, 'current_prebind_request_root_exact_ENOENT')
            os.mkdir(base.name, 448, dir_fd=chain.parent_fd)
            root = os.open(base.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
            os.fchmod(root, 448)
            os.fsync(root)
            os.fsync(chain.parent_fd)
        child = None
        try:
            before = directory_identity(os.fstat(root))
            need(before[2:] == (999, 989, 16832) and before == directory_identity(chain.named_leaf()), 'current_prebind_existing_service_request_root')
            os.mkdir(path.name, 448, dir_fd=root)
            child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            os.fchmod(child, 448)
            z = os.fstat(child)
            need((z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (999, 989, 448) and metadata(z) == metadata(os.stat(path.name, dir_fd=root, follow_symlinks=False)), 'current_prebind_service_private_directory')
            os.fsync(child)
            os.fsync(root)
            need(before == directory_identity(os.fstat(root)) == directory_identity(chain.named_leaf()), 'current_prebind_request_parent_unchanged')
            chain.recheck()
        finally:
            if child is not None:
                os.close(child)
            os.close(root)

def prepare(stages, body):
    g = stages.g
    need(body['stage_operation'] == stages.active['stage_operation'], 'current_prebind_body_cannot_select_actor')
    with g.facade._lifecycle_lock:
        g.live_baseline = None
        g.current('current-prebind-before-request', fenced=True)
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            a = snapshot(stages)
            root = Path(REQUEST_ROOT) / a['stage_operation']
            raw = encode(a)
            request = {'schema': 'current-stage-prebind-request/v1', 'operation': OPERATION, 'nonce': a['stage_operation'], 'current': a['current'], 'actor_sha256': sha(raw), 'stage_operation': a['stage_operation']}
            _late().actor_validator(g).checked_request(encode(request), a['current'])
            result = {'request': request, 'actor': a, 'clock_started': False, 'work_may_resume': False}
            need(len(encode(result)) <= 1048320, 'current_prebind_existing_private_reply_1MiB_no_increase')
            private_dir(root)
            exclusive(root / 'actor.json', a)
            exclusive(root / 'request.json', request)
            exclusive(root / 'current-context.json', a['current'])
            need(snapshot(stages) == a, 'current_prebind_request_no_actor_change')
            return result

def read_private(path):
    path = Path(path)
    base = Path(REQUEST_ROOT)
    need(path.parent.parent == base and re.fullmatch('[0-9a-f]{32}', path.parent.name) and (path.name in ('actor.json', 'request.json', 'current-context.json')), 'current_prebind_fixed_private_leaf')
    with HeldParent(base, legacy=True) as chain:
        root = os.open(base.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        d = None
        try:
            need(directory_identity(os.fstat(root))[2:] == (999, 989, 16832), 'current_prebind_private_request_root')
            d = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            need(directory_identity(os.fstat(d))[2:] == (999, 989, 16832), 'current_prebind_private_actor_directory')
            before = directory_identity(os.fstat(d))
            f = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=d)
            try:
                s = metadata(os.fstat(f))
                need(s[3:7] == [999, 989, 33152, 1] and s[2] <= 2097152, 'current_prebind_private_actor_F9')
                b = os.pread(f, s[2] + 1, 0)
                need(len(b) == s[2] and s == metadata(os.fstat(f)) == metadata(os.stat(path.name, dir_fd=d, follow_symlinks=False)) and (before == directory_identity(os.fstat(d)) == directory_identity(os.stat(path.parent.name, dir_fd=root, follow_symlinks=False))), 'current_prebind_private_actor_stable')
                chain.recheck()
                return (b, s)
            finally:
                os.close(f)
        finally:
            if d is not None:
                os.close(d)
            os.close(root)

def _late():
    need(APPROVED_LATE_CONTEXT_PATH is not None and APPROVED_LATE_CONTEXT_SHA is not None, 'current_prebind_shared_late_context_SOURCE_None')
    path = Path(APPROVED_LATE_CONTEXT_PATH)
    raw, st = protected_read(path, limit=2097152)
    need(sha(raw) == APPROVED_LATE_CONTEXT_SHA and st[3:7] == [0, 989, 33056, 1], 'current_prebind_exact_shared_late_context_source')
    m = types.ModuleType('current_prebind_private_late_context')
    m.__file__ = str(path)
    m.__dict__['__builtins__'] = __builtins__
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m

def qualified(stages, stage, now, *, historical=False):
    source()
    ar, _ = read_private(Path(REQUEST_ROOT) / stage / 'actor.json')
    a = strict(ar)
    need(a['stage_operation'] == stage, 'current_prebind_request_path_stage')
    raw, st = protected_read(Path(QUALIFIED_ROOT) / stage / 'not-launched-qualified.json', limit=2097152)
    context = _late()
    consume = context.consume_history if historical else context.consume
    t = consume('current-stage-prebind', stages.g, raw, st, ar, now)
    return (t, raw, st, ar)

def remaining(used, ranges):
    out = list(used)
    for row in ranges:
        matches = [i for i, x in enumerate(out) if x == row]
        need(len(matches) == 1, 'current_prebind_release_exact_owned_ranges_once')
        out.pop(matches[0])
    return out

def finish(stages, body):
    g = stages.g
    a = stages.active
    need(g.lock.locked() and a is not None and (a['stage_operation'] == body['stage_operation']), 'current_prebind_finish_owned_active')
    t, raw, st, ar = qualified(stages, a['stage_operation'], g.runtime.manager._now())
    need(snapshot(stages) == strict(ar), 'current_prebind_latest_actor_unchanged')
    with g.facade._lifecycle_lock:
        g.current_epoch()
        g.live_baseline = None
        proof = g.current('current-prebind-terminal-current', fenced=True)
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            g.same()
            again = qualified(stages, a['stage_operation'], g.runtime.manager._now())
            need(again == (t, raw, st, ar) and snapshot(stages) == strict(ar), 'current_prebind_publish_fresh_whole30_actor')
            ranges = remaining(stages.used, a['plan']['ranges'])
            exclusive(a['root'] / 'terminal.json', t)
            done = {'schema': 'current-stage-not-launched-completed/v1', 'stage_operation': a['stage_operation'], 'state': negative.STATE, 'terminal_sha256': sha(encode(t)), 'proof_sha256': sha(raw), 'qualified_F9': st, 'actor_sha256': sha(ar), 'current': proof, 'original_deadline_monotonic': a['deadline'], 'work_deadline_extended': False, 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'finished_at': g.runtime.manager._now()}
            exclusive(a['root'] / 'completed.json', done)
            try:
                g.s.finish_operator_maintenance()
                exclusive(a['root'] / 'fence-released.json', {'stage_operation': a['stage_operation'], 'completed_sha256': sha(encode(done)), 'operator_maintenance_observed': False, 'observed_at': g.runtime.manager._now()})
            except BaseException:
                g.s.restore_operator_block()
                raise
            stages.used = ranges
            stages.active = None
            stages.closed = False
            g.live_baseline = None
            return done

def is_record(rows):
    return 'terminal.json' in rows and strict(rows['terminal.json']).get('schema') == 'fixed-image-current-not-launched-terminal/v2'

def historical(stages, stage, rows):
    """Full producer/consumer at original finish time, never live admission."""
    source()
    ar, _ = read_private(Path(REQUEST_ROOT) / stage / 'actor.json')
    a = strict(ar)
    i = strict(rows['intent.json'])
    d = strict(rows['completed.json'])
    f = strict(rows['fence-released.json'])
    need({n: negative.original(v, (999, 989, 33152, 1)) for n, v in a['records'].items()} == {n: r for n, r in rows.items() if n not in ('terminal.json', 'completed.json', 'fence-released.json')}, 'current_prebind_warm_full_actor_originals')
    need(d['stage_operation'] == f['stage_operation'] == a['stage_operation'] == stage and d['terminal_sha256'] == sha(rows['terminal.json']) and (f['completed_sha256'] == sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (d['finished_at'] <= f['observed_at']), 'current_prebind_history_complete_before_private_consumer')
    t, raw, st, held_actor = qualified(stages, stage, d['finished_at'], historical=True)
    need(held_actor == ar and encode(t) == rows['terminal.json'] and (d['schema'] == 'current-stage-not-launched-completed/v1') and (d['state'] == negative.STATE) and (d['terminal_sha256'] == sha(rows['terminal.json'])) and (d['proof_sha256'] == sha(raw)) and (d['qualified_F9'] == st) and (d['actor_sha256'] == sha(ar)) and (d['original_deadline_monotonic'] == a['original_deadline_monotonic'] == i['deadline_monotonic']) and (d['work_deadline_extended'] is d['image_imported'] is d['CPU_success'] is False) and (d['models_started'] == 0) and (f['completed_sha256'] == sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (d['finished_at'] <= f['observed_at']), 'current_prebind_warm_exact_causal_completion')
    need(a['current']['config_sha256'] == stages.g.config['_config_sha256'] and a['current']['source118'] == stages.g.config['PC_source_pins'], 'current_prebind_warm_source_not_new_authority')
    return d
