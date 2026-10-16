# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Typed held owner history. Historical lease views are never live Grants."""
import base64, os, stat, types
from pathlib import Path
from plan import need, strict, encode
from root_io import sha
from legacy_actor import held_actor
from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, metadata, directory_identity
import history_reader
APPROVED_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_NORMAL_HISTORY = None
APPROVED_PRIOR_NORMAL = None
ACTOR_ROOT = None

def full_history(read):
    ref = APPROVED_NORMAL_HISTORY
    need(type(ref) is dict and ref['path'] == '/opt/dgx-v4/hx/mimo-registry-r16-history/normal-history.json' and (type(APPROVED_REVIEW) is str), 'R16_normal_history_Root_SOURCE_None')
    raw, f = read(Path(ref['path']), limit=2097152)
    need(sha(raw) == ref['sha256'] and f == ref['F9'] and (f[3:7] == [0, 989, 33056, 1]), 'R16_normal_data_actual_Root_SHA_fullF9')
    v = strict(raw)
    p = history_reader.owner_policy()
    need(v['schema'] == 'R16-failed-owner-normal-history/v1' and v['old_records'] == p['old_records'] and (v['old_completed'] == p['old_completed']) and (v['old_terminal'] == p['old_terminal']) and (v['old_plan'] == p['old_plan']) and (v['current_A_source'] == p['old_A_sources']), 'R16_normal_data_exact_owner_Source_binding')
    b = history_reader.load({'review_sha256': APPROVED_REVIEW})
    source = history_reader.epoch_APPROVED_BINDING['source_bundle']
    sr, sf = history_reader.epoch_held_root(source['path'], source['sha256'], mode=288, cap=2097152)
    need(sf == source['F9'], 'R16_normal_original_consumer_closure_Root_F9')
    sources = history_reader.epoch_open_bundle(sr)
    domain = history_reader.old_domain_from_snapshot(b.snapshot, sources)
    need(domain == v['old_domain'], 'R16_normal_full_original_bridge_algorithms')
    need(read(Path(ref['path']), limit=2097152) == (raw, f), 'R16_normal_data_held_after_full_history')
    return (raw, v, b)

def lease_same(expected_holder):
    """Only a historical receiver callback. No pretend lease.held or Grant."""
    need(type(expected_holder) is int and expected_holder > 1, 'R16_history_explicit_phase_lease_holder')
    path = Path('/srv/dgx-home-ai/runtime/MAINTENANCE.lock')
    with HeldParent(path, legacy=True) as chain:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            st = metadata(os.fstat(fd))
            need(st == metadata(chain.named_leaf()) and st[0:2] == [2096, 69257] and (st[3:7] == [999, 989, 33152, 1]), 'R16_history_physical_original_lease_FD_named')
            key = f'{os.major(st[0]):02x}:{os.minor(st[0]):02x}:{st[1]}'
            rows = [a for a in (row.split() for row in Path('/proc/locks').read_text().splitlines()) if len(a) == 8 and a[1:4] == ['FLOCK', 'ADVISORY', 'WRITE'] and (a[5] == key)]
            need([int(a[4]) for a in rows] == [expected_holder], 'R16_history_phase_exact_sole_lease_holder')
            need(st == metadata(os.fstat(fd)) == metadata(chain.named_leaf()), 'R16_history_lease_fullF9_after')
            chain.recheck()
        finally:
            os.close(fd)

def actors(read, expected_holder):
    raw, v, b = full_history(read)
    root = Path(ACTOR_ROOT)
    out = {}
    same = lambda: lease_same(expected_holder)
    same()
    for stage in sorted(b.snapshot['actors']):
        a = held_actor(root / stage)
        rows = {n: base64.b64decode(row['raw_b64'], validate=True) for n, row in a['files'].items()}
        stats = {n: row['F9'] for n, row in a['files'].items()}
        b.consume(stage, rows, stats)
        out[stage] = a
    p = history_reader.owner_policy()
    view = types.SimpleNamespace(root=root, read=read, used=[], g=types.SimpleNamespace(same=same, lock=None, runtime=None))
    for stage in sorted(set(p['old_completed']) | {p['stage']}):
        rows, stats = history_reader.owner_actor_snapshot(view, stage)
        if stage in p['old_completed']:
            history_reader.owner_completed_history(view, stage, rows)
        elif set(rows) == set(p['old_records']):
            history_reader.owner_pending(read, rows, stats, p)
        else:
            need(set(rows) == set(p['old_records']) | {'terminal.json', 'completed.json', 'fence-released.json'}, 'R16_owner_no_partial_or_unknown_actor_completion')
            history_reader.owner_history(view, stage, rows)
        out[stage] = {'path': str(root / stage), 'files': {n: {'raw_b64': base64.b64encode(body).decode(), 'sha256': sha(body), 'F9': stats[n]} for n, body in rows.items()}}
    same()
    return out

def packed_histories(read, root):
    need(APPROVED_ROOT is not None and str(root) == APPROVED_ROOT, 'R16_normal_fixed_PC_source_Root')
    raw, v, b = full_history(read)
    return ({'PC': raw, 'A': raw, 'sources': None}, {})

def history(pc_raw, expected_holder):
    raw, v, b = full_history(history_reader.read)
    need(pc_raw == raw, 'R16_normal_exact_history_argument')
    return {'actors': actors(history_reader.read, expected_holder), 'historical_only': True, 'retry_authorized': False, 'used': b.result['used']}
