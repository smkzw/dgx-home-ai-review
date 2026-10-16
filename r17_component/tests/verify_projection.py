# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Narrow actual FD journal/projection fault boundaries; not full owner eligibility.
The tiny recipe here exercises metadata storage only. Full historical/source
eligibility and Stages/Recovery integration remain separately required.
"""
import importlib.util, json, os, pathlib, sys
H = pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
j = load('R17_projection_journal', H / 'SOURCE/owner_decision.py')
p = load('R17_projection', H / 'SOURCE/owner_projection.py')
j.SERVICE_UID = p.UID = os.getuid()
j.SERVICE_GID = p.GID = os.getgid()
out = H / ('CPU_PROJECTIONS_' + (sys.argv[1] if len(sys.argv) > 1 else 'WITNESS_V2'))
out.mkdir(mode=448)
terminal = p.encode({'state': 'FAILED_REGISTRY_QUIESCENT'})
recipe = {'schema': 'owner-projection-recipe/v2', 'operation': 'a' * 32, 'stage': 'b' * 32, 'old_terminal': {'sha256': p.sha(terminal)}, 'original_deadline_monotonic': 99.0, 'release_clock': {}, 'request': {'request_nonce': 'c' * 32}, 'qualification': {}, 'prior': {}, 'legacy_original': {}, 'eligibility': {'schema': 'failed-owner-terminal-release-eligibility/v2', 'stage_operation': 'b' * 32, 'old_terminal_sha256': p.sha(terminal), 'original_deadline_monotonic': 99.0, 'work_may_resume': False, 'new_current': None, 'activation_request_nonce': 'c' * 32}, 'current': {}, 'recorded_at': 1000.0}
binding = {'operation': 'a' * 32, 'stage': 'b' * 32, 'prepared_closure_sha256': '0' * 64, 'initial_identity': {}, 'original_deadline_monotonic': 99.0, 'old_terminal_sha256': p.sha(terminal)}
finishes = []

def clock():
    n = 101.0 + len(finishes)
    return {'PC_boot_id': 'CPU', 'PC_monotonic_sent': 100.0, 'PC_monotonic_observed': n, 'PC_monotonic_elapsed': n - 100.0, 'permit_deadline_monotonic': 220.0, 'PC_wall_observed': 1000.0 + n - 100.0}

def finish():
    finishes.append('actual callback')

def setup(label, commit=True):
    root = out / label
    root.mkdir(mode=448)
    for name in ('journal', 'actor', 'source'):
        (root / name).mkdir(mode=448)
    fds = {name: os.open(root / name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) for name in ('journal', 'actor', 'source')}
    journal = j.Journal(fds['journal'], 'a' * 32)
    journal.prepare(binding)
    if commit:
        journal.commit({'recipe': recipe}, clock, finish, lambda: None)
    return (root, fds, journal)
root, fds, journal = setup('partial_then_complete')
wanted = p.render(recipe, terminal, journal.state()['witness']['maintenance_finish_observed'])
(root / 'actor/completed.json').write_bytes(wanted['actor']['completed.json'])
(root / 'actor/completed.json').chmod(384)
refs = p.project(journal, fds['actor'], fds['source'], recipe, terminal, set())
assert set(refs) == {'actor', 'source'} and len(finishes) == 1
before = {kind: {n: p.f9((root / kind / n).stat()) for n in rows} for kind, rows in refs.items()}
assert p.project(journal, fds['actor'], fds['source'], recipe, terminal, set()) == refs and len(finishes) == 1
assert before == {kind: {n: p.f9((root / kind / n).stat()) for n in rows} for kind, rows in refs.items()}
leaf = root / 'actor/completed.json'
leaf.rename(root / 'retired-completed.json')
leaf.write_bytes(wanted['actor']['completed.json'])
leaf.chmod(384)
try:
    p.project(journal, fds['actor'], fds['source'], recipe, terminal, set())
except p.ProjectionRefused as e:
    assert str(e) == 'owner_projection_sealed_fullF9_changed'
    inode = str(e)
else:
    raise AssertionError('samebytes replacement accepted')
root2, fd2, journal2 = setup('uncommitted', False)
try:
    p.project(journal2, fd2['actor'], fd2['source'], recipe, terminal, set())
except p.ProjectionRefused as e:
    assert str(e) == 'owner_projection_requires_durable_finish_witness'
    uncommitted = str(e)
else:
    raise AssertionError('PREPARED allowed projection')
assert not list((root2 / 'actor').iterdir()) and (not list((root2 / 'source').iterdir()))
root3, fd3, journal3 = setup('truncated_descriptor')
leaf = root3 / 'journal' / ('a' * 32) / 'projections.json'
leaf.write_bytes(b'{')
leaf.chmod(384)
assert journal3.classify()['state'] == 'UNKNOWN_HELD' and leaf.read_bytes() == b'{'
result = {'actual_Journal_FD_OEXCL_fsync': True, 'legal_COMMITTED_partial_metadata_recovered': True, 'complete_second_projection_no_write_no_finish': True, 'samebytes_inode_refused': inode, 'PREPARED_no_projection': uncommitted, 'truncated_descriptor_UNKNOWN_HELD': True, 'full_owner_eligibility': 'not claimed by this narrow fixture', 'Stages_Recovery_complete_warm': 'pending', 'native': 0}
(H / 'PROJECTION_V2_RESULT.json').write_bytes(p.encode(result))
print(json.dumps(result, sort_keys=True))
for rows in (fds, fd2, fd3):
    for fd in rows.values():
        os.close(fd)
for obj in (journal, journal2, journal3):
    obj.close()
