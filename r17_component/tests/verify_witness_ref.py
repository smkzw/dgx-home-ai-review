# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""A confirmed exact witness must not survive same-byte inode replacement."""
import importlib.util, json, os, pathlib, threading
H = pathlib.Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location('R17_witness_ref_journal', H / 'SOURCE/owner_decision.py')
j = importlib.util.module_from_spec(s)
s.loader.exec_module(j)
j.SERVICE_UID = os.getuid()
j.SERVICE_GID = os.getgid()
root = H / 'CPU_WITNESS_REF'
root.mkdir(mode=448)
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
op = 'd' * 32
obj = j.Journal(fd, op)
obj.prepare({'operation': op, 'stage': 'a' * 32, 'prepared_closure_sha256': 'b' * 64, 'initial_identity': {}, 'original_deadline_monotonic': 1.0, 'old_terminal_sha256': 'c' * 64})
clock = {'PC_boot_id': 'CPU', 'PC_monotonic_sent': 100.0, 'PC_monotonic_observed': 110.0, 'PC_monotonic_elapsed': 10.0, 'permit_deadline_monotonic': 220.0}
finishes = []
obj.commit({'work_may_resume': False}, lambda: dict(clock), lambda: finishes.append('finish'), lambda: None)
assert obj.state()['state'] == 'COMMITTED'
original = obj._metadata_confirmed
path = root / op / 'durability-witness.json'
raw = path.read_bytes()
path.rename(root / 'retired-witness.json')
path.write_bytes(raw)
path.chmod(384)
assert obj.state()['state'] == 'FINISH_WITNESS_PRESENT' and obj._metadata_confirmed == original
refs = {kind: {n: {'sha256': 'f' * 64, 'F9': [1] * 9} for n in names} for kind, names in [('actor', ('terminal.json', 'completed.json', 'fence-released.json')), ('source', ('intent.json', 'completed.json', 'fence-released.json'))]}
try:
    obj.record_projections(refs)
except j.DecisionRefused as e:
    assert str(e) == 'owner_decision_projection_once_after_legal_finish'
    reason = str(e)
else:
    raise AssertionError('drifted witness carried COMMITTED into projection seal')
lock = threading.RLock()
with lock:
    assert obj.confirm_metadata_durability(lock)['state'] == 'COMMITTED'
assert obj._metadata_confirmed != original and len(finishes) == 1
result = {'confirmed_exact_SHA_F9_bound': True, 'samebytes_newinode_downgraded': 'FINISH_WITNESS_PRESENT', 'projection_refused': reason, 'fresh_actual_barrier_required': True, 'finish_calls': 1, 'native': 0}
(H / 'WITNESS_REF_RESULT.json').write_bytes(j.encode(result))
print(json.dumps(result, sort_keys=True))
obj.close()
os.close(fd)
