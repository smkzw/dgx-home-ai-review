# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Real local FD/O_EXCL/fsync faults. UID/GID projected only as test constants.
No Runtime/real maintenance release; finish boundary is explicitly observed.
"""
import hashlib, json, os, pathlib, tempfile, types, sys, threading
H = pathlib.Path(__file__).resolve().parents[1]

def load(n, p):
    m = types.ModuleType(n)
    m.__file__ = str(p)
    exec(compile(p.read_bytes(), str(p), 'exec'), m.__dict__)
    return m
j = load('r17_decision', H / 'SOURCE/owner_decision.py')
clock = load('r17_clock', H / 'SOURCE/owner_clock.py')
j.SERVICE_UID = os.getuid()
j.SERVICE_GID = os.getgid()
parent = H / ('CPU_DECISION_' + (sys.argv[1] if len(sys.argv) > 1 else 'LEGACY'))
parent.mkdir(mode=448, exist_ok=True)
parent.chmod(448)
fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
base = {'PC_boot_id': 'boot', 'PC_sent_at': 1000.0, 'PC_monotonic_sent': 100.0}
permit = {'PC_boot_id': 'boot', 'PC_issued_at': 995.0, 'PC_monotonic_origin': 95.0, 'PC_deadline_monotonic': 215.0, 'duration_seconds': 120}
points = ['before_mkdir', 'after_mkdir', 'after_mkdir_fsync'] + [prefix + name for name in ('prepared.json', 'decision.json', 'durability-witness.json') for prefix in ('before_', 'after_write_', 'after_file_fsync_', 'after_directory_fsync_')] + ['after_physical_finish']
records = []

class InjectedCrash(BaseException):
    pass
for ordinal, point in enumerate(points):
    op = f'{ordinal + 1:032x}'
    state = {'held': True, 'finish_calls': 0}
    now = [110.0]

    def check():
        return clock.check(base, permit, 'boot', now[0], 1000.0 + now[0] - 100.0)

    def finish():
        state['finish_calls'] += 1
        state['held'] = False

    def restore():
        state['held'] = True

    def fault(value):
        if value == point:
            raise InjectedCrash(point)
    original = j.Journal(fd, op, fault=fault)
    try:
        original.prepare({'operation': op, 'stage': 'd' * 32, 'prepared_closure_sha256': 'c' * 64, 'initial_identity': {'pid': 99}, 'original_deadline_monotonic': 50.0, 'old_terminal_sha256': 'e' * 64})
        original.commit({'work_may_resume': False}, check, finish, restore)
    except InjectedCrash:
        pass
    finally:
        original.close()
    state['held'] = True
    again = j.Journal(fd, op)
    try:
        try:
            value = again.state()
        except (j.DecisionRefused, json.JSONDecodeError):
            value = {'state': 'UNKNOWN_HELD', 'held': True}
        assert value['state'] in ('ABSENT', 'UNKNOWN_HELD', 'PREPARED', 'EXPIRED', 'FINISH_WITNESS_PRESENT', 'COMMITTED') and value['held'] is True
        assert state['held'] and state['finish_calls'] <= 1
        records.append({'point': point, 'cold': value['state'], 'finish_calls': state['finish_calls'], 'held_after_cold': state['held']})
    finally:
        again.close()
for label, slowpoint in [('durability', 'after_directory_fsync_decision.json'), ('physical', 'after_physical_finish')]:
    op = hashlib.sha256(label.encode()).hexdigest()[:32]
    now = [110.0]
    state = {'held': True, 'finish_calls': 0}

    def fault(value):
        if value == slowpoint:
            now[0] = 130.001
    original = j.Journal(fd, op, fault=fault)
    original.prepare({'operation': op, 'stage': 'd' * 32, 'prepared_closure_sha256': 'c' * 64, 'initial_identity': {'pid': 99}, 'original_deadline_monotonic': 50.0, 'old_terminal_sha256': 'e' * 64})
    try:
        original.commit({'work_may_resume': False}, check, finish, restore)
    except clock.ClockRefused as e:
        assert str(e) == 'owner_clock_original_BEGIN_whole30'
    else:
        raise AssertionError('late physical/durable finish accepted')
    assert original.state()['state'] == 'EXPIRED' and state['held']
    original.close()
    records.append({'late': label, 'state': 'EXPIRED', 'held': True})
op = 'f' * 32
now = [110.0]
state = {'held': True, 'finish_calls': 0}
original = j.Journal(fd, op)
original.prepare({'operation': op, 'stage': 'd' * 32, 'prepared_closure_sha256': 'c' * 64, 'initial_identity': {'pid': 99}, 'original_deadline_monotonic': 50.0, 'old_terminal_sha256': 'e' * 64})
value = original.commit({'work_may_resume': False}, check, finish, restore)
assert value['state'] == 'COMMITTED' and state['finish_calls'] == 1
original.close()
again = j.Journal(fd, op)
value = again.state()
assert value['state'] == 'FINISH_WITNESS_PRESENT' and state['finish_calls'] == 1
lock = threading.RLock()
with lock:
    value = again.confirm_metadata_durability(lock)
assert value['state'] == 'COMMITTED' and state['finish_calls'] == 1
again.close()
os.close(fd)
result = {'faults': records, 'legal_commit_finish_calls': state['finish_calls'], 'classification_never_releases': True, 'UID_GID': 'local test projection only', 'real_FD_OEXCL_fsync': True, 'native': 0}
(H / 'DECISION_RESULT.json').write_bytes(j.encode(result))
print(json.dumps({'faults': len(records), 'legal_commit_finish_calls': 1, 'native': 0}))
