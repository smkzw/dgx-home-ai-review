# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual bounded fsync failures, true RLock ownership, and whole30 tail."""
import importlib.util, json, os, pathlib, sys, threading
H = pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m
j = load('R17_barrier_journal', H / 'SOURCE/owner_decision.py')
c = load('R17_barrier_clock', H / 'SOURCE/owner_clock.py')
j.SERVICE_UID = os.getuid()
j.SERVICE_GID = os.getgid()
out = H / 'CPU_COLD_BARRIER'
out.mkdir(mode=448)
lock = threading.RLock()
cases = []

class Crash(BaseException):
    pass
base = {'PC_boot_id': 'boot', 'PC_sent_at': 1000.0, 'PC_monotonic_sent': 100.0}
permit = {'PC_boot_id': 'boot', 'PC_issued_at': 995.0, 'PC_monotonic_origin': 95.0, 'PC_deadline_monotonic': 215.0, 'duration_seconds': 120}
for point in ('after_write_durability-witness.json', 'after_file_fsync_durability-witness.json', 'before_final_state'):
    root = out / point
    root.mkdir(mode=448)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    state = {'held': True, 'finishes': 0}

    def finish():
        state.update(held=False, finishes=state['finishes'] + 1)

    def restore():
        state['held'] = True

    def fault(p):
        if p == point:
            raise Crash(p)
    op = 'a' * 32
    original = j.Journal(fd, op, fault=fault)
    original.prepare({'operation': op, 'stage': 'b' * 32, 'prepared_closure_sha256': 'c' * 64, 'initial_identity': {}, 'original_deadline_monotonic': 50.0, 'old_terminal_sha256': 'd' * 64})
    try:
        original.commit({'work_may_resume': False}, lambda: c.check(base, permit, 'boot', 110.0, 1010.0), finish, restore)
    except Crash:
        pass
    else:
        raise AssertionError('tail fault not reached')
    assert state['held'] and state['finishes'] == 1 and (original.classify()['state'] == 'FINISH_WITNESS_PRESENT')
    with lock:
        try:
            original.confirm_metadata_durability(lock)
        except j.DecisionRefused as e:
            assert str(e) == 'owner_decision_failed_process_not_cold_reentry'
        else:
            raise AssertionError('same failed process redeemed itself')
    original.close()
    for index, barrier in enumerate(('before_cold_witness_fsync', 'after_cold_witness_fsync', 'after_cold_directory_fsync', 'after_cold_parent_fsync')):

        def bad(p):
            if p == barrier:
                raise Crash(p)
        cold = j.Journal(fd, op, fault=bad)
        with lock:
            try:
                cold.confirm_metadata_durability(lock)
            except Crash:
                pass
            else:
                raise AssertionError('barrier fault not reached')
        assert cold.classify()['state'] == 'FINISH_WITNESS_PRESENT' and state['held'] and (state['finishes'] == 1)
        cold.close()
    cold = j.Journal(fd, op)
    try:
        cold.confirm_metadata_durability(lock)
    except j.DecisionRefused as e:
        assert str(e) == 'owner_decision_existing_scheduler_lock'
    else:
        raise AssertionError('unheld lock accepted')
    with lock:
        result = cold.confirm_metadata_durability(lock)
    assert result['state'] == 'COMMITTED' and result['held'] and (state['finishes'] == 1)
    cases.append({'fault': point, 'cold_before': 'FINISH_WITNESS_PRESENT', 'barriers_failed': 4, 'cold_after': 'COMMITTED', 'finish_calls': 1, 'held': True})
    cold.close()
    os.close(fd)
root = out / 'post_clock_need'
root.mkdir(mode=448)
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
original = j.Journal(fd, 'e' * 32)
original.prepare({'operation': 'e' * 32, 'stage': 'b' * 32, 'prepared_closure_sha256': 'c' * 64, 'initial_identity': {}, 'original_deadline_monotonic': 50.0, 'old_terminal_sha256': 'd' * 64})
count = [0]
held = [True]
finishes = [0]

def check():
    count[0] += 1
    v = c.check(base, permit, 'boot', 110.0, 1010.0)
    if count[0] == 3:
        v['PC_boot_id'] = 'foreign'
    return v

def finish():
    held[0] = False
    finishes[0] += 1
try:
    original.commit({'work_may_resume': False}, check, finish, lambda: held.__setitem__(0, True))
except j.DecisionRefused as e:
    assert str(e) == 'owner_decision_same_boot_durable_observation'
else:
    raise AssertionError('post-clock need not reached')
assert held[0] and finishes == [1] and (original.classify()['state'] == 'UNKNOWN_HELD')
original.close()
os.close(fd)
result = {'actual_local_FD_fsync': True, 'cases': cases, 'post_clock_need_restores_held': True, 'no_second_physical_finish': True, 'Runtime_Recovery_ctor': 'pending', 'native': 0}
(H / 'BARRIER_RESULT.json').write_bytes(j.encode(result))
print(json.dumps(result, sort_keys=True))
