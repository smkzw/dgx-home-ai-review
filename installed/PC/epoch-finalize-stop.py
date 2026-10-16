# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Last DAG leaf: exact FINAL index literal. One Root launch/finalize/archive/stop."""
import os, sys, time, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
sys.path.insert(0, str(Path(__file__).resolve().parent / 'pc'))
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
from managed_scope import argv, positive
from scope_observer import observe
from bounded_process import capture
ROLE = 'epoch'
APPROVED_FINAL_INDEX_SHA = '5edd00d1c71f46a2c1abf9fb97f08860a636bbe1436dcdb5f2ed68970a3c4ee3'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
MODE = 'finalize-stop'

def validate():
    need(ROLE in ('history', 'epoch') and MODE in ('launch', 'finalize-stop') and (APPROVED_FINAL_INDEX_SHA is not None) and (APPROVED_REVIEW is not None), 'entry_default_None_harddeny')
    need(os.getuid() == os.geteuid() == 0 and sys.platform == 'linux' and (__import__('platform').node() == 'vicky'), 'Root_entry_only')
    source_root = HISTORY_ROOT if ROLE == 'history' else PC_ROOT
    raw, st = protected_read(source_root / (ROLE + '-index.json'))
    need(sha(raw) == APPROVED_FINAL_INDEX_SHA, 'literal_complete_final_index_not_runtime_bool')
    index = strict(raw)
    need(index['review_sha256'] == APPROVED_REVIEW and index['role'] == ROLE and (index['operation'] == EPOCH_OPERATION), 'fixed_role_scope_namespace')
    for name, pin in index['files'].items():
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'relative_known_closure_leaf')
        body, meta = protected_read(source_root / name, limit=2097152)
        need(sha(body) == pin, 'exact_complete_final_bytes_before_effect')
    return index

def main():
    index = validate()
    source_root = HISTORY_ROOT if ROLE == 'history' else PC_ROOT
    unit = HISTORY_UNIT if ROLE == 'history' else SCOPE_UNIT
    worker = source_root / (ROLE + '-scope/worker.py')
    state = source_root / (ROLE + '-scope/once')
    from inputs import io_utils as io
    if MODE == 'launch':
        old = capture(['/usr/bin/systemctl', 'show', unit, '--property=LoadState,MainPID'], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 10, cap=4096)
        need(old.returncode == 0 and (not old.stderr) and (dict((x.split('=', 1) for x in old.stdout.decode().splitlines())) == {'LoadState': 'not-found', 'MainPID': '0'}) and (not state.exists()), 'new_scope_launch_once_no_old_retry')
        io.fresh(source_root / (ROLE + '-launch-intent.json'), encode({'operation': EPOCH_OPERATION, 'unit': unit, 'index_sha256': APPROVED_FINAL_INDEX_SHA, 'observed_at': time.time(), 'automatic_retry': False}))
        r = capture(argv(str(worker), unit), env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 30, cap=65536)
        io.fresh(source_root / (ROLE + '-launch-result.json'), encode({'rc': r.returncode, 'stdout_raw_utf8': r.stdout.decode(), 'stderr_raw_utf8': r.stderr.decode(), 'observed_at': time.time()}))
        need(r.returncode == 0 and (not r.stderr), 'launch_failed_no_retry')
        return 0
    proof = observe(ROLE)
    returnedraw, rs = protected_read(state / 'returned-zero.json')
    returned = strict(returnedraw)
    positive(proof, returned, index['files'][ROLE + '-scope/worker.py'], unit=unit)
    code, cs = protected_read(source_root / (ROLE + '-finalize.py'))
    need(sha(code) == index['files'][ROLE + '-finalize.py'], 'source_closed_qualifier_loader')
    m = types.ModuleType('root_actual_registry_finalize')
    m.__file__ = str(source_root / (ROLE + '-finalize.py'))
    exec(compile(code, m.__file__, 'exec'), m.__dict__)
    result = m.main()
    io.fresh(source_root / (ROLE + '-archived-qualified.json'), encode({'scope': proof, 'returned_raw_utf8': returnedraw.decode(), 'returned_sha256': sha(returnedraw), 'returned_F9': rs, 'result': result, 'observed_at': time.time()}))
    reread = observe(ROLE)
    need(reread['unit'] == proof['unit'] and reread['cgroup_procs'] == [], 'same_retained_actual_exit_before_stop')
    io.fresh(source_root / (ROLE + '-owned-stop-intent.json'), encode({'unit': unit, 'invocation_id': proof['unit']['InvocationID'], 'observed_at': time.time(), 'calls': 1}))
    r = capture(['/usr/bin/systemctl', 'stop', unit], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 30, cap=65536)
    io.fresh(source_root / (ROLE + '-owned-stop-result.json'), encode({'rc': r.returncode, 'stdout_raw_utf8': r.stdout.decode(), 'stderr_raw_utf8': r.stderr.decode(), 'observed_at': time.time()}))
    need(r.returncode == 0 and (not r.stderr), 'owned_stop_failed_no_retry')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
