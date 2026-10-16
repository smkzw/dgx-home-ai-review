# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One finite managed Root worker, no action at import. Generic source DAG leaf."""
import json, os, platform, re, signal, sys, time, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'pc'))
sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
ROLE = 'epoch'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'

def run():
    if APPROVED_REVIEW is None or ROLE is None:
        return 0
    need(ROLE in ('history', 'epoch') and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux') and (platform.node() == 'vicky'), 'finite_Root_PC_worker_role')
    source_root = HISTORY_ROOT if ROLE == 'history' else PC_ROOT
    raw, st = protected_read(source_root / (ROLE + '-index.json'))
    index = strict(raw)
    need(index['review_sha256'] == APPROVED_REVIEW and index['role'] == ROLE and (index['operation'] == EPOCH_OPERATION), 'fixed_root_review_not_json_enable')
    loaderpath = source_root / (ROLE + '-scope/loader.py')
    loader, ls = protected_read(loaderpath)
    need(sha(loader) == index['files'][ROLE + '-scope/loader.py'], 'actual_source_closed_loader')
    workerpath = source_root / (ROLE + '-scope/worker.py')
    worker, ws = protected_read(workerpath)
    need(sha(worker) == index['files'][ROLE + '-scope/worker.py'], 'own_worker_final_source')
    state = source_root / (ROLE + '-scope/once')
    need(not state.exists() and (not state.is_symlink()), 'once_scope_not_replayed')
    state.mkdir(mode=448)
    from inputs import io_utils as io
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    inv = os.environ.get('INVOCATION_ID', '')
    need(re.fullmatch('[0-9a-f]{32}', inv), 'native_systemd_invocation')
    identity = {'operation': EPOCH_OPERATION, 'worker_pid': os.getpid(), 'worker_path': str(workerpath), 'worker_sha256': sha(worker), 'worker_F9': ws, 'loader_sha256': sha(loader), 'loader_F9': ls, 'boot_id': boot, 'invocation_id': inv, 'index_sha256': sha(raw), 'index_F9': st, 'observed_at': time.time()}
    io.fresh(state / 'intent.json', encode(identity))
    end = time.monotonic() + 840
    oldterm = signal.getsignal(signal.SIGTERM)
    oldalarm = signal.getsignal(signal.SIGALRM)

    class Interrupted(BaseException):
        pass

    def interrupt(sig, frame):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
        raise Interrupted()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 840)
    try:
        m = types.ModuleType('held_registry_once_loader')
        m.__file__ = str(loaderpath)
        exec(compile(loader, m.__file__, 'exec'), m.__dict__)
        result = m.main()
        need(type(result) is dict and time.monotonic() < end, 'loader_result_within_absolute_window')
        code, again = protected_read(loaderpath)
        need(code == loader and again == ls, 'actual_loader_source_F9_after_return')
        returned = dict(identity, finished_at=time.time(), loader_returned_zero=True, result=result)
        io.fresh(state / 'returned-zero.json', encode(returned))
        return 0
    except BaseException as error:
        io.fresh(state / 'failed.json', encode(dict(identity, finished_at=time.time(), error_type=type(error).__name__, reason_code='finite_worker_failed', source_reason=source_reason(error), source_frames=source_frames(error), partial_preserved=True, automatic_retry=False)))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGTERM, oldterm)
        signal.signal(signal.SIGALRM, oldalarm)
if __name__ == '__main__':
    raise SystemExit(run())
