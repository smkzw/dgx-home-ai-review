# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite independent readonly Root qualification. No retries or model actions."""
import hashlib, json, os, re, signal, sys, time, types
from pathlib import Path
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16')
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'

def main():
    if APPROVED_REVIEW is None:
        raise RuntimeError('renewal_source_pending')
    if os.getuid() != os.geteuid() or os.geteuid() != 0 or sys.platform != 'linux':
        raise RuntimeError('Root_renewal_worker_only')
    sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
    from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, need, sha, encode, strict
    iraw, is_ = protected_read(ROOT / 'epoch-index.json')
    ix = strict(iraw)
    need(ix['review_sha256'] == APPROVED_REVIEW, 'new_source_review')
    raw, st = protected_read(ROOT / 'renewal-loader.py', limit=2097152)
    need(sha(raw) == ix['files']['renewal-loader.py'], 'actual_loader_in_source_index')
    worker, ws = protected_read(ROOT / 'renewal-worker.py')
    need(sha(worker) == ix['files']['renewal-worker.py'], 'same_worker_source_index')
    inv = os.environ.get('INVOCATION_ID', '')
    need(re.fullmatch('[0-9a-f]{32}', inv), 'actual_systemd_invocation')

    class Interrupted(BaseException):
        pass

    def stop(sig, frame):
        raise Interrupted()
    old = {s: signal.getsignal(s) for s in (signal.SIGALRM, signal.SIGTERM)}
    for s in old:
        signal.signal(s, stop)
    signal.setitimer(signal.ITIMER_REAL, 90)
    try:
        m = types.ModuleType('new_current_root_renewal')
        m.__file__ = str(ROOT / 'renewal-loader.py')
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        result = m.main('collect')
        iraw, ist = protected_read(ROOT / 'pc/inputs/io_utils.py')
        need(sha(iraw) == ix['files']['pc/inputs/io_utils.py'], 'actual_renewal_IO_source')
        io = types.ModuleType('renewal_root_IO')
        io.__file__ = str(ROOT / 'pc/inputs/io_utils.py')
        exec(compile(iraw, io.__file__, 'exec'), io.__dict__)
        parent = ROOT / 'runtime-qualifications' / result['manager_identity']['invocation_id']
        returned = {'operation': ix['operation'], 'worker_pid': os.getpid(), 'worker_path': str(ROOT / 'renewal-worker.py'), 'worker_sha256': sha(worker), 'worker_F9': ws, 'loader_sha256': sha(raw), 'loader_F9': st, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': inv, 'observed_at': result['observed_at'], 'finished_at': time.time(), 'loader_returned_zero': True, 'result': result}
        io.fresh(parent / 'returned-zero.json', encode(returned), mode=288, gid=989)
        return 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for s, v in old.items():
            signal.signal(s, v)
if __name__ == '__main__':
    raise SystemExit(main())
