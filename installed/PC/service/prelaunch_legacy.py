# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact immutable old A-entry validator closure. Never a live admission."""
import sys, types
from pathlib import Path
from history_namespace import Namespace
from contract import need, sha
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-nodecold-r6/service')
ORDER = ('plan.py', 'bounded_process.py', 'root_io.py', 'observer.py', 'entry_clock.py')

def load(policy):
    previous = {}
    modules = {}
    namespace = Namespace(str(ROOT), {n: policy['Root65']['service/' + n]['sha256'] for n in ORDER})
    try:
        for name in ORDER:
            raw, st = protected_read(ROOT / name, limit=2097152)
            pin = policy['Root65']['service/' + name]
            need(sha(raw) == pin['sha256'] and st == pin['F9'], 'original_historical_validator_source_fullSHA_F9')
            m = namespace.load(name, raw, str(ROOT / name))
            modules[name[:-3]] = m
        need(modules['plan'].OPERATION == policy['operation'], 'old_validator_operation_not_new_grant')
        return modules
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
