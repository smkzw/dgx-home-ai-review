# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Parent-only transport for one necessary R12 epoch; not source admission.
Caller must complete final source/CPU/fresh hardware acceptance first.
No automatic main/run, replay, rollback or clock extension is provided.
"""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import subprocess
import time
EPOCH = '2b9e9b631cebc13ae6b1550ee59c13ed'
HELPER = Path('/REDACTED_HOME/AI-Staging/DGX_HOME_AI_20261011_V4/runtime/parent_checks/R21_CONTINUE_NATIVE_R1/native_parent.py')
HELPER_SHA = 'dcdd599f2f672cced4c494b5e5934510f0d64f6034fa32c4a094e40ea0acc237'
WARNING_SHA = 'b280c454d6f559e56eb3f5ed39f3ba084b8d1744a3ff7fe016b21ff86dea1aca'

def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

class EpochOnce:

    def __init__(self, work, graph):
        p = graph['packet']
        need(p['operation'] == EPOCH and p['entry_phase'] == 'LIVE_IDLE_FAILED_TERMINAL_HELD' and (p['grant_operation'] == 'ed7021db9df4c839d02f3271361924de') and (type(p['review_sha256']) is str) and (re.fullmatch('[0-9a-f]{64}', p['review_sha256']) is not None), 'only_new_R12_epoch_domain')
        index = json.loads(graph['PC']['epoch-index.json'])
        need(index['review_sha256'] == p['review_sha256'] and index['operation'] == EPOCH and all((sha(graph['PC'][n]) == pin for n, pin in index['files'].items())), 'complete_same_new_physical_index')
        need(sha(HELPER.read_bytes()) == HELPER_SHA, 'fixed_existing_parent_transport')
        spec = importlib.util.spec_from_file_location('R12_epoch_fixed_native', HELPER)
        self.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.native)
        self.work = Path(work)
        need(not self.work.exists(), 'new_epoch_parent_once_no_replay')
        self.work.mkdir(mode=448)
        self.started = time.monotonic()
        self.end = self.started + 900
        self.p = p
        self.native.fresh(self.work / 'parent-window.json', encode({'schema': 'R12-parent-finite-epoch/v1', 'operation': EPOCH, 'review_sha256': p['review_sha256'], 'issued_at': time.time(), 'monotonic_origin': self.started, 'monotonic_deadline': self.end, 'whole_seconds': 900, 'automatic_retry': False, 'source_or_hardware_admission_from_this_file': False}))

    def actual(self, tag, code, *, node='pc', timeout=65):
        need(type(tag) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,95}', tag) is not None and (node in ('pc', 'spark-a', 'spark-c')), 'fixed_parent_epoch_phase_and_nodes')
        remaining = self.end - time.monotonic()
        need(remaining > 0 and type(timeout) in (int, float) and math.isfinite(timeout) and (timeout > 0), 'original_parent_epoch900_expired_no_reset')
        timeout = min(timeout, remaining)
        raw = code.encode() if isinstance(code, str) else code
        need(type(raw) is bytes and 0 < len(raw) <= 8388608, 'existing_user_source_bundle_transport_cap')
        self.native.fresh(self.work / (tag + '-intent.json'), encode({'phase': tag, 'node': node, 'operation': EPOCH, 'source_sha256': sha(raw), 'issued_at': time.time(), 'timeout_seconds': timeout, 'automatic_retry': False}))
        native_tag = 'r16-epoch-' + EPOCH + '-' + tag
        try:
            result = self.native.capture(native_tag, raw, node=node, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            observed = {'phase': tag, 'remote_outcome': 'unknown_no_retry', 'timeout_seconds': error.timeout}
            for stream, value in (('stdout', error.output), ('stderr', error.stderr)):
                observed[stream + '_present'] = value is not None
                if value is not None:
                    b = value if isinstance(value, bytes) else value.encode()
                    self.native.fresh(self.work / (tag + '-timeout-' + stream + '.raw'), b)
                    observed[stream + '_sha256'] = sha(b)
                    observed[stream + '_bytes'] = len(b)
            self.native.fresh(self.work / (tag + '-timeout-original.json'), encode(observed))
            raise
        stderr = (self.native.HERE / native_tag / 'actual.stderr').read_bytes()
        allowed = stderr == b'' or (node == 'pc' and len(stderr) == 132 and (sha(stderr) == WARNING_SHA))
        self.native.fresh(self.work / (tag + '-result.json'), encode(result))
        self.native.fresh(self.work / (tag + '-stderr-audit.json'), encode({'stderr_bytes': len(stderr), 'stderr_sha256': sha(stderr), 'exact_known_or_empty': allowed, 'effect_not_rolled_back': True}))
        need(allowed, 'unexpected_stderr_original_preserved_no_retry')
        return result
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_no_native_epoch_admission')
