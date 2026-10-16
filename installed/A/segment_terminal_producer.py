# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual retained stage result+quiescent kernel; source never invents EXIT."""
import base64, os, time
from pathlib import Path
import plan
from root_io import held, fresh, sha
from observer import collect
from bounded_process import capture
import old_failed_kernel as kernel

def env(path):
    raw, st = held(path, mode=384)
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st}

def produce(stage, control, unitraw, approved):
    u = dict((s.split('=', 1) for s in unitraw.decode().splitlines()))
    root = Path(plan.ROOT)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    pid = int(u['ExecMainPID'])
    source = Path(plan.STAGE) / 'segment_worker.py'
    rawcontext, cs = held(control / 'context.json', mode=384)
    c = plan.strict(rawcontext)
    plan.need(u['Id'] == plan.UNIT and u['MainPID'] == '0' and (u['LoadState'] == 'loaded') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] in ('0', '1')) and (pid > 1), 'owned_retained_stage_terminal_not_unit_missing')
    observed = time.time()
    state = 'ASSET_STAGE_COMPLETED' if u['ExecMainStatus'] == '0' else 'FAILED_REGISTRY_QUIESCENT'
    result = root / ('segments-completed.json' if state == 'ASSET_STAGE_COMPLETED' else 'failed.json')
    kernel.ALLOWED_UNIT = plan.UNIT
    k = kernel.kernel_after_stop(plan.UNIT, pid, boot, time.monotonic() + 15)
    v = {'schema': 'fixed-image-owned-stage-terminal/v1', 'stage_operation': stage, 'operation_family': plan.OPERATION, 'review_sha256': approved['review_sha256'], 'manager_identity': c['manager_identity'], 'config_sha256': c['PC_config_sha256'], 'source118': c['current_PC_source118'], 'plan_sha256': sha(held(control / 'plan.json')[0]), 'plan_original': env(control / 'plan.json'), 'source_index_sha256': approved['index_sha256'], 'worker_sha256': approved['worker_sha256'], 'producer_sha256': sha(held(Path(plan.STAGE) / 'segment_terminal_producer.py')[0]), 'scope': {'unit': u, 'unit_raw_utf8': unitraw.decode(), 'unit_raw_sha256': sha(unitraw), 'boot_id': boot, 'cgroup_procs': []}, 'runtime_original': env(control / 'runtime-max-original.json'), 'initial_kernel_original': env(root / 'initial-kernel-unit.json'), 'context_original': env(control / 'context.json'), 'intent_original': env(root / 'intent.json'), 'result_original': env(result), 'cleanup_original': env(root / 'owned-cleanup.json'), 'kernel_original': k, 'owned_stop_originals': None, 'terminal_request_original': env(control / 'terminal-clock-request.json'), 'state': state, 'image_imported': False, 'models_started': 0, 'observed_at': observed}
    fresh(control / 'retained-terminal-original.json', plan.encode(v))
    if state == 'ASSET_STAGE_COMPLETED':
        fresh(control / 'stage-stop-intent.json', plan.encode({'unit': plan.UNIT, 'invocation_id': u['InvocationID'], 'retained_original_sha256': sha(held(control / 'retained-terminal-original.json')[0]), 'observed_at': time.time()}))
        r = capture(['/usr/bin/systemctl', 'stop', plan.UNIT], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 30, cap=65536)
        fresh(control / 'stage-stop-result.json', plan.encode({'rc': r.returncode, 'stdout_b64': base64.b64encode(r.stdout).decode(), 'stderr_b64': base64.b64encode(r.stderr).decode(), 'observed_at': time.time()}))
        plan.need(r.returncode == 0 and (not r.stderr), 'stage_actual_ownedstop_no_retry')
        v['owned_stop_originals'] = {n: env(control / n) for n in ('stage-stop-intent.json', 'stage-stop-result.json')}
        v['observed_at'] = time.time()
        v['kernel_original'] = kernel.kernel_after_stop(plan.UNIT, pid, boot, time.monotonic() + 15)
    raw = plan.encode(v)
    path = control / 'terminal-qualified.json'
    fresh(path, raw)
    _, st = held(path, mode=384)
    return {'qualified_raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st, 'stage_operation': stage}
