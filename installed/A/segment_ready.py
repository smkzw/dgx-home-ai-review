# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Archive genuine stage-readiness EXIT0, then normal ownedstop, then response."""
import base64, time
from pathlib import Path
import plan, stage_entry_clock as clock
from root_io import held, fresh, sha
from bounded_process import capture
from observer import positive

def finalize(stage, control, proof, approved):
    req, rs = held(control / 'entry-clock-request.json', mode=384)
    r = plan.strict(req)
    ctx, cs = held(control / 'entry-context.json', mode=384)
    c = plan.strict(ctx)
    moment, _ = held(control / 'entry-clock-start.json', mode=384)
    m = plan.strict(moment)
    plan.need(r['nonce'] == stage and r['unit'] == plan.ENTRY_UNIT, 'stage_actual_ready_request_unit')
    b = plan.strict(proof['returned_original']['raw_utf8'])
    q = {'schema': 'registry-R26-A-entry-qualified/v1', 'operation': plan.OPERATION, 'producer_sha256': sha(held(Path(plan.STAGE) / 'root_agent.py')[0]), 'readonly_worker_sha256': approved['ready_worker_sha256'], 'actual_readonly_scope': proof, 'manager_identity': c['manager_identity'], 'current_PC_source118': c['current_PC_source118'], 'PC_config_sha256': c['PC_config_sha256'], 'models_started': 0, 'observed_at': time.time(), 'result': b['result'], 'source_index_sha256': approved['index_sha256']}
    qr = plan.encode(q)
    path = control / 'entry-qualified.json'
    fresh(path, qr)
    _, qs = held(path, mode=384)
    raw = plan.encode({'unit': plan.ENTRY_UNIT, 'InvocationID': proof['unit']['InvocationID'], 'receipt_sha256': sha(qr), 'observed_at': time.time()})
    fresh(control / 'entry-stop-intent.json', raw)
    stop = capture(['/usr/bin/systemctl', 'stop', plan.ENTRY_UNIT], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 30, cap=65536)
    fresh(control / 'entry-stop-result.json', plan.encode({'rc': stop.returncode, 'stdout_b64': base64.b64encode(stop.stdout).decode(), 'stderr_b64': base64.b64encode(stop.stderr).decode(), 'observed_at': time.time()}))
    plan.need(stop.returncode == 0 and (not stop.stderr), 'actual_readiness_owned_stop0')
    origins = {}
    for n in ('entry-stop-intent.json', 'entry-stop-result.json'):
        raw, s = held(control / n, mode=384)
        origins[n] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': s}
    clock.APPROVED_POLICY = approved['clock_policy']
    response = clock.A_response(req, rs, qr, qs, started_at=m['A_started_at'], finished_at=time.time(), elapsed=time.monotonic() - m['A_monotonic_started'], positive=positive, stop_originals=origins)
    fresh(control / 'entry-clock-response.json', response)
    return {'stage_operation': stage, 'response_raw_b64': base64.b64encode(response).decode(), 'response_sha256': sha(response), 'owned_stop_calls': 1}
