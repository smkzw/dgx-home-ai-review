# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Full retained EXIT0 and archive/ownedstop originals, then pure typed A consumer."""
import base64, math, re
from plan import need, strict, encode
from root_io import sha
import prelaunch_negative as negative
import old_failed_kernel as kernel
import gate_protocol as protocol

def original(row):
    return negative.original(row)

def seconds(raw):
    if re.fullmatch('[0-9]+', raw):
        return int(raw) / 1000000
    factors = {'us': 1e-06, 'ms': 0.001, 's': 1, 'min': 60, 'h': 3600}
    parts = re.findall('([0-9]+(?:\\.[0-9]+)?)(us|ms|min|s|h)', raw)
    need(parts and ''.join((a + b for a, b in parts)) == raw.replace(' ', ''), 'R11_actual_duration')
    return sum((float(x) * factors[y] for x, y in parts))

def positive(scope, ret, worker_pin, request):
    u = scope['unit']
    raw = scope['unit_raw_utf8'].encode()
    need(sha(raw) == scope['unit_sha256'] and dict((x.split('=', 1) for x in raw.decode().splitlines())) == u, 'R11_scope_original_raw')
    need(u['Id'] == request['unit'] and u['Type'] == 'exec' and (u['User'] == u['Group'] == 'root') and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['NRestarts'] == '0') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (u['KillMode'] == 'process'), 'R11_true_retained_owned_EXIT0')
    need(seconds(u['CPUQuotaPerSecUSec']) == 1 and u['MemoryMax'] == '201326592' and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '32') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (seconds(u['RuntimeMaxUSec']) == 120) and (seconds(u['TimeoutStopUSec']) == 30), 'R11_actual_scope_resource_caps')
    need(type(ret['worker_pid']) is int and ret['worker_pid'] > 1 and (u['ExecMainPID'] == str(ret['worker_pid'])) and (u['InvocationID'] == ret['invocation_id']) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (scope['boot_id'] == ret['boot_id']) and (scope['cgroup_procs'] == []) and (ret['worker_sha256'] == worker_pin) and (ret['loader_sha256'] == worker_pin) and (ret['loader_returned_zero'] is True) and (ret['operation'] == protocol.OPERATION) and (ret['unit'] == request['unit']), 'R11_same_boot_inv_PID_source')
    need(ret['worker_path'] == request['root'] + '/worker.py' and 'path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + ret['worker_path'] + ' --worker ;' in u['ExecStart'], 'R11_actual_fixed_worker_exec')
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (ret['observed_at'], ret['finished_at'], scope['observed_at']))) and ret['observed_at'] <= ret['finished_at'] <= scope['observed_at'], 'R11_original_return_before_collect')
    return ret

def validate(out, request_raw, current, worker_pin, history_raw, phase):
    r = protocol.request(request_raw, current, worker_pin, phase)
    need(set(out) == {'request_nonce', 'request_sha256', 'phase', 'unit', 'actual_scope', 'returned_original', 'returned_original_leaf', 'body_original', 'owned_stop_originals', 'captured_original'}, 'R11_full_scope_envelope')
    need(out['request_nonce'] == r['nonce'] and out['request_sha256'] == sha(request_raw) and (out['phase'] == phase) and (out['unit'] == r['unit']), 'R11_scope_same_request_phase')
    ret = strict(original(out['returned_original_leaf']))
    need(ret == out['returned_original'], 'R11_returned_actual_leaf_not_derived_bool')
    positive(out['actual_scope'], ret, worker_pin, r)
    body_raw = original(out['body_original'])
    body = strict(body_raw)
    need(set(body) == {'schema', 'outer_request_original', 'request_sha256', 'proof', 'kernel', 'boot_id', 'invocation_id', 'pid', 'worker_sha256', 'observed_at', 'finished_at'} and body['schema'] == 'R11-prestart-readonly-body/v1' and (original(body['outer_request_original']) == request_raw) and (body['request_sha256'] == sha(request_raw)) and (body['worker_sha256'] == worker_pin) and (body['pid'] == ret['worker_pid']) and (body['invocation_id'] == ret['invocation_id']) and (body['boot_id'] == ret['boot_id']) and (ret['result'] == {'body_sha256': sha(body_raw)}), 'R11_body_original_identity')
    need(body['kernel'] == {'cpu.max': '100000 100000', 'memory.max': '201326592', 'memory.swap.max': '0', 'pids.max': '32', 'cgroup.procs': str(ret['worker_pid'])}, 'R11_worker_actual_kernel')
    need(body['observed_at'] <= body['proof']['started_at'] <= body['proof']['finished_at'] <= body['finished_at'] <= ret['finished_at'], 'R11_body_time_order')
    negative.validate(body['proof'], history_raw, current)
    archive = strict(original(out['captured_original']))
    need(archive == {k: v for k, v in out.items() if k not in ('owned_stop_originals', 'captured_original')}, 'R11_archived_capture_exact')
    leaves = out['owned_stop_originals']
    need(set(leaves) == {'owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'}, 'R11_complete_ownedstop_three')
    si, sr, so = (strict(original(leaves[n])) for n in ('owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'))
    need(set(si) == {'unit', 'invocation_id', 'owned_scope_stop_calls', 'issued_at'} and si['unit'] == r['unit'] and (si['invocation_id'] == ret['invocation_id']) and (type(si['owned_scope_stop_calls']) is int) and (si['owned_scope_stop_calls'] == 1) and (type(sr['rc']) is int) and (sr['rc'] == 0) and (sr['stderr_b64'] == '') and (out['actual_scope']['observed_at'] <= si['issued_at'] <= sr['observed_at'] <= so['observed_at']), 'R11_actual_owned_stop_order_rc0')
    base64.b64decode(sr['stdout_b64'], validate=True)
    u = so['unit']
    raw = so['unit_raw_utf8'].encode()
    need(sha(raw) == so['unit_sha256'] and dict((x.split('=', 1) for x in raw.decode().splitlines())) == u and (u['Id'] == r['unit']) and (u['MainPID'] == '0') and (u['ActiveState'] == 'inactive') and (u['SubState'] == 'dead') and (u['NRestarts'] == '0') and (so['cgroup_procs'] == []) and (so['boot_id'] == ret['boot_id']), 'R11_poststop_original_current_negative')
    if u['LoadState'] == 'loaded':
        need(so['poststop_unit_branch'] == 'loaded-same-invocation' and u['InvocationID'] == ret['invocation_id'] and (u['ExecMainPID'] == str(ret['worker_pid'])) and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['ControlGroup'] in ('', '/system.slice/' + r['unit'])), 'R11_loaded_poststop_exact_original_inv')
    else:
        need(so['poststop_unit_branch'] == 'collected-with-independent-kernel-proof' and u['LoadState'] == 'not-found' and (u['InvocationID'] == u['ControlGroup'] == u['Type'] == u['User'] == u['Group'] == '') and (u['ExecMainPID'] == u['ExecMainCode'] == u['ExecMainStatus'] == '0') and (u['Result'] == 'success'), 'R11_collected_exact_missing_not_EXIT0')
    kernel.validate_failed_kernel(so['poststop_kernel_original'], r['unit'], ret['worker_pid'], ret['boot_id'], sr['observed_at'])
    return {'phase': phase, 'state': 'NOT_LAUNCHED_QUIESCENT', 'aggregate_exit_status': None, 'readonly_scope_retained_EXIT0': True, 'proof': body['proof'], 'request': r}
