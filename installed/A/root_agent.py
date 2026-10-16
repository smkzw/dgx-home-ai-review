# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
CLOCK_POLICY_SHA = '255d819017e61982e94f02aa7f1e17ce557f4a6f6015fe7003a1d173e166688d'
'Small fixed Root metadata/owned scope RPC; not generic code or shell execution.'
import base64, os, platform, re, socket, stat, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan
from root_io import held, fresh, sha
from bounded_process import capture
APPROVED_AGENT = {'index_sha256': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9', 'entry_worker_sha256': '5b51f3bc679363e2317cad3ef6402fad45744db74664accf8129bd4edff99fb3', 'root_worker_sha256': 'c31ec3088783e274c8d4a12a5234d702a5058e2a2ff315c4c7d292ebfff9a05c', 'ready_worker_sha256': 'b7b66f6114bd035a98713adfe1cea67b0e96bf70b4f026f15e503b91aae15ccd', 'worker_sha256': 'e976ddc881c539de2984319cf96abc0e6410108e8d37a28c925e4b6526ae8b49', 'segment_wrappers': {'segment_runtime.py': '356294b8ce09d3eee16948b89009a03ee21388d484ff539f41acbb952dbb4eb6', 'segment_ready_worker.py': 'b7b66f6114bd035a98713adfe1cea67b0e96bf70b4f026f15e503b91aae15ccd'}, 'stage_clock_policy': {'operation': 'ed7021db9df4c839d02f3271361924de', 'source_review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9', 'worker_sha256': 'b7b66f6114bd035a98713adfe1cea67b0e96bf70b4f026f15e503b91aae15ccd', 'source_index_sha256': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'clock_policy_sha256': '255d819017e61982e94f02aa7f1e17ce557f4a6f6015fe7003a1d173e166688d', 'max_clock_skew_seconds': 30}}
KINDS = frozenset(('clock', 'bind-entry-context', 'bind-context', 'entry-clock-start', 'entry-observe', 'entry-finalize-stop', 'fetch-start', 'fetch-next', 'fetch-answer', 'fetch-observe', 'fetch-finalize-stop', 'fetch-failed-qualify', 'asset-prepare', 'asset-ready-start', 'asset-ready-observe', 'asset-ready-finalize', 'asset-bind', 'asset-start', 'asset-next', 'asset-answer', 'asset-observe', 'asset-finalize'))

def unit_call(args, seconds=5):
    r = capture(args, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + seconds, cap=4194304)
    plan.need(r.returncode == 0 and (not r.stderr), 'owned_RPC_command_nonzero_or_stderr')
    return r.stdout

def run(p):
    plan.need(APPROVED_AGENT is not None and os.getuid() == os.geteuid() == 0 and (platform.node() == 'spark-a321') and (sys.platform == 'linux'), 'Root_agent_SOURCE_default_None')
    plan.need(set(p) == {'action', 'operation', 'nonce', 'payload'} and p['operation'] == plan.OPERATION and (p['action'] in KINDS) and re.fullmatch('[0-9a-f]{32}', p['nonce']), 'fixed_A_RPC_not_arbitrary_P')
    raw, _ = held(Path(plan.STAGE) / 'source-index.json', APPROVED_AGENT['index_sha256'])
    index = plan.strict(raw)
    plan.need(index['review_sha256'] == APPROVED_AGENT['review_sha256'], 'actual_sealed_A_index')
    for n, h in index['files'].items():
        held(Path(plan.STAGE) / n, h, cap=2097152)
    action = p['action']
    if action.startswith('asset-'):
        for name, pin in APPROVED_AGENT['segment_wrappers'].items():
            held(Path(plan.STAGE) / name, pin, mode=384)
        import segment_agent
        segment_agent.APPROVED = dict(APPROVED_AGENT, root_agent_sha256=sha(Path(__file__).read_bytes()), clock_policy=dict(APPROVED_AGENT['stage_clock_policy'], producer_sha256=sha(Path(__file__).read_bytes())))
        return segment_agent.run(p)
    if action == 'clock':
        return {'nonce': p['nonce'], 'A_observed_at': time.time(), 'A_monotonic': time.monotonic(), 'source_sha256': sha(Path(__file__).read_bytes()), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    if action == 'bind-entry-context':
        c = p['payload']
        plan.need(set(c) == {'operation', 'review_sha256', 'current_PC_source118', 'manager_identity', 'PC_config_sha256', 'tools', 'PC_qualification_original', 'PC_root_rpc_source_sha256', 'NVMe_device', 'NVMe_major_minor'}, 'fixed_entry_context_data_no_paths')
        plan.need(c['operation'] == plan.OPERATION and c['review_sha256'] == APPROVED_AGENT['review_sha256'] and (len(c['current_PC_source118']) == 118), 'new_entry_source_scope')
        from parent_source import qualified_PC
        qualified_PC(c['PC_qualification_original'], c, review=APPROVED_AGENT['review_sha256'])
        plan.need(not Path(plan.ROOT).exists(), 'entry_bind_before_new_payload')
        fresh(Path(plan.STAGE) / 'entry-context.json', plan.encode(c))
        raw, st = held(Path(plan.STAGE) / 'entry-context.json')
        return {'sha256': sha(raw), 'stat': st, 'observed_at': time.time()}
    if action == 'entry-clock-start':
        import entry_clock
        data = p['payload']
        plan.need(set(data) == {'request_raw_b64', 'request_sha256'}, 'fixed_new_PC_clock_request_only')
        request = entry_clock.decode(data['request_raw_b64'])
        plan.need(sha(request) == data['request_sha256'], 'actual_PC_request_raw_SHA')
        rr = entry_clock.strict(request)
        ctx, ctxst = held(Path(plan.STAGE) / 'entry-context.json', mode=384)
        c = plan.strict(ctx)
        entry_clock.APPROVED_POLICY = {'operation': plan.OPERATION, 'source_review_sha256': APPROVED_AGENT['review_sha256'], 'producer_sha256': sha(Path(__file__).read_bytes()), 'worker_sha256': APPROVED_AGENT['entry_worker_sha256'], 'source_index_sha256': APPROVED_AGENT['index_sha256'], 'clock_policy_sha256': CLOCK_POLICY_SHA, 'max_clock_skew_seconds': 30}
        entry_clock.request_check(rr, {'review_sha256': c['review_sha256'], 'PC_source_pins': c['current_PC_source118'], '_config_sha256': c['PC_config_sha256']}, c['manager_identity'])
        plan.need(rr['unit'] == plan.ENTRY_UNIT, 'new_source_nonce_unit_exact')
        fresh(Path(plan.STAGE) / 'entry-clock-request.json', request)
        fresh(Path(plan.STAGE) / 'entry-clock-start.json', plan.encode({'A_started_at': time.time(), 'A_monotonic_started': time.monotonic(), 'request_sha256': sha(request), 'nonce': rr['nonce']}))
        action = 'entry-start'
        p = dict(p, payload={})
    if action == 'bind-context':
        from qualification import parent_preflight
        data = p['payload']
        plan.need(set(data) == {'context', 'proof'}, 'only_fixed_context_proof_data')
        c = data['context']
        proof = data['proof']
        c['initial_pulse_original']['A_received_at'] = time.time()
        c['context_producer_sha256'] = sha(Path(__file__).read_bytes())
        c['parent_proof_sha256'] = sha(plan.encode(proof))
        parent_preflight(proof, c)
        plan.need(c['source_release_sha256'] == APPROVED_AGENT['review_sha256'] and c['owned_aggregate_unit'] == plan.UNIT and (c['owned_aggregate_cgroup'] == plan.CG) and (c['manifest_sha256'] == plan.MANIFEST) and (c['config_sha256'] == plan.CONFIG), 'fixed_dynamic_parent_data_scope')
        plan.need(not Path(plan.ROOT).exists(), 'context_before_single_aggregate_launch')
        fresh(Path(plan.STAGE) / 'current-parent-proof.json', plan.encode(proof))
        fresh(Path(plan.STAGE) / 'context.json', plan.encode(c))
        _, st = held(Path(plan.STAGE) / 'context.json')
        return {'context_sha256': sha(plan.encode(c)), 'context_F9': st, 'original_grant_operation': plan.OPERATION, 'A_received_at': c['initial_pulse_original']['A_received_at'], 'observed_at': time.time()}
    if action == 'fetch-failed-qualify':
        plan.need(p['payload'] == {}, 'fixed_failed_terminal_no_caller_proof')
        from root_loader import context_for_failure
        import failed_terminal
        rawunit = unit_call(['/usr/bin/systemctl', 'show', plan.UNIT])
        ctx = context_for_failure()
        value = failed_terminal.produce(held, rawunit, ctx, APPROVED_AGENT['index_sha256'], APPROVED_AGENT['root_worker_sha256'], time.time())
        raw = plan.encode(value)
        path = Path(plan.STAGE) / 'failed-registry-terminal.json'
        fresh(path, raw)
        _, st = held(path, mode=384)
        return {'qualified_raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st, 'actual_retained_EXIT1': True, 'models_started': 0}
    readonly = action.startswith('entry-')
    unit = plan.ENTRY_UNIT if readonly else plan.UNIT
    state = Path(plan.ENTRY_STATE) if readonly else Path(plan.ROOT)
    worker = Path(plan.STAGE) / ('entry_worker.py' if readonly else 'root_worker.py')
    wp = APPROVED_AGENT['entry_worker_sha256' if readonly else 'root_worker_sha256']
    plan.need(p['payload'] == {} or action == 'fetch-answer', 'fixed_action_payload')
    if action.endswith('start'):
        guard = Path(plan.STAGE) / ('entry-launch-intent.json' if readonly else 'fetch-launch-intent.json')
        plan.need(not guard.exists(), 'durable_no_repeat_launch')
        old = unit_call(['/usr/bin/systemctl', 'show', unit, '--property=LoadState'])
        plan.need(old == b'LoadState=not-found\n', 'new_actual_named_unit_absent')
        if readonly:
            state.mkdir(mode=448)
            os.chmod(state, 448)
            argv = plan.entry_argv()
        else:
            from root_loader import context
            c = context()
            plan.context_nvme(c)
            argv = plan.scope_argv(c['NVMe_IO_device'], c['remaining_seconds'])
            c['runtime_max_seconds'] = int(c['remaining_seconds'])
            fresh(Path(plan.STAGE) / 'runtime-max-original.json', plan.encode({'runtime_max_seconds': c['runtime_max_seconds'], 'context_sha256': sha(held(Path(plan.STAGE) / 'context.json')[0]), 'observed_at': time.time()}))
            plan.need(not state.exists(), 'new_actual_payload_namespace_absent')
        fresh(guard, plan.encode({'operation': plan.OPERATION, 'request_nonce': p['nonce'], 'worker_sha256': wp, 'unit': unit, 'observed_at': time.time(), 'retry': False}))
        raw = unit_call(argv, 10)
        return {'launched': unit, 'operation': plan.OPERATION, 'native_outcome': None}
    if action in ('fetch-next', 'fetch-answer'):
        from broker import exchange
        from root_loader import context
        c = context(admit=False)
        end = time.monotonic() + min(8, c['remaining_seconds'])
        uraw = unit_call(['/usr/bin/systemctl', 'show', plan.UNIT, '--property=Id', '--property=ActiveState', '--property=SubState', '--property=MainPID', '--property=InvocationID'])
        u = dict((x.split('=', 1) for x in uraw.decode().splitlines()))
        pid = int(u['MainPID'])
        if action == 'fetch-next' and pid == 0:
            from observer import collect, positive
            proof = collect(plan.UNIT, Path(plan.ROOT) / 'returned-zero.json', worker, wp, time.monotonic() + 5)
            positive(proof, plan.UNIT, wp)
            return {'ok': True, 'pending': None, 'failure': None}
        plan.need(pid > 1 and u['Id'] == plan.UNIT and (u['ActiveState'] == 'active') and (u['SubState'] == 'running') and re.fullmatch('[0-9a-f]{32}', u['InvocationID']), 'actual_owned_live_worker')
        argv = Path('/proc/' + str(pid) + '/cmdline').read_bytes().split(b'\x00')
        plan.need(argv[:4] == [b'/usr/bin/python3', b'-I', b'-B', str(worker).encode()], 'actual_source_worker_for_metadata')
        if action == 'fetch-next' and (not Path(plan.SOCKET).exists()):
            return {'ok': True, 'pending': None, 'failure': None}
        z = Path(plan.SOCKET).lstat()
        plan.need(stat.S_ISSOCK(z.st_mode) and z.st_uid == z.st_gid == 0 and (stat.S_IMODE(z.st_mode) == 384), 'owned_Root_metadata_socket')
        if action == 'fetch-next':
            return exchange({'action': 'parent-next', 'operation': plan.OPERATION}, end, server_pid=pid)
        answer = p['payload']
        plan.need(set(answer) == {'nonce', 'answer'} and re.fullmatch('[0-9a-f]{32}', answer['nonce']), 'only_pending_nonce_answer')
        if type(answer['answer']) is dict and 'original_raw_b64' in answer['answer']:
            answer['answer']['A_received_at'] = time.time()
        return exchange({'action': 'parent-answer', 'operation': plan.OPERATION, **answer}, end, server_pid=pid)
    from observer import collect, positive
    if action.endswith('observe'):
        raw = unit_call(['/usr/bin/systemctl', 'show', unit])
        u = dict((x.split('=', 1) for x in raw.decode().splitlines()))
        if u['MainPID'] != '0':
            plan.need(u['Id'] == unit and u['LoadState'] == 'loaded' and (u['ActiveState'] == 'active') and (u['SubState'] == 'running') and (int(u['MainPID']) > 1) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and ('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + str(worker) + ' ;' in u['ExecStart']), 'actual_same_owned_running_source_before_terminal')
            held(worker, wp, mode=384)
            if (state / 'returned-zero.json').exists():
                rr, rs = held(state / 'returned-zero.json', mode=384)
                returned = plan.strict(rr)
                plan.need(returned['operation'] == plan.OPERATION and returned['worker_sha256'] == wp and (str(returned['worker_pid']) == u['MainPID']) and (returned['invocation_id'] == u['InvocationID']) and (returned['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()) and (returned['child_rc'] == returned['stderr_bytes'] == 0), 'running_return_marker_same_native_identity')
            return {'pending': True, 'unit_raw_utf8': raw.decode(), 'unit_raw_sha256': sha(raw), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observed_at': time.time()}
    proof = collect(unit, state / 'returned-zero.json', worker, wp, time.monotonic() + 5)
    if action.endswith('observe'):
        return proof
    positive(proof, unit, wp, readonly)
    marker = Path(plan.STAGE) / ('entry-finalize-intent.json' if readonly else 'fetch-finalize-intent.json')
    fresh(marker, plan.encode({'operation': plan.OPERATION, 'request_nonce': p['nonce'], 'raw_scope': proof, 'observed_at': time.time()}))
    if readonly:
        returned = plan.strict(proof['returned_original']['raw_utf8'])
        result = returned['result']
        raw = plan.encode({'schema': 'registry-R26-A-entry-qualified/v1', 'operation': plan.OPERATION, 'producer_sha256': sha(Path(__file__).read_bytes()), 'source_index_sha256': index['files'] and APPROVED_AGENT['index_sha256'], 'actual_readonly_scope': proof, 'readonly_worker_sha256': wp, 'current_PC_source118': result['current_PC_source118'], 'manager_identity': result['manager_identity'], 'PC_config_sha256': result['PC_config_sha256'], 'result': result, 'models_started': 0, 'observed_at': time.time()})
        path = Path(plan.STAGE) / 'entry-qualified.json'
    else:
        from root_loader import context
        import terminal
        terminal.APPROVED_WORKER_SHA = wp
        terminal.APPROVED_FINAL_INDEX_SHA = APPROVED_AGENT['index_sha256']
        raw = plan.encode(terminal.produce(held, proof, context(admit=False), time.time()))
        path = Path(plan.STAGE) / 'fetch-qualified.json'
    fresh(path, raw)
    _, st = held(path)
    fresh(Path(str(path) + '.origin.json'), plan.encode({'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st, 'scope': proof, 'observed_at': time.time()}))
    current = collect(unit, state / 'returned-zero.json', worker, wp, time.monotonic() + 5)
    plan.need(current['unit'] == proof['unit'] and current['returned_original'] == proof['returned_original'], 'same_owned_identity_before_stop')
    stopname = 'entry' if readonly else 'fetch'
    fresh(Path(plan.STAGE) / (stopname + '-stop-intent.json'), plan.encode({'unit': unit, 'InvocationID': proof['unit']['InvocationID'], 'receipt_sha256': sha(raw), 'observed_at': time.time()}))
    stopresult = capture(['/usr/bin/systemctl', 'stop', unit], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=time.monotonic() + 30, cap=65536)
    fresh(Path(plan.STAGE) / (stopname + '-stop-result.json'), plan.encode({'rc': stopresult.returncode, 'stdout_b64': base64.b64encode(stopresult.stdout).decode(), 'stderr_b64': base64.b64encode(stopresult.stderr).decode(), 'observed_at': time.time()}))
    plan.need(stopresult.returncode == 0 and (not stopresult.stderr), 'actual_owned_stop_result0_no_retry')
    if readonly:
        import entry_clock
        request, requeststat = held(Path(plan.STAGE) / 'entry-clock-request.json', mode=384)
        moment, ms = held(Path(plan.STAGE) / 'entry-clock-start.json', mode=384)
        m = plan.strict(moment)
        entry_clock.APPROVED_POLICY = {'operation': plan.OPERATION, 'source_review_sha256': APPROVED_AGENT['review_sha256'], 'producer_sha256': sha(Path(__file__).read_bytes()), 'worker_sha256': wp, 'source_index_sha256': APPROVED_AGENT['index_sha256'], 'clock_policy_sha256': CLOCK_POLICY_SHA, 'max_clock_skew_seconds': 30}
        stops = {}
        for name in ('entry-stop-intent.json', 'entry-stop-result.json'):
            data, ds = held(Path(plan.STAGE) / name, mode=384)
            stops[name] = {'raw_b64': base64.b64encode(data).decode(), 'sha256': sha(data), 'stat': ds}
        response = entry_clock.A_response(request, requeststat, raw, st, started_at=m['A_started_at'], finished_at=time.time(), elapsed=time.monotonic() - m['A_monotonic_started'], positive=positive, stop_originals=stops)
        fresh(Path(plan.STAGE) / 'entry-clock-response.json', response)
        return {'response_raw_b64': base64.b64encode(response).decode(), 'response_sha256': sha(response), 'owned_stop_calls': 1}
    return {'qualified_raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st, 'scope': proof, 'owned_stop_calls': 1, 'observed_at': time.time()}

def main():
    plan.need(APPROVED_AGENT is not None, 'Root_agent_default_None')
    raw = sys.stdin.buffer.read(4194305)
    plan.need(len(raw) <= 4194304, 'bounded_RPC_stdin')
    try:
        result = run(plan.strict(raw))
        out = plan.encode(result)
        plan.need(len(out) <= 4194304, 'bounded_RPC_stdout')
        sys.stdout.buffer.write(out)
    except BaseException as error:
        import diagnostics
        value = diagnostics.details(error, 'source_context')
        value.update(reason_code='owned_A_RPC_failed_no_retry', native_success=False)
        sys.stdout.buffer.write(plan.encode(value))
        return 1
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
