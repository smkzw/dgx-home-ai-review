# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed source-held A stage RPC, no caller command/function/URL inputs."""
import base64, os, re, sys, time
from pathlib import Path
import plan, segment_runtime
from root_io import held, fresh, sha, f9
from bounded_process import capture
APPROVED = None

def envelope(path):
    raw, st = held(path, mode=384)
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st}

def command(argv, end, cap=262144):
    r = capture(argv, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=end, cap=cap)
    plan.need(r.returncode == 0 and (not r.stderr), 'fixed_stage_command_failed')
    return r.stdout

def run(request):
    plan.need(APPROVED is not None and os.getuid() == os.geteuid() == 0, 'stage_agent_SOURCE_Root')
    data = request['payload']
    stage = data.get('stage_operation')
    control, root = segment_runtime.configure(stage)
    action = request['action']
    indexraw, st = held(Path(plan.STAGE) / 'source-index.json', APPROVED['index_sha256'], mode=384)
    ix = plan.strict(indexraw)
    for n, pin in ix['files'].items():
        held(Path(plan.STAGE) / n, pin, mode=384)
    if action == 'asset-prepare':
        plan.need(set(data) == {'stage_operation', 'plan_raw_b64', 'plan_sha256', 'entry_context', 'clock_request'}, 'stage_fixed_prepare_data')
        raw = base64.b64decode(data['plan_raw_b64'], validate=True)
        p = plan.strict(raw)
        c = data['entry_context']
        plan.need(sha(raw) == data['plan_sha256'] and p['stage_operation'] == stage and (p['operation_family'] == plan.OPERATION) and (p['review_sha256'] == APPROVED['review_sha256']) and (p['manager_identity'] == c['manager_identity']) and (p['config_sha256'] == c['PC_config_sha256']), 'stage_prepare_exact_current_plan')
        from parent_source import qualified_PC
        qualified_PC(c['PC_qualification_original'], c, review=APPROVED['review_sha256'])
        from asset_segments import exact_ranges
        exact_ranges(p['ranges'])
        parent = control.parent
        if not parent.exists():
            parent.mkdir(mode=448)
            os.chmod(parent, 448)
        control.mkdir(mode=448)
        os.chmod(control, 448)
        (control / 'readiness').mkdir(mode=448)
        os.chmod(control / 'readiness', 448)
        for name, b in [('plan.json', raw), ('entry-context.json', plan.encode(c)), ('entry-clock-request.json', base64.b64decode(data['clock_request']['request_raw_b64'], validate=True))]:
            fresh(control / name, b)
        fresh(control / 'entry-clock-start.json', plan.encode({'A_started_at': time.time(), 'A_monotonic_started': time.monotonic()}))
        return {'prepared': stage, 'native_success': False}
    if action == 'asset-ready-start':
        plan.need(set(data) == {'stage_operation'}, 'fixed_ready_start')
        argv = plan.entry_argv()
        argv = ['--unit=' + plan.ENTRY_UNIT if a.startswith('--unit=') else plan.STAGE + '/segment_ready_worker.py' if a == plan.STAGE + '/entry_worker.py' else a for a in argv]
        argv += ['-never-sent'] if False else []
        argv.insert(argv.index('/usr/bin/python3'), '--setenv=STAGE_OPERATION=' + stage)
        guard = control / 'entry-launch-intent.json'
        fresh(guard, plan.encode({'unit': plan.ENTRY_UNIT, 'stage_operation': stage, 'observed_at': time.time(), 'retry': False}))
        plan.need(command(['/usr/bin/systemctl', 'show', plan.ENTRY_UNIT, '--property=LoadState'], time.monotonic() + 5) == b'LoadState=not-found\n', 'new_stage_readiness_unit_unused')
        command(argv, time.monotonic() + 10)
        return {'launched': plan.ENTRY_UNIT}
    if action == 'asset-bind':
        plan.need(set(data) == {'stage_operation', 'context', 'proof'}, 'fixed_stage_context_data')
        c = data['context']
        c['initial_pulse_original']['A_received_at'] = time.time()
        c['context_producer_sha256'] = APPROVED['root_agent_sha256']
        c['stage_operation'] = stage
        c['plan_sha256'] = sha(held(control / 'plan.json')[0])
        c['parent_proof_sha256'] = sha(plan.encode(data['proof']))
        from qualification import parent_preflight
        parent_preflight(data['proof'], c)
        plan.context_nvme(c)
        plan.need(c['owned_aggregate_unit'] == plan.UNIT and c['owned_aggregate_cgroup'] == plan.CG, 'exact_stage_private_aggregate')
        fresh(control / 'context.json', plan.encode(c))
        fresh(control / 'parent-proof.json', plan.encode(data['proof']))
        return {'context_sha256': sha(plan.encode(c))}
    if action == 'asset-start':
        plan.need(set(data) == {'stage_operation'}, 'fixed_stage_start_no_command')
        c, p = segment_runtime.context(stage)
        remaining = c['remaining_seconds']
        fresh(control / 'launch-intent.json', plan.encode({'stage_operation': stage, 'unit': plan.UNIT, 'worker_sha256': APPROVED['worker_sha256'], 'remaining_seconds': remaining, 'observed_at': time.time(), 'automatic_retry': False}))
        plan.need(command(['/usr/bin/systemctl', 'show', plan.UNIT, '--property=LoadState'], time.monotonic() + 5) == b'LoadState=not-found\n', 'new_selected_stage_unit_unused')
        segment_runtime.payload_parent(stage, create=True)
        sockets = Path(segment_runtime.BASE_DATA) / 'sockets'
        if not sockets.exists():
            sockets.mkdir(mode=448)
            os.chmod(sockets, 448)
        fd = os.open(sockets, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            z = os.fstat(fd)
            named = sockets.lstat()
            plan.need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) and z.st_uid == z.st_gid == 0 and (z.st_mode & 511 == 448), 'stage_socket_private_parent_FD')
        finally:
            os.close(fd)
        argv = plan.scope_argv(c['NVMe_IO_device'], remaining)
        argv[-1] = plan.STAGE + '/segment_worker.py'
        argv.append(stage)
        fresh(control / 'runtime-max-original.json', plan.encode({'runtime_max_seconds': int(remaining), 'context_sha256': sha(held(control / 'context.json')[0]), 'observed_at': time.time()}))
        command(argv, time.monotonic() + 10)
        return {'launched': plan.UNIT}
    if action in ('asset-next', 'asset-answer'):
        from broker import exchange
        c, p = segment_runtime.context(stage, admit=False)
        raw = command(['/usr/bin/systemctl', 'show', plan.UNIT, '--property=Id', '--property=MainPID', '--property=InvocationID', '--property=LoadState', '--property=ActiveState', '--property=SubState'], time.monotonic() + 5)
        u = dict((x.split('=', 1) for x in raw.decode().splitlines()))
        pid = int(u['MainPID'])
        if pid == 0:
            plan.need(u.get('LoadState') == 'loaded' and u.get('ActiveState') == 'active' and (u.get('SubState') == 'exited'), 'stage_metadata_zeroPID_not_unknown_or_failed')
            return {'ok': True, 'pending': None, 'failure': None}
        plan.need(u['Id'] == plan.UNIT and pid > 1 and re.fullmatch('[0-9a-f]{32}', u['InvocationID']), 'live_stage_metadata_owned_worker')
        if action == 'asset-next':
            plan.need(u['LoadState'] == 'loaded' and u['ActiveState'] == 'active' and (u['SubState'] == 'running'), 'stage_metadata_actual_owned_running')
            try:
                Path(plan.SOCKET).lstat()
            except FileNotFoundError as e:
                plan.need(e.errno == 2, 'stage_metadata_socket_absence_errno')
                return {'ok': True, 'pending': None, 'failure': None}
            return exchange({'action': 'parent-next', 'operation': plan.OPERATION}, time.monotonic() + 8, server_pid=pid)
        plan.need(set(data) == {'stage_operation', 'nonce', 'answer'}, 'fixed_stage_metadata_answer')
        answer = dict(data['answer'])
        if type(answer) is dict and 'original_raw_b64' in answer:
            answer['A_received_at'] = time.time()
        return exchange({'action': 'parent-answer', 'operation': plan.OPERATION, 'nonce': data['nonce'], 'answer': answer}, time.monotonic() + 8, server_pid=pid)
    if action in ('asset-ready-observe', 'asset-ready-finalize', 'asset-observe', 'asset-finalize'):
        readonly = 'ready' in action
        unit = plan.ENTRY_UNIT if readonly else plan.UNIT
        worker = Path(plan.STAGE) / ('segment_ready_worker.py' if readonly else 'segment_worker.py')
        wp = APPROVED['ready_worker_sha256' if readonly else 'worker_sha256']
        state = Path(plan.ENTRY_STATE) if readonly else Path(plan.ROOT)
        from observer import collect, positive
        rawunit = command(['/usr/bin/systemctl', 'show', unit], time.monotonic() + 5)
        u = dict((x.split('=', 1) for x in rawunit.decode().splitlines()))
        if u['MainPID'] != '0':
            plan.need(u['Id'] == unit and u['LoadState'] == 'loaded' and (u['ActiveState'] == 'active') and (u['SubState'] == 'running') and (int(u['MainPID']) > 1) and (wp == sha(held(worker, wp)[0])), 'owned_actual_stage_running_not_terminal')
            return {'pending': True}
        if readonly:
            proof = collect(unit, state / 'returned-zero.json', worker, wp, time.monotonic() + 5)
            positive(proof, unit, wp, True)
            if action == 'asset-ready-observe':
                return {'pending': False, 'scope': proof}
            from segment_ready import finalize
            return finalize(stage, control, proof, APPROVED)
        from segment_terminal_producer import produce
        if action == 'asset-observe':
            return {'pending': False, 'actual_unit_original': rawunit.decode()}
        plan.need(set(data) == {'stage_operation', 'terminal_clock'}, 'exact_actual_terminal_clock_payload')
        clock = data['terminal_clock']
        plan.need(set(clock) == {'request_raw_b64', 'request_sha256'}, 'terminal_request_fullraw_no_callback')
        request = base64.b64decode(clock['request_raw_b64'], validate=True)
        r = plan.strict(request)
        plan.need(sha(request) == clock['request_sha256'] and r['schema'] == 'fixed-stage-terminal-clock-request/v1' and (r['stage_operation'] == stage) and (r['operation'] == plan.OPERATION), 'actual_terminal_request_source_nonce')
        ctx = plan.strict(held(control / 'context.json', mode=384)[0])
        plan.need(r['manager_identity'] == ctx['manager_identity'] and r['config_sha256'] == ctx['PC_config_sha256'] and (r['source118'] == ctx['current_PC_source118']) and (r['review_sha256'] == ctx['source_release_sha256']), 'terminal_request_actual_context')
        fresh(control / 'terminal-clock-request.json', request)
        return produce(stage, control, rawunit, APPROVED)
    raise plan.Refused('unknown_fixed_asset_action')
