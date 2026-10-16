# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import point_clock
'Metadata-only encrypted stdin IO. Default None; no image or token logs.'
import base64, json, math, os, select, subprocess, time, uuid
from pathlib import Path
import plan
import budget_contract, safe_error, parent_budget, compact_transport, transport_evidence, private_mux
PARENT_WINDOW = None
CLEANUP_ONLY = False
PC_BOOTSTRAP_CODE = None
from root_io import sha
APPROVED_PARENT = None
VPS_ALIAS = 'metadata-vps'
PC_LOADER = '/opt/dgx-v4/hx/mimo-registry-r16/parent-root-rpc.py'
PC_STDERR_SHA256 = 'b280c454d6f559e56eb3f5ed39f3ba084b8d1744a3ff7fe016b21ff86dea1aca'
PC_STDERR_EXACT = base64.b64decode(None, validate=True)

def captured(argv, raw, end, cap=4194304, *, node=None, safe_action=None):
    global LAST_ROUTE_TRACE, LAST_TRANSPORT_DIAGNOSTIC
    p = None
    evidence = None
    streams = {}
    phase = 'budget'
    complete = False
    failure = None
    cleanup_failure = None
    now = time.monotonic()
    route = LAST_ROUTE_TRACE
    marks = {'capture_enter': now}
    if type(route) is dict and route.get('_argv_id') == id(argv):
        marks.update(route['marks'])
    LAST_ROUTE_TRACE = None
    counts = {'request_bytes': len(raw), 'stdin_bytes': 0, 'stdout_bytes': 0, 'stderr_bytes': 0, 'decoded_bytes': 0}
    error_class = None
    error_errno = None
    classes = {'Refused', 'RuntimeError', 'ValueError', 'TypeError', 'AssertionError', 'TimeoutExpired', 'BrokenPipeError', 'ConnectionResetError', 'BlockingIOError', 'InterruptedError', 'FileNotFoundError', 'PermissionError', 'OSError', 'JSONDecodeError', 'UnicodeDecodeError'}

    def mark(name):
        marks[name] = time.monotonic()
    try:
        plan.need(PARENT_WINDOW is not None, 'actual_new_parent_budget_pending')
        PARENT_WINDOW.check_cleanup() if CLEANUP_ONLY else PARENT_WINDOW.check()
        end = end if CLEANUP_ONLY else min(end, PARENT_WINDOW.end)
        mark('budget_checked')
        phase = 'evidence_begin'
        if EVIDENCE_WRITER is not None:
            evidence = EVIDENCE_WRITER.begin(node, safe_action, raw)
        mark('evidence_begin_done')
        phase = 'body_encode'
        if node in ('pc', 'a'):
            raw = compact_transport.body(raw, PC_BOOTSTRAP_SOURCE if node == 'pc' else A_BOOTSTRAP_SOURCE)
        plan.need(node in (None, 'a', 'pc', 'vps') and type(raw) is bytes and (len(raw) <= 4194304) and (type(cap) is int) and (0 < cap <= 4194304), 'explicit_fixed_transport_bounded_input')
        plan.need(time.monotonic() < end, 'parent_transport_prepare_within_deadline')
        counts['stdin_bytes'] = len(raw)
        mark('body_encoded')
        phase = 'popen'
        p = subprocess.Popen(argv, env={'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mark('popen_returned')
        os.set_blocking(p.stdin.fileno(), False)
        streams = {p.stdout: bytearray(), p.stderr: bytearray()}
        active = list(streams)
        view = memoryview(raw)
        if not view:
            p.stdin.close()
            mark('stdin_closed')
        phase = 'io_wait'
        while active or view:
            plan.need(time.monotonic() < end, 'parent_transport_absolute_deadline')
            reads, writes, _ = select.select(active, [p.stdin] if view else [], [], min(0.25, max(0, end - time.monotonic())))
            for f in reads:
                data = os.read(f.fileno(), 65536)
                if not data:
                    active.remove(f)
                    mark('stdout_EOF' if f is p.stdout else 'stderr_EOF')
                else:
                    key = 'stdout_bytes' if f is p.stdout else 'stderr_bytes'
                    counts[key] += len(data)
                    streams[f].extend(data)
                    plan.need(sum(map(len, streams.values())) <= cap, 'parent_transport_output_cap')
                    first = 'stdout_first_byte' if f is p.stdout else 'stderr_first_byte'
                    if first not in marks:
                        mark(first)
            if writes:
                n = os.write(p.stdin.fileno(), view)
                view = view[n:]
                if not view:
                    p.stdin.close()
                    mark('stdin_closed')
        phase = 'process_wait'
        rc = p.wait(timeout=max(0.001, end - time.monotonic()))
        mark('process_reaped')
        plan.need(time.monotonic() < end, 'parent_transport_exit_within_deadline')
        complete = True
        stderr = bytes(streams[p.stderr])
        stdout = bytes(streams[p.stdout])
        phase = 'evidence_response'
        if EVIDENCE_WRITER is not None:
            EVIDENCE_WRITER.response(evidence, stdout, stderr, rc, complete=True)
        mark('evidence_response_done')
        phase = 'decode'
        if node in ('pc', 'a'):
            stdout, diag = compact_transport.decode(stdout)
            mark('decoded')
            counts['decoded_bytes'] = len(stdout)
            phase = 'evidence_decoded'
            if EVIDENCE_WRITER is not None:
                EVIDENCE_WRITER.decoded(evidence, stdout, diag)
            if diag is not None:
                LAST_SAFE_DIAGNOSTIC.clear()
                LAST_SAFE_DIAGNOSTIC.update(diag)
        mark('evidence_decoded_done')
        phase = 'exit_stderr'
        if rc != 0 and node == 'pc' and (safe_action in safe_error.READONLY):
            try:
                row = plan.strict(stdout)
                code = row['source_reason_code']
            except Exception:
                code = None
            if code in safe_error.CODES:
                raise plan.Refused(code)
        plan.need(rc == 0 and (not stderr or (node == 'pc' and stderr == PC_STDERR_EXACT and (sha(stderr) == PC_STDERR_SHA256))), 'actual_transport_exit0_exact_node_stderr')
        phase = 'strict_JSON'
        if node == 'pc':
            plan.need(type(plan.strict(stdout)) is dict, 'PC_single_strict_JSON_object_stdout')
        mark('strict_JSON_done')
        phase = 'final_deadline'
        plan.need(time.monotonic() < end, 'parent_transport_decode_evidence_absolute_deadline')
        mark('accepted_before_close')
    except BaseException as e:
        failure = e
        error_class = type(e).__name__ if type(e).__name__ in classes else 'OTHER'
        error_errno = getattr(e, 'errno', None) if isinstance(e, OSError) else None
        if type(error_errno) is not int or not 0 <= error_errno <= 4096:
            error_errno = None
    finally:
        failure_phase = phase
        phase = 'owned_close'
        try:
            if p is not None:
                if p.poll() is None:
                    p.terminate()
                    mark('owned_TERM_sent')
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        raise plan.Refused('owned_parent_SSH_alive_no_force') from None
                for f in (p.stdin, p.stdout, p.stderr):
                    if not f.closed:
                        f.close()
            mark('owned_close_done')
        except BaseException as e:
            cleanup_failure = e
            failure_phase = 'owned_close'
            error_class = type(e).__name__ if type(e).__name__ in classes else 'OTHER'
        finally:
            if evidence is not None and (not evidence['stored']):
                try:
                    EVIDENCE_WRITER.response(evidence, bytes(streams.get(p.stdout, b'')) if p else b'', bytes(streams.get(p.stderr, b'')) if p else b'', p.poll() if p else None, complete=False)
                    mark('failure_originals_stored')
                except BaseException as e:
                    if failure is None:
                        failure = e
                        failure_phase = 'evidence_response'
                        error_class = type(e).__name__ if type(e).__name__ in classes else 'OTHER'
        record = {'schema': 'parent-safe-transport-phases/v1', 'node': node, 'phase': failure_phase if failure is not None or cleanup_failure is not None else 'pre_record_deadline', 'error_class': error_class, 'errno': error_errno, 'marks': marks, 'counts': counts, 'deadline_monotonic': end, 'observed_monotonic': time.monotonic(), 'transport_EOF_and_exit_in_budget': complete, 'actual_returncode': p.poll() if p else None, 'owned_PID': p.pid if p else None, 'owned_reaped': p is None or p.poll() is not None, 'accepted_output': None, 'diagnostic_is_authority': False}
        LAST_TRANSPORT_DIAGNOSTIC = record
        if EVIDENCE_WRITER is not None:
            EVIDENCE_WRITER.diagnostic(evidence, record)
        mark('diagnostic_record_done')
    if cleanup_failure is not None:
        raise plan.Refused('owned_parent_SSH_alive_no_force') from None
    if failure is not None:
        if safe_action in safe_error.READONLY and type(failure).__name__ == 'Refused' and (str(failure) in safe_error.CODES):
            raise failure
        raise plan.Refused('parent_metadata_transport_failed_no_retry') from None
    if time.monotonic() >= end:
        record['phase'] = 'post_record_deadline'
        record['error_class'] = 'Refused'
        record['observed_monotonic'] = time.monotonic()
        if EVIDENCE_WRITER is not None:
            EVIDENCE_WRITER.diagnostic(evidence, record, late=True)
        raise plan.Refused('parent_metadata_transport_failed_no_retry') from None
    record['accepted_output'] = True
    record['observed_monotonic'] = time.monotonic()
    return stdout

def ssh(node, path):
    base = ['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no', '-o', 'ControlPath=none']
    if node == 'a':
        plan.need(path == plan.AGENT, 'fixed_A_compact_agent')
        return base + ['-o', 'ProxyJump=control-host', '-o', 'HostName=192.0.2.10', '-o', 'HostKeyAlias=gpu-a.example.invalid', 'spark-a', 'sudo -n /usr/bin/python3 -I -B -c ' + __import__('shlex').quote(A_BOOTSTRAP_CODE)]
    if node == 'pc':
        plan.need(path == PC_LOADER and PC_BOOTSTRAP_CODE is not None, 'fixed_PC_stdin_code')
        command = "$ProgressPreference='SilentlyContinue'; & wsl.exe -d Ubuntu-24.04 -u root -- /usr/bin/python3 -I -B -c " + "'" + PC_BOOTSTRAP_CODE.replace("'", "''") + "'; exit $LASTEXITCODE"
        return base + ['control-host', 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + base64.b64encode(command.encode('utf-16le')).decode()]
    plan.need(node == 'vps' and VPS_ALIAS is not None and (VPS_ALIAS in APPROVED_PARENT['existing_key_only_VPS_aliases']), 'fixed_existing_VPS_key_metadata_route')
    return base + ['-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', VPS_ALIAS, '/usr/bin/python3 -I -B -c ' + __import__('shlex').quote("import base64;exec(compile(base64.b64decode('" + APPROVED_PARENT['public_source_b64'] + "'),'<fixed-public-metadata>','exec'))")]

class IO:

    def __init__(self, end):
        global PARENT_WINDOW
        plan.need(PARENT_WINDOW is None, 'one_new_parent_budget')
        PARENT_WINDOW = parent_budget.Window()
        end = min(end, PARENT_WINDOW.end)
        plan.need(APPROVED_PARENT is not None and APPPROVED_VALID(APPROVED_PARENT), 'parent_SOURCE_default_None')
        self.end = end
        self.source_sha256 = sha(Path(__file__).read_bytes())
        self.tokens = 0
        self.token_deadline = None
        self.failed = False

    def rpc(self, node, action, payload, end):
        plan.need(not self.failed and time.monotonic() < min(self.end, end), 'parent_original_whole_window')
        raw = plan.encode({'action': action, 'operation': plan.OPERATION, 'nonce': uuid.uuid4().hex, 'payload': payload})
        try:
            actual_response = captured(ssh(node, plan.AGENT if node == 'a' else PC_LOADER), raw, min(self.end, end), node=node, safe_action=action)
            value = plan.strict(actual_response)
            if action == 'clock':
                self.last_clock_raw = actual_response
            if action == 'entry-finalize-stop':
                response = plan.strict(base64.b64decode(value['response_raw_b64'], validate=True))
                plan.need(sha(base64.b64decode(value['response_raw_b64'], validate=True)) == value['response_sha256'], 'actual_A_clock_response_original_SHA')
                self.entry_original = {'qualified_raw_b64': response['entry_raw_b64'], 'sha256': response['entry_sha256'], 'stat': response['entry_stat'], 'owned_stop_calls': response['owned_stop_calls']}
            return value
        except BaseException as e:
            self.failed = True
            if action in safe_error.READONLY and type(e).__name__ == 'Refused' and (str(e) in safe_error.CODES):
                raise
            raise plan.Refused('parent_owned_RPC_failed_no_retry') from None

    def next_request(self, operation, end):
        plan.need(operation == plan.OPERATION, 'fixed_metadata_operation')
        v = self.rpc('a', 'fetch-next', {}, end)
        plan.need(set(v) == {'ok', 'pending', 'failure'} and v['ok'] is True and (v['failure'] is None), 'owned_broker_current_no_failure')
        return v['pending']

    def answer(self, operation, nonce, answer, end):
        plan.need(operation == plan.OPERATION, 'fixed_metadata_operation')
        self.rpc('a', 'fetch-answer', {'nonce': nonce, 'answer': answer}, end)

    def public(self, payload, end):
        raw = captured(ssh('vps', ''), plan.encode(payload), min(self.end, end), 65536, node='vps')
        return plan.strict(raw)

    def public_dns(self, host, nonce, end):
        return self.public({'kind': 'dns', 'host': host, 'nonce': nonce}, end)

    def anonymous_repo_token(self, repo, permission, nonce, end):
        plan.need(repo == 'lmsysorg/sglang' and permission == 'pull' and (self.tokens < 6) and (self.token_deadline is None or self.token_deadline - time.monotonic() <= 30), 'fixed_anonymous_public_repo_token_budget')
        start = time.monotonic()
        self.tokens += 1
        v = self.public({'kind': 'anonymous-token', 'nonce': nonce}, end)
        floor = v['expires_in'] - math.ceil(time.monotonic() - start) - 12
        plan.need(45 < floor <= 300, 'conservative_token_remaining_too_short')
        self.token_deadline = time.monotonic() + floor
        return {'token': v['token'], 'ttl_floor_seconds': floor}

    def new_grant_pulse(self, operation, nonce, end):
        plan.need(operation == plan.OPERATION, 'fixed_current_grant')
        return self.rpc('pc', 'pulse-registry-directfetch', {'request_nonce': nonce}, end)

def APPPROVED_VALID(p):
    return type(p) is dict and p['operation'] == plan.OPERATION and (p['source_review_sha256'] is not None) and (p['actual_ancestor_qualified_sha256'] is not None) and (p['actual_current_epoch_qualified_sha256'] is not None) and (sha(base64.b64decode(p['public_source_b64'], validate=True)) == p['public_source_sha256'])

def bind_context(self, c, initial, end):
    before = self.rpc('a', 'clock', {}, min(end, time.monotonic() + 8))
    a_sent = before['A_observed_at']
    nonce = before['nonce']
    before_raw = self.last_clock_raw
    frame = self.rpc('pc', 'pulse-registry-directfetch', {}, min(end, time.monotonic() + 90))
    after = self.rpc('a', 'clock', {}, min(end, time.monotonic() + 8))
    a_received = after['A_observed_at']
    after_raw = self.last_clock_raw
    clock = point_clock.make(before_raw, frame, after_raw)
    clock_elapsed = after['A_monotonic'] - before['A_monotonic']
    point_event = plan.strict(base64.b64decode(frame['original_raw_b64'], validate=True))
    ctx = dict(c)
    ctx.update({'initial_pulse_original': dict(frame, A_received_at=a_received), 'A_minus_PC_clock_lower': a_sent - point_event['observed_at'], 'A_minus_PC_clock_upper': a_received - point_event['observed_at'], 'remaining_seconds': budget_contract.bounded_remaining(parent_remaining=min(self.end, end) - time.monotonic(), pulse_remaining=plan.strict(base64.b64decode(frame['original_raw_b64']))['remaining_seconds'], PC_phase_elapsed=frame['PC_monotonic_elapsed'], A_bracket_elapsed=clock_elapsed)})
    plan.need(hasattr(self, 'entry_original'), 'actual_A_readonly_qualification_before_grant_context')
    entry = plan.strict(base64.b64decode(self.entry_original['qualified_raw_b64'], validate=True))
    plan.need(sha(base64.b64decode(self.entry_original['qualified_raw_b64'], validate=True)) == self.entry_original['sha256'] and self.entry_original['owned_stop_calls'] == 1, 'actual_entry_original_not_count_only')
    result = entry['result']
    nvme = plan.validate_nvme_identity(result['NVMe_identity'])
    pulse = plan.strict(base64.b64decode(frame['original_raw_b64'], validate=True))
    ctx.update({'pulse_identity': {k: pulse[k] for k in ('config_sha256', 'manager_epoch_sha256', 'manager_source', 'clear_reservation_original', 'clear_reservation_sha256')}, 'initial_free_bytes': result['NVMe_free_bytes'], 'A_boot_id': entry['actual_readonly_scope']['boot_id'], 'private_config_parse_proof': result['private_config'], 'tools': result['tools'], 'NVMe_device': nvme['filesystem']['path'], 'NVMe_major_minor': nvme['filesystem']['major_minor'], 'NVMe_IO_device': nvme['originating_io']['path'], 'NVMe_IO_major_minor': nvme['originating_io']['major_minor'], 'NVMe_identity': nvme})
    proof = {'schema': 'registry-R26-A-fresh-source-and-grant/v1', 'operation': plan.OPERATION, 'source_release_sha256': c['source_release_sha256'], 'manager_identity': c['manager_identity'], 'current_PC_source118': c['current_PC_source118'], 'PC_config_sha256': c['PC_config_sha256'], 'current_epoch_raw_sha256': c['current_epoch_raw_sha256'], 'historical_ancestor_sha256': c['historical_ancestor_sha256'], 'fresh_wholeidle_original_sha256': pulse['clear_reservation_sha256'], 'A_route': {'source': '192.0.2.10', 'interface': 'enP7s7', 'gateway': '192.0.2.10', 'application_proxy': False}, 'A_boot_id': ctx['A_boot_id'], 'NVMe_identity': nvme, 'scope_namespace_absent': result['payload_namespace_absent'], 'NVMe_free_bytes': result['NVMe_free_bytes'], 'MemAvailable_bytes': result['MemAvailable_bytes'], 'observed_at': entry['observed_at'], 'clock_original': clock, 'request_nonce': nonce}
    ctx['parent_proof_observed_at'] = proof['observed_at']
    return self.rpc('a', 'bind-context', {'context': ctx, 'proof': proof}, end)
IO.bind_context = bind_context

def metadata_step(self, end):
    from parent_metadata import Responder
    if not hasattr(self, 'responder'):
        self.responder = Responder(self, self.end)
    return self.responder.step()
IO.metadata_step = metadata_step

def bind_entry(self, c, end):
    actual = self.rpc('pc', 'source-context', {}, end)
    plan.need(actual['qualified_sha256'] == APPROVED_PARENT['actual_current_epoch_qualified_sha256'] == c['current_epoch_raw_sha256'], 'real_late_current_qualification_not_future_slot')
    v = plan.strict(base64.b64decode(actual['qualified_raw_b64'], validate=True))
    plan.need(v['ancestor']['ancestor_sha256'] == APPROVED_PARENT['actual_ancestor_qualified_sha256'] == c['historical_ancestor_sha256'], 'real_ancestor_not_new_PID')
    entry = {'operation': plan.OPERATION, 'review_sha256': c['source_release_sha256'], 'current_PC_source118': c['current_PC_source118'], 'manager_identity': c['manager_identity'], 'PC_config_sha256': c['PC_config_sha256'], 'tools': c['tools'], 'PC_qualification_original': actual, 'PC_root_rpc_source_sha256': APPROVED_PARENT['PC_rpc_sha256'], 'NVMe_device': c['NVMe_device'], 'NVMe_major_minor': c['NVMe_major_minor']}
    return self.rpc('a', 'bind-entry-context', entry, end)
IO.bind_entry = bind_entry
PC_BOOTSTRAP_SOURCE = None

def guard_window(self):
    return PARENT_WINDOW.check()
IO.guard_window = guard_window
A_BOOTSTRAP_SOURCE = None
A_BOOTSTRAP_CODE = None
LAST_SAFE_DIAGNOSTIC = {}
EVIDENCE_WRITER = None
PRIVATE_MUX = None
plain_ssh = ssh

def ssh(node, path):
    global LAST_ROUTE_TRACE
    trace = {'marks': {'route_enter': time.monotonic()}}
    LAST_ROUTE_TRACE = None
    result = None
    try:
        argv = plain_ssh(node, path)
        trace['marks']['plain_argv_done'] = time.monotonic()
        if node in ('pc', 'a'):
            plan.need(PRIVATE_MUX is not None, 'prepared_owned_private_transport_pending')
            result = PRIVATE_MUX.argv(node, argv[-1])
        else:
            result = argv
        trace['marks']['mux_argv_done'] = time.monotonic()
        trace['_argv_id'] = id(result)
        LAST_ROUTE_TRACE = trace
        return result
    except BaseException as error:
        name = type(error).__name__
        code = getattr(error, 'errno', None) if isinstance(error, OSError) else None
        if type(code) is not int or not 0 <= code <= 4096:
            code = None
        record = {'schema': 'parent-safe-transport-phases/v1', 'node': node, 'phase': 'route_argv', 'error_class': name if name in ('Refused', 'ValueError', 'TimeoutExpired', 'OSError', 'FileNotFoundError', 'PermissionError') else 'OTHER', 'errno': code, 'marks': trace['marks'], 'counts': {'request_bytes': 0, 'stdin_bytes': 0, 'stdout_bytes': 0, 'stderr_bytes': 0, 'decoded_bytes': 0}, 'deadline_monotonic': None, 'observed_monotonic': time.monotonic(), 'transport_EOF_and_exit_in_budget': False, 'actual_returncode': None, 'owned_PID': None, 'owned_reaped': True, 'accepted_output': None, 'diagnostic_is_authority': False}
        if EVIDENCE_WRITER is not None:
            EVIDENCE_WRITER.diagnostic(None, record)
        raise
original_IO_init = IO.__init__

def initialized(self, end):
    global PRIVATE_MUX, EVIDENCE_WRITER
    original_IO_init(self, end)
    root = PARENT_WINDOW.path.parent
    evidence = root / 'transport-originals'
    EVIDENCE_WRITER = transport_evidence.Writer(evidence)
    muxroot = root / 'private-mux'
    muxroot.mkdir(mode=448)
    os.chmod(muxroot, 448)
    commands = {'pc': plain_ssh('pc', PC_LOADER)[-1], 'a': plain_ssh('a', plan.AGENT)[-1]}
    plan.need(len(commands['pc']) < 8191, 'actual_Windows_command_limit')
    private_mux.APPROVED_COMMANDS = commands
    PRIVATE_MUX = private_mux.PrivateMux(muxroot, min(self.end, PARENT_WINDOW.end))
    try:
        PRIVATE_MUX.start()
        PARENT_WINDOW.check()
    except BaseException:
        try:
            PRIVATE_MUX.close()
        except BaseException:
            pass
        raise
IO.__init__ = initialized

def close_transport(self):
    global PRIVATE_MUX
    if PRIVATE_MUX is not None and (not PRIVATE_MUX.closed):
        return PRIVATE_MUX.close()
IO.close_transport = close_transport

def cleanup_rpc(self, node, action, payload, end):
    global CLEANUP_ONLY
    plan.need((node, action) in (('a', 'fetch-failed-qualify'), ('pc', 'publish-failed-terminal'), ('pc', 'finish-failed-registry'), ('a', 'asset-finalize'), ('a', 'asset-observe'), ('pc', 'finish-asset-stage'), ('pc', 'begin-asset-terminal-clock'), ('pc', 'publish-asset-terminal'), ('pc', 'finish-failed-asset-stage')), 'only_fixed_failed_terminal_cleanup')
    plan.need(payload == {} and action not in ('asset-observe', 'finish-asset-stage') or action == 'publish-failed-terminal' or (action in ('begin-asset-terminal-clock', 'finish-failed-asset-stage', 'asset-observe', 'finish-asset-stage') and set(payload) == {'stage_operation'} and __import__('re').fullmatch('[0-9a-f]{32}', payload['stage_operation'])) or (action == 'asset-finalize' and set(payload) == {'stage_operation', 'terminal_clock'}) or (action == 'publish-asset-terminal' and set(payload) == {'stage_operation', 'qualified_raw_b64', 'sha256', 'stat'}), 'cleanup_payload_scope')
    if not hasattr(self, 'cleanup_end'):
        self.cleanup_end = time.monotonic() + 90
    end = min(end, self.cleanup_end)
    plan.need(time.monotonic() < end, 'cleanup_only90_no_work_extension')
    PARENT_WINDOW.check_cleanup()
    old = CLEANUP_ONLY
    CLEANUP_ONLY = True
    try:
        raw = plan.encode({'action': action, 'operation': plan.OPERATION, 'nonce': uuid.uuid4().hex, 'payload': payload})
        return plan.strict(captured(plain_ssh(node, plan.AGENT if node == 'a' else PC_LOADER), raw, end, node=node, safe_action=action))
    finally:
        CLEANUP_ONLY = old
IO.cleanup_rpc = cleanup_rpc
'Late-bound IO subclass; exact fixed stage, original clock/compact transport.'
STAGE_OPERATION = 'd3d3eaaf1a078b03b953c3090f774fbc'
BASE_IO = IO

class StageIO(BASE_IO):

    def __init__(self, end):
        plan.need(type(STAGE_OPERATION) is str and __import__('re').fullmatch('[0-9a-f]{32}', STAGE_OPERATION), 'actual_stage_operation_None')
        self.stage_operation = STAGE_OPERATION
        super().__init__(end)
        self.window = PARENT_WINDOW

    def rpc(self, node, action, payload, end):
        maps = {'pulse-registry-directfetch': 'pulse-asset-stage', 'bind-context': 'asset-bind', 'fetch-next': 'asset-next', 'fetch-answer': 'asset-answer'}
        mapped = maps.get(action, action)
        value = dict(payload)
        if mapped in ('pulse-asset-stage', 'reserve-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage', 'asset-bind', 'asset-next', 'asset-answer'):
            value['stage_operation'] = self.stage_operation
            value.pop('request_nonce', None)
        v = super().rpc(node, mapped, value, end)
        if mapped == 'asset-ready-finalize':
            response = plan.strict(base64.b64decode(v['response_raw_b64'], validate=True))
            self.entry_original = {'qualified_raw_b64': response['entry_raw_b64'], 'sha256': response['entry_sha256'], 'stat': response['entry_stat'], 'owned_stop_calls': v['owned_stop_calls']}
        return v

    def cleanup_rpc(self, node, action, payload, end):
        maps = {'fetch-failed-qualify': 'asset-finalize', 'publish-failed-terminal': 'publish-asset-terminal', 'finish-failed-registry': 'finish-failed-asset-stage'}
        action = maps.get(action, action)
        value = dict(payload, stage_operation=self.stage_operation)
        return super().cleanup_rpc(node, action, value, end)
IO = StageIO
LAST_ROUTE_TRACE = None
LAST_TRANSPORT_DIAGNOSTIC = None
