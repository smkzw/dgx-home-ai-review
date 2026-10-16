# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
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
