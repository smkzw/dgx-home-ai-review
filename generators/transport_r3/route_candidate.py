# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
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
