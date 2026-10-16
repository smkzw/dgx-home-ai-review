# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def diagnostic(self, token, record, *, late=False):
    """Only closed numeric/phase transport observations; never payload or error str."""
    import math
    keys = {'schema', 'node', 'phase', 'error_class', 'errno', 'marks', 'counts', 'deadline_monotonic', 'observed_monotonic', 'transport_EOF_and_exit_in_budget', 'actual_returncode', 'owned_PID', 'owned_reaped', 'accepted_output', 'diagnostic_is_authority'}
    phases = {'budget', 'evidence_begin', 'body_encode', 'popen', 'io_wait', 'process_wait', 'evidence_response', 'decode', 'evidence_decoded', 'exit_stderr', 'strict_JSON', 'final_deadline', 'owned_close', 'pre_record_deadline', 'post_record_deadline', 'route_argv'}
    mark_names = {'route_enter', 'plain_argv_done', 'mux_argv_done', 'capture_enter', 'budget_checked', 'evidence_begin_done', 'body_encoded', 'popen_returned', 'stdin_closed', 'stdout_EOF', 'stderr_EOF', 'stdout_first_byte', 'stderr_first_byte', 'process_reaped', 'evidence_response_done', 'decoded', 'evidence_decoded_done', 'strict_JSON_done', 'accepted_before_close', 'owned_TERM_sent', 'owned_close_done', 'failure_originals_stored', 'diagnostic_record_done'}
    classes = {'Refused', 'RuntimeError', 'ValueError', 'TypeError', 'AssertionError', 'TimeoutExpired', 'BrokenPipeError', 'ConnectionResetError', 'BlockingIOError', 'InterruptedError', 'FileNotFoundError', 'PermissionError', 'OSError', 'JSONDecodeError', 'UnicodeDecodeError', 'OTHER', None}
    need(type(record) is dict and set(record) == keys and (record['schema'] == 'parent-safe-transport-phases/v1') and (record['node'] in ('pc', 'a', 'vps', None)) and (record['phase'] in phases) and (record['error_class'] in classes) and (record['diagnostic_is_authority'] is False), 'safe_closed_transport_diagnostic')
    for key in ('deadline_monotonic', 'observed_monotonic'):
        v = record[key]
        need(v is None and key == 'deadline_monotonic' or (type(v) in (int, float) and math.isfinite(v)), 'safe_diagnostic_clock')
    need(type(record['marks']) is dict and set(record['marks']) <= mark_names and all((type(v) in (int, float) and math.isfinite(v) for v in record['marks'].values())), 'safe_diagnostic_marks')
    need(type(record['counts']) is dict and set(record['counts']) == {'request_bytes', 'stdin_bytes', 'stdout_bytes', 'stderr_bytes', 'decoded_bytes'} and all((type(v) is int and 0 <= v <= 4259840 for v in record['counts'].values())), 'safe_diagnostic_counts')
    need(record['errno'] is None or (type(record['errno']) is int and 0 <= record['errno'] <= 4096), 'safe_diagnostic_errno')
    need(record['actual_returncode'] is None or type(record['actual_returncode']) is int, 'safe_diagnostic_real_rc')
    need(record['owned_PID'] is None or (type(record['owned_PID']) is int and record['owned_PID'] > 0), 'safe_diagnostic_owned_PID')
    need(type(record['owned_reaped']) is bool and type(record['transport_EOF_and_exit_in_budget']) is bool and (record['accepted_output'] in (None, False, True)), 'safe_diagnostic_flags')
    if token is not None:
        path = token['path'] / ('transport-late-diagnostic.json' if late else 'transport-diagnostic.json')
    else:
        self.diagnostic_ordinal = getattr(self, 'diagnostic_ordinal', 0) + 1
        need(self.diagnostic_ordinal <= 4096, 'finite_diagnostic_count')
        path = self.root / ('route-diagnostic-' + str(self.diagnostic_ordinal) + '.json')
    raw = encode(record)
    need(len(raw) <= 16384, 'small_safe_diagnostic')
    return save(path, raw)
