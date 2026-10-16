# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed Range failure evidence only; no message, headers, URLs or locals.

This additive diagnostic is never used to admit a request, accept bytes or
release maintenance. All original Range/observer exceptions still fail closed.
"""
import http.client, ssl, subprocess
PHASES = frozenset(('registry.peer', 'registry.connect', 'registry.send', 'registry.headers', 'registry.redirect', 'cdn.peer', 'cdn.connect', 'cdn.send', 'cdn.headers', 'range.headers', 'body.read', 'body.EOF', 'range.admission'))
ERRNOS = frozenset((2, 5, 13, 22, 28, 32, 101, 104, 110, 111, 113))
CODES = frozenset(('range_HTTP206_required', 'exact_range_offset_total_length', 'unambiguous_range_identity_framing', 'no_ambiguous_range_redirect_or_multipart', 'range_exchange_failed', 'range_failed_noRetry', 'fixed_range_target', 'range_origin_only_bearer', 'bounded_range_headers', 'one_original_range_redirect', 'fixed_cdn_redirect', 'bounded_redirect_path', 'peer_proof_schema', 'fresh_dns_route', 'actual_direct_wired_route', 'public_ipv4_dns', 'peer_in_current_original_dns', 'original_dns_host', 'range_metadata_deadline', 'range_token_safe_before_send', 'range_safe_token', 'whole_deadline', 'request_deadline', 'TLS_or_hostname_failed', 'owned_HTTP_close_failed', 'certificate_hostname_refused', 'certificate_hostname_command_failed', 'fixed_openssl_path_certificate_deadline', 'CA_required', 'connected_peer_identity', 'actual_A_route_command', 'actual_A_direct_peer_route', 'range_true_EOF_required', 'range_truncation_or_chunk', 'supervision_failed_sticky', 'supervision_sticky_failure', 'sampled_worker_RSS_budget', 'fresh_unexpired_original_pulse', 'pulse_monotonic_not_replayed', 'fresh_actual_kernel_read', 'same_actual_PID_start_ticks', 'bounded_trace_no_foreign_writer', 'original_window_expired_or_clock_invalid', 'original_deadline_can_only_shorten', 'actual_conservative_PC_pulse_age', 'fresh_A_receipt_of_original_pulse', 'original_stage_remaining_runtime_no_extension'))
CLASSES = ((http.client.RemoteDisconnected, 'HTTP_REMOTE_DISCONNECT'), (ssl.SSLCertVerificationError, 'TLS_CERTIFICATE'), (ssl.SSLEOFError, 'TLS_EOF'), (ssl.SSLError, 'TLS_PROTOCOL'), (subprocess.TimeoutExpired, 'TOOL_TIMEOUT'), (TimeoutError, 'TIMEOUT'), (ConnectionRefusedError, 'CONNECT_REFUSED'), (ConnectionResetError, 'CONNECT_RESET'), (BrokenPipeError, 'BROKEN_PIPE'), (http.client.LineTooLong, 'HTTP_LINE_LIMIT'), (http.client.BadStatusLine, 'HTTP_STATUS_PARSE'), (http.client.IncompleteRead, 'HTTP_INCOMPLETE_READ'), (http.client.HTTPException, 'HTTP_PROTOCOL'), (OSError, 'OS_ERROR'))

def scalar(error):
    tag = next((tag for kind, tag in CLASSES if isinstance(error, kind)), 'OTHER_EXCEPTION')
    eno = error.errno if isinstance(error, OSError) else None
    args = error.args if isinstance(error, BaseException) else ()
    code = args[0] if type(args) is tuple and len(args) == 1 and (type(args[0]) is str) and (args[0] in CODES) else None
    return {'class': tag, 'errno': eno if type(eno) is int and eno in ERRNOS else None, 'policy_code': code}

def failure(error, phase, status=None):
    if phase not in PHASES:
        phase = 'range.admission'
    status = status if type(status) is int and 100 <= status <= 599 else None
    prior = find(error)
    if prior is not None:
        return prior
    rows = []
    seen = set()
    while error is not None and id(error) not in seen and (len(rows) < 6):
        seen.add(id(error))
        rows.append(scalar(error))
        error = error.__context__
    return {'schema': 'fixed-range-safe-failure/v1', 'phase': phase, 'status': status, 'chain': rows, 'context_truncated': error is not None}

def valid(v):
    return type(v) is dict and set(v) == {'schema', 'phase', 'status', 'chain', 'context_truncated'} and (v['schema'] == 'fixed-range-safe-failure/v1') and (v['phase'] in PHASES) and (v['status'] is None or (type(v['status']) is int and 100 <= v['status'] <= 599)) and (type(v['context_truncated']) is bool) and (type(v['chain']) is list) and (1 <= len(v['chain']) <= 6) and all((type(r) is dict and set(r) == {'class', 'errno', 'policy_code'} and (r['class'] in {'OTHER_EXCEPTION', *(tag for _, tag in CLASSES)}) and (r['errno'] is None or (type(r['errno']) is int and r['errno'] in ERRNOS)) and (r['policy_code'] is None or (type(r['policy_code']) is str and r['policy_code'] in CODES)) for r in v['chain']))

def find(error):
    seen = set()
    while error is not None and id(error) not in seen and (len(seen) < 8):
        seen.add(id(error))
        v = getattr(error, '_range_safe_failure', None)
        if valid(v):
            return v
        error = error.__context__
    return None
