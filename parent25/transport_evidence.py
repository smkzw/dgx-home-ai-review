# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""O_EXCL originals for fixed nonsecret clock/pulse/bind/status actions only."""
import base64, hashlib, json, os, stat, time
from pathlib import Path
ACTIONS = frozenset(('clock', 'pulse-registry-directfetch', 'bind-context', 'source-context', 'status-registry-source', 'reserve-asset-stage', 'pulse-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage', 'publish-asset-plan', 'begin-asset-entry-clock', 'publish-asset-entry-clock', 'publish-asset-terminal', 'begin-asset-terminal-clock', 'asset-prepare', 'asset-ready-start', 'asset-ready-observe', 'asset-ready-finalize', 'asset-bind', 'asset-start', 'asset-next', 'asset-observe', 'asset-finalize', 'fetch-failed-qualify', 'publish-failed-terminal', 'finish-failed-registry', 'reserve-registry-directfetch', 'activate-registry-source'))
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, c):
    if not v:
        raise RuntimeError(c)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def save(p, raw):
    need(type(raw) is bytes and len(raw) <= 4194304, 'bounded_nonsecret_transport_original')
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    try:
        os.fchmod(fd, 384)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        z = os.fstat(fd)
        need(z.st_uid == os.getuid() and z.st_nlink == 1 and (stat.S_IMODE(z.st_mode) == 384), 'local_original_owner_mode')
    finally:
        os.close(fd)
    fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'path': str(p), 'sha256': sha(raw), 'stat': [getattr(z, k) for k in FIELDS]}

class Writer:

    def __init__(self, root):
        self.root = Path(root)
        need(not self.root.exists(), 'new_transport_original_namespace')
        self.root.mkdir(mode=448)
        os.chmod(self.root, 448)
        self.ordinal = 0

    def begin(self, node, action, raw):
        if action not in ACTIONS or node not in ('pc', 'a'):
            return None
        v = json.loads(raw)
        need(set(v) == {'action', 'operation', 'nonce', 'payload'} and v['action'] == action, 'fixed_nonsecret_original_request')
        self.ordinal += 1
        path = self.root / (str(self.ordinal) + '-' + action)
        path.mkdir(mode=448)
        os.chmod(path, 448)
        token = {'path': path, 'node': node, 'action': action, 'sent_wall': time.time(), 'sent_mono': time.monotonic(), 'stored': False}
        ref = save(path / 'request.raw', raw)
        save(path / 'intent.json', encode({'schema': 'reserved-parent-safe-transport-intent/v1', 'node': node, 'action': action, 'request_original': ref, 'local_sent_wall': token['sent_wall'], 'local_sent_monotonic': token['sent_mono'], 'automatic_retry': False}))
        return token

    def response(self, token, wire, stderr, rc, *, complete):
        if token is None:
            return
        need(not token['stored'] and (rc is None or type(rc) is int), 'once_original_response')
        token['stored'] = True
        wr = save(token['path'] / 'compact-response.raw', wire)
        er = save(token['path'] / 'stderr.raw', stderr)
        save(token['path'] / 'response.json', encode({'schema': 'reserved-parent-safe-transport-response/v1', 'node': token['node'], 'action': token['action'], 'compact_original': wr, 'stderr_original': er, 'actual_returncode': rc, 'transport_complete': complete, 'local_sent_wall': token['sent_wall'], 'local_received_wall': time.time(), 'local_sent_monotonic': token['sent_mono'], 'local_received_monotonic': time.monotonic(), 'automatic_retry': False}))

    def decoded(self, token, raw, diagnostic):
        if token is None:
            return
        ref = save(token['path'] / 'decoded-response.raw', raw)
        save(token['path'] / 'decoded.json', encode({'schema': 'reserved-parent-safe-decoded-original/v1', 'original': ref, 'source_diagnostic': diagnostic}))

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
Writer.diagnostic = diagnostic
