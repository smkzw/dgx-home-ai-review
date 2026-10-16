# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Reusable Root-local read-only halves. No SSH, systemd-run, stop or writes.
No default approved policy. Cross-host transport/clock/protected publication and
new epoch integration remain the parent's finite reviewed production closure.
"""
import base64, os, socket, struct, subprocess, time
from pathlib import Path
from proc_lifetime import scan as scan_process_lifetimes
from prelaunch_history import need, sha, encode, policy, partial
from old_failed_kernel import kernel_after_stop
PC_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-nodecold-r6')
SOCKET = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/operator.sock')
APPROVED_CAPTURE_POLICY = None

def capture_policy(praw):
    need(type(APPROVED_CAPTURE_POLICY) is dict and APPROVED_CAPTURE_POLICY == {'historical_policy_sha256': sha(praw)}, 'Root_capture_reviewed_policy_literal_pending')

def envelope(raw, s):
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}

def leaf(path, common, *, uid, gid, mode, legacy=False):
    with common.HeldParent(path, legacy=legacy) as chain:
        fd = chain.open_leaf()
        try:
            z = os.fstat(fd)
            s = common.metadata(z)
            need(__import__('stat').S_ISREG(z.st_mode) and s[3:7] == [uid, gid, 32768 | mode, 1] and (0 <= s[2] <= 8 * 1024 ** 2), 'fixed_original_leaf_policy')
            raw = os.pread(fd, s[2] + 1, 0)
            need(len(raw) == s[2] and s == common.metadata(os.fstat(fd)) == common.metadata(chain.named_leaf()), 'held_full_SHA_F9')
            chain.recheck()
            return envelope(raw, s)
        finally:
            os.close(fd)

def absent(path, common):
    with common.HeldParent(path) as chain:
        try:
            chain.named_leaf()
        except FileNotFoundError:
            return {'exists': False, 'is_symlink': False}
        need(False, 'prelaunch_path_exists_or_symlink')

def fixed_sources(root, pins, common):
    out = {}
    for n, pin in pins.items():
        r = leaf(root / n, common, uid=pin['F9'][3], gid=pin['F9'][4], mode=pin['F9'][5] & 511)
        need(r['sha256'] == pin['sha256'] and r['F9'] == pin['F9'], 'original_source_changed')
        out[n] = {'sha256': r['sha256'], 'F9': r['F9']}
    return out

def registry_records(root, pins, common, expected_directory_F9=None):
    with common.HeldParent(root.parent / '.registry-ancestry', legacy=True) as chain:
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            z = os.fstat(fd)
            before = common.directory_identity(z)
            need(expected_directory_F9 is not None and common.metadata(z) == expected_directory_F9, 'exact_old_registry_directory_F9')
            need((z.st_uid, z.st_gid, z.st_mode & 511) == (999, 989, 448), 'actual_service999_private_registry_directory')
            need(set(os.listdir(fd)) == set(pins), 'original_partial_exact_directory')
            records = {}
            for name in sorted(pins):
                leaf_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    z = os.fstat(leaf_fd)
                    meta = common.metadata(z)
                    need(__import__('stat').S_ISREG(z.st_mode) and meta[3:7] == [999, 989, 33152, 1] and (meta[2] <= 8 * 1024 ** 2), 'actual_999_original_leaf')
                    raw = os.pread(leaf_fd, meta[2] + 1, 0)
                    need(len(raw) == meta[2] and meta == common.metadata(os.fstat(leaf_fd)) == common.metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'actual_service_leaf_full_F9')
                    records[name] = envelope(raw, meta)
                finally:
                    os.close(leaf_fd)
            need(before == common.directory_identity(os.fstat(fd)) == common.directory_identity(os.stat(root.name, dir_fd=chain.parent_fd, follow_symlinks=False)) and set(os.listdir(fd)) == set(pins), 'actual_service_directory_identity_entries_stable')
            chain.recheck()
            return records
        finally:
            os.close(fd)

def proc_scan(root):
    return scan_process_lifetimes(root)

def A_half(praw, common):
    capture_policy(praw)
    need(os.getuid() == os.geteuid() == 0, 'Root_capture_UID')
    p = policy(praw)
    root = Path(p['A_root'])
    data = Path(p['A_data'])
    start = time.time()
    records = {n: leaf(root / n, common, uid=0, gid=0, mode=384) for n in p['A_records']}
    refs = {}
    for name, pin in p['A_failed_records'].items():
        item = leaf(data / name, common, uid=0, gid=0, mode=384)
        need({k: item[k] for k in ('sha256', 'F9')} == pin, 'whole_preserved_failed_A_file_SHA_F9')
        refs[name] = pin
    cleanup = leaf(data / 'owned-cleanup.json', common, uid=0, gid=0, mode=384)
    need({k: cleanup[k] for k in ('sha256', 'F9')} == p['A_cleanup'], 'actual_owned_cleanup_original_SHA_F9')
    entries = sorted((x.name for x in data.iterdir()))
    metadata = []
    for row in p['A_blob_metadata']:
        path = data / 'blobs' / row['name']
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = common.metadata(os.fstat(fd))
            need(st == row['F9'] == common.metadata(path.lstat()), 'preserved_partial_blob_identity_only')
            metadata.append({'name': row['name'], 'F9': st})
        finally:
            os.close(fd)
    no_engine = {str(data / n): absent(data / n, common) for n in ('containerd.sock', 'containerd.toml', 'private-config-validated.json', 'returned-zero.json', 'initialized-registry.raw')}
    empty_dirs = {}
    for n in ('containerd-data', 'containerd-exec', 'private-opt', 'private-overlay'):
        path = data / n
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = common.metadata(os.fstat(fd))
            need(st[3:6] == [0, 0, 16832] and os.listdir(fd) == [] and (st == common.metadata(path.lstat())), 'actual_private_daemon_dirs_empty_before_recovery')
            empty_dirs[n] = {'stat': st, 'entries': []}
        finally:
            os.close(fd)
    kernel = kernel_after_stop(p['aggregate_unit'], 3235350, p['A_failed_unit']['boot_id'], time.monotonic() + 15)
    out = {'records': records, 'A34': fixed_sources(root, p['A34'], common), 'failed_file_refs': refs, 'cleanup_ref': p['A_cleanup'], 'payload_entries': entries, 'blob_metadata': metadata, 'old_worker_kernel': kernel, 'no_engine_paths': no_engine, 'empty_private_dirs': empty_dirs, 'process_scan': proc_scan(root), 'observed_at': time.time(), 'started_at': start}
    need(entries == p['A_payload_entries'] and out['A34'] == fixed_sources(root, p['A34'], common), 'failed_partial_and_A_source_unchanged')
    for name, pin in p['A_failed_records'].items():
        row = leaf(data / name, common, uid=0, gid=0, mode=384)
        need({k: row[k] for k in ('sha256', 'F9')} == pin, 'failure_original_after_process_scan')
    return out

def status(nonce, p, common):
    need(os.getuid() == os.geteuid() == 0, 'Root_private_readonly_peer')
    before = SOCKET.lstat()
    need(before.st_uid == 999 and before.st_gid == 989 and (before.st_mode == 49536), 'original_owner_private_socket')
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5)
    try:
        c.connect(str(SOCKET))
        pid, uid, gid = struct.unpack('3i', c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need((pid, uid, gid) == (p.get('live_current', p)['manager_identity']['pid'], 999, 989), 'same_actual_owner_not_admin_impersonation')
        c.sendall(encode({'action': 'status-registry-source', 'operation': p.get('live_operation', p['operation']), 'request_nonce': nonce}))
        raw = bytearray()
        while len(raw) <= 1048576:
            part = c.recv(min(65536, 1048577 - len(raw)))
            if not part:
                break
            raw.extend(part)
        need(len(raw) <= 1048576 and common.metadata(before) == common.metadata(SOCKET.lstat()), 'bounded_same_private_socket_readonly_original')
        return bytes(raw)
    finally:
        c.close()

def PC_half(praw, nonce, current, common):
    """current is actual protected CurrentReader.capture result, never a flag.
 Parent must held-load that existing producer under Root65 digest before call.
 """
    capture_policy(praw)
    need(os.getuid() == os.geteuid() == 0, 'Root_capture_UID')
    p = policy(praw)
    live = p.get('live_current', p)
    root = Path(p['registry_root'])
    need(current['manager_identity'] == live['manager_identity'] and current['config_sha256'] == live['config_sha256'] and (current['current_source118'] == live['current_source118']), 'actual_protected_CurrentReader_old_owner')
    records = registry_records(root, p['records'], common, p['registry_directory_F9'])
    out = {'records': partial(records, p), 'Root65': fixed_sources(PC_ROOT, p['Root65'], common), 'manager_identity': current['manager_identity'], 'lease_full_F9': current['lease_full_F9'], 'Cleaf': current['Cleaf'], 'status_raw_b64': base64.b64encode(status(nonce, p, common)).decode()}
    need(records == registry_records(root, p['records'], common, p['registry_directory_F9']), 'partial_drift_after_readonly_status')
    return out

def assemble(nonce, pc, a, *, started, finished, monotonic_elapsed):
    return {'schema': 'registry-prelaunch-readonly-observation/v1', 'request_nonce': nonce, 'PC_started_at': started, 'PC_finished_at': finished, 'PC_monotonic_elapsed': monotonic_elapsed, 'PC': pc, 'A': a}
if __name__ == '__main__':
    raise SystemExit('SOURCE_CPU_ONLY_capture_policy_None_no_native')
