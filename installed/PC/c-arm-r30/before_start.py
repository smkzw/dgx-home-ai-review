# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite Root late C30 barrier while original physical lease is held. No start."""
import os, time, secrets, types
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, encode, protected_read, HeldParent
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30')
APPROVED_SOURCE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_C_CONSUMER = '6ecc4b1eb2bbc0f6c94c0f1279e0f7e2f6f5f881950d541076006a5d0b975e48'
APPROVED_C_CLOCK = 'a0871c3f922bb221ece31931332bf0d0d9b217beb780a5face1ad8503b6b714e'

def fresh(path, raw, mode=288, gid=989):
    need(type(raw) is bytes and len(raw) <= 4194304 and (mode == 288) and (gid == 989), 'fixed_Root_barrier_bound')
    with HeldParent(path) as h:
        h.recheck()
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=h.parent_fd)
        try:
            os.fchmod(fd, mode)
            os.fchown(fd, 0, gid)
            with os.fdopen(os.dup(fd), 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
        finally:
            os.close(fd)
        os.fsync(h.parent_fd)
        h.recheck()
    return protected_read(path)

def prepare(native, p, before, end):
    need(APPROVED_SOURCE_REVIEW is not None and APPROVED_C_CONSUMER is not None and (os.getuid() == os.geteuid() == 0), 'Root_reviewed_C30_barrier_pending')
    cfg = strict(p['new_config_raw_utf8'])
    need(cfg['review_sha256'] == p['review_sha256'] == APPROVED_SOURCE_REVIEW and native.holders() == [native.pid()] and (native.lock_F9() == before['lease_full_F9']), 'actual_newconfig_same_owned_original_lease')
    config_raw, configstat = protected_read('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
    need(config_raw == p['new_config_raw_utf8'].encode(), 'actual_after_CAS_newconfig_not_old_snapshot')
    nonce = secrets.token_hex(16)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    fresh(ROOT / 'awaiting-C30-prestage.json', encode({'schema': 'C30-unclocked-source-prestage-request/v1', 'request_nonce': nonce, 'config_sha256': sha(config_raw), 'config_stat': configstat, 'review_sha256': APPROVED_SOURCE_REVIEW, 'boot_id': boot, 'clock_started': False, 'worker_pid': os.getpid(), 'issued_at': time.time(), 'PC_monotonic_issued': time.monotonic()}))
    ackpath = ROOT / 'prestage-ack.json'
    prep_end = min(end, time.monotonic() + 120)
    while not ackpath.exists():
        need(time.monotonic() < prep_end, 'bounded_unclocked_C30_prestage_ack_no_retry')
        time.sleep(0.05)
    clockraw, _ = protected_read(ROOT / 'C_clock.py', limit=2097152)
    need(sha(clockraw) == APPROVED_C_CLOCK, 'exact_C30_prepared_ack_consumer')
    clock = types.ModuleType('fixed_C30_prestage_ack')
    clock.__file__ = str(ROOT / 'C_clock.py')
    exec(compile(clockraw, clock.__file__, 'exec'), clock.__dict__)
    request_raw, request_stat, ackraw, ackstat, ack = clock.checked_prestage(nonce, sha(config_raw))
    need(native.holders() == [native.pid()] and protected_read('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json') == (config_raw, configstat), 'same_config_lease_after_prestage_before_AB')
    ab = native.live_idle_observation(end)
    nodes = strict(ab['raw_utf8'])
    need(sha(ab['raw_utf8'].encode()) == ab['sha256'], 'genuine_AB_fullraw')
    fresh(ROOT / 'startup-AB-original.json', encode(dict(ab, nodes=nodes, source_review_sha256=APPROVED_SOURCE_REVIEW, target_config_sha256=sha(config_raw))))
    issued = time.time()
    mono = time.monotonic()
    barrier = {'schema': 'R26-current-C-start-barrier/v1', 'request_nonce': nonce, 'release_sha256': APPROVED_SOURCE_REVIEW, 'operation': p['operation'], 'config_sha256': sha(config_raw), 'config_stat': configstat, 'issued_at': issued, 'PC_monotonic_issued': mono, 'normal_start_calls': 0, 'automatic_retry': False, 'worker_pid': os.getpid(), 'lease_F9': native.lock_F9(), 'prestage_ack_sha256': sha(ackraw), 'prestage_ack_stat': ackstat, 'prestage_request_sha256': sha(request_raw), 'prestage_request_stat': request_stat}
    fresh(ROOT / 'awaiting-current-C30.json', encode(barrier))
    raw, st = protected_read(ROOT / 'current_C_consumer.py', limit=2097152)
    need(sha(raw) == APPROVED_C_CONSUMER, 'strict_C30_receiver_source')
    consumer = types.ModuleType('actual_late_C30_receiver')
    consumer.__file__ = str(ROOT / 'current_C_consumer.py')
    exec(compile(raw, consumer.__file__, 'exec'), consumer.__dict__)
    target = ROOT / 'current-C-received.json'
    stop = min(end, mono + 30)
    while not target.exists():
        need(time.monotonic() < stop, 'bounded_current_C30_not_received_no_retry')
        time.sleep(0.05)
    now = time.time()
    result = consumer.consume(protected_read, dict(cfg, _config_sha256=sha(config_raw)), now)
    need(result['request_nonce'] == nonce and native.holders() == [native.pid()] and (native.lock_F9() == before['lease_full_F9']) and (protected_read('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json') == (config_raw, configstat)), 'same_nonce_actual_owned_lease_and_config_after_C30')
    need(now - issued <= 30, 'original_AB_C_window_not_retimestamped')
    return result
