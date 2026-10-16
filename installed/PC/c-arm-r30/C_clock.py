# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual PC Root send/receive originals at late C startup barrier. No Manager."""
import os, time, math, re
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, encode, protected_read
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30')
CLOCK = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30/current-C-clock')
CONFIG = Path('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
APPROVED_SOURCE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_C_SOURCE_REVIEW = 'fa6248b0add8787f1767382be17cca2f12a9063a24bda293175ab323e798293b'
APPROVED_TARGET_CONFIG_SHA = None

def actual_config():
    need(APPROVED_SOURCE_REVIEW is not None and APPROVED_C_SOURCE_REVIEW is not None and (os.getuid() == os.geteuid() == 0), 'reviewed_PC_C_clock_pending')
    raw, st = protected_read(CONFIG)
    cfg = strict(raw)
    need(cfg['review_sha256'] == APPROVED_SOURCE_REVIEW, 'actual_future_config_review')
    barrier, bs = protected_read(ROOT / 'awaiting-current-C30.json')
    v = strict(barrier)
    need(v['schema'] == 'R26-current-C-start-barrier/v1' and v['release_sha256'] == APPROVED_SOURCE_REVIEW and (v['config_sha256'] == sha(raw)) and (v['normal_start_calls'] == 0) and (v['automatic_retry'] is False) and (0 <= time.time() - v['issued_at'] <= 30), 'real_current_once_installer_late_barrier')
    _, _, ar, ast, _ = checked_prestage(v['request_nonce'], sha(raw))
    need(v['prestage_ack_sha256'] == sha(ar) and v['prestage_ack_stat'] == ast, 'late_barrier_original_preparation_bound_not_retimestamped')
    return (cfg, sha(raw), sha(barrier), bs, v)

def prepare(nonce, io):
    cfg, h, b, bs, v = actual_config()
    need(nonce == v['request_nonce'] and 0 <= time.monotonic() - v['PC_monotonic_issued'] <= 30, 'fixed_actual_barrier_nonce_and_clock')
    raw, rs, ar, ast, a = checked_prestage(nonce, h)
    need(v['prestage_ack_sha256'] == sha(ar) and v['prestage_ack_stat'] == ast and (not CLOCK.exists()) and (not CLOCK.is_symlink()), 'late_barrier_binds_exact_prior_unclocked_ack')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    io.fresh(ROOT / 'prepared-C-request.json', raw, mode=288, gid=989)
    _, rs = protected_read(ROOT / 'prepared-C-request.json')
    item = {'schema': 'PC-C-R26-request-prepared-not-clock/v1', 'nonce': nonce, 'request_sha256': sha(raw), 'request_stat': rs, 'PC_boot_id': boot, 'config_sha256': h, 'barrier_sha256': b, 'barrier_stat': bs, 'prepared_observed_at': time.time(), 'prestage_ack_sha256': sha(ar), 'prestage_ack_stat': ast}
    io.fresh(ROOT / 'prepared-C-request-original.json', encode(item), mode=288, gid=989)
    return {'request_raw_utf8': raw.decode(), 'request_sha256': sha(raw), 'request_stat': rs, 'prepared_original': item, 'clock_started': False}

def begin(nonce, io):
    cfg, h, b, bs, v = actual_config()
    need(re.fullmatch('[0-9a-f]{32}', nonce) and nonce == v['request_nonce'] and (0 <= time.monotonic() - v['PC_monotonic_issued'] <= 30), 'fixed_actual_barrier_nonce_and_clock')
    raw, rs = protected_read(ROOT / 'prepared-C-request.json')
    original, ost = protected_read(ROOT / 'prepared-C-request-original.json')
    prepared = strict(original)
    request = strict(raw)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(request == {'schema': 'c-unarmed-before-pc-r30-readonly-request/v1', 'action': 'collect-current-C', 'nonce': nonce, 'source_review_sha256': APPROVED_C_SOURCE_REVIEW, 'PC_config_sha256': h, 'PC_boot_id': boot} and encode(request) == raw and (prepared['schema'] == 'PC-C-R26-request-prepared-not-clock/v1') and (prepared['nonce'] == nonce) and (prepared['request_sha256'] == sha(raw)) and (prepared['request_stat'] == rs) and (prepared['PC_boot_id'] == boot) and (prepared['config_sha256'] == h) and (prepared['barrier_sha256'] == b) and (prepared['barrier_stat'] == bs), 'same_protected_prepared_request_not_clock_refresh')
    need(0 <= time.time() - prepared['prepared_observed_at'] <= 30 and (not CLOCK.exists()) and (not CLOCK.is_symlink()), 'prepared_once_before_real_BEGIN')
    CLOCK.mkdir(mode=488)
    fd = os.open(CLOCK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchown(fd, 0, 989)
        os.fchmod(fd, 488)
        os.fsync(fd)
    finally:
        os.close(fd)
    io.fresh(CLOCK / 'send.json', raw, mode=288, gid=989)
    _, st = protected_read(CLOCK / 'send.json')
    moment = {'schema': 'PC-C-R26-readonly-send-moment/v1', 'nonce': nonce, 'PC_sent_at': time.time(), 'PC_monotonic_sent': time.monotonic(), 'PC_boot_id': boot, 'PC_config_sha256': h, 'source_review_sha256': APPROVED_SOURCE_REVIEW, 'original_send_sha256': sha(raw), 'original_send_stat': st, 'barrier_sha256': b, 'barrier_stat': bs}
    io.fresh(CLOCK / 'send-moment.json', encode(moment), mode=288, gid=989)
    return {'request_raw_utf8': raw.decode(), 'request_sha256': sha(raw), 'request_stat': st, 'moment': moment}

def finish(nonce, io):
    cfg, h, b, bs, v = actual_config()
    request, ss = protected_read(CLOCK / 'send.json')
    mr, _ = protected_read(CLOCK / 'send-moment.json')
    m = strict(mr)
    received = time.time()
    mono = time.monotonic()
    need(m['nonce'] == strict(request)['nonce'] == nonce == v['request_nonce'] and m['original_send_sha256'] == sha(request) and (m['original_send_stat'] == ss) and (m['PC_boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()) and (m['PC_config_sha256'] == h) and (m['barrier_sha256'] == b) and (m['barrier_stat'] == bs), 'same_exact_late_send_Root_original_no_refresh')
    elapsed = mono - m['PC_monotonic_sent']
    wall = received - m['PC_sent_at']
    need(0 <= elapsed <= 10 and 0 <= wall <= 10, 'original_C_window_elapsed_not_extended')
    out = {k: m[k] for k in ('nonce', 'PC_sent_at', 'PC_boot_id', 'PC_config_sha256', 'source_review_sha256', 'original_send_sha256', 'original_send_stat')}
    out.update(schema='PC-C-R26-readonly-clock/v1', PC_received_at=received, PC_monotonic_elapsed=elapsed)
    io.fresh(CLOCK / 'received.json', encode(out), mode=288, gid=989)
    return out

def receipt(nonce):
    actual_config()
    raw, st = protected_read(CLOCK / 'received.json')
    m = strict(raw)
    sr, ss = protected_read(CLOCK / 'send.json')
    need(m['nonce'] == nonce and m['original_send_sha256'] == sha(sr) and (m['original_send_stat'] == ss), 'clock_exact_original_request')
    return (raw, st)
APPROVED_C_TYPED_SHA = '3ffbd640d76972a3920e49108a423fd70dfc025ec189bb1230c77034c3b93cdf'
CROOT = '/opt/dgx-v4/runtime/g8-clock-probe-c30-mimo-registry-r16'
CUNIT = 'dgx-v4-c-unarmed-before-pc-r30-readonly.service'

def prestage_request(nonce, io):
    cfgraw, cs = protected_read(CONFIG)
    cfg = strict(cfgraw)
    need(os.getuid() == os.geteuid() == 0 and cfg['review_sha256'] == APPROVED_SOURCE_REVIEW, 'actual_new_config_for_unclocked_prestage')
    br, bs = protected_read(ROOT / 'awaiting-C30-prestage.json')
    v = strict(br)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(v['schema'] == 'C30-unclocked-source-prestage-request/v1' and v['request_nonce'] == nonce and (v['config_sha256'] == sha(cfgraw)) and (v['review_sha256'] == APPROVED_SOURCE_REVIEW) and (v['boot_id'] == boot) and (v['clock_started'] is False), 'same_actual_unclocked_prestage_nonce_config_boot')
    raw = encode({'schema': 'c-unarmed-before-pc-r30-readonly-request/v1', 'action': 'collect-current-C', 'nonce': nonce, 'source_review_sha256': APPROVED_C_SOURCE_REVIEW, 'PC_config_sha256': sha(cfgraw), 'PC_boot_id': boot})
    io.fresh(ROOT / 'prestage-C-request.json', raw, mode=288, gid=989)
    _, rs = protected_read(ROOT / 'prestage-C-request.json')
    item = {'schema': 'C30-unclocked-PC-prestage-original/v1', 'request_sha256': sha(raw), 'request_stat': rs, 'barrier_sha256': sha(br), 'barrier_stat': bs, 'config_stat': cs, 'PC_boot_id': boot, 'config_sha256': sha(cfgraw), 'source_review_sha256': APPROVED_SOURCE_REVIEW, 'nonce': nonce, 'clock_started': False}
    io.fresh(ROOT / 'prestage-PC-original.json', encode(item), mode=288, gid=989)
    return {'request_raw_utf8': raw.decode(), 'request_sha256': sha(raw), 'request_stat': rs, 'clock_started': False, 'prestage_original': item}

def prestage_ack(nonce, origin, io):
    import base64, types
    cfgraw, cs = protected_read(CONFIG)
    cfg = strict(cfgraw)
    rr, rs = protected_read(ROOT / 'prestage-C-request.json')
    pr, ps = protected_read(ROOT / 'prestage-PC-original.json')
    p = strict(pr)
    request = strict(rr)
    need(p['nonce'] == request['nonce'] == nonce and p['config_stat'] == cs and (p['config_sha256'] == sha(cfgraw)) and (p['request_sha256'] == sha(rr)) and (p['request_stat'] == rs) and (cfg['review_sha256'] == APPROVED_SOURCE_REVIEW), 'same_unclocked_PC_request_before_ack')
    need(type(origin) is dict and set(origin) == {'prepared_raw_b64', 'prepared_sha256', 'prepared_stat', 'prepared_path', 'clock_started'} and (origin['clock_started'] is False) and (origin['prepared_path'] == CROOT + '/prepared-source-original.json'), 'exact_C30_prepared_origin_envelope')
    raw = base64.b64decode(origin['prepared_raw_b64'], validate=True)
    st = origin['prepared_stat']
    q = strict(raw)
    need(len(raw) <= 2097152 and sha(raw) == origin['prepared_sha256'] and (type(st) is list) and (len(st) == 9) and all((type(x) is int for x in st)) and (st[2] == len(raw)) and (st[3:7] == [0, 0, 33152, 1]), 'complete_C30_Root_original_F9')
    need(q['schema'] == 'C30-source-prestaged-no-readonly-launch/v1' and q['root'] == CROOT and (q['unit'] == CUNIT) and (q['nonce'] == nonce) and (q['source_review_sha256'] == APPROVED_C_SOURCE_REVIEW) and (q['request_sha256'] == sha(rr)) and (q['launch_calls'] == 0) and (type(q['prepared_observed_at']) in (int, float)) and math.isfinite(q['prepared_observed_at']), 'C30_prepared_actual_source_request_no_clock')
    tr, _ = protected_read(ROOT / 'C_typed_consumer.py', limit=2097152)
    need(sha(tr) == APPROVED_C_TYPED_SHA, 'exact_prestage_C_materializer_source')
    m = types.ModuleType('fixed_C30_prestage_materializer')
    m.__file__ = str(ROOT / 'C_typed_consumer.py')
    exec(compile(tr, m.__file__, 'exec'), m.__dict__)
    b = types.ModuleType('fixed_C30_prestage_builder')
    b.__file__ = '<pinned_C30_builder>'
    exec(compile(m.APPROVED_C_SOURCE_BODIES['build.py'], b.__file__, 'exec'), b.__dict__)
    plan = b.materialize(m.APPROVED_C_REVIEW_RAW, rr, m.APPROVED_C_SOURCE_BODIES)
    need(set(q['files']) == set(plan['file_pins']) and len(q['files']) == 8, 'all8_C30_prestaged_sources')
    for name, pin in plan['file_pins'].items():
        row = q['files'][name]
        z = row['stat']
        need(row['sha256'] == pin and type(z) is list and (len(z) == 9) and all((type(x) is int for x in z)) and (z[3] == 0) and (z[6] == 1) and (not z[5] & 18), 'all8_C30_source_SHA_fullF9')
    ack = {'schema': 'C30-unclocked-prestage-acknowledged/v1', 'nonce': nonce, 'config_sha256': sha(cfgraw), 'source_review_sha256': APPROVED_SOURCE_REVIEW, 'PC_boot_id': p['PC_boot_id'], 'request_sha256': sha(rr), 'request_stat': rs, 'PC_original_sha256': sha(pr), 'PC_original_stat': ps, 'C_origin': origin, 'clock_started': False}
    io.fresh(ROOT / 'prestage-ack.json', encode(ack), mode=288, gid=989)
    return ack

def checked_prestage(nonce, config_sha):
    raw, st = protected_read(ROOT / 'prestage-ack.json')
    a = strict(raw)
    pr, ps = protected_read(ROOT / 'prestage-PC-original.json')
    p = strict(pr)
    rr, rs = protected_read(ROOT / 'prestage-C-request.json')
    need(a['schema'] == 'C30-unclocked-prestage-acknowledged/v1' and a['nonce'] == nonce and (a['config_sha256'] == config_sha) and (a['source_review_sha256'] == APPROVED_SOURCE_REVIEW) and (a['PC_boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()) and (a['PC_original_sha256'] == sha(pr)) and (a['PC_original_stat'] == ps) and (a['request_sha256'] == p['request_sha256'] == sha(rr)) and (a['request_stat'] == p['request_stat'] == rs) and (a['clock_started'] is False), 'same_immutable_prestage_ack_request_originals')
    return (rr, rs, raw, st, a)
