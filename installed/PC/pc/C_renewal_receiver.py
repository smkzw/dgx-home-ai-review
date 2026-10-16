# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict current nonce/PID C receiver. No C-scope launch, no model API."""
import os, secrets, time, types, re, stat, base64
from pathlib import Path
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, HeldParent
APPROVED_INTERFACE_SHA = '409bc196e359ccc2e2a331d2634771dd85dea12f013baf8401130e7c94e2e3cf'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
ROOT = PC_ROOT / 'c-arm-r26/renewals'

def readable_directory(path, *, create):
    """Fixed Root receipt directory, exact 0:989/0750 despite UMask0077."""
    with HeldParent(path) as h:
        h.recheck()
        if create:
            os.mkdir(path.name, mode=488, dir_fd=h.parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=h.parent_fd)
        try:
            if create:
                os.fchown(fd, 0, 989)
                os.fchmod(fd, 488)
                os.fsync(fd)
                os.fsync(h.parent_fd)
            z = os.fstat(fd)
            named = os.stat(path.name, dir_fd=h.parent_fd, follow_symlinks=False)
            need(stat.S_ISDIR(z.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488) and ((z.st_dev, z.st_ino) == (named.st_dev, named.st_ino)), 'exact_Root_readable_directory_identity')
            h.recheck()
        finally:
            os.close(fd)

def interface():
    need(APPROVED_INTERFACE_SHA is not None and APPROVED_REVIEW is not None, 'current_C_renewal_interface_pending')
    raw, st = protected_read(PC_ROOT / 'C_renewal_interface.py', limit=2097152)
    need(sha(raw) == APPROVED_INTERFACE_SHA, 'actual_C_renewal_source')
    m = types.ModuleType('fixed_C_renewal_interface')
    m.__file__ = str(PC_ROOT / 'C_renewal_interface.py')
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m

def manager_identity(identity):
    need(set(identity) == {'pid', 'start_ticks', 'boot_id', 'invocation_id'} and type(identity['pid']) is int and (identity['pid'] > 1) and (type(identity['start_ticks']) is str) and (re.fullmatch('[1-9][0-9]*', identity['start_ticks']) is not None), 'actual_proc_identity_ABI_not_approximated')
    return dict(identity)

def clock_config(config, identity):
    from node_adapter.client import load_config
    path = Path('/etc/dgx-home-ai/node-adapter.json')
    raw, st = protected_read(path)
    need(sha(raw) == config['PC_source_pins'][str(path)], 'actual_clock_channel_config_source')
    cfg = load_config(path)
    need(protected_read(path) == (raw, st) and cfg.connect_timeout_seconds <= 5, 'same_clock_channel_schema')
    return dict(config, _manager_identity=identity, max_clock_skew_seconds=cfg.max_clock_skew_seconds)

def begin(native):
    need(os.getuid() == os.geteuid() == 0, 'Root_C_renewal_clock_only')
    current = native.capture_current(time.monotonic() + 30)
    identity = manager_identity(current['manager_identity'])
    cfg = native.current.config
    m = interface()
    nonce = secrets.token_hex(16)
    need(nonce != '0' * 32, 'genuine_random_nonce')
    request = {'schema': 'c-unarmed-renewal-r26-readonly-request/v1', 'action': 'collect-current-C', 'nonce': nonce, 'source_review_sha256': sha(m.APPROVED_SOURCE_REVIEW_RAW), 'PC_config_sha256': cfg['_config_sha256'], 'PC_boot_id': identity['boot_id'], 'PC_manager_identity': identity}
    raw = encode(request)
    parent = ROOT / nonce
    need(not parent.exists(), 'new_clock_once')
    if ROOT.exists():
        readable_directory(ROOT, create=False)
        need(all((re.fullmatch('[0-9a-f]{32}|selected-[0-9a-f]{32}\\.json', name) for name in os.listdir(ROOT))), 'only_prior_current_C_once_entries')
        for name in os.listdir(ROOT):
            if re.fullmatch('[0-9a-f]{32}', name):
                readable_directory(ROOT / name, create=False)
            else:
                prior_raw, meta = protected_read(ROOT / name)
                need(meta[3:7] == [0, 989, 33056, 1], 'protected_prior_selector_not_foreign')
    else:
        readable_directory(ROOT, create=True)
    readable_directory(parent, create=True)
    native.exclusive(parent / 'request.json', raw)
    body, st = protected_read(parent / 'request.json')
    clock = {'schema': 'PC-C-R26-renewal-readonly-clock/v1', 'nonce': nonce, 'PC_sent_at': native.wall(), 'PC_received_at': None, 'PC_monotonic_elapsed': None, 'original_send_sha256': sha(raw), 'original_send_stat': st, 'source_review_sha256': APPROVED_REVIEW, 'PC_config_sha256': cfg['_config_sha256'], 'PC_boot_id': identity['boot_id'], 'PC_manager_identity': identity}
    native.exclusive(parent / 'clock-begin.json', encode({'clock': clock, 'PC_monotonic_issued': time.monotonic(), 'manager_identity': identity, 'request_raw_utf8': body.decode()}))
    return {'request_raw_utf8': body.decode(), 'nonce': nonce, 'manager_identity': identity}

def owned_stop(originals, C):
    names = {'owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'}
    need(type(originals) is dict and set(originals) == names, 'actual_C_owned_stop_three_originals')
    values = {}
    for name, item in originals.items():
        raw = base64.b64decode(item['raw_b64'], validate=True)
        st = item['stat']
        need(item['path'] == C['root'] + '/' + name and sha(raw) == item['sha256'] and (type(st) is list) and (len(st) == 9) and all((type(x) is int for x in st)) and (st[2] == len(raw)) and (st[3:7] == [0, 0, 33152, 1]), 'actual_Spark_Root_owned_stop_original_F9')
        values[name] = strict(raw)
    intent = values['owned-stop-intent.json']
    result = values['owned-stop-result.json']
    observed = values['owned-stop-observed.json']
    u = observed['unit']
    original = base64.b64decode(observed['unit_raw_b64'], validate=True)
    need(sha(original) == observed['unit_raw_sha256'] and dict((x.split('=', 1) for x in original.decode().splitlines())) == u, 'actual_poststop_unit_raw')
    need(intent['unit'] == C['unit'] and intent['invocation_id'] == C['intent']['invocation_id'] and (intent['owned_scope_stop_calls'] == 1) and (type(intent['owned_scope_stop_calls']) is int) and (result['rc'] == 0) and (base64.b64decode(result['stderr_b64'], validate=True) == b'') and (u['MainPID'] == '0') and (u['ActiveState'] == 'inactive') and (observed['cgroup_procs'] == []) and (observed['boot_id'] == C['intent']['boot_id']), 'actual_C_owned_stop1_before_PC_mirror')
    need(C['observed_at'] <= intent['issued_at'] <= result['observed_at'] <= observed['observed_at'], 'C_actual_capture_ownedstop_time_order')
    return originals

def publish_envelope(native, nonce, envelope_raw):
    v = strict(envelope_raw)
    need(type(v) is dict and set(v) == {'schema', 'receipt_path', 'receipt_raw_b64', 'receipt_sha256', 'receipt_stat', 'owned_stop_originals'} and (v['schema'] == 'C-renewal-origin-readback/v1'), 'complete_actual_Spark_origin_envelope')
    raw = base64.b64decode(v['receipt_raw_b64'], validate=True)
    need(sha(raw) == v['receipt_sha256'] and v['receipt_path'] == '/opt/dgx-v4/c-unarmed-renewal-r26-' + nonce + '/readonly-qualified.json', 'exact_actual_C_origin_readback_not_reencoded_body')
    result = publish(native, nonce, raw, v['receipt_stat'], v['owned_stop_originals'])
    native.exclusive(ROOT / nonce / 'Spark-origin-envelope.json', envelope_raw)
    return result

def publish(native, nonce, receipt_raw, receipt_stat, owned_stop_originals):
    need(re.fullmatch('[0-9a-f]{32}', nonce) and nonce != '0' * 32, 'exact_renewal_nonce')
    parent = ROOT / nonce
    raw, st = protected_read(parent / 'clock-begin.json')
    b = strict(raw)
    clock = dict(b['clock'])
    current = native.capture_current(time.monotonic() + 30)
    identity = current['manager_identity']
    cfg = native.current.config
    need(identity == b['manager_identity'] and cfg['_config_sha256'] == clock['PC_config_sha256'] and (identity['boot_id'] == clock['PC_boot_id']), 'current_same_PID_before_C_publish')
    clock['PC_received_at'] = native.wall()
    clock['PC_monotonic_elapsed'] = time.monotonic() - b['PC_monotonic_issued']
    need(0 <= clock['PC_monotonic_elapsed'] <= 10, 'whole_real_C_renewal10_no_refresh')
    actualcfg = clock_config(cfg, identity)
    m = interface()
    result = m.consume_current_C(receipt_raw, receipt_stat, clock, actualcfg, native.wall())
    stop = owned_stop(owned_stop_originals, strict(receipt_raw))
    need(result['nonce'] == nonce, 'same_source_bound_nonce')
    native.exclusive(parent / 'C-receipt.json', receipt_raw)
    native.exclusive(parent / 'C-origin.json', encode({'origin_stat': receipt_stat, 'origin_sha256': sha(receipt_raw), 'owned_stop_originals': stop}))
    native.exclusive(parent / 'clock-finish.json', encode(clock))
    return {'nonce': nonce, 'result_schema': result['schema'], 'receipt_sha256': sha(receipt_raw), 'models_started': 0}

def consume(read, config, identity, now):
    selector = ROOT / ('selected-' + identity['invocation_id'] + '.json')
    raw, st = read(selector)
    selection = strict(raw)
    need(selection['schema'] == 'PC-current-C-renewal-selection/v1' and selection['manager_identity'] == identity and (selection['config_sha256'] == config['_config_sha256']), 'exact_current_C_selection')
    nonce = selection['nonce']
    need(re.fullmatch('[0-9a-f]{32}', nonce) and nonce != '0' * 32, 'current_C_nonce')
    parent = ROOT / nonce
    receipt, mirrorstat = read(parent / 'C-receipt.json', limit=4194304)
    origin, os_ = read(parent / 'C-origin.json', limit=4194304)
    clockraw, cs = read(parent / 'clock-finish.json')
    clock = strict(clockraw)
    o = strict(origin)
    envelope, es = read(parent / 'Spark-origin-envelope.json', limit=4194304)
    ev = strict(envelope)
    need(ev['receipt_raw_b64'] == base64.b64encode(receipt).decode() and ev['receipt_sha256'] == sha(receipt) and (ev['receipt_stat'] == o['origin_stat']) and (ev['owned_stop_originals'] == o['owned_stop_originals']), 'full_actual_envelope_and_stop_origin_rechecked')
    for meta in (st, mirrorstat, os_, cs, es):
        need(meta[3:7] == [0, 989, 33056, 1], 'PC_mirrors_are_distinct_protected_readable_Root_originals')
    need(o['origin_sha256'] == sha(receipt) and selection['clock_sha256'] == sha(clockraw), 'C_original_not_mirror_root_stat')
    m = interface()
    out = m.consume_current_C(receipt, o['origin_stat'], clock, clock_config(config, identity), now)
    owned_stop(o['owned_stop_originals'], strict(receipt))
    originals = {str(path): {'sha256': sha(body), 'stat': meta} for path, (body, meta) in ((selector, (raw, st)), (parent / 'C-receipt.json', (receipt, mirrorstat)), (parent / 'C-origin.json', (origin, os_)), (parent / 'clock-finish.json', (clockraw, cs)), (parent / 'Spark-origin-envelope.json', (envelope, es)))}
    return {'consumer_source_sha256': sha(Path(__file__).read_bytes()), 'manager_identity': identity, 'source_review_sha256': APPROVED_REVIEW, 'Root_scope_EXIT0': True, 'typed_consumed': out, 'originals': originals}

def select(native, nonce):
    current = native.capture_current(time.monotonic() + 30)
    identity = current['manager_identity']
    parent = ROOT / nonce
    clockraw, cs = protected_read(parent / 'clock-finish.json')
    clock = strict(clockraw)
    need(clock['PC_manager_identity'] == identity and clock['PC_config_sha256'] == native.current.config['_config_sha256'], 'same_current_C_select')
    native.exclusive(ROOT / ('selected-' + identity['invocation_id'] + '.json'), encode({'schema': 'PC-current-C-renewal-selection/v1', 'nonce': nonce, 'manager_identity': identity, 'config_sha256': clock['PC_config_sha256'], 'clock_sha256': sha(clockraw), 'observed_at': native.wall()}))
    return {'selected': nonce, 'manager_identity': identity}
