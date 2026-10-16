# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Trusted internal late scope derivation. No caller-selected source or permission.
A fresh private renderer/held closure per call; service globals are never rebound.
"""
import base64, builtins, os, re, sys, types
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read
from contract import PC_ROOT, OPERATION, APPROVED_REVIEW
APPROVED_RENDERER = None
APPROVED_LOADER = None
APPROVED_TEMPLATES = None
APPROVED_STATIC = None
APPROVED_CURRENT_READER_SHA = None
APPROVED_A_ORIGIN = None

def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def _pure(raw, path, name):

    def imports(module, globals=None, locals=None, fromlist=(), level=0):
        need(not level and module.split('.')[0] in sys.stdlib_module_names, 'late_scope_only_pinned_source_or_stdlib')
        return builtins.__import__(module, globals, locals, fromlist, level)
    m = types.ModuleType(name)
    m.__file__ = str(path)
    m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m

def current_policy(g=None):
    """Held Root-origin source data, not a caller permission or mutable global."""
    need(type(APPROVED_A_ORIGIN) is dict, 'late_scope_A_origin_SOURCE_None')
    raw, st = protected_read(PC_ROOT / 'A-source-origin.json', limit=2097152)
    v = strict(raw)
    need(st[3:7] == [0, 989, 33056, 1] and set(v) == {'schema', 'current', 'A_original'} and (v['schema'] == 'R12-PC-held-A-source-origin/v1'), 'late_scope_A_origin_PC_original')
    if g is not None:
        need(v['current']['config_sha256'] == g.config['_config_sha256'] and v['current']['source118'] == g.config['PC_source_pins'] and (v['current']['review_sha256'] == APPROVED_REVIEW), 'late_scope_A_origin_same_static_source')
    row = v['A_original']
    b = base64.b64decode(row['raw_b64'], validate=True)
    need(set(row) == {'raw_b64', 'sha256', 'F9'} and sha(b) == row['sha256'] and (row['F9'][2] == len(b)) and (row['F9'][3:7] == [0, 0, 33152, 1]), 'late_scope_original_A_raw_F9')
    a = strict(b)
    fixed = APPROVED_A_ORIGIN
    need(set(a) == {'schema', 'source_root', 'source_epoch', 'review_sha256', 'files', 'boot_original'} and a['schema'] == 'R12-A-source-held-original/v1' and (a['source_root'] == fixed['source_root']) and (a['source_epoch'] == OPERATION) and (a['review_sha256'] == APPROVED_REVIEW) and (set(a['files']) == set(fixed['source_pins'])), 'late_scope_A_origin_exact_complete_source')
    for n, r in a['files'].items():
        f = r['F9']
        need(set(r) == {'sha256', 'F9'} and r['sha256'] == fixed['source_pins'][n] and (type(f) is list) and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[0] > 0) and (f[1] > 0) and (f[2] == fixed['source_sizes'][n]) and (f[3:7] == [0, 0, 33152, 1]), 'late_scope_A_origin_every_full_source_F9')
    boot = a['boot_original']
    br = base64.b64decode(boot['raw_b64'], validate=True)
    need(set(boot) == {'raw_b64', 'sha256', 'F9'} and sha(br) == boot['sha256'] and (len(br) == 37) and (boot['F9'][2] == 0) and (boot['F9'][3] == 0) and (boot['F9'][6] == 1) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\n', br.decode()), 'late_scope_A_origin_actual_boot')
    need(protected_read(PC_ROOT / 'A-source-origin.json', limit=2097152) == (raw, st), 'late_scope_A_origin_held_after')
    return {'source_root': fixed['source_root'], 'data_root': fixed['data_root'], 'sources': a['files'], 'index_sha256': fixed['index_sha256'], 'ready_worker_sha256': fixed['ready_worker_sha256'], 'boot_id': br.decode().strip()}

def actor_validator(g):
    """One internal private module; no service/global approval rebinding."""
    policy = current_policy(g)
    packet, ps = protected_read(PC_ROOT / 'epoch-packet.json', limit=2097152)
    p = strict(packet)
    path = PC_ROOT / 'service/current_negative.py'
    raw, st = protected_read(path, limit=2097152)
    need(p['operation'] == OPERATION and p['newmap'] == g.config['PC_source_pins'] and (sha(p['new_config_raw_utf8'].encode()) == g.config['_config_sha256']) and (sha(raw) == p['helpers']['current_negative.py']) and (st[3:7] == [0, 989, 33056, 1]), 'late_scope_actor_actual_held_validator')
    m = types.ModuleType('private_current_actor_validator')
    m.__file__ = str(path)
    m.__dict__['__builtins__'] = __builtins__
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    m.APPROVED_POLICY = policy
    m.APPROVED_REVIEW = APPROVED_REVIEW
    m.ROOT = PC_ROOT / 'current-prebind-readonly'
    m.OPERATION = OPERATION
    need(protected_read(path, limit=2097152) == (raw, st) and protected_read(PC_ROOT / 'epoch-packet.json', limit=2097152) == (packet, ps), 'late_scope_actor_source_F9_after')
    return m

def _consume(mode, g, qualified_raw, qualified_F9, actor_raw, now, *, historical):
    need(mode in ('historical-fixed', 'current-stage-prebind', 'failed-empty-range-repair') and type(APPROVED_STATIC) is dict and (mode in APPROVED_STATIC) and (type(APPROVED_TEMPLATES) is dict) and (mode in APPROVED_TEMPLATES) and (APPROVED_RENDERER is not None) and (APPROVED_LOADER is not None) and (APPROVED_CURRENT_READER_SHA is not None), 'late_scope_SOURCE_None_harddeny')
    need(historical or g.lock.locked(), 'late_scope_same_private_grant_lock')
    g.same()

    def source_context():
        if historical and mode == 'failed-empty-range-repair':
            from current_epoch import consume_installation
            value = consume_installation(protected_read, g.config, now)
            need(value['historical_only'] is True, 'empty_repair_original_installation_history_only')
            return value
        return g.current_epoch()
    source_context()
    need(g.config['review_sha256'] == APPROVED_REVIEW, 'late_scope_internal_new_source_review')
    v = strict(qualified_raw)
    c = v['current'] if historical else {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'manager_identity': identity(), 'source118': g.config['PC_source_pins']}
    need(c['review_sha256'] == APPROVED_REVIEW and c['config_sha256'] == g.config['_config_sha256'] and (c['source118'] == g.config['PC_source_pins']), 'late_scope_history_same_source_not_new_PID_authority')
    need(v['current'] == c and v['review_sha256'] == APPROVED_REVIEW and (qualified_F9[2] == len(qualified_raw)) and (qualified_F9[3:7] == [0, 989, 33056, 1]), 'late_scope_actual_internal_current_Root_receipt')
    held = {}

    def read(path, pin=None):
        path = Path(path)
        raw, f9 = held[path] if path in held else protected_read(path, limit=2097152)
        need(pin is None or sha(raw) == pin, 'late_scope_exact_source_pin')
        held[path] = (raw, f9)
        return (raw, f9)
    br = base64.b64decode(v['begin']['raw_b64'], validate=True)
    need(sha(br) == v['begin']['sha256'], 'late_scope_full_BEGIN_original')
    nonce = strict(br)['request_nonce']
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'late_scope_actual_request_nonce')
    if mode == 'historical-fixed':
        need(actor_raw is None and (historical or g.asset_stages.zero_pending is not None), 'late_scope_fixed_history_no_caller_actor')
        target = PC_ROOT / 'zero-readonly' / nonce
    else:
        need(type(actor_raw) is bytes, 'late_scope_owned_current_actor_only')
        actor = strict(actor_raw)
        need(actor['current'] == c and nonce == actor['stage_operation'], 'late_scope_actor_current_context_and_owned_nonce')
        if not historical:
            active = g.asset_stages.active
            if mode == 'failed-empty-range-repair':
                from empty_range_repair import actor as original_actor
                original, _, _ = original_actor(g.asset_stages, actor['stage_operation'])
                need(active is None and original == actor_raw, 'late_scope_empty_repair_internal_original_no_active_work')
            else:
                need(active is not None and actor['stage_operation'] == active['stage_operation'] and (actor['plan_original']['sha256'] == active['plan_ref']['sha256']) and (actor['ordinal'] == active['ordinal']), 'late_scope_actor_not_body_selected')
        target = PC_ROOT / ('asset-empty-repairs' if mode == 'failed-empty-range-repair' else 'current-prebind-readonly') / actor['stage_operation']
    qraw, qf = read(target / ('qualified.json' if mode == 'failed-empty-range-repair' else 'not-launched-qualified.json'))
    need(qraw == qualified_raw, 'late_scope_original_qualified_not_restamped_copy')
    packet_raw, _ = read(PC_ROOT / 'epoch-packet.json')
    p = strict(packet_raw)
    cfg = p['new_config_raw_utf8'].encode()
    need(sha(cfg) == c['config_sha256'] and strict(cfg)['PC_source_pins'] == c['source118'] and (p['operation'] == OPERATION) and (p['newmap'] == c['source118']), 'late_scope_new_packet_config_current118')
    reader, _ = read(PC_ROOT / 'pc/current_reader.py', APPROVED_CURRENT_READER_SHA)
    renderer_raw, _ = read(APPROVED_RENDERER['path'], APPROVED_RENDERER['sha256'])
    loader_raw, _ = read(APPROVED_LOADER['path'], APPROVED_LOADER['sha256'])
    renderer = _pure(renderer_raw, APPROVED_RENDERER['path'], 'private_late_renderer')
    templates = {}
    for n, row in APPROVED_TEMPLATES[mode].items():
        if 'bundle_key' in row:
            bundle = strict(read(row['path'], row['bundle_sha256'])[0])
            need(set(bundle) == {'schema', 'files'} and bundle['schema'] == 'R12-readonly-template-source/v1' and (row['bundle_key'] in (n, mode + ':' + n)), 'late_scope_fixed_template_bundle')
            item = bundle['files'][row['bundle_key']]
            raw = base64.b64decode(item['source_bytes_base64'], validate=True)
            need(sha(raw) == item['sha256'] == row['sha256'] and len(raw) == item['source_bytes'], 'late_scope_template_original_fullbytes')
        else:
            raw = read(row['path'], row['sha256'])[0]
        templates[n] = raw
    static = APPROVED_STATIC[mode]
    scope_policy = current_policy(g) if mode in ('current-stage-prebind', 'failed-empty-range-repair') else static['policy']
    approved = {'mode': mode, 'review': APPROVED_REVIEW, 'policy': scope_policy, 'operation': OPERATION, 'current_reader_sha256': sha(reader), 'current_reader_input_pins': p['input_pins'], 'packed_pins': static['packed_pins'], 'publication_operation': static['publication_operation']}
    plan = renderer.render_plan(c, nonce, actor_raw, approved=approved, templates=templates, loader=loader_raw)
    need(plan['PC']['root'] == str(target), 'late_scope_derived_fixed_namespace')
    for name, raw in plan['PC']['files'].items():
        need(read(target / name)[0] == raw, 'late_scope_rederived_complete_PC_source_bytes')
    ack_raw, _ = read(target / 'prestage-ack.json')
    ack = strict(ack_raw)
    need(ack['schema'] == 'zero-readonly-prestage-ack/v1' and ack['root'] == plan['A']['root'] and (ack['nonce'] == nonce) and (ack['request_sha256'] == sha(plan['A']['files']['request.json'])) and (ack['clock_started'] is False) and (set(ack['files']) == set(plan['A']['files'])), 'late_scope_full_A_prepublication_source_set')
    for name, raw in plan['A']['files'].items():
        row = ack['files'][name]
        f = row['F9']
        need(row['sha256'] == sha(raw) and type(f) is list and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[2] == len(raw)) and (f[3:7] == [0, 0, 33152, 1]), 'late_scope_actual_A_fullsource_SHA_F9')
    loader = _pure(loader_raw, APPROVED_LOADER['path'], 'private_late_scope_loader')
    context = loader.load(target, sha(plan['PC']['files']['spec.json']))
    consumer = context.module('zero_qualified' if mode == 'historical-fixed' else 'current_qualified')
    outer = strict(context.module('receipt_codec').unpack(v['A_proof']))
    context.module('zero_runtime').clock_causality(context, outer, br)
    consume_at = now if historical else g.runtime.manager._now()
    if mode == 'historical-fixed':
        pcraw, araw, _ = context.module('not_launched_history').histories()
        result = consumer.consume(qualified_raw, qf, araw, pcraw, c, consume_at)
    else:
        result = consumer.consume(qualified_raw, qf, actor_raw, actor_raw, c, consume_at)
    need(all((protected_read(path, limit=2097152) == row for path, row in held.items())), 'late_scope_held_source_F9_after_full_consumer')
    g.same()
    source_context()
    if not historical:
        final_now = g.runtime.manager._now()
        begin = strict(br)
        need(0 <= final_now - begin['PC_sent_at'] <= 30, 'late_scope_final_real_now_original_BEGIN_whole30')
    return result

def consume(mode, g, qualified_raw, qualified_F9, actor_raw, now):
    return _consume(mode, g, qualified_raw, qualified_F9, actor_raw, now, historical=False)

def consume_history(mode, g, qualified_raw, qualified_F9, actor_raw, event_time):
    """Only complete immutable completion-chain callers; no writes or release.
 The caller must first verify intent/completed/fence and bind event_time to its
 original completion. This does not accept a current work request or clear hold.
 """
    return _consume(mode, g, qualified_raw, qualified_F9, actor_raw, event_time, historical=True)
