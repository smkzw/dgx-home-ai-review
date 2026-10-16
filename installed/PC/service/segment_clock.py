# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Per-stage real PC/A entry clocks; original90/300 gates are unchanged."""
import os, re, stat, time
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, protected_read, need, metadata
from root_io import held
from contract import PC_ROOT, OPERATION
import stage_entry_clock as core
from observer import positive
from entry_clock_store import resource
ROOT = PC_ROOT / 'asset-entry-clocks'
TERMINAL_ROOT = PC_ROOT / 'asset-terminal-clocks'

def folder(stage):
    need(type(stage) is str and re.fullmatch('[0-9a-f]{32}', stage) and (stage != OPERATION), 'unique_stage_clock_namespace')
    return ROOT / stage

def directory(path, create=False):
    with HeldParent(path) as chain:
        if create:
            os.mkdir(path.name, 488, dir_fd=chain.parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            if create:
                os.fchown(fd, 0, 989)
                os.fchmod(fd, 488)
                os.fsync(fd)
            z = os.fstat(fd)
            n = chain.named_leaf()
            need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == (n.st_dev, n.st_ino, n.st_uid, n.st_gid, n.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488), 'shared_stage_clock_FD_identity')
        finally:
            os.close(fd)
        chain.recheck()

def begin(config, identity, stage):
    need(os.getuid() == os.geteuid() == 0, 'Root_stage_clock_begin')
    if not ROOT.exists():
        directory(ROOT, True)
    else:
        directory(ROOT)
    p = folder(stage)
    directory(p, True)
    return core.begin(writer(p), reader, p, config, identity, stage)

def reader(p):
    return held(p, cap=2097152)

def writer(root):

    def write(p, raw, *, mode, gid):
        need(p.parent == root and p.name in ('send.json', 'send-moment.json', 'response.json', 'received.json') and (mode == 288) and (gid == 989) and (len(raw) <= 2097152), 'fixed_stage_clock_four_originals')
        with HeldParent(p) as chain:
            fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=chain.parent_fd)
            try:
                os.fchown(fd, 0, gid)
                os.fchmod(fd, mode)
                view = memoryview(raw)
                while view:
                    n = os.write(fd, view)
                    need(n > 0, 'stage_clock_write_progress')
                    view = view[n:]
                os.fsync(fd)
                need(metadata(os.fstat(fd)) == metadata(chain.named_leaf()), 'stage_clock_named_held_identity')
            finally:
                os.close(fd)
            os.fsync(chain.parent_fd)
            chain.recheck()
        body, s = reader(p)
        need(body == raw and s[3:7] == [0, 989, 33056, 1], 'stage_clock_protected_readback')
    return write

def finish(config, identity, stage, response):
    need(os.getuid() == os.geteuid() == 0, 'Root_stage_clock_finish')
    p = folder(stage)
    directory(ROOT)
    directory(p)
    v = core.strict(response)
    resource(core.strict(core.decode(v['entry_raw_b64'])))
    return core.finish(reader, writer(p), p, response, config, identity, positive=positive)

def consume(config, identity, stage, now):
    p = folder(stage)
    directory(ROOT)
    directory(p)
    value = core.consume(reader, p, config, identity, now, positive=positive, validate_resources=resource)
    return value

def terminal_begin(config, identity, stage):
    """PC-domain real BEGIN immediately before the one A finalization request."""
    need(os.getuid() == os.geteuid() == 0, 'Root_stage_terminal_clock_begin')
    core.identity_check(identity)
    folder(stage)
    if not TERMINAL_ROOT.exists():
        directory(TERMINAL_ROOT, True)
    else:
        directory(TERMINAL_ROOT)
    root = TERMINAL_ROOT / stage
    directory(root, True)
    request = {'schema': 'fixed-stage-terminal-clock-request/v1', 'nonce': __import__('secrets').token_hex(16), 'operation': OPERATION, 'stage_operation': stage, 'manager_identity': identity, 'config_sha256': config['_config_sha256'], 'source118': config['PC_source_pins'], 'review_sha256': config['review_sha256']}
    raw = core.encode(request)
    writer(root)(root / 'send.json', raw, mode=288, gid=989)
    body, stat = reader(root / 'send.json')
    moment = {'schema': 'fixed-stage-terminal-PC-send/v1', 'request_sha256': core.sha(raw), 'request_stat': stat, 'PC_sent_at': time.time(), 'PC_monotonic_sent': time.monotonic()}
    writer(root)(root / 'send-moment.json', core.encode(moment), mode=288, gid=989)
    return {'request_raw_b64': __import__('base64').b64encode(body).decode(), 'request_sha256': core.sha(body)}

def terminal_request(read, config, identity, stage, terminal):
    root = TERMINAL_ROOT / stage
    req, rs = read(root / 'send.json')
    mr, ms = read(root / 'send-moment.json')
    r = core.strict(req)
    m = core.strict(mr)
    core.f9(rs, req, gid=989, mode=288)
    core.f9(ms, mr, gid=989, mode=288)
    core.shape(r, {'schema', 'nonce', 'operation', 'stage_operation', 'manager_identity', 'config_sha256', 'source118', 'review_sha256'}, 'terminal_clock_request_schema')
    core.shape(m, {'schema', 'request_sha256', 'request_stat', 'PC_sent_at', 'PC_monotonic_sent'}, 'terminal_clock_moment_schema')
    need(r['schema'] == 'fixed-stage-terminal-clock-request/v1' and __import__('re').fullmatch('[0-9a-f]{32}', r['nonce']) and (r['operation'] == OPERATION) and (r['stage_operation'] == stage) and (r['manager_identity'] == identity) and (r['config_sha256'] == config['_config_sha256']) and (r['source118'] == config['PC_source_pins']) and (r['review_sha256'] == config['review_sha256']), 'terminal_clock_current_request')
    need(m['schema'] == 'fixed-stage-terminal-PC-send/v1' and m['request_sha256'] == core.sha(req) and (m['request_stat'] == rs) and all((core.number(m[k]) for k in ('PC_sent_at', 'PC_monotonic_sent'))), 'terminal_clock_original_send_binding')
    a = terminal['terminal_request_original']
    core.shape(a, {'raw_b64', 'sha256', 'stat'}, 'terminal_actual_A_request_origin')
    ar = core.decode(a['raw_b64'])
    core.f9(a['stat'], ar, gid=0, mode=384)
    need(ar == req and a['sha256'] == core.sha(req), 'terminal_A_same_request_no_retime')
    return (root, req, rs, r, m)

def terminal_finish(read, write, config, identity, stage, raw, origin_stat):
    v = core.strict(raw)
    root, req, rs, r, m = terminal_request(read, config, identity, stage, v)
    now = time.time()
    duration = time.monotonic() - m['PC_monotonic_sent']
    wall = now - m['PC_sent_at']
    core.f9(origin_stat, raw, gid=0, mode=384)
    need(all((core.number(x) for x in (duration, wall))) and 0 <= duration <= 30 and (0 <= wall <= 30) and (abs(wall - duration) <= 30), 'terminal_original_PC_whole30_not_crosshost_wall')
    result = {'schema': 'fixed-stage-terminal-PC-received/v1', 'request_sha256': core.sha(req), 'request_stat': rs, 'nonce': r['nonce'], 'terminal_sha256': core.sha(raw), 'terminal_origin_F9': origin_stat, 'PC_received_at': now, 'PC_monotonic_elapsed': duration}
    write(root / 'received.json', core.encode(result), mode=288, gid=989)
    return result

def terminal_consume(read, config, identity, stage, raw, now, *, historical=False):
    v = core.strict(raw)
    root, req, rs, r, m = terminal_request(read, config, identity, stage, v)
    cr, cs = read(root / 'received.json')
    c = core.strict(cr)
    core.f9(cs, cr, gid=989, mode=288)
    core.shape(c, {'schema', 'request_sha256', 'request_stat', 'nonce', 'terminal_sha256', 'terminal_origin_F9', 'PC_received_at', 'PC_monotonic_elapsed'}, 'terminal_local_received_schema')
    need(c['schema'] == 'fixed-stage-terminal-PC-received/v1' and c['request_sha256'] == core.sha(req) and (c['request_stat'] == rs) and (c['nonce'] == r['nonce']) and (c['terminal_sha256'] == core.sha(raw)), 'terminal_local_full_original_chain')
    core.f9(c['terminal_origin_F9'], raw, gid=0, mode=384)
    need(all((core.number(x) for x in (now, c['PC_received_at'], c['PC_monotonic_elapsed']))) and 0 <= c['PC_monotonic_elapsed'] <= 30 and (0 <= c['PC_received_at'] - m['PC_sent_at'] <= 30) and (abs(c['PC_received_at'] - m['PC_sent_at'] - c['PC_monotonic_elapsed']) <= 30), 'terminal_received_PC_clock_interval')
    need(historical or (0 <= now - c['PC_received_at'] and c['PC_monotonic_elapsed'] + now - c['PC_received_at'] <= 30), 'terminal_PC_local_conservative_age30')
    return c
