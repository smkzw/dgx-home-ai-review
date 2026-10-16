# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same-PC/sameboot deadline kernel. No authorization or clock acquisition here."""
import math as r17_math

class r17_ClockRefused(ValueError):
    pass

def r17_clock_number(value):
    return type(value) in (int, float) and r17_math.isfinite(value)

def r17_clock_require(value, reason):
    if not value:
        raise r17_ClockRefused(reason)

def r17_owner_clock(begin, permit, boot, monotonic_now, wall_now):
    r17_clock_require(type(begin) is dict and type(permit) is dict, 'owner_clock_complete_objects')
    r17_clock_require(begin['PC_boot_id'] == boot == permit['PC_boot_id'], 'owner_clock_same_boot')
    sent = begin['PC_monotonic_sent']
    origin, end = (permit['PC_monotonic_origin'], permit['PC_deadline_monotonic'])
    seconds = permit['duration_seconds']
    r17_clock_require(all((r17_clock_number(v) for v in (sent, origin, end, monotonic_now, wall_now, begin['PC_sent_at'], permit['PC_issued_at']))), 'owner_clock_finite_original_domain')
    r17_clock_require(type(seconds) is int and 1 <= seconds <= 120 and (end == origin + seconds), 'owner_clock_original_permit_formula')
    r17_clock_require(origin <= sent <= monotonic_now < end, 'owner_clock_original_permit_monotonic')
    elapsed = monotonic_now - sent
    r17_clock_require(elapsed <= 30, 'owner_clock_original_BEGIN_whole30')
    wall_elapsed = wall_now - begin['PC_sent_at']
    r17_clock_require(0 <= wall_now - permit['PC_issued_at'] <= seconds and wall_elapsed >= 0 and (abs(wall_elapsed - elapsed) <= 5), 'owner_clock_wall_audit_drift')
    return {'PC_boot_id': boot, 'PC_monotonic_sent': sent, 'PC_monotonic_observed': monotonic_now, 'PC_monotonic_elapsed': elapsed, 'PC_wall_observed': wall_now, 'PC_whole30_remaining': 30 - elapsed, 'permit_deadline_monotonic': end}

def owner_permit_v2(read, write, config, identity):
    p = owner_policy()
    owner_need(config['review_sha256'] == p['new_review'], 'owner_permit_new_review')
    t = owner_old_terminal(read, p)
    owner_need(p['old_worker'] == {'unit': t['scope']['unit']['Id'], 'pid': int(t['scope']['unit']['ExecMainPID']), 'boot_id': t['scope']['boot_id']}, 'owner_permit_Source_old_worker_exact')
    current = {'review_sha256': config['review_sha256'], 'config_sha256': config['_config_sha256'], 'source118': config['PC_source_pins'], 'manager_identity': identity}
    now = owner_time.time()
    mono = owner_time.monotonic()
    v = {'schema': 'failed-owner-terminal-release-permit/v2', 'operation': p['probe_operation'], 'nonce': p['probe_nonce'], 'stage_operation': p['stage'], 'new_current': current, 'old_terminal': p['old_terminal'], 'old_records': p['old_records'], 'old_plan': p['old_plan'], 'PC_boot_id': current['manager_identity']['boot_id'], 'PC_issued_at': now, 'PC_monotonic_origin': mono, 'PC_deadline_monotonic': mono + 120, 'duration_seconds': 120, 'automatic_retry': False}
    return owner_root_write(read, write, p['permit_path'], v)

def owner_begin_v2(read, write):
    p = owner_policy()
    raw, st = read(p['permit_path'], limit=2097152)
    v = owner_strict(raw)
    ref = {'path': p['permit_path'], 'sha256': owner_sha(raw), 'F9': st}
    owner_need(st[3:7] == [0, 989, 33056, 1] and v['schema'] == 'failed-owner-terminal-release-permit/v2' and (v['nonce'] == p['probe_nonce']) and (v['stage_operation'] == p['stage']) and (v['old_terminal'] == p['old_terminal']) and (v['old_records'] == p['old_records']) and (v['old_plan'] == p['old_plan']) and (v['automatic_retry'] is False), 'owner_BEGIN_same_Root_permit')
    owner_need(0 <= owner_time.time() - v['PC_issued_at'] <= v['duration_seconds'] == 120 and v['PC_monotonic_origin'] <= owner_time.monotonic() < v['PC_deadline_monotonic'], 'owner_BEGIN_original_PC_finite_window')
    root = owner_Path(p['qualified_path']).parent
    request = {'schema': 'failed-owner-terminal-PC-request/v1', 'nonce': v['nonce'], 'stage_operation': p['stage'], 'permit_original': ref, 'new_current': v['new_current'], 'old_terminal_sha256': p['old_terminal']['sha256']}
    rr = owner_root_write(read, write, root / 'request.json', request)
    m = {'schema': 'failed-owner-terminal-PC-send/v2', 'request_original': rr, 'PC_boot_id': v['PC_boot_id'], 'PC_sent_at': owner_time.time(), 'PC_monotonic_sent': owner_time.monotonic()}
    mr = owner_root_write(read, write, root / 'send-moment.json', m)
    br, bs = read(root / 'send-moment.json', limit=2097152)
    return {'PC_begin_original': {'raw_b64': owner_base64.b64encode(br).decode(), 'sha256': owner_sha(br), 'F9': bs}, 'request_original': rr, 'request_raw_b64': owner_base64.b64encode(owner_encode(request)).decode(), 'send_moment_original': mr}

def owner_finish_v2(read, write, A_original, scope):
    p = owner_policy()
    root = owner_Path(p['qualified_path']).parent
    rr, rs = read(root / 'request.json', limit=2097152)
    mr, ms = read(root / 'send-moment.json', limit=2097152)
    request, moment = (owner_strict(rr), owner_strict(mr))
    pref = request['permit_original']
    pv = owner_strict(owner_held(read, pref, [0, 989, 33056, 1], 2097152))
    owner_need(request['nonce'] == p['probe_nonce'] == pv['nonce'] and request['stage_operation'] == p['stage'] and (request['old_terminal_sha256'] == p['old_terminal']['sha256']) and (moment['request_original'] == {'path': str(root / 'request.json'), 'sha256': owner_sha(rr), 'F9': rs}), 'owner_finish_same_original_BEGIN')
    a = owner_base64.b64decode(A_original['raw_b64'], validate=True)
    owner_need(owner_sha(a) == A_original['sha256'] and A_original['F9'][2] == len(a) and (A_original['F9'][3:7] == [0, 0, 33152, 1]), 'owner_finish_actual_A_original')
    t = owner_old_terminal(read, p)
    owner_checked_A_v2(read, p, {'original_terminal': t, 'terminal_sha256': p['old_terminal']['sha256']}, request, {'A_original': A_original, 'scope': scope, 'send_moment_original': {'path': str(root / 'send-moment.json'), 'sha256': owner_sha(mr), 'F9': ms}})
    now = owner_time.time()
    duration = owner_time.monotonic() - moment['PC_monotonic_sent']
    r17_owner_clock(moment, pv, owner_Path('/proc/sys/kernel/random/boot_id').read_text().strip(), owner_time.monotonic(), now)
    received = {'schema': 'failed-owner-terminal-PC-received/v2', 'request_original': moment['request_original'], 'A_original': A_original, 'scope_sha256': owner_sha(owner_encode(scope)), 'PC_boot_id': moment['PC_boot_id'], 'PC_received_at': now, 'PC_monotonic_elapsed': duration}
    cr = owner_root_write(read, write, root / 'received.json', received)
    q = {'schema': 'failed-owner-terminal-fresh-qualified/v2', 'permit_original': pref, 'request_original': moment['request_original'], 'send_moment_original': {'path': str(root / 'send-moment.json'), 'sha256': owner_sha(mr), 'F9': ms}, 'received_original': cr, 'A_original': A_original, 'scope': scope}
    ref = owner_root_write(read, write, p['qualified_path'], q)
    return {'qualified_original': ref, 'clock_original': received, 'work_started': False, 'release_committed': False}

def owner_fresh_v2(read, p, g, pend, body, now, *, historical=False, event=None):
    """New finite release eligibility, independent of preserved terminal clock.
 All Root dynamic records are full protected originals, not caller booleans.
 """
    raw, st = read(p['permit_path'], limit=2097152)
    permit = owner_strict(raw)
    owner_need(st[3:7] == [0, 989, 33056, 1] and st[2] == len(raw), 'owner_permit_Root_full_origin')
    owner_need(set(permit) == {'schema', 'operation', 'nonce', 'stage_operation', 'new_current', 'old_terminal', 'old_records', 'old_plan', 'PC_boot_id', 'PC_issued_at', 'PC_monotonic_origin', 'PC_deadline_monotonic', 'duration_seconds', 'automatic_retry'} and permit['schema'] == 'failed-owner-terminal-release-permit/v2' and (permit['stage_operation'] == p['stage']) and (permit['operation'] == p['probe_operation']) and owner_re.fullmatch('[0-9a-f]{32}', permit['nonce']) and (permit['automatic_retry'] is False) and (permit['nonce'] == p['probe_nonce']), 'owner_exact_finite_Root_permit')
    owner_need(permit['old_terminal'] == p['old_terminal'] and permit['old_records'] == p['old_records'] and (permit['old_plan'] == p['old_plan']), 'owner_permit_full_immutable_old_binding')
    owner_need(all((owner_number(permit[k]) for k in ('PC_issued_at', 'PC_monotonic_origin', 'PC_deadline_monotonic'))) and type(permit['duration_seconds']) is int and (1 <= permit['duration_seconds'] <= 120) and (permit['PC_deadline_monotonic'] == permit['PC_monotonic_origin'] + permit['duration_seconds']), 'owner_finite_release_not_work_window')
    current = permit['new_current']
    owner_need(set(current) == {'manager_identity', 'config_sha256', 'source118', 'review_sha256'} and current['review_sha256'] == p['new_review'], 'owner_exact_new_source_current')
    owner_need(historical or (current['config_sha256'] == g.config['_config_sha256'] and current['source118'] == g.config['PC_source_pins'] and (current['review_sha256'] == g.config['review_sha256']) and (current['manager_identity'] == __import__('asset_stage', fromlist=['identity']).identity()) and (0 <= now - permit['PC_issued_at'] <= permit['duration_seconds']) and (permit['PC_monotonic_origin'] <= g.clock() < permit['PC_deadline_monotonic'])), 'owner_current_newsole_finite_PC_domain')
    qraw, qs = read(p['qualified_path'], limit=4194304)
    q = owner_strict(qraw)
    owner_need(qs[3:7] == [0, 989, 33056, 1] and qs[2] == len(qraw) and (set(q) == {'schema', 'permit_original', 'request_original', 'send_moment_original', 'received_original', 'A_original', 'scope'}) and (q['schema'] == 'failed-owner-terminal-fresh-qualified/v2'), 'owner_qualified_full_Root_origin')
    pr = {'path': p['permit_path'], 'sha256': owner_sha(raw), 'F9': st}
    owner_need(q['permit_original'] == pr, 'owner_qualified_exact_permit_F9')
    objects = []
    for name in ('request_original', 'send_moment_original', 'received_original'):
        r = q[name]
        objects.append(owner_strict(owner_held(read, r, [0, 989, 33056, 1], 2097152)))
    request, moment, received = objects
    owner_need(set(request) == {'schema', 'nonce', 'stage_operation', 'permit_original', 'new_current', 'old_terminal_sha256'} and request == {'schema': 'failed-owner-terminal-PC-request/v1', 'nonce': permit['nonce'], 'stage_operation': p['stage'], 'permit_original': pr, 'new_current': current, 'old_terminal_sha256': pend['terminal_sha256']}, 'owner_new_paired_request_exact')
    owner_need(set(moment) == {'schema', 'request_original', 'PC_boot_id', 'PC_sent_at', 'PC_monotonic_sent'} and moment['schema'] == 'failed-owner-terminal-PC-send/v2' and (moment['request_original'] == q['request_original']) and owner_number(moment['PC_sent_at']) and owner_number(moment['PC_monotonic_sent']), 'owner_real_new_PC_send')
    owner_checked_A_v2(read, p, pend, request, q)
    owner_need(set(received) == {'schema', 'request_original', 'A_original', 'scope_sha256', 'PC_boot_id', 'PC_received_at', 'PC_monotonic_elapsed'} and received['schema'] == 'failed-owner-terminal-PC-received/v2' and (received['PC_boot_id'] == moment['PC_boot_id'] == permit['PC_boot_id'] == current['manager_identity']['boot_id']) and (received['request_original'] == q['request_original']) and (received['A_original'] == q['A_original']) and (received['scope_sha256'] == owner_sha(owner_encode(q['scope']))) and all((owner_number(received[k]) for k in ('PC_received_at', 'PC_monotonic_elapsed'))) and (0 <= received['PC_monotonic_elapsed'] <= 30) and (0 <= received['PC_received_at'] - moment['PC_sent_at'] <= 30) and (abs(received['PC_received_at'] - moment['PC_sent_at'] - received['PC_monotonic_elapsed']) <= 5), 'owner_new_PC_whole30_original')
    now = now if historical else g.runtime.manager._now()
    if not historical:
        r17_owner_clock(moment, permit, __import__('asset_stage', fromlist=['identity']).identity()['boot_id'], g.clock(), now)
    result = {'schema': 'failed-owner-terminal-release-eligibility/v2', 'stage_operation': p['stage'], 'old_terminal_sha256': pend['terminal_sha256'], 'permit_original': pr, 'qualified_original': {'path': p['qualified_path'], 'sha256': owner_sha(qraw), 'F9': qs}, 'new_current': current, 'PC_release_clock': {'PC_boot_id': moment['PC_boot_id'], 'PC_monotonic_sent': moment['PC_monotonic_sent'], 'PC_sent_at': moment['PC_sent_at'], 'received_at': received['PC_received_at'], 'elapsed': received['PC_monotonic_elapsed'], 'permit_wall': permit['PC_issued_at'], 'permit_seconds': permit['duration_seconds'], 'permit_monotonic_origin': permit['PC_monotonic_origin'], 'permit_monotonic_deadline': permit['PC_deadline_monotonic']}, 'activation_request_nonce': body['request_nonce'] if not historical else event['activation_request_nonce'], 'original_deadline_monotonic': pend['original_deadline_monotonic'], 'work_may_resume': False, 'observed_at': now}
    if historical:
        owner_need(event == result, 'owner_historical_exact_completion_event_not_current_permission')
    return result

def owner_checked_A_v2(read, p, pend, request, q):
    ar = q['A_original']
    owner_need(type(ar) is dict and set(ar) == {'raw_b64', 'sha256', 'F9'}, 'owner_A_origin_exact_envelope')
    araw = owner_base64.b64decode(ar['raw_b64'], validate=True)
    owner_need(len(araw) <= 2097152 and owner_sha(araw) == ar['sha256'] and (ar['F9'][2] == len(araw)) and (ar['F9'][3:7] == [0, 0, 33152, 1]), 'owner_full_A_origin_distinct_from_PC_mirror')
    a = owner_strict(araw)
    owner_need(set(a) == {'schema', 'request_raw_b64', 'request_sha256', 'old_terminal_sha256', 'source_before', 'source_after', 'kernel_before', 'kernel_after', 'started_at', 'finished_at', 'monotonic_elapsed', 'PC_begin_original'} and a['schema'] == 'failed-owner-terminal-A-readonly/v2', 'owner_fresh_A_complete_shape')
    rr = owner_base64.b64decode(a['request_raw_b64'], validate=True)
    owner_need(rr == owner_encode(request) and owner_sha(rr) == a['request_sha256'] and (a['old_terminal_sha256'] == pend['terminal_sha256']) and (a['source_before'] == a['source_after'] == p['old_A_sources']), 'owner_fresh_A_request_and_old_sources_not_bool')
    owner_need(all((owner_number(a[k]) for k in ('started_at', 'finished_at', 'monotonic_elapsed'))) and 0 <= a['monotonic_elapsed'] <= 30 and (a['started_at'] <= a['finished_at']) and (abs(a['finished_at'] - a['started_at'] - a['monotonic_elapsed']) <= 5), 'owner_A_own_domain_whole30')
    begin = a['PC_begin_original']
    owner_need(type(begin) is dict and set(begin) == {'raw_b64', 'sha256', 'F9'}, 'owner_A_actual_PC_BEGIN_original')
    br = owner_base64.b64decode(begin['raw_b64'], validate=True)
    owner_need(owner_sha(br) == begin['sha256'] and begin['F9'][2] == len(br) and (begin['F9'][3:7] == [0, 989, 33056, 1]), 'owner_A_PC_BEGIN_full_origin')
    bm = owner_strict(br)
    owner_need(bm['schema'] == 'failed-owner-terminal-PC-send/v2' and bm['PC_boot_id'] == request['new_current']['manager_identity']['boot_id'] and (bm['request_original'] == {'path': str(owner_Path(p['qualified_path']).parent / 'request.json'), 'sha256': owner_sha(owner_encode(request)), 'F9': bm['request_original']['F9']}), 'owner_A_BEGIN_same_request')
    owner_need(owner_held(read, q['send_moment_original'], [0, 989, 33056, 1], 2097152) == br and q['send_moment_original']['F9'] == begin['F9'], 'owner_A_BEGIN_same_actual_PC_raw_F9')
    ctx = owner_Context(p['old_sources'], read)
    try:
        t = pend['original_terminal']
        unit = t['scope']['unit']['Id']
        pid = int(t['scope']['unit']['ExecMainPID'])
        boot = t['scope']['boot_id']
        kernel = ctx.module('old_failed_kernel')
        owner_need(a['kernel_before']['finished_at'] <= a['kernel_after']['started_at'], 'owner_fresh_two_kernel_scans_ordered')
        for k in ('kernel_before', 'kernel_after'):
            v = kernel.validate_failed_kernel(a[k], unit, pid, boot, a['started_at'])
            owner_need(v['finished_at'] <= a['finished_at'], 'owner_fresh_kernel_inside_outer_A_frame')
        scope = q['scope']
        b = ctx.module('ready_history').positive(scope, p['probe_unit'], p['probe_worker_sha'], True, operation=p['probe_operation'])
        owner_need(b['proof_sha256'] == owner_sha(owner_encode(a)) and b['request_sha256'] == owner_sha(rr) and (b['observed_at'] <= scope['observed_at']) and (scope['boot_id'] == boot), 'owner_actual_new_readonly_scope_binds_full_A_body')
        stops = scope['owner_scope_termination']
        owner_need(type(stops) is dict and set(stops) == {'owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'}, 'R16_owner_scope_complete_owned_stop_originals')
        values = {}
        for name, row in stops.items():
            body = owner_base64.b64decode(row['raw_b64'], validate=True)
            owner_need(set(row) == {'raw_b64', 'sha256', 'F9'} and owner_sha(body) == row['sha256'] and (row['F9'][2] == len(body) <= 2097152) and (row['F9'][3:7] == [0, 0, 33152, 1]), 'R16_owner_scope_stop_original_fullSHA_F9')
            values[name] = owner_strict(body)
        intent = values['owned-stop-intent.json']
        result = values['owned-stop-result.json']
        after = values['owned-stop-observed.json']
        owned_unit = p['probe_unit']
        actual_pid = int(scope['unit']['ExecMainPID'])
        owner_need(intent['unit'] == owned_unit and intent['invocation_id'] == scope['unit']['InvocationID'] and (intent['worker_pid'] == actual_pid) and (intent['body_sha256'] == owner_sha(araw)) and (intent['owned_stop_calls'] == 1) and (result['rc'] == 0) and (owner_base64.b64decode(result['stdout_b64'], validate=True) == owner_base64.b64decode(result['stderr_b64'], validate=True) == b''), 'R16_owner_exact_captured_owned_stop_once')
        afterraw = after['unit_raw_utf8'].encode()
        owner_need(owner_sha(afterraw) == after['unit_sha256'] and dict((x.split('=', 1) for x in afterraw.decode().splitlines())) == after['unit'] and (after['boot_id'] == scope['boot_id']) and (after['cgroup_procs'] == []) and (scope['observed_at'] <= intent['issued_at'] <= result['observed_at'] <= after['observed_at']), 'R16_owner_stop_same_boot_original_order')
        kernel.validate_failed_kernel(after['poststop_kernel_original'], owned_unit, actual_pid, scope['boot_id'], after['observed_at'])
        owner_stopped_unit_branch({'unit': scope['unit']}, after)
    finally:
        ctx.recheck()
    return a

def owner_final_clock_v2(eligibility, g):
    c = eligibility['PC_release_clock']
    moment = {k: c[k] for k in ('PC_boot_id', 'PC_monotonic_sent', 'PC_sent_at')}
    permit = {'PC_boot_id': c['PC_boot_id'], 'PC_issued_at': c['permit_wall'], 'PC_monotonic_origin': c['permit_monotonic_origin'], 'PC_deadline_monotonic': c['permit_monotonic_deadline'], 'duration_seconds': c['permit_seconds']}
    current = __import__('asset_stage', fromlist=['identity']).identity()
    return r17_owner_clock(moment, permit, current['boot_id'], g.clock(), g.runtime.manager._now())
