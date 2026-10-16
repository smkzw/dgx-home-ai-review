# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
from prelaunch_stop import stopped as classify_stopped
'Fresh read-only idle provenance on the existing Adapter/Runtime; no lifecycle.'
import hashlib, json, math, os, secrets, stat, time
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, encode, fresh, metadata
from B_OWNER_RECOVERY_R25_WIRING.collector import history_and_work
PROFILES = ('glm-ab', 'qwen-a-c', 'image-turbo-c')
NODES = ('spark-a', 'spark-b')
APPROVED_NODE_WRAPPER_SHA = '3d63d6fa7e9107b851fbd6d6d1d1367259821eb91d23514c53d49fa98ba26fec'
CLOCK_FIELDS = {'schema', 'PC_sent_at', 'PC_received_at', 'PC_adapter_received_at', 'PC_monotonic_elapsed', 'remote_reply_observed_at', 'configured_max_clock_skew_seconds', 'reply_canonical_sha256'}

def number(v):
    need(type(v) in (int, float) and math.isfinite(v), 'finite_live_clock')
    return v

def clock(item, now):
    c = item['clock_receipt']
    r = item['reply']
    meta = item['transport']
    request_raw = item['original_request_utf8'].encode()
    response_raw = item['original_response_utf8'].encode()
    request = strict(request_raw)
    need(sha(request_raw) == item['original_request_sha256'] and sha(response_raw) == item['original_response_sha256'] and (strict(response_raw) == r), 'same_full_original_current_idle_request_reply')
    need(request['action'] == r['action'] == 'current_idle_snapshot' and request['node'] == r['node'] and (request['request_id'] == r['request_id']) and ((request['profile'], request['owner'], request['generation']) == (r['profile'], r['owner'], r['generation'])), 'exact_fixed_channel_echo')
    need(set(c) == CLOCK_FIELDS and c['schema'] == 'PC-current-idle-snapshot-clock/v1', 'exact_current_idle_clock')
    sent = number(c['PC_sent_at'])
    recv = number(c['PC_received_at'])
    ar = number(c['PC_adapter_received_at'])
    elapsed = number(c['PC_monotonic_elapsed'])
    remote = number(r['observed_at'])
    skew = number(c['configured_max_clock_skew_seconds'])
    need(0 <= skew <= 30 and 0 <= elapsed <= 20 and (sent <= ar <= recv) and (0 <= recv - sent <= 20), 'current_idle_transport20')
    for v in (sent, recv, ar):
        fresh(v, now, 30)
    need(meta['reason'] is None and meta['action'] == 'current_idle_snapshot' and (meta['node'] == r['node']) and (meta['request_id'] == r['request_id']) and (meta['received_at'] == ar) and (meta['remote_observed_at'] == remote), 'actual_current_idle_transport')
    need(c['reply_canonical_sha256'] == sha(encode(r)) and c['remote_reply_observed_at'] == remote and (sent - skew <= remote <= ar + skew), 'same_original_remote_clock')
    s = r['snapshot']
    start = number(s['observed_at'])
    finish = number(s['finished_at'])
    need(start <= finish <= remote and remote - start + now - ar + elapsed <= 30, 'combined_current_idle_age30')
    for key in ('guard_state', 'guard_status'):
        v = strict(s[key]['raw_utf8'])
        stamp = number(v['observed_at']) if key == 'guard_status' else None
        if stamp is not None:
            need(0 <= remote - stamp and remote - stamp + now - ar + elapsed <= 30, 'fresh_guard_current_idle')
    return c

def exchange_current_idle(adapter, node, generation):
    """One fixed new read-only action over the actual existing SSH transport.
 No transport/Adapter constructor, default90 change, retry, or arbitrary argv.
 The existing owned-child _collect implements absolute20 + reap/close on error.
 """
    from node_adapter.client import SshTransport
    from node_adapter import protocol
    need(node in NODES and type(generation) is int and (generation > 0) and isinstance(adapter._transport, SshTransport), 'fixed_current_idle_existing_transport')
    need(adapter.config.connect_timeout_seconds <= 5 and tuple(adapter.config.profiles['glm-ab'].nodes) == NODES, 'actual_AB_route_and_connect5')
    transport = adapter._transport
    request = {'schema': protocol.SCHEMA, 'request_id': secrets.token_hex(16), 'node': node, 'action': 'current_idle_snapshot', 'profile': 'glm-ab', 'owner': 'dgx-hx-service', 'generation': generation}
    payload = protocol.encode_request(request, max_bytes=adapter.config.max_request_bytes)
    sent = adapter._clock()
    begin = time.monotonic()
    end = begin + 20
    argv = transport.build_argv(adapter.config.hosts[node])
    proc = transport._spawn(argv)
    out = transport._collect(proc, payload, snapshot_deadline=end)
    recv = adapter._clock()
    elapsed = time.monotonic() - begin
    need(not out.spawn_error and (not out.timed_out) and (not out.output_exceeded) and (out.returncode == 0) and (not out.stderr) and (elapsed <= 20), 'finite_current_idle_exchange_no_retry')
    reply = protocol.validate_reply(out.stdout, expect_action='current_idle_snapshot', expect_node=node, expect_request_id=request['request_id'], identity=('glm-ab', 'dgx-hx-service', generation), max_bytes=adapter.config.max_output_bytes, sent_at=sent, received_at=recv, max_skew_seconds=adapter.config.max_clock_skew_seconds)
    need(reply['status'] == 'ok' and reply.get('readonly') is True, 'positive_current_idle_Root_reply')
    meta = {'node': node, 'action': 'current_idle_snapshot', 'request_id': request['request_id'], 'received_at': recv, 'remote_observed_at': reply['observed_at'], 'reason': None}
    c = {'schema': 'PC-current-idle-snapshot-clock/v1', 'PC_sent_at': sent, 'PC_received_at': recv, 'PC_adapter_received_at': recv, 'PC_monotonic_elapsed': elapsed, 'remote_reply_observed_at': reply['observed_at'], 'configured_max_clock_skew_seconds': adapter.config.max_clock_skew_seconds, 'reply_canonical_sha256': sha(encode(reply))}
    item = {'reply': reply, 'transport': meta, 'clock_receipt': c, 'original_request_utf8': payload.decode(), 'original_request_sha256': sha(payload), 'original_response_utf8': out.stdout.decode(), 'original_response_sha256': sha(out.stdout)}
    clock(item, adapter._clock())
    return item

def _validate(proof, config, now, *, fenced, baseline=None, stopped=False):
    need(APPROVED_NODE_WRAPPER_SHA is not None, 'actual_AB_current_idle_source_install_pending')
    for v in (proof['observed_at'], proof['finished_at']):
        fresh(v, now, 30)
    need(set(proof['Core_profiles']) == set(PROFILES) and set(proof['nodes']) == set(NODES), 'complete_live_Core_and_AB')
    core = {}
    for name, p in proof['Core_profiles'].items():
        need(p['profile'] == name and p['state'] == 'STOPPED' and (p['owner'] is None) and (type(p['generation']) is int) and (p['generation'] > 0), 'current_Core_stopped_positive_generation')
        core[name] = p['generation']
    if not stopped:
        need(proof['scheduler']['operator_maintenance'] is fenced, 'actual_expected_live_maintenance')
        for p in proof['scheduler']['profiles'].values():
            need(type(p['active']) is int and type(p['queued']) is int and (p['active'] == p['queued'] == 0) and (p['uncertain'] is p['draining'] is False), 'actual_current_scheduler_idle')
    else:
        need(fenced is True and proof['schema'] == 'PC-stopped-current-idle-R26-R6/v1' and (proof['root_uid'] == 0), 'stopped_Root_type_not_fake_scheduler')
        kernel = proof['kernel_original']
        need(set(kernel) == {'owned_cgroup_processes', 'cgroup_originals', 'original_CG_absent', 'kernel_socket_owners', 'proc_net_unix_sha256', 'old_PID_absent', 'observed_at'}, 'exact_stopped_kernel_original')
        fresh(kernel['observed_at'], now, 30)
        need(kernel['observed_at'] <= proof['observed_at'] <= proof['finished_at'] and all((proof[k] == v for k, v in kernel.items() if k != 'observed_at')), 'distinct_stopped_kernel_current_clock_order')
        classify_stopped(proof)
        need(type(proof['owned_installer_pid']) is int and proof['owned_installer_pid'] > 1 and (proof['lease_holders'] == [proof['owned_installer_pid']]) and (proof['old_PID_absent'] is True) and (proof['other_Manager_PIDs'] == []), 'actual_owned_original_lease_not_foreign')
    for r in proof['core_nodes']:
        need(r['hold_profile'] is r['hold_owner'] is r['hold_generation'] is None and r['quarantined'] is False, 'actual_live_nodes_noholds_noQUAR')
    rows = proof['rows']
    need(rows['active_jobs'] == rows['active_requests'] == [] and rows['historical_terminal_uncertain_count'] == 9 and (rows['historical_terminal_uncertain_sha256'] == config['historical_terminal_uncertain_sha256']), 'historical_uncertain9_and_current_noactive')
    need(proof['lease_dev_inode'] == config['lease_dev_inode'] == [2096, 69257] and set(proof['PC_source_files']) == set(config['PC_source_pins']) and (len(config['PC_source_pins']) == 118), 'live_same_physicallease_current118')
    for path, pin in config['PC_source_pins'].items():
        v = proof['PC_source_files'][path]
        st = v['stat']
        need(v['sha256'] == pin and type(st) is list and (len(st) == 9) and all((type(x) is int for x in st)) and (st[3] == 0) and (st[6] == 1) and stat.S_ISREG(st[5]) and (not st[5] & 18), 'live_actual_PC_source_F9')
    records = {}
    for node, item in proof['nodes'].items():
        clock(item, now)
        s = item['reply']['snapshot']
        r = s['record']
        gpu = s['gpu']
        container = s['container']
        data = container['data'] or {}
        need(item['reply']['generation'] == core['glm-ab'] and type(item['reply']['generation']) is int and (item['reply']['profile'] == 'glm-ab') and (item['reply']['owner'] == 'dgx-hx-service'), 'Root_collected_current_Core_envelope_not_caller_selected_generation')
        need(s['schema'] == 'AB-current-idle-root-snapshot/v1' and s['root_uid'] == 0 and (s['guard_process_verified'] is True) and (item['reply']['node'] == node), 'new_readonly_Root_origin')
        need(r['state'] == 'CLEAR' and r['owner'] == 'dgx-hx-service' and (type(r['generation']) is int) and (r['generation'] > 0) and (type(r['profile']) is str) and (type(r['container_id']) is str) and __import__('re').fullmatch('[0-9a-f]{64}', r['container_id']) and (r['released_at'] is not None) and (r['released_at'] <= r['updated_at']), 'current_released_record_not_running_or_unknown')
        need(sha(s['record_utf8'].encode()) == s['record_sha256'] and strict(s['record_utf8']) == r, 'actual_transactional_live_record_raw')
        need(gpu['complete'] is True and gpu['truncated'] is False and (gpu['empty'] is True) and (gpu['processes'] == gpu['containers'] == []), 'complete_live_GPUempty')
        need(container['exists'] is False or (container['exists'] is True and data.get('running') is False and (data.get('status') in ('created', 'exited', 'dead'))), 'current_container_known_inactive')
        need(set(s['sources']) == set(config['node_source_pins'][node]) and len(s['sources']) == 9, 'current_exact_AB9')
        for path, pin in config['node_source_pins'][node].items():
            v = s['sources'][path]
            st = v['stat']
            need(v['path'] == path and v['sha256'] == pin and (len(st) == 9) and (st[3] == 0) and (st[6] == 1) and (not st[5] & 18), 'current_AB_source_F9')
        need(s['sources']['/opt/dgx-v4/runtime/node_adapter/node_wrapper.py']['sha256'] == APPROVED_NODE_WRAPPER_SHA, 'actual_current_idle_wrapper_installed')
        for key in ('guard_status', 'guard_state'):
            v = s[key]
            need(sha(v['raw_utf8'].encode()) == v['sha256'] and v['stat'][2] == len(v['raw_utf8'].encode()) and (v['stat'][3] == 0) and (v['stat'][6] == 1), 'actual_Guard_root_raw_F9')
        g = strict(s['guard_status']['raw_utf8'])
        gs = strict(s['guard_state']['raw_utf8'])
        need(g['state'] == gs['phase'] == 'IDLE_HOLD_RETAINED' and g['reason_code'] == 'idle_db_clear' and (gs['clear_authorized'] is True) and (gs['tracked'] is gs['terminal'] is None) and (gs['retained_unknown'] is False) and (gs['last_record'] == {k: r[k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'released_at', 'updated_at')}), 'live_Guard_accepts_exact_current_CLEAR')
        records[node] = {k: r[k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'released_at', 'updated_at')}
    result = {'Core_generations': core, 'Node_records': records, 'PC_source_pins': config['PC_source_pins'], 'lease_dev_inode': proof['lease_dev_inode']}
    need(baseline is None or baseline == result, 'current_baseline_changed_no_rebase_during_grant')
    return result

def collect(runtime, lease, config, phase, *, fenced):
    need(runtime.owner_recovery.runtime is runtime and runtime.manager.store is runtime.control_store and (runtime.manager.adapter is runtime.adapter) and (runtime.owner_recovery.lease is lease), 'same_original_Runtime_Adapter_Manager')
    started = time.monotonic()
    op = runtime.owner_recovery
    now = runtime.manager._now()
    s = runtime.server.scheduler
    timing = {'schema': 'PC-current-idle-collection-monotonic/v1', 'clock_domain': 'same-PC-process-monotonic', 'phase': phase, 'started_monotonic': started, 'segments': {}, 'AB': {}, 'authorization': False}
    lock_requested = time.monotonic()
    with op.cpu_bridge.facade._lifecycle_lock:
        timing['segments']['lifecycle_lock_wait'] = [lock_requested, time.monotonic()]
        before = time.monotonic()
        with s._lock:
            need(s._operator_maintenance is fenced and (not (s._operator_tick_inflight or s._operator_public_inflight or s._operator_creative_pulse_inflight or (s._creative is not None) or s._infos or any(s._queues.values()) or any(s._active.values()) or s._uncertain or s._ensuring or s._dispatch_checks or s._draining)), 'live_idle_shared_all_work_zero')
            core = {p: runtime.control_store.profile_view(p) for p in PROFILES}
        timing['segments']['scheduler_pre'] = [before, time.monotonic()]
        before = time.monotonic()
        source = op.collector.source_and_lease()
        timing['segments']['source_before'] = [before, time.monotonic()]

        def one(node):
            begin = time.monotonic()
            item = exchange_current_idle(runtime.adapter, node, core['glm-ab']['generation'])
            return (item, [begin, time.monotonic()])
        from concurrent.futures import ThreadPoolExecutor
        before = time.monotonic()
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix='registry-current-idle') as pool:
            pending = {n: pool.submit(one, n) for n in NODES}
            results = {n: pending[n].result() for n in NODES}
        timing['segments']['AB_join'] = [before, time.monotonic()]
        nodes = {n: results[n][0] for n in NODES}
        timing['AB'] = {n: results[n][1] for n in NODES}
        before = time.monotonic()
        proof = dict(source, Core_profiles=core, nodes=nodes, core_nodes=runtime.control_store.nodes_view(), rows=history_and_work(runtime), scheduler=s.status(), observed_at=now, finished_at=runtime.manager._now(), phase=phase)
        timing['segments']['proof_assembly'] = [before, time.monotonic()]
        before = time.monotonic()
        source_after = op.collector.source_and_lease()
        timing['segments']['source_after'] = [before, time.monotonic()]
        need(source == source_after, 'source_lease_drift_after_collect')
        before = time.monotonic()
        with s._lock:
            need(core == {p: runtime.control_store.profile_view(p) for p in PROFILES}, 'Core_drift_during_live_idle_collect')
            need(s._operator_maintenance is fenced and (not (s._operator_tick_inflight or s._operator_public_inflight or s._operator_creative_pulse_inflight or (s._creative is not None) or s._infos or any(s._queues.values()) or any(s._active.values()) or s._uncertain or s._ensuring or s._dispatch_checks or s._draining)), 'no_work_entered_during_current_idle_IO')
            validate_live_idle(proof, config, runtime.manager._now(), fenced=fenced)
        timing['segments']['scheduler_post_and_validate'] = [before, time.monotonic()]
    finished = time.monotonic()
    timing['finished_monotonic'] = finished
    timing['elapsed_monotonic'] = finished - started
    need(all((started <= a <= b <= finished for a, b in (*timing['segments'].values(), *timing['AB'].values()))), 'PC_collection_monotonic_order')
    proof['PC_collection_timing'] = timing
    return proof

def validate_live_idle(proof, config, now, *, fenced, baseline=None):
    return _validate(proof, config, now, fenced=fenced, baseline=baseline)

def validate_stopped_idle(proof, config, now, *, fenced, baseline=None):
    return _validate(proof, config, now, fenced=fenced, baseline=baseline, stopped=True)
