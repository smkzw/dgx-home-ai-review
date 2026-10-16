# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Real read-only producers over the existing sole-runtime + forced node channel."""
from __future__ import annotations
import json, os, time, math
from pathlib import Path
from .common import need, protected_read, metadata, sha, encode, strict, fresh
PROFILE = 'glm-ab'
OWNER = 'dgx-hx-service'
GEN = 10
NODES = ('spark-a', 'spark-b')
FIXED_PC_SOURCE_PATHS = frozenset({'/etc/dgx-home-ai/composition.json', '/etc/dgx-home-ai/g8-c-firsttrial-config.json', '/etc/dgx-home-ai/g8-g7-command-surfaces.json', '/etc/dgx-home-ai/hx-service.json', '/etc/dgx-home-ai/llm-gateway.json', '/etc/dgx-home-ai/node-adapter.json', '/etc/dgx-home-ai/profiles.json', '/etc/dgx-home-ai/ssh/control-ssh.conf', '/etc/dgx-home-ai/ssh/engine-ssh.conf', '/etc/dgx-home-ai/ssh/sparks-known-hosts', '/etc/dgx-v4/creative-runtime.json', '/opt/dgx-v4/hx/bin/hx-bootstrap.py', '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/__init__.py', '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/collector.py', '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py', '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/__init__.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/adapter.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/cache_checks.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/compiler.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/coordinator.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R1/node_guard_candidate.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/PYTHON_INPUTS.json', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/WEIGHT_INPUTS.json', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/__init__.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/command.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/config.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/durable.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/gateway.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/publisher.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R2/source_inputs.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R3/__init__.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R3/config.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R3/gateway.py', '/opt/dgx-v4/hx/runtime/G7_INTEGRATION_CANDIDATE_R3/runtime.py', '/opt/dgx-v4/hx/runtime/G7_PROFILE_CANDIDATE_R1/deepseek_profile/__init__.py', '/opt/dgx-v4/hx/runtime/G7_PROFILE_CANDIDATE_R1/deepseek_profile/adapter.py', '/opt/dgx-v4/hx/runtime/G7_PROFILE_CANDIDATE_R1/deepseek_profile/front.py', '/opt/dgx-v4/hx/runtime/G7_PROFILE_CANDIDATE_R1/deepseek_profile/plan.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/__init__.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/adapter.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/contract.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/manager.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/node_guard.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/node_wrapper.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/permit.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_IMPLEMENTATION_R1/store.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R2/__init__.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R2/adapter.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R2/contract.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R3/__init__.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R3/command.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R3/runtime.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_TELEMETRY_R3/sampler.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/__init__.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/command.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/config.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/gateway.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/proof.py', '/opt/dgx-v4/hx/runtime/G7_QUALIFICATION_VERIFICATION_R1/publisher.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/TURBO_T2I_API_CANDIDATE.json', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/__init__.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/adapter.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/attach.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/composition_entry.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/contract.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/controller.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/gateway.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/hx_bootstrap.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/permit.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/samples.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/schema_contract.json', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/service_factory.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/store_admission.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/__init__.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/adapter.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/comfy_contract.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/gateway.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/runtime_config.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/shared_scheduler.py', '/opt/dgx-v4/hx/runtime/control_plane/__init__.py', '/opt/dgx-v4/hx/runtime/control_plane/adapter.py', '/opt/dgx-v4/hx/runtime/control_plane/cli.py', '/opt/dgx-v4/hx/runtime/control_plane/config.py', '/opt/dgx-v4/hx/runtime/control_plane/errors.py', '/opt/dgx-v4/hx/runtime/control_plane/fixture_runner.py', '/opt/dgx-v4/hx/runtime/control_plane/httpapi.py', '/opt/dgx-v4/hx/runtime/control_plane/manager.py', '/opt/dgx-v4/hx/runtime/control_plane/store.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/__init__.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/__main__.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/composition.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/node_guard.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/readiness.py', '/opt/dgx-v4/hx/runtime/deployment_integrations/thread_scope.py', '/opt/dgx-v4/hx/runtime/engine_front/__init__.py', '/opt/dgx-v4/hx/runtime/engine_front/front.py', '/opt/dgx-v4/hx/runtime/hx_service/__init__.py', '/opt/dgx-v4/hx/runtime/hx_service/__main__.py', '/opt/dgx-v4/hx/runtime/hx_service/facade.py', '/opt/dgx-v4/hx/runtime/hx_service/service.py', '/opt/dgx-v4/hx/runtime/llm_gateway/__init__.py', '/opt/dgx-v4/hx/runtime/llm_gateway/__main__.py', '/opt/dgx-v4/hx/runtime/llm_gateway/config.py', '/opt/dgx-v4/hx/runtime/llm_gateway/errors.py', '/opt/dgx-v4/hx/runtime/llm_gateway/facade.py', '/opt/dgx-v4/hx/runtime/llm_gateway/registry.py', '/opt/dgx-v4/hx/runtime/llm_gateway/scheduler.py', '/opt/dgx-v4/hx/runtime/llm_gateway/server.py', '/opt/dgx-v4/hx/runtime/llm_gateway/state.py', '/opt/dgx-v4/hx/runtime/llm_gateway/upstream.py', '/opt/dgx-v4/hx/runtime/llm_gateway/validation.py', '/opt/dgx-v4/hx/runtime/node_adapter/__init__.py', '/opt/dgx-v4/hx/runtime/node_adapter/client.py', '/opt/dgx-v4/hx/runtime/node_adapter/node_wrapper.py', '/opt/dgx-v4/hx/runtime/node_adapter/protocol.py', '/opt/dgx-v4/hx/runtime/runtime_observer/observer.py', '/opt/dgx-v4/hx/scripts/safety_contract.py'})

def unwrap(facade):
    while hasattr(facade, '_facade'):
        facade = facade._facade
    return facade

def history_and_work(runtime):
    from llm_gateway.state import ACTIVE_REQUEST_STATES, TERMINAL_REQUEST_STATES
    from control_plane.store import ACTIVE_JOB_STATES
    gateway = runtime.gateway_store
    control = runtime.control_store
    requests = [dict(r) for r in gateway._connection().execute('SELECT * FROM requests ORDER BY request_id')]
    history = [r for r in requests if r['uncertain'] == 1 and r['state'] in TERMINAL_REQUEST_STATES]
    placeholders = ','.join(('?' for _ in ACTIVE_JOB_STATES))
    jobs = [dict(r) for r in control._connection().execute('SELECT job_id,state FROM jobs WHERE state IN (' + placeholders + ')', tuple(ACTIVE_JOB_STATES))]
    active = [r for r in requests if r['state'] in ACTIVE_REQUEST_STATES]
    return {'requests': requests, 'active_requests': active, 'active_jobs': jobs, 'historical_terminal_uncertain_count': len(history), 'historical_terminal_uncertain_sha256': sha(json.dumps(history, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())}
CLOCK_FIELDS = {'schema', 'PC_sent_at', 'PC_received_at', 'PC_adapter_received_at', 'PC_monotonic_elapsed', 'remote_reply_observed_at', 'configured_max_clock_skew_seconds', 'reply_canonical_sha256'}

def clock_number(value):
    need(type(value) in (int, float) and math.isfinite(value), 'finite_clock_number')
    return value

def validate_snapshot_clock(item, now, max_age):
    c = item.get('clock_receipt')
    need(type(c) is dict and set(c) == CLOCK_FIELDS and (c['schema'] == 'PC-owner-snapshot-receipt-clock/v1'), 'local_snapshot_clock_required')
    reply = item['reply']
    meta = item['transport']
    sent = clock_number(c['PC_sent_at'])
    received = clock_number(c['PC_received_at'])
    adapter_received = clock_number(c['PC_adapter_received_at'])
    elapsed = clock_number(c['PC_monotonic_elapsed'])
    remote = clock_number(reply['observed_at'])
    skew = clock_number(c['configured_max_clock_skew_seconds'])
    need(0 <= skew <= 30 and 0 <= elapsed <= 20 and (sent <= adapter_received <= received) and (0 <= received - sent <= 20), 'bounded_local_snapshot_exchange')
    fresh(sent, now, max_age)
    fresh(adapter_received, now, max_age)
    fresh(received, now, max_age)
    need(meta.get('reason') is None and meta.get('request_id') == reply['request_id'] and (meta.get('node') == reply['node']) and (meta.get('action') == 'owner_recovery_snapshot') and (meta.get('received_at') == adapter_received) and (meta.get('remote_observed_at') == remote), 'same_validated_snapshot_transport')
    need(c['reply_canonical_sha256'] == sha(encode(reply)) and c['remote_reply_observed_at'] == remote and (sent - skew <= remote <= adapter_received + skew), 'original_remote_reply_clock_bound')
    snap = reply['snapshot']
    start = clock_number(snap['observed_at'])
    finish = clock_number(snap['finished_at'])
    need(start <= finish <= remote, 'same_node_snapshot_order')
    fresh(start, remote, max_age)
    fresh(finish, remote, max_age)
    need(remote - start + now - adapter_received + elapsed <= max_age, 'combined_snapshot_age')
    return c

def fresh_node_stamp(item, stamp, now, max_age):
    c = validate_snapshot_clock(item, now, max_age)
    remote = clock_number(item['reply']['observed_at'])
    stamp = clock_number(stamp)
    fresh(stamp, remote, max_age)
    need(remote - stamp + now - c['PC_adapter_received_at'] + c['PC_monotonic_elapsed'] <= max_age, 'combined_remote_evidence_age')
    return c['PC_adapter_received_at']

def snapshot_clock_receipt(reply, meta, *, sent, received, elapsed, skew, now, max_age):
    c = {'schema': 'PC-owner-snapshot-receipt-clock/v1', 'PC_sent_at': sent, 'PC_received_at': received, 'PC_adapter_received_at': meta['received_at'], 'PC_monotonic_elapsed': elapsed, 'remote_reply_observed_at': reply['observed_at'], 'configured_max_clock_skew_seconds': skew, 'reply_canonical_sha256': sha(encode(reply))}
    item = {'reply': reply, 'transport': meta, 'clock_receipt': c}
    validate_snapshot_clock(item, now, max_age)
    return c

class Collector:

    def __init__(self, runtime, lease, config):
        self.runtime = runtime
        self.lease = lease
        self.config = config

    def source_and_lease(self):
        runtime = self.runtime
        need(self.runtime.adapter.config.connect_timeout_seconds <= 5, 'bounded_existing_connect_required')
        need(self.lease.held, 'same_maintenance_lease_required')
        s = os.fstat(self.lease._fd)
        named = self.lease.path.lstat()
        need(metadata(s) == metadata(named) and [s.st_dev, s.st_ino] == self.config['lease_dev_inode'], 'physical_lease_binding')
        need(runtime.manager.store is runtime.control_store and runtime.manager.adapter is runtime.adapter, 'same_sole_runtime')
        need(frozenset(self.config['PC_source_pins']) == FIXED_PC_SOURCE_PATHS, 'exact_fixed_PC_source_namespace118')
        sources = {}
        for path, pin in self.config['PC_source_pins'].items():
            raw, meta = protected_read(path, limit=1048576)
            need(sha(raw) == pin, 'current_PC_source_epoch_changed')
            sources[path] = {'sha256': pin, 'stat': meta}
        return {'manager_pid': os.getpid(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'manager_start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'lease_dev_inode': [s.st_dev, s.st_ino], 'PC_source_files': sources}

    def nodes(self):
        result = {}
        for node in NODES:
            sent = self.runtime.manager._now()
            monotonic_started = time.monotonic()
            reply, meta = self.runtime.adapter._exchange(node, 'owner_recovery_snapshot', profile=PROFILE, owner=OWNER, generation=GEN, scoped_owner_snapshot_timeout=20)
            need(isinstance(reply, dict) and reply.get('status') == 'ok' and (reply.get('readonly') is True) and (meta.get('reason') is None), 'actual_root_snapshot_required')
            received = self.runtime.manager._now()
            elapsed = time.monotonic() - monotonic_started
            now = self.runtime.manager._now()
            snap = reply.get('snapshot')
            need(isinstance(snap, dict) and snap.get('root_uid') == 0 and (snap.get('guard_process_verified') is True), 'root_origin_required')
            clock = snapshot_clock_receipt(reply, meta, sent=sent, received=received, elapsed=elapsed, skew=self.runtime.adapter.config.max_clock_skew_seconds, now=now, max_age=self.config['max_age_seconds'])
            sources = snap.get('sources', {})
            expected = self.config['node_source_pins'][node]
            need(set(sources) == set(expected), 'complete_physical_AB9')
            for path, pin in expected.items():
                item = sources[path]
                need(item['path'] == path and item['sha256'] == pin and (item['stat'][3] == 0) and (item['stat'][6] == 1) and (not item['stat'][5] & 18), 'actual_node_source_binding')
            record = snap['record']
            need((record['profile'], record['owner'], record['generation'], record['container_id']) == (PROFILE, OWNER, GEN, self.config['container_ids'][node]), 'original_node_identity')
            need(sha(snap['record_utf8'].encode()) == snap['record_sha256'] and strict(snap['record_utf8']) == record, 'transactional_record_snapshot_identity')
            for key in ('guard_state', 'guard_status'):
                item = snap[key]
                need(sha(item['raw_utf8'].encode()) == item['sha256'] and item['stat'][3] == 0 and (item['stat'][6] == 1), 'guard_root_raw_binding')
            result[node] = {'reply': reply, 'transport': meta, 'clock_receipt': clock}
        return result

    def collect(self, phase, *, engine=True):
        started = self.runtime.manager._now()
        proof = self.source_and_lease()
        proof['observed_at'] = started
        proof['phase'] = phase
        proof['core_profile'] = self.runtime.control_store.profile_view(PROFILE)
        proof['core_nodes'] = self.runtime.control_store.nodes_view()
        proof['rows'] = history_and_work(self.runtime)
        proof['adapter_journal'] = self.runtime.adapter._journal.lookup(PROFILE, GEN)
        proof['scheduler'] = self.runtime.server.scheduler.status()
        proof['nodes'] = self.nodes()
        if engine:
            actual = proof['nodes']['spark-a']['reply']['snapshot']['native_engine']
            need(isinstance(actual, dict), 'native_engine_count_required')
            health = strict(actual['health_raw_utf8'])
            models = strict(actual['models_raw_utf8'])
            count = health.get('requests_running')
            busy = health.get('busy')
            need(type(count) is int and count >= 0 and (type(busy) is bool) and (count == 0 or busy is True), 'native_health_count_schema')
            need(count == 0 and busy is False, 'native_engine_busy')
            need(isinstance(models.get('data'), list) and all((isinstance(r, dict) and isinstance(r.get('id'), str) for r in models['data'])) and (self.config['expected_model_id'] in [r['id'] for r in models['data']]), 'actual_native_model_required')
            engine_received = fresh_node_stamp(proof['nodes']['spark-a'], actual['observed_at'], self.runtime.manager._now(), self.config['max_age_seconds'])
            need(proof['nodes']['spark-a']['reply']['snapshot']['observed_at'] <= actual['observed_at'] <= proof['nodes']['spark-a']['reply']['snapshot']['finished_at'], 'engine_same_snapshot_interval')
            proof['engine_active'] = {'known': True, 'profile': PROFILE, 'generation': GEN, 'model_id': self.config['expected_model_id'], 'active_requests': count, 'observed_at': engine_received, 'source_remote_observed_at': actual['observed_at'], 'freshness_clock_domain': 'PC_adapter_received', 'count_source': 'actual_A_native_health_bound_to_both_AB_root_snapshots_not_READY_claim'}
        proof['finished_at'] = self.runtime.manager._now()
        need(not proof['rows']['active_requests'] and (not proof['rows']['active_jobs']), 'no_current_work')
        need(proof['rows']['historical_terminal_uncertain_count'] == 9 and proof['rows']['historical_terminal_uncertain_sha256'] == self.config['historical_terminal_uncertain_sha256'], 'immutable_history9')
        return proof

def validate_before(proof, config, now):
    fresh(proof['observed_at'], now, config['max_age_seconds'])
    fresh(proof['finished_at'], now, config['max_age_seconds'])
    p = proof['core_profile']
    need(p['profile'] == PROFILE and p['owner'] == OWNER and (p['generation'] == GEN) and (tuple(p['nodes']) == NODES), 'original_Core_profile')
    need(p['state'] in ('STARTING', 'RECONCILING', 'FAILED', 'QUARANTINED', 'READY'), 'held_stop_state')
    for node in NODES:
        row = next((r for r in proof['core_nodes'] if r['node'] == node))
        need((row['hold_profile'], row['hold_owner'], row['hold_generation']) == (PROFILE, OWNER, GEN) and row['quarantined'] is False, 'original_whole_AB_Core_holds_no_override')
    journal = proof['adapter_journal']
    need(journal['owner'] == OWNER and journal['generation'] == GEN and (journal['nodes'] == list(NODES)), 'journal_owner_fence')
    need(proof['scheduler']['operator_maintenance'] is True, 'scheduler_fence')
    for row in proof['scheduler']['profiles'].values():
        need(row['active'] == row['queued'] == 0 and row['uncertain'] is False and (row['draining'] is False), 'scheduler_idle_all_profiles')
    idle = proof['engine_active']
    fresh(idle.get('observed_at'), now, config['max_age_seconds'])
    need(idle.get('known') is True and type(idle.get('active_requests')) is int and (idle['active_requests'] == 0) and (idle.get('generation') == GEN) and (idle.get('profile') == PROFILE) and (idle.get('model_id') == config['expected_model_id']), 'fresh_engine_idle_original_gen_model')
    for node, item in proof['nodes'].items():
        s = item['reply']['snapshot']
        r = s['record']
        data = s['container']['data'] or {}
        gpu = s['gpu']
        need((r['profile'], r['owner'], r['generation'], r['container_id']) == (PROFILE, OWNER, GEN, config['container_ids'][node]), 'original_node_record_fence')
        need(r['state'] in ('RUNNING', 'QUARANTINED') and s['container']['exists'] is True, 'owned_container_expected')
        labels = data.get('labels', {})
        need(labels.get('dgx-v4.owner') == OWNER and labels.get('dgx-v4.profile') == PROFILE and (labels.get('dgx-v4.generation') == str(GEN)) and (labels.get('dgx-v4.node') == node), 'container_labels')
        ext = s.get('extended')
        need(isinstance(ext, list) and len(ext) == 7 and (ext[0] == r['container_id']) and (ext[1] == config['image']) and (ext[2] == config['image']) and ext[3].isdigit() and (int(ext[3]) > 0) and (ext[4] == '0') and (ext[5:] == ['false', 'false']), 'original_container_no_restart')
        need(data.get('restart_policy') == 'no' and s['actual_image'] == config['image'] and (s['manifest_image'] == config['image']), 'original_pinned_image')
        need(gpu['complete'] is True and gpu['truncated'] is False and all((c['id'] == r['container_id'] and c['mapped'] is True for c in gpu['containers'])), 'complete_owned_GPU')
        top = s['top']
        need(top is not None and top['returncode'] == 0, 'top_known')
        pids = {int(x) for x in top['raw_utf8'].splitlines()[1:] if x.strip().isdigit()}
        for process in gpu['processes']:
            pid = process['pid']
            text = s['cgroups'].get(str(pid), '')
            import re
            need(pid in pids and set(re.findall('(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', text)) == {r['container_id']}, 'current_GPU_owner_unknown')

def validate_clear(proof, before, config, now):
    fresh(proof['observed_at'], now, config['max_age_seconds'])
    fresh(proof['finished_at'], now, config['max_age_seconds'])
    need(proof['rows']['requests'] == before['rows']['requests'], 'requests_history_unchanged')
    need(proof['scheduler']['operator_maintenance'] is True, 'sticky_scheduler_fence_required')
    for node, item in proof['nodes'].items():
        s = item['reply']['snapshot']
        old = before['nodes'][node]['reply']['snapshot']['record']
        r = s['record']
        gpu = s['gpu']
        need((r['profile'], r['owner'], r['generation'], r['container_id']) == (PROFILE, OWNER, GEN, config['container_ids'][node]), 'original_CLEAR_node_record_fence')
        need(r['state'] == 'CLEAR' and r['released_at'] is not None and (old['updated_at'] <= r['released_at'] <= r['updated_at']), 'real_positive_CLEAR_time')
        need(gpu['complete'] is True and gpu['truncated'] is False and (gpu['empty'] is True) and (gpu['processes'] == gpu['containers'] == []), 'complete_empty_GPU')
        data = s['container']['data'] or {}
        need(s['container']['exists'] is False or (s['container']['exists'] is True and data.get('running') is False and (data.get('status') in ('created', 'exited', 'dead'))), 'container_inactive_known')
        guard = strict(s['guard_status']['raw_utf8'])
        state = strict(s['guard_state']['raw_utf8'])
        fresh_node_stamp(item, guard.get('observed_at'), now, config['max_age_seconds'])
        need(guard['state'] == 'IDLE_HOLD_RETAINED' and guard['reason_code'] == 'idle_db_clear' and (state['clear_authorized'] is True), 'guard_positive_CLEAR_pending')
        need(state['last_record'] == {k: r[k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'released_at', 'updated_at')}, 'guard_same_released_record')
