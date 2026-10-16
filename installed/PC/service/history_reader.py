# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""PC service fixed Root shared-file reader; held import before history."""
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
OWNER = [0, 989, 33056, 1]

def read(path, limit=2097152):
    return protected_read(path, limit=limit)
'Closed R14B immutable finite-actor history. Never a grant/retry/resource gate.\nAll actual cutover slots are None until Root captures a complete closed set and\nparent review pins the snapshot. This module has no native/Runtime executor.\n'
import base64 as epoch_base64, builtins as epoch_builtins, hashlib as epoch_hashlib, json as epoch_json, math as epoch_math, os as epoch_os, pathlib as epoch_pathlib, re as epoch_re, stat as epoch_stat, sys as epoch_sys, types as epoch_types, zlib as epoch_zlib
epoch_ACTUAL_BINDING = None
epoch_NATIVE_ELIGIBLE = False
epoch_OLD_EPOCH = {'A_source': {'boot_id': 'redacted-32c02e882269', 'data_root': '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14', 'index_sha256': '9b9cc0a2c97ec234482aa20a2f195024651f9f821d2f78480ca75f04d7958256', 'ready_worker_sha256': 'cf565910ef8430c8b4bcec8c1a3805e9e3e58a262592f18856631dbd9aebb746', 'source_root': '/opt/dgx-v4/mimo-registry-native-r26-role-context-r14', 'sources': {'EXPECTED_DUMP.json': None, 'OFFICIAL_MERGED_BASELINE.json': None, 'asset_segments.py': None, 'bounded_process.py': None, 'broker.py': None, 'config-original.json': None, 'containerd.candidate.toml': None, 'diagnostics.py': None, 'download_worker.py': None, 'entry_clock.py': None, 'entry_worker.py': None, 'failed_terminal.py': None, 'fetch/config-original.json': None, 'fetch/contract.py': None, 'fetch/entry.py': None, 'fetch/fetch.py': None, 'fetch/manifest-original.json': None, 'fetch/oci.py': None, 'fetch/supervision.py': None, 'fetch/transport.py': None, 'manifest-original.json': None, 'namespace.py': None, 'native.py': None, 'observer.py': None, 'old_failed_kernel.py': None, 'parent_metadata.py': None, 'parent_source.py': None, 'pc_contract.py': None, 'pc_managed_scope.py': None, 'plan.py': None, 'point_clock.py': None, 'private_config.py': None, 'qualification.py': None, 'range_catalog.py': None, 'range_component.py': None, 'range_diagnostic.py': None, 'range_fetch.py': None, 'range_http.py': None, 'range_transport.py': None, 'root_agent.py': None, 'root_io.py': None, 'root_loader.py': None, 'root_worker.py': None, 'segment_agent.py': None, 'segment_download_worker.py': None, 'segment_ready.py': None, 'segment_ready_worker.py': None, 'segment_runtime.py': None, 'segment_terminal_producer.py': None, 'segment_worker.py': None, 'source-index.json': None, 'stage_entry_clock.py': None, 'stage_naming.py': None, 'terminal.py': None, 'topology.py': None}}, 'old_current': None, 'operation': 'ed7021db9df4c839d02f3271361924de', 'parent_acceptance_sha256': '226c819acd1f8b0555910ef09f87fd9433ba1a3d3c34fd032061048e92003882', 'qualification_completed_original': None, 'qualification_summary': {'Core_generations': {'glm-ab': 14, 'image-turbo-c': 1, 'qwen-a-c': 11}, 'historical_only': True, 'initial_identity': {'boot_id': 'redacted-2606f3e07a03', 'invocation_id': '69c59077d950b1dff986304287b2fa6c', 'pid': 2023335, 'start_ticks': '34798009'}, 'source_qualified_sha256': 'deb0365552c06e04acd864d3fbb8cc06d5d826ea26e44dc6f32a35b1752036d7'}, 'qualified_original': None}
epoch_OLD_SOURCE_PINS = {'B_OWNER_RECOVERY_R25_WIRING.common.py': {'bytes': 5608, 'sha256': 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'}, 'actor_io.py': {'bytes': 1727, 'sha256': 'd0b22afc488403de892d5191c4ddb3812fdc4d297ec5179780e7e0295d971ffe'}, 'asset_segments.py': {'bytes': 11877, 'sha256': '380dcc93cbc0cf34ed3eeefe75ea4e3219ea74f1b87bb4efe985a260daf351d6'}, 'bounded_process.py': {'bytes': 1175, 'sha256': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f'}, 'config-original.json': {'bytes': 61956, 'sha256': '3e17fc3d95b489c35f8c4be0d7d0d1292853c68f0dea3d046851c4e1bc12d1f9'}, 'contract.py': {'bytes': 53367, 'sha256': 'db7b197f1de4626c8b13502f4c7f8c0dc483a1b06c905c96003eae17012fb398'}, 'entry_clock.py': {'bytes': 17413, 'sha256': '1fb8f9e6c8e63fb455a8d5d0444f5ec364da7d885b0c46d358f012f5a42f661f'}, 'entry_clock_store.py': {'bytes': 3308, 'sha256': '94985916e9be568a9b261569ea35e5d5e29cf1664e0120c49ec8bef0ab6375a4'}, 'lineage.py': {'bytes': 21284, 'sha256': 'b999a26d489e00ed7feedffd154cb1e3739073d2afa9420e6d7db32bd4511478'}, 'manifest-original.json': {'bytes': 13484, 'sha256': '2e4bcc8bf4b5811670197334201ea4668001a81325749be1d1d1febffe215514'}, 'observer.py': {'bytes': 3975, 'sha256': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef'}, 'old_failed_kernel.py': {'bytes': 8265, 'sha256': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd'}, 'plan.py': {'bytes': 7425, 'sha256': 'f51ea20e6e3b6fadd75145ea5c133981b9c2e21f3ea5d3897cf752ce7ecbaa79'}, 'range_catalog.py': {'bytes': 4134, 'sha256': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde'}, 'range_component.py': {'bytes': 4760, 'sha256': '46ea4378229ada599beecb4e4c1b78d4d9be0ef77bb9d43ba32bec8e3c5233ad'}, 'root_io.py': {'bytes': 3020, 'sha256': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e'}, 'segment_clock.py': {'bytes': 7316, 'sha256': '4fcbb8a297ed980ade98f6e4fe3b8bf4060e1fe35334c8141a94b6bb19f443b3'}, 'segment_terminal.py': {'bytes': 12075, 'sha256': '842e3cb60346cf1b7b1e71392ac0dc571e480d96c75d1c66e2773f88a93d3e23'}, 'stage_entry_clock.py': {'bytes': 17413, 'sha256': '0eae38416aa790cd8269c3f81e4443e9d50dce789fd3b877804208e53c7de78c'}, 'stage_naming.py': {'bytes': 341, 'sha256': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d'}}
epoch_APPROVED_BINDING = {'old_metadata': {'config-original.json': None, 'manifest-original.json': None}, 'snapshot': None, 'source_bundle': None}
epoch_PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-native-r26-role-context-r14'
epoch_ACTOR_ROOT = None
epoch_SCHEMA = 'R14B-complete-finite-epoch-history-snapshot/v1'

def epoch_need(v, r):
    if not v:
        raise ValueError(r)

def epoch_sha(b):
    return epoch_hashlib.sha256(b).hexdigest()

def epoch_encode(v):
    return (epoch_json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def epoch_strict(raw):

    def pairs(xs):
        out = {}
        for k, v in xs:
            epoch_need(k not in out, 'history_duplicate_key')
            out[k] = v
        return out
    v = epoch_json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: epoch_need(False, 'history_nonfinite'))
    epoch_encode(v)
    return v

def epoch_pack(raw):
    epoch_need(type(raw) is bytes and 0 < len(raw) <= 4194304, 'history_raw4MiB')
    z = epoch_zlib.compress(raw, 9)
    epoch_need(len(z) <= 1048576, 'history_compressed1MiB')
    return {'bytes': len(raw), 'sha256': epoch_sha(raw), 'zlib_base64': epoch_base64.b64encode(z).decode()}

def epoch_unpack(p):
    epoch_need(type(p) is dict and set(p) == {'bytes', 'sha256', 'zlib_base64'} and (type(p['bytes']) is int) and (0 < p['bytes'] <= 4194304), 'history_exact_packed_sizes')
    z = epoch_base64.b64decode(p['zlib_base64'], validate=True)
    epoch_need(len(z) <= 1048576 and epoch_base64.b64encode(z).decode() == p['zlib_base64'], 'history_compressed_canonical')
    d = epoch_zlib.decompressobj()
    raw = d.decompress(z, p['bytes'] + 1)
    epoch_need(len(raw) == p['bytes'] and d.eof and (d.unused_data == d.unconsumed_tail == b'') and (epoch_sha(raw) == p['sha256']), 'history_lossless_EOF_SHA')
    return raw

def epoch_original(raw, f9, path):
    epoch_need(type(path) is str and path.startswith('/') and (type(f9) is list) and (len(f9) == 9) and all((type(n) is int and n >= 0 for n in f9)) and (f9[2] == len(raw)) and (f9[6] == 1), 'history_full_original_F9')
    return {'path': path, 'F9': f9, 'packed': epoch_pack(raw)}

def epoch_raw(row, owner):
    epoch_need(type(row) is dict and set(row) == {'path', 'F9', 'packed'}, 'history_exact_origin_row')
    b = epoch_unpack(row['packed'])
    epoch_need(row['F9'][2] == len(b) and row['F9'][3:7] == owner, 'history_exact_origin_domain')
    return b

class epoch_OldContext:
    """Exact reviewed OLD modules, closed imports and restored sys.modules.
 Native callables exist only as unchanged source; this receiver only calls the
 original terminal.consume(historical=True), never observer.collect/run.
 """

    def __init__(self, sources, code_root):
        epoch_need(type(epoch_OLD_SOURCE_PINS) is dict and set(sources) == set(epoch_OLD_SOURCE_PINS), 'history_exact_old_source_closure')
        self.sources = sources
        self.loaded = {}
        self.code_root = epoch_pathlib.Path(code_root)
        for n, b in sources.items():
            epoch_need(epoch_sha(b) == epoch_OLD_SOURCE_PINS[n]['sha256'] and len(b) == epoch_OLD_SOURCE_PINS[n]['bytes'], 'history_original_complete_source_SHA')

    def imports(self, name, gl=None, lo=None, fromlist=(), level=0):
        if not level and name + '.py' in self.sources:
            return self.module(name)
        if not level and name == 'B_OWNER_RECOVERY_R25_WIRING':
            p = epoch_types.ModuleType(name)
            p.common = self.module(name + '.common')
            return p
        epoch_need(not level and name.split('.')[0] in epoch_sys.stdlib_module_names, 'history_no_ambient_module')
        return epoch_builtins.__import__(name, gl, lo, fromlist, level)

    def module(self, name):
        if name in self.loaded:
            return self.loaded[name]
        key = name + '.py'
        epoch_need(key in self.sources, 'history_closed_module')
        private_name = '_R15_oldhistory_' + str(id(self)) + '_' + name.replace('.', '_')
        m = epoch_types.ModuleType(private_name)
        m.__file__ = str(self.code_root / key)
        m.__dict__['__builtins__'] = dict(vars(epoch_builtins), __import__=self.imports)
        self.loaded[name] = m
        absent = object()
        previous = epoch_sys.modules.get(private_name, absent)
        epoch_sys.modules[private_name] = m
        try:
            exec(compile(self.sources[key], m.__file__, 'exec'), m.__dict__)
        except BaseException:
            self.loaded.pop(name, None)
            raise
        finally:
            if previous is absent:
                epoch_sys.modules.pop(private_name, None)
            else:
                epoch_sys.modules[private_name] = previous
        return m

def epoch_old_config():
    epoch_need(type(epoch_OLD_EPOCH) is dict, 'history_old_epoch_None')
    c = epoch_OLD_EPOCH['old_current']
    return {'review_sha256': c['review_sha256'], '_config_sha256': c['config_sha256'], 'PC_source_pins': c['source118']}

def epoch_qualification(snapshot):
    h = epoch_OLD_EPOCH
    for key in ('qualified_original', 'qualification_completed_original'):
        r = snapshot[key]
        expected = h[key]
        b = epoch_raw(r, [0, 989, 33056, 1])
        epoch_need(r['path'] == expected['path'] and epoch_sha(b) == expected['sha256'] and (r['F9'] == expected['F9']), 'history_original_accepted_qualification_fullSHA_F9')
    q = epoch_strict(epoch_raw(snapshot['qualified_original'], [0, 989, 33056, 1]))
    done = epoch_strict(epoch_raw(snapshot['qualification_completed_original'], [0, 989, 33056, 1]))
    c = h['old_current']
    epoch_need(q['schema'] == 'registry-R26-current118-source-qualified/v1' and q['review_sha256'] == c['review_sha256'] and (q['current']['manager_identity'] == done['manager_identity'] == c['manager_identity']) and (q['current']['config_sha256'] == c['config_sha256']) and (q['current']['current_source118'] == c['source118']) and (q['operation'] == q['grant_operation'] == h['operation']) and (done['receipt_sha256'] == epoch_sha(epoch_raw(snapshot['qualified_original'], [0, 989, 33056, 1])) == h['qualification_summary']['source_qualified_sha256']) and (q['observed_at'] <= done['observed_at']), 'history_accepted_old_qualification_event_only')
    return q

def epoch_actor_chain(stage, records):
    epoch_need(epoch_re.fullmatch('[0-9a-f]{32}', stage) and set(records) >= {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'}, 'history_no_missing_unfinished_actor')
    rows = {n: epoch_raw(r, [999, 989, 33152, 1]) for n, r in records.items()}
    for n, r in records.items():
        epoch_need(r['path'] == epoch_ACTOR_ROOT + '/' + stage + '/' + n, 'history_actor_original_canonical')
    i, res, t, c, f = (epoch_strict(rows[n]) for n in ('intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'))
    epoch_need(set(i) == {'schema', 'operation_family', 'stage_operation', 'plan', 'plan_ref', 'source_release_sha256', 'duration_seconds', 'deadline_monotonic', 'current_qualification', 'before', 'request', 'empty_repair', 'automatic_retry', 'issued_at'} and i['schema'] == 'fixed-image-finite-stage-intent/v1' and (set(res) == {'stage_operation', 'plan_ref', 'deadline_monotonic', 'budget', 'after', 'observed_at'}) and (set(c) == {'schema', 'stage_operation', 'state', 'terminal_sha256', 'current', 'original_deadline_monotonic', 'work_deadline_extended', 'image_imported', 'CPU_success', 'models_started', 'finished_at'}) and (set(f) == {'stage_operation', 'completed_sha256', 'operator_maintenance_observed', 'observed_at'}), 'history_exact_original_actor_schemas')
    p = i['plan']
    h = epoch_OLD_EPOCH
    old = h['old_current']
    base = {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'}
    ordinals = []
    for n in set(rows) - base:
        match = epoch_re.fullmatch('pulse-([1-9][0-9]{0,3})\\.json', n)
        epoch_need(match, 'history_unknown_actor_leaf')
        ordinals.append(int(match[1]))
    epoch_need(sorted(ordinals) == list(range(1, len(ordinals) + 1)), 'history_complete_contiguous_all_ordinal_pulses')
    epoch_need(i['stage_operation'] == res['stage_operation'] == t['stage_operation'] == c['stage_operation'] == stage and i['operation_family'] == t['operation_family'] == h['operation'] and (p['stage_operation'] == stage) and (p['operation_family'] == h['operation']) and (p['review_sha256'] == old['review_sha256']) and (p['config_sha256'] == old['config_sha256']) and (p['manager_identity'] == old['manager_identity']) and (p['source118_sha256'] == epoch_sha(epoch_encode(old['source118']))) and (i['source_release_sha256'] == old['review_sha256']) and (i['automatic_retry'] is False), 'history_fixed_R14B_epoch_not_any_legacy')
    epoch_need(res['plan_ref'] == i['plan_ref'] and i['plan_ref']['sha256'] == t['plan_sha256'] == epoch_sha(epoch_encode(p)) and (i['deadline_monotonic'] == p['PC_plan_deadline_monotonic']) and (res['deadline_monotonic'] == i['deadline_monotonic']), 'history_original_plan_and_deadline_not_rebased')
    epoch_need(c['state'] == t['state'] in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT') and c['terminal_sha256'] == epoch_sha(rows['terminal.json']) and (f['completed_sha256'] == epoch_sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (c['image_imported'] is False), 'history_terminal_completed_fence_complete')
    epoch_need(c['schema'] == 'fixed-image-finite-stage-completed/v1' and c['original_deadline_monotonic'] == i['deadline_monotonic'] and (c['work_deadline_extended'] is False) and (c['CPU_success'] is False) and (type(c['models_started']) is int) and (c['models_started'] == 0) and (f['stage_operation'] == stage) and all((type(x) in (int, float) and epoch_math.isfinite(x) for x in (res['observed_at'], c['finished_at'], f['observed_at']))) and (res['observed_at'] <= c['finished_at'] <= f['observed_at']), 'history_original_finish_full_fields_no_extension')
    context = epoch_strict(epoch_base64.b64decode(t['context_original']['raw_b64'], validate=True))
    first = context['initial_pulse_original']
    first_raw = epoch_base64.b64decode(first['original_raw_b64'], validate=True)
    fp = epoch_strict(first_raw)
    epoch_need(epoch_sha(first_raw) == first['original_sha256'] and rows.get('pulse-' + str(fp['ordinal']) + '.json') == first_raw and (fp['clear_reservation_original'] == res) and (fp['clear_reservation_sha256'] == epoch_sha(rows['reserved.json'])), 'history_original_finish_owned_context_pulse_not_another_actor')
    last_time = res['observed_at']
    last_remaining = p['duration_seconds']
    nonces = set()
    for ordinal in sorted(ordinals):
        v = epoch_strict(rows['pulse-' + str(ordinal) + '.json'])
        epoch_need(v['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and v['operation'] == h['operation'] and (v['source_release_sha256'] == old['review_sha256']) and (v['config_sha256'] == old['config_sha256']) and (v['manager_epoch_sha256'] == epoch_sha(epoch_encode(old['source118']))) and (v['ordinal'] == ordinal) and epoch_re.fullmatch('[0-9a-f]{32}', v['request_nonce']) and (v['clear_reservation_original'] == res) and (v['clear_reservation_sha256'] == epoch_sha(rows['reserved.json'])) and (0 < v['remaining_seconds'] <= p['duration_seconds']), 'history_original_pulse_source_ordinal_reservation')
        source = v['manager_source']
        epoch_need(set(source) == {'PC_source_files', 'boot_id', 'lease_dev_inode', 'manager_pid', 'manager_start_ticks'} and source['boot_id'] == old['manager_identity']['boot_id'] and (source['manager_pid'] == old['manager_identity']['pid']) and (source['manager_start_ticks'] == old['manager_identity']['start_ticks']) and (source['lease_dev_inode'] == [2096, 69257]) and (set(source['PC_source_files']) == set(old['source118'])), 'history_original_pulse_sole_owner_physical_lease')
        for path, row in source['PC_source_files'].items():
            epoch_need(set(row) == {'sha256', 'stat'} and row['sha256'] == old['source118'][path] and (len(row['stat']) == 9) and (row['stat'][3] == 0) and (row['stat'][6] == 1) and (not row['stat'][5] & 18), 'history_original_all118_source_F9')
        epoch_need(v['budget'] == res['budget'] and v['budget'] == dict(CPU=1, memory_bytes=4294967296, swap_bytes=0, tasks=256, io_read_bytes_per_second=62914560, io_write_bytes_per_second=62914560, runtime_seconds=v['budget']['runtime_seconds']) and (type(v['budget']['runtime_seconds']) is int) and (0 < v['budget']['runtime_seconds'] <= p['duration_seconds']) and all((type(x) in (int, float) and epoch_math.isfinite(x) for x in (v['remaining_seconds'], v['observed_at']))) and (v['remaining_seconds'] <= last_remaining) and (last_time <= v['observed_at'] <= c['finished_at']) and (v['request_nonce'] not in nonces), 'history_original_pulse_budget_time_monotonic_nonce')
        last_time = v['observed_at']
        last_remaining = v['remaining_seconds']
        nonces.add(v['request_nonce'])
    return (rows, i, t)

class epoch_SnapshotReader:

    def __init__(self, snapshot):
        self.rows = snapshot['PC_originals']
        self.used = set()

    def read(self, path, limit=4194304, **kwargs):
        path = str(path)
        epoch_need(path in self.rows, 'history_missing_original_canonical')
        r = self.rows[path]
        epoch_need(r['path'] == path, 'history_original_index_canonical')
        b = epoch_raw(r, [0, 989, 33056, 1])
        epoch_need(len(b) <= limit, 'history_original_cap')
        self.used.add(path)
        return (b, r['F9'])

def epoch_consume_snapshot(snapshot, sources, code_root):
    """Pure validation only; not a callable native grant or caller JSON authority."""
    epoch_need(type(snapshot) is dict and set(snapshot) == {'schema', 'operation', 'actors', 'PC_originals', 'A_receipts', 'qualified_original', 'qualification_completed_original', 'actor_directory_before', 'actor_directory_after', 'A_sources'} and (snapshot['schema'] == epoch_SCHEMA) and (snapshot['operation'] == epoch_OLD_EPOCH['operation']), 'history_exact_snapshot_schema')
    epoch_need(type(snapshot['actors']) is dict and 0 < len(snapshot['actors']) <= 4096 and (snapshot['actor_directory_before'] == snapshot['actor_directory_after'] == sorted(snapshot['actors'])), 'history_exact_complete_cutover_actor_set')
    epoch_need(snapshot['A_sources'] == epoch_OLD_EPOCH['A_source']['sources'], 'history_old_A55_full_source_SHA_F9')
    epoch_qualification(snapshot)
    ctx = epoch_OldContext(sources, code_root)
    terminal = ctx.module('segment_terminal')
    catalog = ctx.module('asset_segments')
    reader = epoch_SnapshotReader(snapshot)
    used = []
    states = {}
    expected_receipts = set()
    for stage, records in sorted(snapshot['actors'].items()):
        rows, intent, t = epoch_actor_chain(stage, records)
        catalog.exact_ranges(intent['plan']['ranges'])
        epoch_need(intent.get('empty_repair') is None, 'history_only_ordinary_old_epoch_not_unreviewed_repair_grant')
        path = epoch_PC_ROOT + '/asset-terminals/' + stage + '.json'
        b, _ = reader.read(path)
        epoch_need(b == rows['terminal.json'], 'history_actual_PCmirror_matches_actor_raw_distinct_F9')
        planpath = epoch_PC_ROOT + '/asset-plans/' + stage + '.json'
        planbytes, planstat = reader.read(planpath)
        epoch_need(intent['plan_ref'] == {'path': planpath, 'sha256': epoch_sha(planbytes), 'F9': planstat} and planbytes == epoch_base64.b64decode(t['plan_original']['raw_b64'], validate=True), 'history_actual_PC_plan_mirror_and_A_origin')
        value = terminal.consume(reader.read, epoch_old_config(), epoch_OLD_EPOCH['old_current']['manager_identity'], stage, t['observed_at'], historical=True)
        epoch_need(epoch_encode(value) == b, 'history_original_full_terminal_consumer')
        epoch_need(value['state'] == t['state'], 'history_no_state_relabel')
        states[stage] = {'state': t['state'], 'terminal_sha256': epoch_sha(b), 'historical_only': True, 'retry_authorized': False}
        for r in intent['plan']['ranges']:
            epoch_need(all((r['digest'] != x['digest'] or max(r['start'], x['start']) >= min(r['start'] + r['count'], x['start'] + x['count']) for x in catalog.APPROVED_LEGACY_REFS)), 'history_original_disjoint_protected_legacy_intervals')
            epoch_need(all((r['digest'] != x['digest'] or max(r['start'], x['start']) >= min(r['start'] + r['count'], x['start'] + x['count']) for x in used)), 'history_no_unreviewed_overlap_or_used_wash')
            used.append(r)
        if t['state'] == 'ASSET_STAGE_COMPLETED':
            result = epoch_strict(epoch_base64.b64decode(t['result_original']['raw_b64'], validate=True))
            for item in result['segments']:
                ref = item['receipt_ref']
                expected_receipts.add(ref['path'])
                row = snapshot['A_receipts'].get(ref['path'])
                epoch_need(row is not None and row['path'] == ref['path'] and (row['F9'] == ref['F9']), 'history_complete_A_success_receipt_origin_F9')
                rr = epoch_raw(row, [0, 0, 33152, 1])
                v = epoch_strict(rr)
                epoch_need(epoch_sha(rr) == ref['sha256'] and v['schema'] == 'fixed-image-immutable-range-segment/v1' and (v['operation_family'] == epoch_OLD_EPOCH['operation']) and (v['stage_operation'] == stage) and (v['source_review_sha256'] == epoch_old_config()['review_sha256']) and (v['plan_sha256'] == t['plan_sha256']) and (v['segment'] == {k: item[k] for k in ('digest', 'start', 'count', 'path', 'sha256', 'F9')}), 'history_success_receipt_full_original_same_plan_segment')
    epoch_need(reader.used == set(snapshot['PC_originals']) and expected_receipts == set(snapshot['A_receipts']), 'history_no_unconsumed_or_missing_originals')
    return {'schema': 'R14B-finite-epoch-historical-only/v1', 'actors': states, 'used': used, 'used_sha256': epoch_sha(epoch_encode(used)), 'historical_only': True, 'retry_authorized': False, 'resource_authorized': False, 'source_activation_authorized': False}

class epoch_Bridge:

    def __init__(self, snapshot, sources, code_root):
        self.snapshot = snapshot
        self.result = epoch_consume_snapshot(snapshot, sources, code_root)

    def require_complete_old_set(self, names, root):
        epoch_need(str(root) == epoch_ACTOR_ROOT and set(self.snapshot['actors']) <= set(names), 'history_original_actor_root_or_cutover_set_omitted')

    def has(self, stage):
        return stage in self.snapshot['actors']

    def consume(self, stage, rows, stats):
        epoch_need(stage in self.snapshot['actors'], 'history_unknown_unbound_old_stage')
        expected = self.snapshot['actors'][stage]
        epoch_need(set(rows) == set(stats) == set(expected), 'history_live_actor_leaf_set_changed')
        for n, r in expected.items():
            epoch_need(rows[n] == epoch_raw(r, [999, 989, 33152, 1]) and stats[n] == r['F9'], 'history_actor_original_changed_after_cutover')
        return epoch_strict(rows['terminal.json'])

def epoch_source_bundle(sources):
    epoch_need(set(sources) == set(epoch_OLD_SOURCE_PINS), 'history_exact_bundle_set')
    return epoch_encode({'schema': 'R14B-old-pure-consumer-closure/v1', 'files': {n: epoch_pack(b) for n, b in sorted(sources.items())}})

def epoch_open_bundle(raw):
    v = epoch_strict(raw)
    epoch_need(set(v) == {'schema', 'files'} and v['schema'] == 'R14B-old-pure-consumer-closure/v1', 'history_exact_bundle_schema')
    return {n: epoch_unpack(p) for n, p in v['files'].items()}

def epoch_load(current_config):
    """Only installed SOURCE-bound Root snapshot + original fixed source closure.
 held_root is stdlib full-FD/named algorithm pasted byte-AST exact below.
 This consumes history and never invokes current_epoch or sets maintenance.
 """
    b = epoch_APPROVED_BINDING
    epoch_need(type(b) is dict and set(b) == {'snapshot', 'source_bundle', 'old_metadata'} and (current_config['review_sha256'] != epoch_old_config()['review_sha256']), 'history_actual_snapshot_None_or_old_review_not_cutover')
    values = {}
    for key in ('snapshot', 'source_bundle'):
        r = b[key]
        data, f = epoch_held_root(epoch_pathlib.Path(r['path']), r['sha256'], mode=288, cap=2097152)
        epoch_need(f == r['F9'] and f[3:7] == [0, 989, 33056, 1], 'history_actual_Root_snapshot_mirror_F9')
        values[key] = data
    sources = epoch_open_bundle(values['source_bundle'])
    epoch_need(set(b['old_metadata']) == {'manifest-original.json', 'config-original.json'}, 'history_complete_fixed_catalog_metadata')
    for n, r in b['old_metadata'].items():
        epoch_need(r['path'] == epoch_PC_ROOT + '/service/' + n and r['sha256'] == epoch_OLD_SOURCE_PINS[n]['sha256'], 'history_fixed_old_catalog_path_SHA')
        data, f = epoch_held_root(epoch_pathlib.Path(r['path']), r['sha256'], mode=288, cap=2097152)
        epoch_need(data == sources[n] and f == r['F9'], 'history_catalog_original_held_F9')
    index = epoch_strict(values['snapshot'])
    epoch_need(set(index) == {'schema', 'snapshot', 'stages'} and index['schema'] == 'R14B-finite-history-Root-index/v1', 'history_Root_exact_index')
    snapshot = dict(index['snapshot'], actors={}, PC_originals={}, A_receipts={})
    stage_data = {}
    for stage, r in index['stages'].items():
        epoch_need(epoch_re.fullmatch('[0-9a-f]{32}', stage) and r['path'] == str(epoch_pathlib.Path(b['snapshot']['path']).parent) + '/stages/' + stage + '.json', 'history_fixed_stage_frame_path')
        data, f = epoch_held_root(r['path'], r['sha256'], mode=288, cap=2097152)
        epoch_need(f == r['F9'] and f[3:7] == [0, 989, 33056, 1], 'history_stage_frame_Root_mirror_fullF9')
        chunk = epoch_expand_stage_frame(stage, data)
        epoch_need(set(chunk) == {'schema', 'stage_operation', 'actor', 'PC_originals', 'A_receipts'} and chunk['schema'] == 'R14B-finite-history-stage-data/v1' and (chunk['stage_operation'] == stage), 'history_stage_frame_exact_schema')
        snapshot['actors'][stage] = chunk['actor']
        for field in ('PC_originals', 'A_receipts'):
            epoch_need(not set(snapshot[field]) & set(chunk[field]), 'history_duplicate_origin_across_frames')
            snapshot[field].update(chunk[field])
        stage_data[stage] = (data, f)
    value = epoch_Bridge(snapshot, sources, epoch_PC_ROOT + '/service')
    for stage, (data, f) in stage_data.items():
        r = index['stages'][stage]
        epoch_need(epoch_held_root(r['path'], r['sha256'], mode=288, cap=2097152) == (data, f), 'history_stage_frame_held_after_consumer')
    for key in ('snapshot', 'source_bundle'):
        r = b[key]
        epoch_need(epoch_held_root(epoch_pathlib.Path(r['path']), r['sha256'], mode=288, cap=2097152) == (values[key], r['F9']), 'history_snapshot_held_after_full_consume')
    for n, r in b['old_metadata'].items():
        data, f = epoch_held_root(epoch_pathlib.Path(r['path']), r['sha256'], mode=288, cap=2097152)
        epoch_need(data == sources[n] and f == r['F9'], 'history_old_metadata_held_after_full_consume')
    return value
epoch_FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def epoch_f9(s):
    return [getattr(s, k) for k in epoch_FIELDS]

def epoch_held_root(path, pin=None, cap=4 * 1024 ** 2, mode=None, *, stat_only=False):
    path = epoch_pathlib.Path(path)
    directories = []
    fd = epoch_os.open('/', epoch_os.O_RDONLY | epoch_os.O_DIRECTORY | epoch_os.O_NOFOLLOW)
    directories.append((fd, epoch_f9(epoch_os.fstat(fd)), None, None))
    leaf = None
    try:
        for part in path.parts[1:-1]:
            new = epoch_os.open(part, epoch_os.O_RDONLY | epoch_os.O_DIRECTORY | epoch_os.O_NOFOLLOW, dir_fd=fd)
            s = epoch_os.fstat(new)
            epoch_need(s.st_uid == 0 and (not s.st_mode & 18) and epoch_stat.S_ISDIR(s.st_mode), 'Root_ancestor_actual_identity')
            directories.append((new, epoch_f9(s), fd, part))
            fd = new
        leaf = epoch_os.open(path.name, epoch_os.O_RDONLY | epoch_os.O_NOFOLLOW, dir_fd=fd)
        before = epoch_os.fstat(leaf)
        epoch_need(epoch_stat.S_ISREG(before.st_mode) and before.st_uid == 0 and (before.st_nlink == 1) and (not before.st_mode & 18) and (stat_only or before.st_size <= cap) and (mode is None or epoch_stat.S_IMODE(before.st_mode) == mode), 'Root_held_leaf')
        epoch_need(not stat_only or pin is None, 'stat_only_must_not_claim_content_SHA')
        raw = b'' if stat_only else epoch_os.pread(leaf, before.st_size + 1, 0)
        epoch_need((stat_only or len(raw) == before.st_size) and epoch_f9(before) == epoch_f9(epoch_os.fstat(leaf)) == epoch_f9(epoch_os.stat(path.name, dir_fd=fd, follow_symlinks=False)) and (pin is None or epoch_sha(raw) == pin), 'Root_leaf_fullSHA_F9_stable')
        for d, before_dir, parent, name in directories:
            current = epoch_f9(epoch_os.fstat(d))
            epoch_need([current[i] for i in (0, 1, 3, 4, 5)] == [before_dir[i] for i in (0, 1, 3, 4, 5)], 'Root_ancestor_held_recheck')
            if parent is not None:
                named = epoch_f9(epoch_os.stat(name, dir_fd=parent, follow_symlinks=False))
                epoch_need([named[i] for i in (0, 1, 3, 4, 5)] == [before_dir[i] for i in (0, 1, 3, 4, 5)], 'Root_ancestor_named_held_binding')
        return (raw, epoch_f9(before))
    finally:
        if leaf is not None:
            epoch_os.close(leaf)
        for d, *_ in reversed(directories):
            epoch_os.close(d)
epoch_APPROVED_CAPTURE_REQUEST = None

def epoch_capture_PC(sources):
    """Future Root readonly entry. Actual invocation/request remains None here.
 No unit queries, writes, kernel/SQL access, grants, or Runtime construction.
 """
    epoch_need(type(epoch_APPROVED_CAPTURE_REQUEST) is dict and epoch_os.getuid() == epoch_os.geteuid() == 0, 'history_capture_actual_request_None_Root_only')
    ctx = epoch_OldContext(sources, epoch_PC_ROOT + '/service')
    io = ctx.module('actor_io')
    common = ctx.module('B_OWNER_RECOVERY_R25_WIRING.common')
    root = epoch_pathlib.Path(epoch_ACTOR_ROOT)
    first = sorted((p.name for p in root.iterdir()))
    epoch_need(0 < len(first) <= 4096, 'history_bounded_actual_complete_epoch')
    actors = {}
    PC = {}
    for stage in first:
        directory = root / stage
        before = {p.name: common.metadata(p.lstat()) for p in directory.iterdir()}
        rows = io.stage_originals(root, stage)
        after = {p.name: common.metadata(p.lstat()) for p in directory.iterdir()}
        epoch_need(before == after and set(rows) == set(before), 'history_capture_actor_complete_F9')
        records = {n: epoch_original(b, before[n], str(directory / n)) for n, b in rows.items()}
        epoch_actor_chain(stage, records)
        actors[stage] = records
        for path in [epoch_PC_ROOT + '/asset-terminals/' + stage + '.json', epoch_PC_ROOT + '/asset-plans/' + stage + '.json'] + [epoch_PC_ROOT + '/asset-terminal-clocks/' + stage + '/' + n for n in ('send.json', 'send-moment.json', 'received.json')]:
            raw, f = epoch_held_root(path, None, mode=288, cap=4194304)
            epoch_need(f[3:7] == [0, 989, 33056, 1], 'history_capture_PC_Root_shared_origin')
            PC[path] = epoch_original(raw, f, path)
    second = sorted((p.name for p in root.iterdir()))
    epoch_need(first == second, 'history_capture_no_actor_set_race')
    out = {'schema': epoch_SCHEMA, 'operation': epoch_OLD_EPOCH['operation'], 'actors': actors, 'PC_originals': PC, 'A_receipts': {}, 'A_sources': {}, 'actor_directory_before': first, 'actor_directory_after': second}
    for key in ('qualified_original', 'qualification_completed_original'):
        ref = epoch_OLD_EPOCH[key]
        raw, f = epoch_held_root(ref['path'], ref['sha256'], mode=288, cap=2097152)
        epoch_need(f == ref['F9'], 'history_capture_actual_old_qualification_original')
        out[key] = epoch_original(raw, f, ref['path'])
    return out

def epoch_capture_A(pc_snapshot):
    """Future independent Root-A readonly FD entry; payload bodies are never read.
 Parent delivers the exact protected PC request. CPU never calls native.
 """
    epoch_need(type(epoch_APPROVED_CAPTURE_REQUEST) is dict and epoch_os.getuid() == epoch_os.geteuid() == 0 and (epoch_sha(epoch_encode(pc_snapshot)) == epoch_APPROVED_CAPTURE_REQUEST['PC_snapshot_sha256']), 'history_A_fixed_received_PC_request_None')
    p = epoch_OLD_EPOCH['A_source']
    sources = {}
    for n, row in p['sources'].items():
        b, f = epoch_held_root(p['source_root'] + '/' + n, row['sha256'], mode=384, cap=2097152)
        epoch_need(f == row['F9'], 'history_A_old_source55_fullF9')
        sources[n] = {'sha256': epoch_sha(b), 'F9': f}
    receipts = {}
    for stage, records in pc_snapshot['actors'].items():
        _, _, t = epoch_actor_chain(stage, records)
        planpath = p['source_root'] + '/stages/' + stage + '/plan.json'
        pr, pf = epoch_held_root(planpath, t['plan_sha256'], mode=384, cap=2097152)
        epoch_need(pr == epoch_base64.b64decode(t['plan_original']['raw_b64'], validate=True) and pf == t['plan_original']['stat'], 'history_A_actual_plan_original')
        if t['state'] == 'ASSET_STAGE_COMPLETED':
            result = epoch_strict(epoch_base64.b64decode(t['result_original']['raw_b64'], validate=True))
            for item in result['segments']:
                ref = item['receipt_ref']
                expected = p['data_root'] + '/stages/' + stage + '/range/segments/' + item['digest'] + '.' + str(item['start']) + '-' + str(item['start'] + item['count'] - 1) + '.segment'
                epoch_need(item['path'] == expected and ref['path'] == expected + '.json', 'history_A_only_fixed_receipt_paths')
                rr, rf = epoch_held_root(ref['path'], ref['sha256'], mode=384, cap=2097152)
                epoch_need(rf == ref['F9'], 'history_A_receipt_actual_F9')
                _, payloadF9 = epoch_held_root(expected, None, mode=384, stat_only=True)
                epoch_need(payloadF9 == item['F9'], 'history_A_success_payload_metadata_only')
                receipts[ref['path']] = epoch_original(rr, rf, ref['path'])
    return {'A_sources': sources, 'A_receipts': receipts}

def epoch_assemble(pc_snapshot, A_capture, sources):
    """Pure producer→consumer seam; result is SOURCE data until Root-sealed/pinned."""
    v = dict(pc_snapshot, **A_capture)
    result = epoch_consume_snapshot(v, sources, epoch_PC_ROOT + '/service')
    frames = epoch_storage_plan(v)
    return {'stage_frames': frames, 'result': result, 'actual_binding': None, 'native_eligible': False}

def epoch_storage_plan(snapshot):
    """v2 exact one-field payload dedup; origin metadata stays distinct.
 No caps raised, no generic pointer/cross-stage/reference authority.
 """
    frames = {}
    for stage, actor in snapshot['actors'].items():
        pc = {p: r for p, r in snapshot['PC_originals'].items() if p in (epoch_PC_ROOT + '/asset-terminals/' + stage + '.json', epoch_PC_ROOT + '/asset-plans/' + stage + '.json') or p.startswith(epoch_PC_ROOT + '/asset-terminal-clocks/' + stage + '/')}
        a = {p: r for p, r in snapshot['A_receipts'].items() if '/stages/' + stage + '/' in p}
        path = epoch_PC_ROOT + '/asset-terminals/' + stage + '.json'
        target = pc[path]
        origin = actor['terminal.json']
        ar = epoch_raw(origin, [999, 989, 33152, 1])
        pr = epoch_raw(target, [0, 989, 33056, 1])
        epoch_need(pr == ar and target['packed'] == origin['packed'], 'history_v2_proven_same_lossless_terminal_payload')
        pc[path] = {'path': target['path'], 'F9': target['F9'], 'payload_ref': {'schema': 'same-stage-actor-terminal-payload/v1', 'actor_leaf': 'terminal.json', 'bytes': len(pr), 'sha256': epoch_sha(pr)}}
        chunk = {'schema': 'R14B-finite-history-stage-data/v2', 'stage_operation': stage, 'actor': actor, 'PC_originals': pc, 'A_receipts': a}
        data = epoch_encode(epoch_pack(epoch_encode(chunk)))
        epoch_need(len(data) <= 2097152, 'history_stage_data_leaf2MiB')
        frames[stage] = data
    epoch_need(set().union(*(set(epoch_strict(epoch_unpack(epoch_strict(data)))['PC_originals']) for data in frames.values())) == set(snapshot['PC_originals']), 'history_storage_no_omitted_PC_original')
    return frames

def epoch_expand_stage_frame(stage, data):
    chunk = epoch_strict(epoch_unpack(epoch_strict(data)))
    epoch_need(set(chunk) == {'schema', 'stage_operation', 'actor', 'PC_originals', 'A_receipts'} and chunk['schema'] == 'R14B-finite-history-stage-data/v2' and (chunk['stage_operation'] == stage), 'history_stage_v2_exact_schema_stage')
    path = epoch_PC_ROOT + '/asset-terminals/' + stage + '.json'
    r = chunk['PC_originals'][path]
    a = chunk['actor']['terminal.json']
    epoch_need(set(r) == {'path', 'F9', 'payload_ref'} and r['path'] == path and (a['path'] == epoch_ACTOR_ROOT + '/' + stage + '/terminal.json'), 'history_v2_only_fixed_same_stage_PC_actor_pair')
    raw = epoch_raw(a, [999, 989, 33152, 1])
    ref = r['payload_ref']
    epoch_need(ref == {'schema': 'same-stage-actor-terminal-payload/v1', 'actor_leaf': 'terminal.json', 'bytes': len(raw), 'sha256': epoch_sha(raw)}, 'history_v2_exact_payload_ref_SHA_bytes')
    chunk['PC_originals'][path] = {'path': r['path'], 'F9': r['F9'], 'packed': a['packed']}
    epoch_need(epoch_raw(chunk['PC_originals'][path], [0, 989, 33056, 1]) == raw, 'history_v2_PC_origin_F9_distinct_fullraw')
    chunk['schema'] = 'R14B-finite-history-stage-data/v1'
    return chunk

def epoch_finalize_index(snapshot, index_path, stage_refs):
    frames = epoch_storage_plan(snapshot)
    epoch_need(set(stage_refs) == set(frames), 'history_actual_all_stage_data_refs')
    parent = str(epoch_pathlib.Path(index_path).parent)
    for stage, row in stage_refs.items():
        epoch_need(row['path'] == parent + '/stages/' + stage + '.json' and row['sha256'] == epoch_sha(frames[stage]) and (row['F9'][2] == len(frames[stage])) and (row['F9'][3:7] == [0, 989, 33056, 1]), 'history_actual_stage_data_Root_ref')
    base = {k: v for k, v in snapshot.items() if k not in ('actors', 'PC_originals', 'A_receipts')}
    raw = epoch_encode({'schema': 'R14B-finite-history-Root-index/v1', 'snapshot': base, 'stages': stage_refs})
    epoch_need(len(raw) <= 2097152, 'history_Root_index2MiB')
    return raw
load = epoch_load
ACTUAL_BINDING = None
NATIVE_ELIGIBLE = False

def old_domain_from_snapshot(snapshot, sources):
    """Pure SOURCE: descriptor may be bound only after full old consumers pass.
 No caller result/bool accepted; recompute qualification/ordinal/clock/receipts.
 """
    result = epoch_consume_snapshot(snapshot, sources, epoch_PC_ROOT + '/service')
    out = {k: epoch_OLD_EPOCH[k] for k in ('operation', 'old_current', 'A_source', 'qualified_original', 'qualification_completed_original', 'qualification_summary')}
    out.update(schema='R14B-sealed-old-domain/v1', snapshot_sha256=epoch_sha(epoch_encode(snapshot)), snapshot_result=result, actors={})
    for stage, records in snapshot['actors'].items():
        rows, i, t = epoch_actor_chain(stage, records)
        out['actors'][stage] = {'state': t['state'], 'original_refs': {n: {'path': r['path'], 'sha256': epoch_sha(rows[n]), 'F9': r['F9']} for n, r in records.items()}, 'terminal_sha256': epoch_sha(rows['terminal.json']), 'completed_sha256': epoch_sha(rows['completed.json']), 'fence_sha256': epoch_sha(rows['fence-released.json']), 'ranges': i['plan']['ranges'], 'manager_identity': t['manager_identity'], 'failed_pid': int(t['scope']['unit']['ExecMainPID']), 'A_boot_id': t['scope']['boot_id'], 'unit': t['scope']['unit']['Id'], 'source_index_sha256': t['source_index_sha256']}
    return epoch_strict(epoch_encode(out))
import builtins as owner_builtins, hashlib as owner_hashlib, sys as owner_sys, types as owner_types

class owner_Refused(ValueError):
    pass

def owner_need(v, r):
    if not v:
        raise owner_Refused(r)

def owner_sha(b):
    return owner_hashlib.sha256(b).hexdigest()

class owner_Context:

    def __init__(self, refs, read):
        owner_need(type(refs) is dict and 1 <= len(refs) <= 96, 'owner_history_closed_source_table')
        self.loaded = {}
        self.sources = {}
        self.refs = refs
        self.read = read
        for name, ref in refs.items():
            owner_need((name.endswith('.py') or name in ('config-original.json', 'manifest-original.json')) and '/' not in name and (set(ref) == {'path', 'sha256', 'F9'}), 'owner_history_exact_source_descriptor')
            raw, st = read(ref['path'], limit=2097152)
            owner_need(st == ref['F9'] and st[3] == 0 and (st[6] == 1) and (not st[5] & 18) and (owner_sha(raw) == ref['sha256']), 'owner_history_held_source_SHA_F9')
            self.sources[name] = raw

    def imports(self, name, gl=None, lo=None, fromlist=(), level=0):
        if level == 1 and gl and (gl.get('__package__') == 'B_OWNER_RECOVERY_R25_WIRING'):
            owner_need(name in ('common', 'collector') and 'B_OWNER_RECOVERY_R25_WIRING.' + name + '.py' in self.sources, 'owner_history_closed_relative_import')
            return self.module('B_OWNER_RECOVERY_R25_WIRING.' + name)
        if not level and name + '.py' in self.sources:
            return self.module(name)
        if not level and name == 'B_OWNER_RECOVERY_R25_WIRING':
            m = owner_types.ModuleType(name)
            m.__path__ = []
            for child in fromlist or ('common',):
                owner_need(child in ('common', 'collector'), 'owner_history_closed_external_member')
                setattr(m, child, self.module(name + '.' + child))
            return m
        owner_need(not level and name.split('.')[0] in owner_sys.stdlib_module_names, 'owner_history_no_ambient_import')
        return owner_builtins.__import__(name, gl, lo, fromlist, level)

    def module(self, name):
        if name in self.loaded:
            return self.loaded[name]
        key = name + '.py'
        owner_need(key in self.sources, 'owner_history_unknown_source')
        private = '_owner_terminal_history_' + str(id(self)) + '_' + name.replace('.', '_')
        m = owner_types.ModuleType(private)
        m.__file__ = self.refs[key]['path']
        m.__package__ = 'B_OWNER_RECOVERY_R25_WIRING' if name.startswith('B_OWNER_RECOVERY_R25_WIRING.') else ''
        m.__dict__['__builtins__'] = dict(vars(owner_builtins), __import__=self.imports)
        self.loaded[name] = m
        missing = object()
        before = owner_sys.modules.get(private, missing)
        owner_sys.modules[private] = m
        try:
            exec(compile(self.sources[key], m.__file__, 'exec'), m.__dict__)
        except BaseException:
            self.loaded.pop(name, None)
            raise
        finally:
            if before is missing:
                owner_sys.modules.pop(private, None)
            else:
                owner_sys.modules[private] = before
        return m

    def recheck(self):
        for name, ref in self.refs.items():
            raw, st = self.read(ref['path'], limit=2097152)
            owner_need(raw == self.sources[name] and st == ref['F9'], 'owner_history_source_after_consume')
'One source-bound failed owner continuation. No work/retry/old-clock renewal.\nTo co-locate with history_reader in a future reviewed source epoch. No action\nis authorized by this unbound component; approved policy is deliberately None.\n'
import base64 as owner_base64, hashlib as owner_hashlib, json as owner_json, math as owner_math, re as owner_re
from pathlib import Path as owner_Path
owner_APPROVED_POLICY = None
owner_FAILED = 'FAILED_REGISTRY_QUIESCENT'

class owner_Refused(ValueError):
    pass

def owner_need(v, r):
    if not v:
        raise owner_Refused(r)

def owner_sha(b):
    return owner_hashlib.sha256(b).hexdigest()

def owner_encode(v):
    return (owner_json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def owner_strict(raw):

    def pairs(rows):
        d = {}
        for k, v in rows:
            owner_need(k not in d, 'owner_duplicate_key')
            d[k] = v
        return d
    return owner_json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: owner_need(False, 'owner_nonfinite'))

def owner_number(x):
    return type(x) in (int, float) and owner_math.isfinite(x)

def owner_held(read, ref, owner, cap=4194304):
    owner_need(type(ref) is dict and set(ref) == {'path', 'sha256', 'F9'}, 'owner_exact_original_reference')
    raw, st = read(ref['path'], limit=cap)
    owner_need(type(st) is list and len(st) == 9 and (st == ref['F9']) and (st[2] == len(raw)) and (st[3:7] == owner) and (owner_sha(raw) == ref['sha256']), 'owner_full_original_raw_SHA_F9')
    return raw

def owner_policy():
    p = owner_APPROVED_POLICY
    owner_need(type(p) is dict and set(p) == {'stage', 'old_config', 'old_identity', 'old_sources', 'old_records', 'old_plan', 'old_terminal', 'old_clocks', 'old_A_sources', 'new_review', 'permit_path', 'qualified_path', 'probe_unit', 'probe_worker_sha', 'probe_operation', 'old_completed', 'old_worker', 'probe_nonce', 'activation_root'}, 'owner_recovery_SOURCE_None')
    owner_need(owner_re.fullmatch('[0-9a-f]{32}', p['stage']) and type(p['new_review']) is str and owner_re.fullmatch('[0-9a-f]{64}', p['new_review']) and (p['new_review'] != p['old_config']['review_sha256']) and (type(p['old_completed']) is dict), 'owner_new_source_epoch_not_old_once')
    owner_need(all((type(p[k]) is str and p[k].startswith('/') for k in ('permit_path', 'qualified_path'))) and type(p['probe_worker_sha']) is str and owner_re.fullmatch('[0-9a-f]{64}', p['probe_worker_sha']) and owner_re.fullmatch('[0-9a-f]{32}', p['probe_operation']) and (type(p['old_A_sources']) is dict) and (len(p['old_A_sources']) == 55) and owner_re.fullmatch('[0-9a-f]{32}', p['probe_nonce']) and (type(p['old_worker']) is dict), 'owner_fresh_SOURCE_slots_None')
    return p

def owner_old_terminal(read, p):
    """Full ORIGINAL consumer at ORIGINAL event; returns history only, no release."""
    raw = owner_held(read, p['old_terminal'], [0, 989, 33056, 1])
    v = owner_strict(raw)
    for ref in p['old_clocks'].values():
        owner_held(read, ref, [0, 989, 33056, 1])
    owner_need(set(p['old_clocks']) == {'send.json', 'send-moment.json', 'received.json'}, 'owner_all_three_old_clock_originals')
    ctx = owner_Context(p['old_sources'], read)
    try:
        t = ctx.module('segment_terminal').consume(read, p['old_config'], p['old_identity'], p['stage'], v['observed_at'], historical=True)
        owner_need(owner_encode(t) == raw and t['state'] == owner_FAILED and (t['manager_identity'] == p['old_identity']), 'owner_only_complete_old_failed_terminal')
        return t
    finally:
        ctx.recheck()

def owner_pending(read, rows, stats, p=None):
    """Constructor consumer: preserve incomplete actor, not old live PID/window."""
    p = owner_policy() if p is None else p
    owner_need(set(rows) == set(stats) == set(p['old_records']), 'owner_exact_pending_actor_entries')
    for name, ref in p['old_records'].items():
        owner_need(type(rows[name]) is bytes and owner_sha(rows[name]) == ref['sha256'] and (stats[name] == ref['F9']) and (stats[name][2] == len(rows[name])) and (stats[name][3:7] == [999, 989, 33152, 1]), 'owner_pending_actor_originals_unchanged')
    base = {'intent.json', 'reserved.json'}
    ordinals = []
    for n in set(rows) - base:
        m = owner_re.fullmatch('pulse-([1-9][0-9]{0,3})\\.json', n)
        owner_need(m is not None, 'owner_pending_no_completion_or_unknown_leaf')
        ordinals.append(int(m[1]))
    owner_need(base <= set(rows) and sorted(ordinals) == list(range(1, len(ordinals) + 1)) and ordinals, 'owner_pending_all_original_pulse_ordinals')
    i, res = (owner_strict(rows[n]) for n in ('intent.json', 'reserved.json'))
    planraw = owner_held(read, p['old_plan'], [0, 989, 33056, 1])
    plan = owner_strict(planraw)
    t = owner_old_terminal(read, p)
    owner_need(i['schema'] == 'fixed-image-finite-stage-intent/v1' and i['stage_operation'] == res['stage_operation'] == plan['stage_operation'] == p['stage'] and (i['plan'] == plan) and (i['plan_ref'] == res['plan_ref'] == p['old_plan']) and (i['deadline_monotonic'] == res['deadline_monotonic'] == plan['PC_plan_deadline_monotonic']) and (i['automatic_retry'] is False), 'owner_original_plan_reservation_deadline')
    owner_need(i['source_release_sha256'] == p['old_config']['review_sha256'] and i['operation_family'] == plan['operation_family'] == t['operation_family'] and (plan['manager_identity'] == p['old_identity']) and (plan['config_sha256'] == p['old_config']['_config_sha256']) and (plan['source118_sha256'] == owner_sha(owner_encode(p['old_config']['PC_source_pins']))) and (owner_sha(planraw) == t['plan_sha256']), 'owner_old_domain_exact_not_new_current')
    prior = res['observed_at']
    remaining = plan['duration_seconds']
    nonces = set()
    for n in sorted(ordinals):
        pulse = owner_strict(rows['pulse-' + str(n) + '.json'])
        source = pulse['manager_source']
        owner_need(pulse['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and pulse['ordinal'] == n and (pulse['operation'] == i['operation_family']) and (pulse['source_release_sha256'] == i['source_release_sha256']) and (pulse['config_sha256'] == plan['config_sha256']) and (pulse['manager_epoch_sha256'] == owner_sha(owner_encode(p['old_config']['PC_source_pins']))) and (pulse['clear_reservation_original'] == res) and (pulse['clear_reservation_sha256'] == owner_sha(rows['reserved.json'])), 'owner_pending_pulse_complete_source_reservation')
        owner_need(source['manager_pid'] == p['old_identity']['pid'] and source['manager_start_ticks'] == p['old_identity']['start_ticks'] and (source['boot_id'] == p['old_identity']['boot_id']) and (source['lease_dev_inode'] == [2096, 69257]) and (set(source['PC_source_files']) == set(p['old_config']['PC_source_pins'])), 'owner_pending_original_sole_lease')
        for path, pin in p['old_config']['PC_source_pins'].items():
            r = source['PC_source_files'][path]
            f = r['stat']
            owner_need(r['sha256'] == pin and len(f) == 9 and (f[3] == 0) and (f[6] == 1) and (not f[5] & 18), 'owner_pending_all118_original_source')
        owner_need(pulse['budget'] == res['budget'] and 0 < pulse['remaining_seconds'] <= remaining and (prior <= pulse['observed_at'] <= t['observed_at']) and owner_re.fullmatch('[0-9a-f]{32}', pulse['request_nonce']) and (pulse['request_nonce'] not in nonces), 'owner_pending_original_budget_nonce_time')
        prior = pulse['observed_at']
        remaining = pulse['remaining_seconds']
        nonces.add(pulse['request_nonce'])
    context = owner_strict(owner_base64.b64decode(t['context_original']['raw_b64'], validate=True))
    first = context['initial_pulse_original']
    b = owner_base64.b64decode(first['original_raw_b64'], validate=True)
    pulse = owner_strict(b)
    owner_need(owner_sha(b) == first['original_sha256'] and rows.get('pulse-' + str(pulse['ordinal']) + '.json') == b and (pulse['clear_reservation_original'] == res), 'owner_pending_terminal_context_owned_pulse')
    return {'schema': 'failed-owner-terminal-pending/v1', 'stage_operation': p['stage'], 'terminal_sha256': owner_sha(owner_encode(t)), 'actor_refs': p['old_records'], 'plan_original': p['old_plan'], 'original_deadline_monotonic': i['deadline_monotonic'], 'ranges': plan['ranges'], 'old_identity': p['old_identity'], 'work_may_resume': False, 'original_terminal': t}

def owner_fresh(read, p, g, pend, body, now, *, historical=False, event=None):
    """New finite release eligibility, independent of preserved terminal clock.
 All Root dynamic records are full protected originals, not caller booleans.
 """
    raw, st = read(p['permit_path'], limit=2097152)
    permit = owner_strict(raw)
    owner_need(st[3:7] == [0, 989, 33056, 1] and st[2] == len(raw), 'owner_permit_Root_full_origin')
    owner_need(set(permit) == {'schema', 'operation', 'nonce', 'stage_operation', 'new_current', 'old_terminal', 'old_records', 'old_plan', 'PC_issued_at', 'PC_monotonic_origin', 'PC_deadline_monotonic', 'duration_seconds', 'automatic_retry'} and permit['schema'] == 'failed-owner-terminal-release-permit/v1' and (permit['stage_operation'] == p['stage']) and (permit['operation'] == p['probe_operation']) and owner_re.fullmatch('[0-9a-f]{32}', permit['nonce']) and (permit['automatic_retry'] is False) and (permit['nonce'] == p['probe_nonce']), 'owner_exact_finite_Root_permit')
    owner_need(permit['old_terminal'] == p['old_terminal'] and permit['old_records'] == p['old_records'] and (permit['old_plan'] == p['old_plan']), 'owner_permit_full_immutable_old_binding')
    owner_need(all((owner_number(permit[k]) for k in ('PC_issued_at', 'PC_monotonic_origin', 'PC_deadline_monotonic'))) and type(permit['duration_seconds']) is int and (1 <= permit['duration_seconds'] <= 120) and (permit['PC_deadline_monotonic'] == permit['PC_monotonic_origin'] + permit['duration_seconds']), 'owner_finite_release_not_work_window')
    current = permit['new_current']
    owner_need(set(current) == {'manager_identity', 'config_sha256', 'source118', 'review_sha256'} and current['review_sha256'] == p['new_review'], 'owner_exact_new_source_current')
    owner_need(historical or (current['config_sha256'] == g.config['_config_sha256'] and current['source118'] == g.config['PC_source_pins'] and (current['review_sha256'] == g.config['review_sha256']) and (current['manager_identity'] == __import__('asset_stage', fromlist=['identity']).identity()) and (0 <= now - permit['PC_issued_at'] <= permit['duration_seconds']) and (permit['PC_monotonic_origin'] <= g.clock() < permit['PC_deadline_monotonic'])), 'owner_current_newsole_finite_PC_domain')
    qraw, qs = read(p['qualified_path'], limit=4194304)
    q = owner_strict(qraw)
    owner_need(qs[3:7] == [0, 989, 33056, 1] and qs[2] == len(qraw) and (set(q) == {'schema', 'permit_original', 'request_original', 'send_moment_original', 'received_original', 'A_original', 'scope'}) and (q['schema'] == 'failed-owner-terminal-fresh-qualified/v1'), 'owner_qualified_full_Root_origin')
    pr = {'path': p['permit_path'], 'sha256': owner_sha(raw), 'F9': st}
    owner_need(q['permit_original'] == pr, 'owner_qualified_exact_permit_F9')
    objects = []
    for name in ('request_original', 'send_moment_original', 'received_original'):
        r = q[name]
        objects.append(owner_strict(owner_held(read, r, [0, 989, 33056, 1], 2097152)))
    request, moment, received = objects
    owner_need(set(request) == {'schema', 'nonce', 'stage_operation', 'permit_original', 'new_current', 'old_terminal_sha256'} and request == {'schema': 'failed-owner-terminal-PC-request/v1', 'nonce': permit['nonce'], 'stage_operation': p['stage'], 'permit_original': pr, 'new_current': current, 'old_terminal_sha256': pend['terminal_sha256']}, 'owner_new_paired_request_exact')
    owner_need(set(moment) == {'schema', 'request_original', 'PC_sent_at', 'PC_monotonic_sent'} and moment['schema'] == 'failed-owner-terminal-PC-send/v1' and (moment['request_original'] == q['request_original']) and owner_number(moment['PC_sent_at']) and owner_number(moment['PC_monotonic_sent']), 'owner_real_new_PC_send')
    owner_checked_A(read, p, pend, request, q)
    owner_need(set(received) == {'schema', 'request_original', 'A_original', 'scope_sha256', 'PC_received_at', 'PC_monotonic_elapsed'} and received['schema'] == 'failed-owner-terminal-PC-received/v1' and (received['request_original'] == q['request_original']) and (received['A_original'] == q['A_original']) and (received['scope_sha256'] == owner_sha(owner_encode(q['scope']))) and all((owner_number(received[k]) for k in ('PC_received_at', 'PC_monotonic_elapsed'))) and (0 <= received['PC_monotonic_elapsed'] <= 30) and (0 <= received['PC_received_at'] - moment['PC_sent_at'] <= 30) and (abs(received['PC_received_at'] - moment['PC_sent_at'] - received['PC_monotonic_elapsed']) <= 5), 'owner_new_PC_whole30_original')
    now = now if historical else g.runtime.manager._now()
    owner_need(historical or (permit['PC_monotonic_origin'] <= g.clock() < permit['PC_deadline_monotonic'] and 0 <= now - permit['PC_issued_at'] <= permit['duration_seconds'] and (0 <= now - received['PC_received_at']) and (received['PC_monotonic_elapsed'] + now - received['PC_received_at'] <= 30)), 'owner_release_new_PC_final_whole30')
    result = {'schema': 'failed-owner-terminal-release-eligibility/v1', 'stage_operation': p['stage'], 'old_terminal_sha256': pend['terminal_sha256'], 'permit_original': pr, 'qualified_original': {'path': p['qualified_path'], 'sha256': owner_sha(qraw), 'F9': qs}, 'new_current': current, 'PC_release_clock': {'received_at': received['PC_received_at'], 'elapsed': received['PC_monotonic_elapsed'], 'permit_wall': permit['PC_issued_at'], 'permit_seconds': permit['duration_seconds'], 'permit_monotonic_origin': permit['PC_monotonic_origin'], 'permit_monotonic_deadline': permit['PC_deadline_monotonic']}, 'activation_request_nonce': body['request_nonce'] if not historical else event['activation_request_nonce'], 'original_deadline_monotonic': pend['original_deadline_monotonic'], 'work_may_resume': False, 'observed_at': now}
    if historical:
        owner_need(event == result, 'owner_historical_exact_completion_event_not_current_permission')
    return result

def owner_actor_snapshot(stages, stage):
    p = owner_policy()
    context = owner_Context(p['old_sources'], stages.read)
    try:
        records = context.module('current_prebind').actor_records(stages, stage)
    finally:
        context.recheck()
    rows = {}
    stats = {}
    for name, r in records.items():
        raw = owner_base64.b64decode(r['raw_b64'], validate=True)
        owner_need(owner_sha(raw) == r['sha256'] and r['F9'][2] == len(raw), 'owner_actual_actor_snapshot_SHA')
        rows[name] = raw
        stats[name] = r['F9']
    return (rows, stats)

def owner_initialise(stages):
    p = owner_policy()
    stage = p['stage']
    folder = stages.root / stage
    if not folder.exists():
        owner_need(False, 'owner_expected_pending_actor_missing')
    rows, stats = owner_actor_snapshot(stages, stage)
    owner_need(not {'terminal.json', 'completed.json', 'fence-released.json'} & set(rows), 'owner_initial_pending_not_partial_commit')
    value = owner_pending(stages.read, rows, stats, p)
    stages.failed_owner_pending = value
    stages.used.extend(value['ranges'])
    stages.g.s.restore_operator_block()
    stages.closed = True
    return stage

def owner_history(stages, stage, rows):
    p = owner_policy()
    owner_need(stage == p['stage'], 'owner_history_exact_stage')
    c = owner_strict(rows['completed.json'])
    f = owner_strict(rows['fence-released.json'])
    owner_need(set(c) == {'schema', 'stage_operation', 'state', 'terminal_sha256', 'current', 'original_deadline_monotonic', 'work_deadline_extended', 'image_imported', 'CPU_success', 'models_started', 'finished_at', 'owner_recovery'} and c['schema'] == 'fixed-image-finite-stage-owner-recovered/v1', 'owner_complete_recovery_schema')
    actual, actual_stats = owner_actor_snapshot(stages, stage)
    owner_need(actual == rows, 'owner_recovered_actual_actor_bytes_before')
    original = {n: raw for n, raw in rows.items() if n not in ('terminal.json', 'completed.json', 'fence-released.json')}
    stats = {n: actual_stats[n] for n in original}
    pend = owner_pending(stages.read, original, stats, p)
    owner_need(rows['terminal.json'] == owner_encode(pend['original_terminal']) and c['terminal_sha256'] == owner_sha(rows['terminal.json']) and (c['state'] == owner_FAILED) and (c['stage_operation'] == stage) and (c['original_deadline_monotonic'] == pend['original_deadline_monotonic']) and (c['work_deadline_extended'] is c['image_imported'] is c['CPU_success'] is False) and (type(c['models_started']) is int) and (c['models_started'] == 0) and (f['stage_operation'] == stage) and (f['completed_sha256'] == owner_sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (c['finished_at'] <= f['observed_at']), 'owner_recovered_failed_complete_fence_not_success')
    result = owner_fresh(stages.read, p, stages.g, pend, None, c['owner_recovery']['observed_at'], historical=True, event=c['owner_recovery'])
    owner_need(result['observed_at'] <= c['finished_at'], 'owner_event_precedes_actual_finish')
    a = c['owner_recovery']['new_current']['manager_identity']['invocation_id']
    root = owner_Path(p['activation_root']) / a
    source_records, source_stats = owner_activation_records(root)
    owner_need(set(source_records) == {'intent.json', 'completed.json', 'fence-released.json'}, 'owner_complete_source_activation_entries')
    ir, dr, fr = (source_records[n] for n in ('intent.json', 'completed.json', 'fence-released.json'))
    intent, done, mark = map(owner_strict, (ir, dr, fr))
    owner_need(intent['owner_recovery'] == result and done['owner_recovery'] == result and (done['state'] == 'SOURCE_EPOCH_READY') and (mark['completed_sha256'] == owner_sha(dr)) and (mark['operator_maintenance_observed'] is False) and (done['observed_at'] <= mark['observed_at']), 'owner_complete_source_activation_fence_chain')
    source_last, source_last_stats = owner_activation_records(root)
    owner_need(source_last == source_records and source_last_stats == source_stats, 'owner_source_activation_fullF9_after_history')
    last, last_stats = owner_actor_snapshot(stages, stage)
    owner_need(last == actual and last_stats == actual_stats, 'owner_recovered_actor_fullF9_after_history')
    stages.used.extend(pend['ranges'])
    return pend['original_terminal']

def owner_activate(recovery, body):
    """Caller already owns original g.lock; one source activation, one fence exit."""
    p = owner_policy()
    g = recovery.g
    stages = g.asset_stages
    pend = stages.failed_owner_pending
    g.current_epoch()
    owner_need(g.lock.locked() and pend is not None and (stages.active is None) and stages.closed and (not stages.legacy_pending) and (not g.active) and (g.deadline is None) and (not recovery.released) and g.operator.negative_cpu_release.pending, 'owner_source_pending_sole_lock')
    source, prior, legacy = recovery.owner_source_context(body)
    from asset_stage import stage_originals
    from B_OWNER_RECOVERY_R25_WIRING.common import exclusive, metadata
    with g.facade._lifecycle_lock:
        g.live_baseline = None
        proof = g.current('failed-owner-source-activation', fenced=True)
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            g.same()
            g.current_epoch()
            rows, stats = owner_actor_snapshot(stages, p['stage'])
            owner_need(owner_pending(stages.read, rows, stats, p) == pend, 'owner_pending_unchanged_before_commit')
            eligibility = owner_fresh(stages.read, p, g, pend, body, g.runtime.manager._now())
            recovery.owner_recheck_source(source, prior, legacy)
            last = owner_fresh(stages.read, p, g, pend, body, g.runtime.manager._now())
            owner_need({k: v for k, v in last.items() if k != 'observed_at'} == {k: v for k, v in eligibility.items() if k != 'observed_at'}, 'owner_same_eligibility_before_first_write')
            recovery.owner_create_root()
            commit_started = owner_final_clock(eligibility, g)
            activation_intent = {'schema': 'asset-source-owner-recovery-intent/v1', 'release_commit_started_at': commit_started, 'request': body, 'qualification': source, 'prior': prior, 'legacy_original': legacy, 'owner_recovery': eligibility, 'current': proof, 'observed_at': g.runtime.manager._now(), 'automatic_retry': False}
            exclusive(recovery.root / 'intent.json', activation_intent)
            try:
                folder = stages.root / p['stage']
                exclusive(folder / 'terminal.json', pend['original_terminal'])
                completion = {'schema': 'fixed-image-finite-stage-owner-recovered/v1', 'stage_operation': p['stage'], 'state': owner_FAILED, 'terminal_sha256': pend['terminal_sha256'], 'current': proof, 'original_deadline_monotonic': pend['original_deadline_monotonic'], 'work_deadline_extended': False, 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'finished_at': g.runtime.manager._now(), 'owner_recovery': eligibility}
                exclusive(folder / 'completed.json', completion)
                activation = {'schema': 'asset-source-owner-recovery-completed/v1', 'state': 'SOURCE_EPOCH_READY', 'owner_recovery': eligibility, 'qualification': source, 'current': proof, 'image_imported': False, 'CPU_success': False, 'models_started': 0, 'observed_at': g.runtime.manager._now()}
                exclusive(recovery.root / 'completed.json', activation)
                owner_final_clock(eligibility, g)
                g.s.finish_operator_maintenance()
                exclusive(folder / 'fence-released.json', {'stage_operation': p['stage'], 'completed_sha256': owner_sha(owner_encode(completion)), 'operator_maintenance_observed': False, 'observed_at': g.runtime.manager._now()})
                exclusive(recovery.root / 'fence-released.json', {'completed_sha256': owner_sha(owner_encode(activation)), 'operator_maintenance_observed': False, 'observed_at': g.runtime.manager._now()})
            except BaseException:
                g.s.restore_operator_block()
                raise
            stages.failed_owner_pending = None
            stages.closed = False
            g.operator.negative_cpu_release.pending = False
            recovery.released = True
            g.live_baseline = None
    return {'source_epoch_activated': True, 'state': 'SOURCE_EPOCH_READY', 'prior_stage_state': owner_FAILED, 'prior_stage_failure_released': True, 'old_failure_preserved': True, 'original_deadline_monotonic': pend['original_deadline_monotonic'], 'work_deadline_extended': False, 'image_imported': False, 'models_started': 0}

def owner_completed_history(stages, stage, rows):
    """A completed same-family actor keeps its original source/repair domain."""
    import types
    p = owner_policy()
    old = p['old_completed'][stage]
    bound = dict(p, stage=stage, **old)
    refs = bound['old_records']
    actual, actual_stats = owner_actor_snapshot(stages, stage)
    owner_need(actual == rows and set(rows) == set(refs), 'owner_prior_complete_actor_set')
    for n, ref in refs.items():
        owner_need(actual_stats[n] == ref['F9'] and owner_sha(rows[n]) == ref['sha256'] and (ref['F9'][2] == len(rows[n])) and (ref['F9'][3:7] == [999, 989, 33152, 1]), 'owner_prior_complete_actor_SHA_F9')
    rawbase = {n: b for n, b in rows.items() if n not in ('terminal.json', 'completed.json', 'fence-released.json')}
    base = dict(bound, old_records={n: refs[n] for n in rawbase})
    pend = owner_pending(stages.read, rawbase, {n: actual_stats[n] for n in rawbase}, base)
    t = pend['original_terminal']
    c, f = (owner_strict(rows[n]) for n in ('completed.json', 'fence-released.json'))
    owner_need(set(c) == {'schema', 'stage_operation', 'state', 'terminal_sha256', 'current', 'original_deadline_monotonic', 'work_deadline_extended', 'image_imported', 'CPU_success', 'models_started', 'finished_at'} and c['schema'] == 'fixed-image-finite-stage-completed/v1' and (rows['terminal.json'] == owner_encode(t)) and (t['state'] == c['state'] == owner_FAILED) and (c['stage_operation'] == stage) and (c['terminal_sha256'] == owner_sha(rows['terminal.json'])) and (c['original_deadline_monotonic'] == pend['original_deadline_monotonic']) and (c['work_deadline_extended'] is c['image_imported'] is c['CPU_success'] is False) and (type(c['models_started']) is int) and (c['models_started'] == 0) and (f['completed_sha256'] == owner_sha(rows['completed.json'])) and (f['operator_maintenance_observed'] is False) and (c['finished_at'] <= f['observed_at']), 'owner_prior_complete_failed_fence_chain')
    ctx = owner_Context(p['old_sources'], stages.read)
    try:
        oldg = types.SimpleNamespace(config=p['old_config'], same=stages.g.same, lock=stages.g.lock, runtime=stages.g.runtime)
        view = types.SimpleNamespace(root=stages.root, read=stages.read, g=oldg, empty_repair_grants=set(), epoch_asset_history=ctx.module('history_reader').load(p['old_config']))
        oldg.asset_stages = view
        ctx.module('empty_range_repair').history(view, stage, rows, view.empty_repair_grants)
    finally:
        ctx.recheck()
    last, last_stats = owner_actor_snapshot(stages, stage)
    owner_need(last == actual and last_stats == actual_stats, 'owner_prior_actor_fullF9_after_history')
    stages.used.extend(pend['ranges'])
    return t

def owner_normal_before(read, p, current_proof, asset_status, now):
    """Explicit LIVE_IDLE_FAILED_TERMINAL_HELD variant; general idle unchanged.
 The caller must pair the two actual Rootpeer responses with its own nonce/5s
 channel algorithm. This function validates their full original payloads only.
 """
    ctx = owner_Context(p['old_sources'], read)
    try:
        baseline = ctx.module('live_idle').validate_live_idle(current_proof, p['old_config'], now, fenced=True)
        owner_need(asset_status['active'] is True and asset_status['sticky'] is True and (asset_status['maintenance_held'] is True) and (asset_status['release_required'] is True) and (asset_status['legacy_failure_pending'] is False) and (asset_status['models_started'] == 0) and (asset_status['active_stage_operation'] == p['stage']), 'owner_normal_before_exact_failed_hold_not_general_idle')
        owner_need(current_proof['manager_pid'] == p['old_identity']['pid'] and current_proof['manager_start_ticks'] == p['old_identity']['start_ticks'] and (current_proof['boot_id'] == p['old_identity']['boot_id']), 'owner_normal_before_original_sole_identity')
        STATE_ROOT = owner_Path(None)
        import types
        view = types.SimpleNamespace(root=STATE_ROOT, read=read)
        rows, stats = owner_actor_snapshot(view, p['stage'])
        pend = owner_pending(read, rows, stats, p)
        owner_need(asset_status['original_deadline_monotonic'] == pend['original_deadline_monotonic'], 'owner_normal_before_old_deadline_not_rebased')
        return {'schema': 'live-idle-owned-failed-terminal-held/v1', 'baseline': baseline, 'failed_owner': pend, 'maintenance_held': True, 'work_may_resume': False}
    finally:
        ctx.recheck()

def owner_final_clock(eligibility, g):
    c = eligibility['PC_release_clock']
    now = g.runtime.manager._now()
    mono = g.clock()
    owner_need(owner_number(now) and owner_number(mono) and (0 <= now - c['received_at']) and (c['elapsed'] + now - c['received_at'] <= 30) and (0 <= now - c['permit_wall'] <= c['permit_seconds']) and (c['permit_monotonic_origin'] <= mono < c['permit_monotonic_deadline']), 'owner_actual_final_commit_PC_whole30')
    return now

def owner_checked_A(read, p, pend, request, q):
    ar = q['A_original']
    owner_need(type(ar) is dict and set(ar) == {'raw_b64', 'sha256', 'F9'}, 'owner_A_origin_exact_envelope')
    araw = owner_base64.b64decode(ar['raw_b64'], validate=True)
    owner_need(len(araw) <= 2097152 and owner_sha(araw) == ar['sha256'] and (ar['F9'][2] == len(araw)) and (ar['F9'][3:7] == [0, 0, 33152, 1]), 'owner_full_A_origin_distinct_from_PC_mirror')
    a = owner_strict(araw)
    owner_need(set(a) == {'schema', 'request_raw_b64', 'request_sha256', 'old_terminal_sha256', 'source_before', 'source_after', 'kernel_before', 'kernel_after', 'started_at', 'finished_at', 'monotonic_elapsed', 'PC_begin_original'} and a['schema'] == 'failed-owner-terminal-A-readonly/v1', 'owner_fresh_A_complete_shape')
    rr = owner_base64.b64decode(a['request_raw_b64'], validate=True)
    owner_need(rr == owner_encode(request) and owner_sha(rr) == a['request_sha256'] and (a['old_terminal_sha256'] == pend['terminal_sha256']) and (a['source_before'] == a['source_after'] == p['old_A_sources']), 'owner_fresh_A_request_and_old_sources_not_bool')
    owner_need(all((owner_number(a[k]) for k in ('started_at', 'finished_at', 'monotonic_elapsed'))) and 0 <= a['monotonic_elapsed'] <= 30 and (a['started_at'] <= a['finished_at']) and (abs(a['finished_at'] - a['started_at'] - a['monotonic_elapsed']) <= 5), 'owner_A_own_domain_whole30')
    begin = a['PC_begin_original']
    owner_need(type(begin) is dict and set(begin) == {'raw_b64', 'sha256', 'F9'}, 'owner_A_actual_PC_BEGIN_original')
    br = owner_base64.b64decode(begin['raw_b64'], validate=True)
    owner_need(owner_sha(br) == begin['sha256'] and begin['F9'][2] == len(br) and (begin['F9'][3:7] == [0, 989, 33056, 1]), 'owner_A_PC_BEGIN_full_origin')
    bm = owner_strict(br)
    owner_need(bm['schema'] == 'failed-owner-terminal-PC-send/v1' and bm['request_original'] == {'path': str(owner_Path(p['qualified_path']).parent / 'request.json'), 'sha256': owner_sha(owner_encode(request)), 'F9': bm['request_original']['F9']}, 'owner_A_BEGIN_same_request')
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

def owner_activation_records(root):
    import os
    from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, metadata, directory_identity
    p = owner_policy()
    root = owner_Path(root)
    base = owner_Path(p['activation_root'])
    owner_need(root.parent == base and owner_re.fullmatch('[0-9a-f]{32}', root.name), 'owner_fixed_source_activation_root')
    with HeldParent(base, legacy=True) as chain:
        fd = os.open(base.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        sub = None
        try:
            before = directory_identity(os.fstat(fd))
            owner_need(before[2:] == (999, 989, 16832), 'owner_activation_service_base')
            sub = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            sd = directory_identity(os.fstat(sub))
            owner_need(sd[2:] == (999, 989, 16832), 'owner_activation_private_invocation')
            names = sorted(os.listdir(sub))
            owner_need(names == ['completed.json', 'fence-released.json', 'intent.json'], 'owner_activation_complete_private_chain')
            rows = {}
            stats = {}
            for name in names:
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sub)
                try:
                    st = metadata(os.fstat(leaf))
                    owner_need(st[3:7] == [999, 989, 33152, 1] and 0 < st[2] <= 4194304, 'owner_activation_private_leaf_F9')
                    raw = os.pread(leaf, st[2] + 1, 0)
                    owner_need(len(raw) == st[2] and st == metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=sub, follow_symlinks=False)), 'owner_activation_original_held_named')
                    rows[name] = raw
                    stats[name] = st
                finally:
                    os.close(leaf)
            owner_need(names == sorted(os.listdir(sub)) and sd == directory_identity(os.fstat(sub)) == directory_identity(os.stat(root.name, dir_fd=fd, follow_symlinks=False)) and (before == directory_identity(os.fstat(fd)) == directory_identity(chain.named_leaf())), 'owner_activation_source_chain_stable')
            chain.recheck()
            return (rows, stats)
        finally:
            if sub is not None:
                os.close(sub)
            os.close(fd)
'Finite Root data producers for the failed-owner release certificate only.\nNo Manager, model, asset worker, private RPC or old terminal-clock action.\nread/write are the original protected Root FD primitives supplied by a held\nentry. In production this code is co-located with history_reader, not ambient.\n'
import base64 as owner_base64, os as owner_os, time as owner_time
from pathlib import Path as owner_Path

def owner_root_write(read, write, path, value):
    owner_need(owner_os.getuid() == owner_os.geteuid() == 0, 'owner_release_Root_data_only')
    raw = owner_encode(value)
    owner_need(len(raw) <= 2097152, 'owner_release_singleleaf2MiB')
    write(owner_Path(path), raw, mode=288, gid=989)
    body, st = read(path, limit=2097152)
    owner_need(body == raw and st[3:7] == [0, 989, 33056, 1] and (st[2] == len(raw)), 'owner_release_original_Root_readback')
    return {'path': str(path), 'sha256': owner_sha(raw), 'F9': st}

def owner_permit(read, write, config, identity):
    p = owner_policy()
    owner_need(config['review_sha256'] == p['new_review'], 'owner_permit_new_review')
    t = owner_old_terminal(read, p)
    owner_need(p['old_worker'] == {'unit': t['scope']['unit']['Id'], 'pid': int(t['scope']['unit']['ExecMainPID']), 'boot_id': t['scope']['boot_id']}, 'owner_permit_Source_old_worker_exact')
    current = {'review_sha256': config['review_sha256'], 'config_sha256': config['_config_sha256'], 'source118': config['PC_source_pins'], 'manager_identity': identity}
    now = owner_time.time()
    mono = owner_time.monotonic()
    v = {'schema': 'failed-owner-terminal-release-permit/v1', 'operation': p['probe_operation'], 'nonce': p['probe_nonce'], 'stage_operation': p['stage'], 'new_current': current, 'old_terminal': p['old_terminal'], 'old_records': p['old_records'], 'old_plan': p['old_plan'], 'PC_issued_at': now, 'PC_monotonic_origin': mono, 'PC_deadline_monotonic': mono + 120, 'duration_seconds': 120, 'automatic_retry': False}
    return owner_root_write(read, write, p['permit_path'], v)

def owner_begin(read, write):
    p = owner_policy()
    raw, st = read(p['permit_path'], limit=2097152)
    v = owner_strict(raw)
    ref = {'path': p['permit_path'], 'sha256': owner_sha(raw), 'F9': st}
    owner_need(st[3:7] == [0, 989, 33056, 1] and v['schema'] == 'failed-owner-terminal-release-permit/v1' and (v['nonce'] == p['probe_nonce']) and (v['stage_operation'] == p['stage']) and (v['old_terminal'] == p['old_terminal']) and (v['old_records'] == p['old_records']) and (v['old_plan'] == p['old_plan']) and (v['automatic_retry'] is False), 'owner_BEGIN_same_Root_permit')
    owner_need(0 <= owner_time.time() - v['PC_issued_at'] <= v['duration_seconds'] == 120 and v['PC_monotonic_origin'] <= owner_time.monotonic() < v['PC_deadline_monotonic'], 'owner_BEGIN_original_PC_finite_window')
    root = owner_Path(p['qualified_path']).parent
    request = {'schema': 'failed-owner-terminal-PC-request/v1', 'nonce': v['nonce'], 'stage_operation': p['stage'], 'permit_original': ref, 'new_current': v['new_current'], 'old_terminal_sha256': p['old_terminal']['sha256']}
    rr = owner_root_write(read, write, root / 'request.json', request)
    m = {'schema': 'failed-owner-terminal-PC-send/v1', 'request_original': rr, 'PC_sent_at': owner_time.time(), 'PC_monotonic_sent': owner_time.monotonic()}
    mr = owner_root_write(read, write, root / 'send-moment.json', m)
    br, bs = read(root / 'send-moment.json', limit=2097152)
    return {'PC_begin_original': {'raw_b64': owner_base64.b64encode(br).decode(), 'sha256': owner_sha(br), 'F9': bs}, 'request_original': rr, 'request_raw_b64': owner_base64.b64encode(owner_encode(request)).decode(), 'send_moment_original': mr}

def owner_collect_A(request_raw, PC_begin_original, p, read_source, kernel, clock=owner_time):
    """Executed only by a SOURCE-bound fresh Root readonly worker, max90.
 read_source is root_io.held; kernel is an isolated held old_failed_kernel
 module whose ALLOWED_UNIT was derived from the fixed old terminal at source
 materialization. It never changes any canonical service module/global.
 """
    owner_need(owner_os.getuid() == owner_os.geteuid() == 0, 'owner_A_readonly_Root')
    br = owner_base64.b64decode(PC_begin_original['raw_b64'], validate=True)
    bm = owner_strict(br)
    owner_need(owner_sha(br) == PC_begin_original['sha256'] and PC_begin_original['F9'][2] == len(br) and (PC_begin_original['F9'][3:7] == [0, 989, 33056, 1]) and (bm['schema'] == 'failed-owner-terminal-PC-send/v1') and (bm['request_original']['sha256'] == owner_sha(request_raw)), 'owner_A_PC_BEGIN_not_unclocked_request')
    r = owner_strict(request_raw)
    owner_need(r['schema'] == 'failed-owner-terminal-PC-request/v1' and r['nonce'] == p['probe_nonce'] and (r['stage_operation'] == p['stage']) and (r['old_terminal_sha256'] == p['old_terminal']['sha256']), 'owner_A_actual_fixed_request')
    started = clock.time()
    mono = clock.monotonic()
    end = mono + 30
    worker = p['old_worker']
    owner_need(kernel.ALLOWED_UNIT == worker['unit'], 'owner_A_private_kernel_exact_old_unit')

    def source():
        out = {}
        for name, ref in p['old_A_sources'].items():
            raw, st = read_source(owner_Path(ref['path']), ref['sha256'], cap=2097152, mode=384)
            owner_need(st == ref['F9'] and owner_sha(raw) == ref['sha256'] and (clock.monotonic() < end), 'owner_A_actual_old55_complete_source_F9')
            out[name] = ref
        return out
    before = source()
    first = kernel.kernel_after_stop(worker['unit'], worker['pid'], worker['boot_id'], end)
    after = source()
    second = kernel.kernel_after_stop(worker['unit'], worker['pid'], worker['boot_id'], end)
    finished = clock.time()
    elapsed = clock.monotonic() - mono
    owner_need(0 <= elapsed <= 30 and before == after, 'owner_A_original_whole30_no_refresh')
    return {'schema': 'failed-owner-terminal-A-readonly/v1', 'PC_begin_original': PC_begin_original, 'request_raw_b64': owner_base64.b64encode(request_raw).decode(), 'request_sha256': owner_sha(request_raw), 'old_terminal_sha256': p['old_terminal']['sha256'], 'source_before': before, 'source_after': after, 'kernel_before': first, 'kernel_after': second, 'started_at': started, 'finished_at': finished, 'monotonic_elapsed': elapsed}

def owner_finish(read, write, A_original, scope):
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
    owner_checked_A(read, p, {'original_terminal': t, 'terminal_sha256': p['old_terminal']['sha256']}, request, {'A_original': A_original, 'scope': scope, 'send_moment_original': {'path': str(root / 'send-moment.json'), 'sha256': owner_sha(mr), 'F9': ms}})
    now = owner_time.time()
    duration = owner_time.monotonic() - moment['PC_monotonic_sent']
    owner_need(owner_number(duration) and 0 <= duration <= 30 and (0 <= now - moment['PC_sent_at'] <= 30), 'owner_finish_PC_original_whole30')
    received = {'schema': 'failed-owner-terminal-PC-received/v1', 'request_original': moment['request_original'], 'A_original': A_original, 'scope_sha256': owner_sha(owner_encode(scope)), 'PC_received_at': now, 'PC_monotonic_elapsed': duration}
    cr = owner_root_write(read, write, root / 'received.json', received)
    q = {'schema': 'failed-owner-terminal-fresh-qualified/v1', 'permit_original': pref, 'request_original': moment['request_original'], 'send_moment_original': {'path': str(root / 'send-moment.json'), 'sha256': owner_sha(mr), 'F9': ms}, 'received_original': cr, 'A_original': A_original, 'scope': scope}
    ref = owner_root_write(read, write, p['qualified_path'], q)
    return {'qualified_original': ref, 'clock_original': received, 'work_started': False, 'release_committed': False}

def owner_stopped_unit_branch(before, after):
    u = after['unit']
    old = before['unit']
    owner_need(u['Id'] == old['Id'] and u['MainPID'] == '0' and (u['ActiveState'] == 'inactive') and (u['SubState'] == 'dead') and (u['ControlGroup'] in ('', '/system.slice/' + old['Id'])) and (u['NRestarts'] == '0'), 'poststop_current_unit_not_active')
    if u['LoadState'] == 'loaded':
        owner_need(u['InvocationID'] == old['InvocationID'] and u['ExecMainPID'] == old['ExecMainPID'] and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success'), 'loaded_poststop_same_original_invocation')
        return 'loaded-same-invocation'
    owner_need(u['LoadState'] == 'not-found' and u['InvocationID'] == '' and (u['ControlGroup'] == '') and (u['ExecMainPID'] == u['ExecMainCode'] == u['ExecMainStatus'] == '0') and (u['Type'] == u['User'] == u['Group'] == '') and (u['Result'] == 'success'), 'collected_poststop_exact_missing_unit')
    return 'collected-with-independent-kernel-proof'
