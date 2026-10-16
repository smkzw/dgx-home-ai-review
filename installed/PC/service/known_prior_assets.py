# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import base64 as old_base64, json as old_json, hashlib as old_hashlib, os as old_os, stat as old_stat
from pathlib import Path as old_Path
from root_io import held as old_held, sha as old_sha
from plan import need as old_need, strict as old_strict, encode as old_encode
old_APPROVED_HISTORY = {'A_source': {'boot_id': 'redacted-32c02e882269', 'data_root': '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14', 'index_sha256': '9b9cc0a2c97ec234482aa20a2f195024651f9f821d2f78480ca75f04d7958256', 'ready_worker_sha256': 'cf565910ef8430c8b4bcec8c1a3805e9e3e58a262592f18856631dbd9aebb746', 'source_root': '/opt/dgx-v4/mimo-registry-native-r26-role-context-r14', 'sources': {'EXPECTED_DUMP.json': None, 'OFFICIAL_MERGED_BASELINE.json': None, 'asset_segments.py': None, 'bounded_process.py': None, 'broker.py': None, 'config-original.json': None, 'containerd.candidate.toml': None, 'diagnostics.py': None, 'download_worker.py': None, 'entry_clock.py': None, 'entry_worker.py': None, 'failed_terminal.py': None, 'fetch/config-original.json': None, 'fetch/contract.py': None, 'fetch/entry.py': None, 'fetch/fetch.py': None, 'fetch/manifest-original.json': None, 'fetch/oci.py': None, 'fetch/supervision.py': None, 'fetch/transport.py': None, 'manifest-original.json': None, 'namespace.py': None, 'native.py': None, 'observer.py': None, 'old_failed_kernel.py': None, 'parent_metadata.py': None, 'parent_source.py': None, 'pc_contract.py': None, 'pc_managed_scope.py': None, 'plan.py': None, 'point_clock.py': None, 'private_config.py': None, 'qualification.py': None, 'range_catalog.py': None, 'range_component.py': None, 'range_diagnostic.py': None, 'range_fetch.py': None, 'range_http.py': None, 'range_transport.py': None, 'root_agent.py': None, 'root_io.py': None, 'root_loader.py': None, 'root_worker.py': None, 'segment_agent.py': None, 'segment_download_worker.py': None, 'segment_ready.py': None, 'segment_ready_worker.py': None, 'segment_runtime.py': None, 'segment_terminal_producer.py': None, 'segment_worker.py': None, 'source-index.json': None, 'stage_entry_clock.py': None, 'stage_naming.py': None, 'terminal.py': None, 'topology.py': None}}, 'actors': {'b7a518bbefa903b6c43c44b9a2f6f6cf': None, '69b0a7b8356ae276839c3cc43044096c': None}, 'old_current': None, 'operation': 'ed7021db9df4c839d02f3271361924de', 'qualification_completed_original': None, 'qualification_summary': {'Core_generations': {'glm-ab': 14, 'image-turbo-c': 1, 'qwen-a-c': 11}, 'historical_only': True, 'initial_identity': {'boot_id': 'redacted-2606f3e07a03', 'invocation_id': '69c59077d950b1dff986304287b2fa6c', 'pid': 2023335, 'start_ticks': '34798009'}, 'source_qualified_sha256': 'deb0365552c06e04acd864d3fbb8cc06d5d826ea26e44dc6f32a35b1752036d7'}, 'qualified_original': None, 'schema': 'R14B-sealed-old-domain/v1', 'snapshot_result': {'actors': {'b7a518bbefa903b6c43c44b9a2f6f6cf': {'historical_only': True, 'retry_authorized': False, 'state': 'FAILED_REGISTRY_QUIESCENT', 'terminal_sha256': '3dcc5a38505ce24a79b9076ca39e1a3813a4f1f7e05a7e04089bf086a0681ecd'}, '69b0a7b8356ae276839c3cc43044096c': {'historical_only': True, 'retry_authorized': False, 'state': 'FAILED_REGISTRY_QUIESCENT', 'terminal_sha256': '455e0b3b131f3ecd92ce86d01fecec4985747c45981e94dc155b25875cf29e5b'}}, 'historical_only': True, 'resource_authorized': False, 'retry_authorized': False, 'schema': 'R14B-finite-epoch-historical-only/v1', 'source_activation_authorized': False, 'used': [{'count': 462849, 'digest': '2ed23d91404d4701b704d1bde211c59a2a564a31c315f05871a6e9403bc19945', 'start': 6291456}, {'count': 376792, 'digest': 'b69841cb303ccedcf38d7b88ef5624621de9afac92f991bd9493046493af0459', 'start': 0}], 'used_sha256': 'dd582c52b50eaed32a8a63812473abde289ee85d82ae93fc673bfd6c403b5fbd'}, 'snapshot_sha256': '17875f46f0529747493cfac1de59bc4e2c36f5715fdad9bf69d812f6e2196d0c'}

def old_bound():
    h = old_APPROVED_HISTORY
    old_need(type(h) is dict and h['schema'] == 'R14B-sealed-old-domain/v1' and (h['operation'] == 'ed7021db9df4c839d02f3271361924de') and (h['snapshot_result']['historical_only'] is True) and (h['snapshot_result']['retry_authorized'] is False), 'old_domain_complete_snapshot_None')
    return h

def old_is_prior(stage):
    return stage in old_bound()['actors']

def old_actor_ancestor(stage, v, ranges, operation):
    h = old_bound()
    old_need(stage in h['actors'] and operation == h['operation'], 'old_domain_unknown_family_or_actor')
    a = h['actors'][stage]
    old_need(a['state'] == 'FAILED_REGISTRY_QUIESCENT' and ranges == a['ranges'] and all((v[k] == a[k] for k in ('original_refs', 'terminal_sha256', 'completed_sha256', 'fence_sha256', 'ranges', 'manager_identity', 'failed_pid', 'A_boot_id', 'unit', 'source_index_sha256'))), 'old_domain_all_original_refs_no_success_relabel')
    return h

def old_terminal_matches(t, stage, current):
    h = old_bound()
    a = h['actors'][stage]
    o = h['old_current']
    old_need(old_sha(old_encode(t)) == a['terminal_sha256'] and t['stage_operation'] == stage and (t['state'] == a['state'] == 'FAILED_REGISTRY_QUIESCENT') and (t['source_index_sha256'] == h['A_source']['index_sha256']) and (t['source118'] == o['source118']) and (t['config_sha256'] == o['config_sha256']) and (t['review_sha256'] == o['review_sha256']) and (t['manager_identity'] == o['manager_identity']), 'old_domain_full_terminal_original_no_current_bypass')
    old_need(type(current) is dict and set(current) == {'review_sha256', 'config_sha256', 'manager_identity', 'source118'} and (len(current['source118']) == 118), 'old_domain_independent_complete_current')
    return True

def old_source_snapshot():
    p = old_bound()['A_source']
    out = {}
    for n, v in p['sources'].items():
        b, f = old_held(old_Path(p['source_root']) / n, v['sha256'], mode=384, cap=2097152)
        old_need(f == v['F9'], 'old_domain_A55_fullbytes_F9')
        out[n] = {'sha256': old_sha(b), 'F9': f}
    return out

def old_qualified_history():
    h = old_bound()
    out = {}
    for k in ('qualified_original', 'qualification_completed_original'):
        r = h[k]
        b, f = old_held(old_Path(r['path']), r['sha256'], mode=288, cap=2097152)
        old_need(f == r['F9'], 'old_domain_original_PC_q_fullF9')
        out[k] = b
    q, c = (old_strict(out[k]) for k in ('qualified_original', 'qualification_completed_original'))
    o = h['old_current']
    old_need(q['review_sha256'] == o['review_sha256'] and q['current']['current_source118'] == o['source118'] and (q['current']['config_sha256'] == o['config_sha256']) and (q['current']['manager_identity'] == c['manager_identity'] == o['manager_identity']) and (q['operation'] == q['grant_operation'] == h['operation']) and (c['receipt_sha256'] == old_sha(out['qualified_original']) == h['qualification_summary']['source_qualified_sha256']) and (q['observed_at'] <= c['observed_at']), 'old_domain_original_accepted_q_event_only')
    return {'historical_only': True, 'source_qualified_sha256': old_sha(out['qualified_original'])}
'Closed historical pre-file-absence variant. No creation, permission or retry.\nThe immutable history descriptor is independently reviewed SOURCE, not a caller\nflag. All present originals are held/read; unknown/missing evidence fails closed.\n'
import base64 as prefile_base64, stat as prefile_stat
from pathlib import Path as prefile_Path
from plan import need as prefile_need, strict as prefile_strict
from root_io import held as prefile_held, sha as prefile_sha
prefile_APPROVED_HISTORY = {'download_failed_original': None, 'entries': {'blobs': [66306, 55189573, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'containerd-data': [66306, 55189567, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'containerd-exec': [66306, 55189568, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'download-failed.json': [66306, 55189580, 395, 0, 0, 33152, 1, 1792132947392628289, 1792132947392628289], 'failed.json': [66306, 55189581, 1186, 0, 0, 33152, 1, 1792132947506628308, 1792132947506628308], 'home': [66306, 55189572, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'initial-kernel-unit.json': [66306, 55189575, 19346, 0, 0, 33152, 1, 1792132917302623837, 1792132917302623837], 'intent.json': [66306, 55189574, 414276, 0, 0, 33152, 1, 1792132917273623833, 1792132917273623833], 'owned-cleanup.json': [66306, 55189582, 1962, 0, 0, 33152, 1, 1792132947562628317, 1792132947562628317], 'private-opt': [66306, 55189569, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'private-overlay': [66306, 55189570, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'segment-resources.jsonl': [66306, 55189579, 0, 0, 0, 33152, 1, 1792132917389623848, 1792132917389623848], 'segments.stderr': [66306, 55189578, 427, 0, 0, 33152, 1, 1792132947491840050, 1792132947491840050], 'segments.stdout': [66306, 55189577, 0, 0, 0, 33152, 1, 1792132917315623839, 1792132917315623839], 'tmp': [66306, 55189571, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833]}, 'failed_original': None, 'failure_location': {'function': 'sample', 'line': 143, 'source': '/opt/dgx-v4/mimo-registry-native-r26-role-context-r14/fetch/supervision.py'}, 'failure_observed_at': 1792132947.3933606, 'metadata_sha256': '06d23b3b05f372fb1fa662a6e8ed113e674f6c2f85515c89227d8fec1e8e14bc', 'producer_sources': {'fetch/supervision.py': '0b4b24b13250bafb38d41e5ef6fe079b725665bf7fbe8f9ca2d96ad2ab5fbbdf', 'segment_download_worker.py': '452d0e1e07e63218b8b12f843b3e1545e17c9e9fb8fa3f438aa11f242bdd0411', 'topology.py': '411036bf0b9b5fe3e419ff4a3ca6663151f086beb06f37962e3fc1c29aaadaac'}, 'range_F9': [66306, 55189566, 4096, 0, 0, 16832, 9, 1792132947562628317, 1792132947562628317], 'result_observed_at': 1792132947.506779, 'root_chain_F9': {'/var': [66306, 1441794, 4096, 0, 0, 16877, 13, 1762332498664000000, 1762332498664000000], '/var/lib': [66306, 1442040, 4096, 0, 0, 16877, 84, 1791724570084815877, 1791724570084815877], '/var/lib/dgx-v4': [66306, 3286406, 4096, 0, 0, 16877, 17, 1792132917184623822, 1792132917184623822], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14': [66306, 55189561, 4096, 0, 0, 16832, 4, 1792132917198623824, 1792132917198623824], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14/stages': [66306, 55189562, 4096, 0, 0, 16832, 3, 1792132917193623823, 1792132917193623823], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14/stages/b7a518bbefa903b6c43c44b9a2f6f6cf': [66306, 55189563, 4096, 0, 0, 16832, 3, 1792132917272623833, 1792132917272623833]}, 'schema': 'failed-range-prefile-absence-static-history/v1', 'stage_operation': 'b7a518bbefa903b6c43c44b9a2f6f6cf', 'terminal_sha256': '3dcc5a38505ce24a79b9076ca39e1a3813a4f1f7e05a7e04089bf086a0681ecd'}
prefile_SCHEMA = 'failed-range-before-first-sample-prefile-absence/v1'
prefile_EMPTY_DIRS = ('blobs', 'containerd-data', 'containerd-exec', 'private-opt', 'private-overlay', 'tmp', 'home')

def prefile_full(row):
    raw = prefile_base64.b64decode(row['raw_b64'], validate=True)
    f = row['F9']
    prefile_need(len(f) == 9 and f[2] == len(raw) <= 2097152 and (f[3:7] == [0, 0, 33152, 1]) and (prefile_sha(raw) == row['sha256']), 'prefile_full_original_SHA_F9')
    return raw

def prefile_history(stage, p):
    h = prefile_APPROVED_HISTORY
    prefile_need(type(h) is dict and h['schema'] == 'failed-range-prefile-absence-static-history/v1' and (h['stage_operation'] == stage), 'prefile_reviewed_history_None_unknown_stage')
    for n, pin in h['producer_sources'].items():
        prefile_need(old_bound()['A_source']['sources'][n]['sha256'] == pin, 'prefile_exact_beforefirstsample_producer_source')
    return h

def prefile_raw_original(t, key):
    row = t[key]
    return {'raw_b64': row['raw_b64'], 'sha256': row['sha256'], 'F9': row['stat']}

def prefile_node_idle(a):
    v = a['fresh_current']
    prefile_need(v['manager_pid'] == a['current']['manager_identity']['pid'] and v['manager_start_ticks'] == a['current']['manager_identity']['start_ticks'] and (v['boot_id'] == a['current']['manager_identity']['boot_id']), 'prefile_actor_current_identity')
    prefile_need(set(v['nodes']) == {'spark-a', 'spark-b'}, 'prefile_complete_AB')
    for node, row in v['nodes'].items():
        s = row['reply']['snapshot']
        r = s['record']
        c = s['container']['data'] or {}
        g = s['gpu']
        state = prefile_strict(s['guard_state']['raw_utf8'].encode())
        prefile_need(s['root_uid'] == 0 and r['state'] == 'CLEAR' and (r['owner'] == 'dgx-hx-service') and (r['profile'] in ('glm-ab', 'qwen-a-c', 'image-turbo-c')) and (type(r['generation']) is int) and (r['generation'] > 0) and (type(r['container_id']) is str) and __import__('re').fullmatch('[0-9a-f]{64}', r['container_id']), 'prefile_same_owned_CLEAR_record')
        prefile_need(s['container']['exists'] is False or (s['container']['exists'] is True and c.get('running') is False and (c.get('status') in ('created', 'exited', 'dead')) and (c.get('id') == r['container_id'])), 'prefile_original_current_known_absent_or_owned_inactive')
        prefile_need(s['guard_process_verified'] is True and s['guard_state']['stat'][3:7] == [0, 0, 33152, 1] and (prefile_sha(s['record_utf8'].encode()) == s['record_sha256']) and (prefile_strict(s['record_utf8'].encode()) == r) and (prefile_sha(s['guard_state']['raw_utf8'].encode()) == s['guard_state']['sha256']) and (set(state['last_record']) == {'container_id', 'generation', 'owner', 'profile', 'released_at', 'state', 'updated_at'}) and (state['last_record'] == {k: r[k] for k in state['last_record']}) and (state['tracked'] is None) and (state['retained_unknown'] is False) and (state['clear_authorized'] is True), 'prefile_original_Guard_same_record')
        prefile_need(g['complete'] is True and g['empty'] is True and (g['truncated'] is False) and (g['containers'] == []) and (g['processes'] == []) and (g['reasons'] == []), 'prefile_full_GPUempty')
    return v

def prefile_validate(value, stage, a, p, directories):
    h = prefile_history(stage, p)
    base = prefile_Path(old_bound()['A_source']['data_root'])
    ranged = base / 'stages' / stage / 'range'
    v = value['pre_file_absence']
    d = directories[str(ranged)]
    prefile_need(set(value) == {'terminal_ref', 'pre_file_absence', 'daemon_socket_absence', 'retained_socket'} and set(v) == {'schema', 'segments_absence', 'failed_original', 'download_failed_original'} and (v['schema'] == prefile_SCHEMA), 'prefile_exact_typed_absence_branch')
    prefile_need(d['F9'] == h['range_F9'] and d['entries'] == sorted(h['entries']) and (d['children'] == h['entries']) and ('segments' not in d['entries']), 'prefile_exact_actual_current_entries_fullF9')
    missing = v['segments_absence']
    prefile_need(missing['path'] == str(ranged / 'segments') and missing['errno'] == 2 and (missing['parent']['path'] == str(ranged)) and (missing['parent']['F9'] == d['F9']) and (missing['parent']['entries'] == d['entries']), 'prefile_positive_ENOENT_held_parent')
    prefile_need(missing['parent']['anchors'] == d['anchors'], 'prefile_absence_exact_full_held_ancestors')
    anchors = {row['path']: row['F9'] for row in d['anchors']}
    for path, f in h['root_chain_F9'].items():
        prefile_need(path in anchors and all((anchors[path][i] == f[i] for i in (0, 1, 3, 4, 5))), 'prefile_original_ancestor_identity_not_recreated')
    for name in ('segment-resources.jsonl', 'segments.stdout'):
        prefile_need(d['children'][name][2] == 0, 'prefile_no_completed_first_sample_or_stdout')
    prefile_need(value['terminal_ref']['sha256'] == h['terminal_sha256'] == a['failed_ancestors'][stage]['terminal_sha256'] and value['terminal_ref']['F9'][3:7] == [0, 0, 33152, 1], 'prefile_complete_original_failed_terminal_pin')
    failed_raw = prefile_full(v['failed_original'])
    child_raw = prefile_full(v['download_failed_original'])
    f = prefile_strict(failed_raw)
    child = prefile_strict(child_raw)
    prefile_need(prefile_sha(failed_raw) == h['failed_original']['sha256'] and v['failed_original']['F9'] == h['failed_original']['F9'] == d['children']['failed.json'], 'prefile_original_terminal_result_fullF9')
    nested = {'raw_b64': f['child_failure_original']['raw_b64'], 'sha256': f['child_failure_original']['sha256'], 'F9': f['child_failure_original']['stat']}
    prefile_need(v['download_failed_original'] == nested and prefile_sha(child_raw) == h['download_failed_original']['sha256'] and (v['download_failed_original']['F9'] == h['download_failed_original']['F9'] == d['children']['download-failed.json']), 'prefile_download_failure_original_fullF9')
    prefile_need(f['schema'] == 'fixed-image-stage-failed/v1' and f['stage_operation'] == stage and (f['automatic_retry'] is False) and (f['partial_preserved'] is True) and (f['phase'] == 'registry.download') and (child['automatic_retry'] is False) and (child['partial_preserved'] is True) and (child['phase'] == 'registry.download') and (child['source_location'] == h['failure_location']) and (child['observed_at'] == h['failure_observed_at'] <= f['observed_at'] == h['result_observed_at']), 'prefile_source_bound_before_first_sample_original_time_order')
    prefile_need(type(a['current']) is dict and len(a['current']['source118']) == 118, 'known_prefile_independent_complete_current')
    return v

def prefile_capture(stage, a, p, d, directories, terminal_raw, terminal_F9, data_absence):
    ranged = prefile_Path(old_bound()['A_source']['data_root']) / 'stages' / stage / 'range'
    h = prefile_history(stage, p)

    def read(name, expected):
        raw, f = prefile_held(ranged / name, expected['sha256'], mode=384, cap=2097152)
        prefile_need(f == expected['F9'], 'prefile_held_original_fullF9')
        return {'raw_b64': prefile_base64.b64encode(raw).decode(), 'sha256': prefile_sha(raw), 'F9': f}
    failed = read('failed.json', h['failed_original'])
    child = read('download-failed.json', h['download_failed_original'])
    t = prefile_strict(terminal_raw)
    prefile_need(prefile_sha(terminal_raw) == h['terminal_sha256'] and t['state'] == 'FAILED_REGISTRY_QUIESCENT' and (t['image_imported'] is False) and (type(t['models_started']) is int) and (t['models_started'] == 0) and (t['scope']['unit']['ExecMainStatus'] == '1') and (failed == prefile_raw_original(t, 'result_original')), 'prefile_held_complete_terminal_matches_failed_original')
    return {'schema': prefile_SCHEMA, 'segments_absence': data_absence({'data_root': str(ranged / 'segments')}), 'failed_original': failed, 'download_failed_original': child}
'Preserve completed prior segments without re-reading their payload bytes.\nService invokes the existing full historical terminal consumer; A binds the same\ncomplete terminal raw, each small receipt fullSHA/F9 and large-file stable F9.\nThis fresh preservation inventory is not a forged original creation receipt.\n'
import ast, base64, builtins, os, re, stat, time
from pathlib import Path
from plan import need, strict, encode
from root_io import held, sha, f9
import zero_negative as primitives
import json
ROLE = 'PC'
PC_TERMINAL_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16/asset-terminals'
ACQUIRE_DEFINITION_SHA = 'e37ae0dae5afe0593890f47b1c1da33b22973e6fd529b36a29d27111b431afa1'
VERSION = 'current-prebind-sealed-old-preservation/v4'
ARCHIVE_DIRS = frozenset(('containerd-data', 'containerd-exec', 'private-opt', 'private-overlay', 'tmp', 'home', 'blobs'))
REGULAR = frozenset(('intent.json', 'initial-kernel-unit.json', 'owned-cleanup.json', 'returned-zero.json', 'segments-completed.json', 'segments.stdout', 'segments.stderr', 'segment-resources.jsonl'))

def service_snapshot(stages, current):
    """Only actual Stages current root; public bodies cannot provide prior rows."""
    from asset_stage import stage_originals
    from current_prebind import actor_records, historical, is_record
    from contract import PC_ROOT
    from history_reader import load, epoch_SnapshotReader
    bridge = load(stages.g.config)
    old = old_bound()
    need(bridge.result == old['snapshot_result'], 'known_prior_full_old_history_before_stage_snapshot')
    reader = epoch_SnapshotReader(bridge.snapshot)
    out = {}
    active = stages.active['stage_operation']
    for folder in sorted(stages.root.iterdir()):
        if folder.name == active:
            continue
        need(folder.is_dir() and (not folder.is_symlink()) and re.fullmatch('[0-9a-f]{32}', folder.name), 'known_prior_exact_stage_namespace')
        rows = stage_originals(stages.root, folder.name)
        if is_record(rows):
            historical(stages, folder.name, rows)
            continue
        required = {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-released.json'}
        need(required <= set(rows), 'known_prior_no_unresolved_or_partial_actor')
        records = actor_records(stages, folder.name)
        if bridge.has(folder.name):
            t = bridge.consume(folder.name, rows, {n: r['F9'] for n, r in records.items()})
            old_terminal_matches(t, folder.name, current)
        else:
            t = stages.terminal(folder.name, historical=True)
        need(encode(t) == rows['terminal.json'] and t['state'] in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT'), 'known_prior_full_existing_terminal_success_or_failed_for_fresh_zero_only')
        d = strict(rows['completed.json'])
        f = strict(rows['fence-released.json'])
        i = strict(rows['intent.json'])
        need(d['terminal_sha256'] == sha(rows['terminal.json']) and f['completed_sha256'] == sha(rows['completed.json']) and (f['operator_maintenance_observed'] is False) and (d['state'] == t['state']) and (d['stage_operation'] == i['stage_operation'] == folder.name), 'known_prior_full_completion_fence_originals')
        oldstage = bridge.has(folder.name)
        root = Path(reader_path_root()) if oldstage else PC_ROOT
        read = reader.read if oldstage else stages.read
        cr, cs = read(root / 'asset-terminal-clocks' / folder.name / 'received.json', limit=2097152)
        clock = strict(cr)
        need(clock['terminal_sha256'] == sha(rows['terminal.json']) and cs[3:7] == [0, 989, 33056, 1], 'known_prior_original_A_origin_from_consumed_PC_clock')
        pcraw, pcf = read(root / 'asset-terminals' / (folder.name + '.json'), limit=2097152)
        need(pcraw == rows['terminal.json'] and pcf[3:7] == [0, 989, 33056, 1], 'known_prior_local_PC_full_terminal_original')
        out[folder.name] = {'terminal_state': t['state'], 'PC_terminal_F9': pcf, 'terminal_sha256': sha(rows['terminal.json']), 'A_terminal_F9': clock['terminal_origin_F9'], 'completed_original': {'sha256': records['completed.json']['sha256'], 'F9': records['completed.json']['F9']}, 'fence_original': {'sha256': records['fence-released.json']['sha256'], 'F9': records['fence-released.json']['F9']}}
        if oldstage:
            out[folder.name]['sealed_old_origin'] = {'snapshot_sha256': old['snapshot_sha256'], 'PC_terminal_path': str(root / 'asset-terminals' / (folder.name + '.json')), 'PC_clock_path': str(root / 'asset-terminal-clocks' / folder.name / 'received.json')}
    need(set(bridge.snapshot['actors']) <= set(out) and len(out) <= 4096, 'known_prior_bounded_stages')
    return out

def shape(prior, stage):
    need(type(prior) is dict and len(prior) <= 4096 and (stage not in prior), 'known_prior_never_current_stage')
    for old, row in prior.items():
        need(type(old) is str and re.fullmatch('[0-9a-f]{32}', old) and (set(row) == {'terminal_state', 'terminal_sha256', 'A_terminal_F9', 'PC_terminal_F9', 'completed_original', 'fence_original'} | ({'sealed_old_origin'} if old_is_prior(old) else set())) and (row['terminal_state'] in ('ASSET_STAGE_COMPLETED', 'FAILED_REGISTRY_QUIESCENT')) and re.fullmatch('[0-9a-f]{64}', row['terminal_sha256']) and (len(row['A_terminal_F9']) == 9) and (row['A_terminal_F9'][3:7] == [0, 0, 33152, 1]), 'known_prior_source_bound_full_A_origin')
        need(len(row['PC_terminal_F9']) == 9 and row['PC_terminal_F9'][3:7] == [0, 989, 33056, 1], 'known_prior_PC_shared_origin')
        if old_is_prior(old):
            sealed_old_row(old, row)
        for k in ('completed_original', 'fence_original'):
            z = row[k]
            need(set(z) == {'sha256', 'F9'} and re.fullmatch('[0-9a-f]{64}', z['sha256']) and (len(z['F9']) == 9) and (z['F9'][3:7] == [999, 989, 33152, 1]), 'known_prior_full_service_reference')
    return prior

def metadata(path, *, directory=False, socket=False):
    path = Path(path)
    z = path.lstat()
    s = f9(z)
    need(s[3] == s[4] == 0 and (stat.S_ISDIR(s[5]) if directory else stat.S_ISSOCK(s[5]) if socket else stat.S_ISREG(s[5])) and (stat.S_IMODE(s[5]) == (448 if directory else 384)) and (s[6] >= 1 if directory else s[6] == 1), 'known_prior_Root_fixed_leaf_type')
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0)
    if not socket:
        fd = os.open(path, flags)
        try:
            need(s == f9(os.fstat(fd)) == f9(path.lstat()), 'known_prior_held_named_F9')
        finally:
            os.close(fd)
    return s

def terminal(policy, stage, row, current):
    sealed = old_is_prior(stage)
    old = sealed_old_row(stage, row) if sealed else None
    policy = old['A_source'] if sealed else policy
    path = Path(policy['source_root']) / 'stages' / stage / 'terminal-qualified.json'
    raw, s = held(path, row['terminal_sha256'], mode=384)
    need(s == row['A_terminal_F9'], 'known_prior_exact_A_terminal_F9')
    v = strict(raw)
    if sealed:
        old_terminal_matches(v, stage, current)
        current = old['old_current']
    need(v['schema'] == 'fixed-image-owned-stage-terminal/v1' and v['state'] == row['terminal_state'] and (v['stage_operation'] == stage) and (v['config_sha256'] == current['config_sha256']) and (v['source118'] == current['source118']) and (v['review_sha256'] == current['review_sha256']) and (v['image_imported'] is False) and (v['models_started'] == 0), 'known_prior_same_source_full_terminal_not_summary_bool')
    if v['state'] == 'FAILED_REGISTRY_QUIESCENT':
        _failed_terminal(v, stage, current)
        return (raw, v, None)
    r = v['result_original']
    result = base64.b64decode(r['raw_b64'], validate=True)
    need(sha(result) == r['sha256'] and len(result) == r['stat'][2] and (r['stat'][3:7] == [0, 0, 33152, 1]), 'known_prior_result_full_original')
    res = strict(result)
    need(res['schema'] == 'fixed-image-selected-segments-returned/v1' and res['stage_operation'] == stage and (res['retry'] == 0) and (res['image_imported'] is res['daemon_started'] is False) and (res['models_started'] == 0), 'known_prior_successful_fixed_segments_only')
    return (raw, v, res)

def receipt_bytes(policy, ref, t):
    """Execute only the exact held original acquire receipt expression.
 The complete acquire definition hash is identical in original A/PC copies;
 unrelated source globals are never imported/executed, no near-copy encoder.
 """
    need(ROLE in ('A', 'PC'), 'known_prior_ROLE_SOURCE_None')
    path = Path(policy['source_root']) / 'asset_segments.py' if ROLE == 'A' else Path(PC_TERMINAL_ROOT).parent / 'service/asset_segments.py'
    raw, _ = held(path, cap=2097152, mode=384 if ROLE == 'A' else 288)
    text = raw.decode()
    tree = ast.parse(text)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'acquire'))
    need(sha(ast.get_source_segment(text, fn).encode()) == ACQUIRE_DEFINITION_SHA, 'known_prior_exact_complete_acquire_definition')
    nodes = [n.value for n in ast.walk(fn) if isinstance(n, ast.Assign) and any((isinstance(x, ast.Name) and x.id == 'rr' for x in n.targets))]
    need(len(nodes) == 1, 'known_prior_original_receipt_expression_unique')

    def only_json(name, *args, **kwargs):
        need(name == 'json', 'known_prior_receipt_stdlib_json_only')
        return json
    item = {k: ref[k] for k in ('path', 'sha256', 'F9', 'digest', 'start', 'count')}
    binding = {'operation_family': t['operation_family'], 'stage_operation': t['stage_operation'], 'source_review_sha256': t['review_sha256'], 'plan_sha256': t['plan_sha256']}
    return eval(compile(ast.Expression(nodes[0]), str(path), 'eval'), {'__builtins__': {'__import__': only_json, 'dict': dict}}, {'item': item, 'binding': binding})

def collect(policy, actor, current, end):
    prior = shape(actor['known_prior_assets'], actor['stage_operation'])
    base = Path(policy['data_root'])
    try:
        base.lstat()
    except FileNotFoundError as e:
        need(e.errno == 2 and (not prior), 'known_prior_missing_BASE_with_prior_unknown')
        return {'schema': 'current-prebind-preserved-assets/v4', 'component_version': VERSION, 'state': 'BASE_ABSENT', 'absence': primitives.data_absence(policy), 'prior': {}}
    need(prior, 'known_prior_present_BASE_requires_consumed_successes')
    before = {}
    receipts = {}
    terminals = {}
    large = []
    empty = {}
    old_sources = old_source_snapshot() if any((old_is_prior(s) for s in prior)) else None

    def directory(path, entries):
        need(time.monotonic() < end, 'known_prior_whole30')
        d = primitives.directory(path, entries)
        need(stat.S_IMODE(d['F9'][5]) == 448 and d['F9'][4] == 0, 'known_prior_Root_private_directory')
        before[str(path)] = {'kind': 'directory', 'F9': d['F9'], 'entries': d['entries']}
        return d
    directory(base, ['stages', 'sockets'])
    directory(base / 'stages', prior)
    directory(base / 'sockets', [s + '.sock' for s in prior])
    for stage, row in sorted(prior.items()):
        raw, v, res = terminal(policy, stage, row, current)
        terminals[stage] = {'sha256': sha(raw), 'F9': row['A_terminal_F9']}
        if row['terminal_state'] == 'FAILED_REGISTRY_QUIESCENT':
            historical = old_is_prior(stage)
            p = sealed_old_row(stage, row)['A_source'] if historical else policy
            if historical and stage == prefile_APPROVED_HISTORY['stage_operation']:
                empty[stage] = _collect_prefile(p, stage, row, v, base, directory, before, end, current)
            else:
                empty[stage] = _collect_empty(p, stage, row, v, base, directory, before, end)
            continue
        root = base / 'stages' / stage
        directory(root, ['range'])
        root = root / 'range'
        names = sorted(os.listdir(root))
        need(REGULAR | ARCHIVE_DIRS | {'segments'} <= set(names) and all((n in REGULAR | ARCHIVE_DIRS | {'segments'} or re.fullmatch('dns-route-[0-9a-f]{32}\\.json', n) for n in names)) and (len(names) <= 256), 'known_prior_only_completed_source_leaves_no_partial_or_token')
        directory(root, names)
        for name in ARCHIVE_DIRS:
            directory(root / name, [])
        segments = res['segments']
        expected = []
        for ref in segments:
            p = Path(ref['path'])
            need(p.parent == root / 'segments' and p.name == ref['digest'] + '.' + str(ref['start']) + '-' + str(ref['start'] + ref['count'] - 1) + '.segment', 'known_prior_fixed_segment_path')
            expected.extend([p.name, p.name + '.json'])
            need(metadata(p) == ref['F9'], 'known_prior_large_asset_original_F9')
            before[str(p)] = {'kind': 'accepted-large-segment', 'F9': ref['F9'], 'accepted_SHA256': ref['sha256']}
            large.append(str(p))
            rr = ref['receipt_ref']
            receipt, rs = held(p.with_name(p.name + '.json'), rr['sha256'], mode=384)
            need(rs == rr['F9'], 'known_prior_receipt_fullSHA_F9')
            q = strict(receipt)
            need(set(q) == {'schema', 'segment', 'operation_family', 'stage_operation', 'source_review_sha256', 'plan_sha256'} and q['schema'] == 'fixed-image-immutable-range-segment/v1' and (q['operation_family'] == v['operation_family']) and (q['stage_operation'] == stage) and (q['source_review_sha256'] == current['review_sha256']) and (q['plan_sha256'] == v['plan_sha256']) and (q['segment'] == {k: ref[k] for k in ('path', 'sha256', 'F9', 'digest', 'start', 'count')}), 'known_prior_receipt_exact_accepted_segment')
            receipts[str(p) + '.json'] = {'sha256': sha(receipt), 'F9': rs}
            before[str(p) + '.json'] = {'kind': 'receipt', 'F9': rs, 'sha256': sha(receipt)}
        directory(root / 'segments', expected)
        for name in set(names) - ARCHIVE_DIRS - {'segments'}:
            p = root / name
            s = metadata(p)
            need(s[2] <= 64 * 1024 ** 2, 'known_prior_bounded_preserved_diagnostics')
            before[str(p)] = {'kind': 'preserved-source-diagnostic', 'F9': s}
        sock = base / 'sockets' / (stage + '.sock')
        before[str(sock)] = {'kind': 'retained-prior-socket', 'F9': metadata(sock, socket=True)}
    need(actor['stage_operation'] not in os.listdir(base / 'stages') and actor['stage_operation'] + '.sock' not in os.listdir(base / 'sockets'), 'known_prior_current_payload_socket_positive_absence')
    for path, row in before.items():
        if row['kind'] == 'directory':
            need(primitives.directory(Path(path), row['entries'])['F9'] == row['F9'], 'known_prior_directory_full_F9_stable')
        else:
            need(metadata(path, socket=row['kind'] == 'retained-prior-socket') == row['F9'], 'known_prior_preserved_full_F9_stable')
    need(old_sources is None or old_source_snapshot() == old_sources, 'known_prior_old_A55_second_full_source_read')
    need(time.monotonic() < end, 'known_prior_whole30')
    return {'sealed_old_sources': old_sources, 'schema': 'current-prebind-preserved-assets/v4', 'component_version': VERSION, 'state': 'KNOWN_PRIOR_ASSETS_PRESERVED', 'base': str(base), 'prior': prior, 'terminals': terminals, 'empty_failures': empty, 'receipts': receipts, 'inventory': before, 'large_payload_bytes_read': 0, 'current_stage_absence': {'path': str(base / 'stages' / actor['stage_operation']), 'errno': 2}, 'current_socket_absence': {'path': str(base / 'sockets' / (actor['stage_operation'] + '.sock')), 'errno': 2}}

def validate(v, policy, actor, current, frame=None):
    prior = shape(actor['known_prior_assets'], actor['stage_operation'])
    need(v['schema'] == 'current-prebind-preserved-assets/v4' and v['component_version'] == VERSION, 'known_prior_exact_version')
    if v['state'] == 'BASE_ABSENT':
        need(set(v) == {'schema', 'component_version', 'state', 'absence', 'prior'} and (not prior) and (v['prior'] == {}), 'known_prior_first_batch_only_empty')
        a = v['absence']
        need(a['path'] == policy['data_root'] and a['errno'] == 2 and (a['parent']['path'] == str(Path(policy['data_root']).parent)) and (Path(policy['data_root']).name not in a['parent']['entries']), 'known_prior_first_BASE_ENOENT')
        return v
    need(set(v) == {'sealed_old_sources', 'schema', 'component_version', 'state', 'base', 'prior', 'terminals', 'empty_failures', 'receipts', 'inventory', 'large_payload_bytes_read', 'current_stage_absence', 'current_socket_absence'} and v['state'] == 'KNOWN_PRIOR_ASSETS_PRESERVED' and (v['base'] == policy['data_root']) and (v['prior'] == prior) and prior and (type(v['large_payload_bytes_read']) is int) and (v['large_payload_bytes_read'] == 0), 'known_prior_exact_completed_preservation')
    need(v['sealed_old_sources'] == (old_bound()['A_source']['sources'] if any((old_is_prior(s) for s in prior)) else None), 'known_prior_complete_old_A55_preserved_source')
    need(set(v['empty_failures']) == {s for s, row in prior.items() if row['terminal_state'] == 'FAILED_REGISTRY_QUIESCENT'}, 'known_empty_no_omitted_or_unproved_failure')
    need(v['current_stage_absence'] == {'path': policy['data_root'] + '/stages/' + actor['stage_operation'], 'errno': 2} and v['current_socket_absence'] == {'path': policy['data_root'] + '/sockets/' + actor['stage_operation'] + '.sock', 'errno': 2}, 'known_prior_current_positive_absence')
    inv = v['inventory']
    need(type(inv) is dict and 3 <= len(inv) <= 65536 and (inv[policy['data_root']]['entries'] == ['sockets', 'stages']) and (inv[policy['data_root'] + '/stages']['entries'] == sorted(prior)) and (inv[policy['data_root'] + '/sockets']['entries'] == sorted((s + '.sock' for s in prior))), 'known_prior_complete_BASE_roots')
    for path, row in inv.items():
        f = row['F9']
        need(type(path) is str and (path == policy['data_root'] or path.startswith(policy['data_root'] + '/')) and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[3] == f[4] == 0) and (stat.S_ISDIR(f[5]) if row['kind'] == 'directory' else stat.S_ISSOCK(f[5]) if row['kind'] == 'retained-prior-socket' else stat.S_ISREG(f[5])) and (stat.S_IMODE(f[5]) == (448 if row['kind'] == 'directory' else 384)), 'known_prior_typed_full_metadata')
    expected_paths = {policy['data_root'], policy['data_root'] + '/stages', policy['data_root'] + '/sockets'}
    expected_receipts = set()
    for stage, row in prior.items():
        tr = v['terminals'][stage]
        need(tr == {'sha256': row['terminal_sha256'], 'F9': row['A_terminal_F9']}, 'known_prior_A_origin_exact_reference')
        need(ROLE in ('A', 'PC'), 'known_prior_ROLE_SOURCE_None')
        if ROLE == 'A':
            raw, t, _ = terminal(policy, stage, row, current)
        else:
            need(PC_TERMINAL_ROOT is not None, 'known_prior_PC_root_SOURCE_None')
            terminal_path = Path(row['sealed_old_origin']['PC_terminal_path']) if old_is_prior(stage) else Path(PC_TERMINAL_ROOT) / (stage + '.json')
            raw, fs = held(terminal_path, row['terminal_sha256'], mode=288)
            need(fs == row['PC_terminal_F9'], 'known_prior_PC_local_fullraw_F9')
            t = strict(raw)
        if row['terminal_state'] == 'FAILED_REGISTRY_QUIESCENT':
            need(sha(raw) == row['terminal_sha256'] and len(raw) == row['A_terminal_F9'][2], 'known_empty_original_terminal_bytes')
            if old_is_prior(stage):
                old = sealed_old_row(stage, row)
                old_terminal_matches(t, stage, current)
                p = old['A_source']
                c = old['old_current']
            else:
                p, c = (policy, current)
            if old_is_prior(stage) and stage == prefile_APPROVED_HISTORY['stage_operation']:
                expected_paths |= _validate_prefile(v['empty_failures'][stage], p, stage, row, t, current, inv, frame)
            else:
                expected_paths |= _validate_empty(v['empty_failures'][stage], p, stage, row, t, c, inv, frame)
            continue
        need(sha(raw) == row['terminal_sha256'] and len(raw) == row['A_terminal_F9'][2], 'known_prior_same_original_bytes_not_copy_bool')
        need(t['schema'] == 'fixed-image-owned-stage-terminal/v1' and t['state'] == 'ASSET_STAGE_COMPLETED' and (t['stage_operation'] == stage) and (t['config_sha256'] == current['config_sha256']) and (t['source118'] == current['source118']) and (t['review_sha256'] == current['review_sha256']), 'known_prior_same_source_completed_raw')
        rr = t['result_original']
        body = base64.b64decode(rr['raw_b64'], validate=True)
        need(sha(body) == rr['sha256'] and len(body) == rr['stat'][2] and (rr['stat'][3:7] == [0, 0, 33152, 1]), 'known_prior_result_original')
        result = strict(body)
        need(result['schema'] == 'fixed-image-selected-segments-returned/v1' and result['stage_operation'] == stage and (result['retry'] == result['models_started'] == 0) and (result['daemon_started'] is result['image_imported'] is False), 'known_prior_result_no_partial')
        root = policy['data_root'] + '/stages/' + stage
        range_ = root + '/range'
        sock = policy['data_root'] + '/sockets/' + stage + '.sock'
        expected_paths |= {root, range_, sock}
        need(inv[root]['entries'] == ['range'] and inv[sock]['kind'] == 'retained-prior-socket', 'known_prior_exact_stage_root_socket')
        names = inv[range_]['entries']
        need(REGULAR | ARCHIVE_DIRS | {'segments'} <= set(names) and len(names) <= 256 and all((n in REGULAR | ARCHIVE_DIRS | {'segments'} or re.fullmatch('dns-route-[0-9a-f]{32}\\.json', n) for n in names)), 'known_prior_exact_source_names')
        for n in names:
            path = range_ + '/' + n
            expected_paths.add(path)
            if n in ARCHIVE_DIRS:
                need(inv[path]['kind'] == 'directory' and inv[path]['entries'] == [], 'known_prior_empty_archive_no_daemon')
            elif n != 'segments':
                need(inv[path]['kind'] == 'preserved-source-diagnostic' and inv[path]['F9'][2] <= 64 * 1024 ** 2, 'known_prior_diagnostic_typed_metadata')
        segment_names = []
        for ref in result['segments']:
            path = ref['path']
            leaf = ref['digest'] + '.' + str(ref['start']) + '-' + str(ref['start'] + ref['count'] - 1) + '.segment'
            need(path == range_ + '/segments/' + leaf and inv[path] == {'kind': 'accepted-large-segment', 'F9': ref['F9'], 'accepted_SHA256': ref['sha256']}, 'known_prior_large_accepted_SHA_F9_without_rehash')
            receipt_path = path + '.json'
            expected_paths |= {path, receipt_path}
            expected_receipts.add(receipt_path)
            segment_names.extend([leaf, leaf + '.json'])
            z = v['receipts'][receipt_path]
            receipt = receipt_bytes(policy, ref, t)
            need(set(z) == {'sha256', 'F9'} and sha(receipt) == z['sha256'] == ref['receipt_ref']['sha256'] and (z['F9'] == ref['receipt_ref']['F9']) and (len(receipt) == z['F9'][2]) and (z['F9'][3:7] == [0, 0, 33152, 1]) and (inv[receipt_path] == {'kind': 'receipt', 'F9': z['F9'], 'sha256': z['sha256']}), 'known_prior_receipt_full_original_binding')
            q = strict(receipt)
            need(set(q) == {'schema', 'segment', 'operation_family', 'stage_operation', 'source_review_sha256', 'plan_sha256'} and q['schema'] == 'fixed-image-immutable-range-segment/v1' and (q['operation_family'] == t['operation_family']) and (q['stage_operation'] == stage) and (q['source_review_sha256'] == current['review_sha256']) and (q['plan_sha256'] == t['plan_sha256']) and (q['segment'] == {k: ref[k] for k in ('path', 'sha256', 'F9', 'digest', 'start', 'count')}), 'known_prior_receipt_fullraw_matches_terminal')
        need(inv[range_ + '/segments']['entries'] == sorted(segment_names), 'known_prior_exact_accepted_segments')
    need(set(inv) == expected_paths and set(v['receipts']) == expected_receipts and (set(v['terminals']) == set(prior)), 'known_prior_no_omitted_or_foreign_inventory')
    return v
EMPTY_REGULAR = frozenset(('intent.json', 'initial-kernel-unit.json', 'owned-cleanup.json', 'failed.json', 'download-failed.json', 'segments.stdout', 'segments.stderr', 'segment-resources.jsonl'))

def _failed_terminal(v, stage, current):
    need(v['state'] == 'FAILED_REGISTRY_QUIESCENT' and v['stage_operation'] == stage and (v['config_sha256'] == current['config_sha256']) and (v['source118'] == current['source118']) and (v['review_sha256'] == current['review_sha256']) and (v['image_imported'] is False) and (v['models_started'] == 0), 'known_empty_original_same_source_failed_not_success')
    u = v['scope']['unit']
    need(u['Id'] == 'dgx-v4-image-segment-' + stage + '.service' and u['MainPID'] == '0' and (int(u['ExecMainPID']) > 1) and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '1') and (u['ActiveState'] == 'failed') and (v['scope']['cgroup_procs'] == []), 'known_empty_original_actual_started_EXIT1')
    rr = v['result_original']
    body = base64.b64decode(rr['raw_b64'], validate=True)
    need(sha(body) == rr['sha256'] and len(body) == rr['stat'][2] and (rr['stat'][3:7] == [0, 0, 33152, 1]), 'known_empty_full_failure_original')
    result = strict(body)
    need(result['schema'] == 'fixed-image-stage-failed/v1' and result['stage_operation'] == stage and (result['partial_preserved'] is True) and (result['automatic_retry'] is False), 'known_empty_failure_kept_failure_unknown_not_NLA')
    original = v['plan_original']
    raw = base64.b64decode(original['raw_b64'], validate=True)
    need(sha(raw) == original['sha256'] and len(raw) == original['stat'][2], 'known_empty_original_finite_plan')
    p = strict(raw)
    need(len(p['ranges']) == 1 and p['stage_operation'] == stage, 'known_empty_single_fixed_failed_interval')
    return (p['ranges'][0], u)

def _collect_empty(policy, stage, row, v, base, directory, before, end):
    import old_failed_kernel as kernel
    r, u = _failed_terminal(v, stage, {'config_sha256': v['config_sha256'], 'source118': v['source118'], 'review_sha256': v['review_sha256']})
    need(v['scope']['boot_id'] == policy['boot_id'], 'known_empty_same_A_boot')
    root = base / 'stages' / stage
    directory(root, ['range'])
    root = root / 'range'
    names = sorted(os.listdir(root))
    need(EMPTY_REGULAR | ARCHIVE_DIRS | {'segments'} >= set(names) - {n for n in names if re.fullmatch('dns-route-[0-9a-f]{32}\\.json', n)} and {'intent.json', 'initial-kernel-unit.json', 'owned-cleanup.json', 'failed.json', 'segments'} <= set(names) and (len(names) <= 256), 'known_empty_complete_closed_failed_source_names')
    directory(root, names)
    for name in ARCHIVE_DIRS:
        directory(root / name, [])
    leaf = r['digest'] + '.' + str(r['start']) + '-' + str(r['start'] + r['count'] - 1) + '.segment'
    directory(root / 'segments', [leaf])
    path = root / 'segments' / leaf
    s = metadata(path)
    need(s[2] == 0, 'known_empty_actual_zero_not_partial')
    before[str(path)] = {'kind': 'preserved-empty-failed-segment', 'F9': s}
    for name in set(names) - ARCHIVE_DIRS - {'segments'}:
        item = root / name
        f = metadata(item)
        need(f[2] <= 64 * 1024 ** 2, 'known_empty_bounded_diagnostics')
        before[str(item)] = {'kind': 'preserved-source-diagnostic', 'F9': f}
    sock = base / 'sockets' / (stage + '.sock')
    before[str(sock)] = {'kind': 'retained-prior-socket', 'F9': metadata(sock, socket=True)}
    kernel.ALLOWED_UNIT = u['Id']
    k = kernel.kernel_after_stop(u['Id'], int(u['ExecMainPID']), policy['boot_id'], end)
    return {'schema': 'known-prior-preserved-empty-failure/v2', 'stage_operation': stage, 'terminal_sha256': row['terminal_sha256'], 'segment_path': str(path), 'segment_F9': s, 'receipt_absence': primitives.data_absence({'data_root': str(path) + '.json'}), 'daemon_absence': primitives.data_absence({'data_root': str(root / 'containerd.sock')}), 'kernel_original': k, 'accepted_bytes': 0, 'failure_relabelled_success': False}

def _validate_empty(e, policy, stage, row, t, current, inv, frame):
    import old_failed_kernel as kernel
    r, u = _failed_terminal(t, stage, current)
    root = policy['data_root'] + '/stages/' + stage
    range_ = root + '/range'
    sock = policy['data_root'] + '/sockets/' + stage + '.sock'
    leaf = r['digest'] + '.' + str(r['start']) + '-' + str(r['start'] + r['count'] - 1) + '.segment'
    path = range_ + '/segments/' + leaf
    need(set(e) == {'schema', 'stage_operation', 'terminal_sha256', 'segment_path', 'segment_F9', 'receipt_absence', 'daemon_absence', 'kernel_original', 'kernel_recheck_original', 'accepted_bytes', 'failure_relabelled_success'} and e['schema'] == 'known-prior-preserved-empty-failure/v2' and (e['stage_operation'] == stage) and (e['terminal_sha256'] == row['terminal_sha256']) and (e['segment_path'] == path) and (type(e['accepted_bytes']) is int) and (e['accepted_bytes'] == 0) and (e['failure_relabelled_success'] is False), 'known_empty_explicit_type_not_accepted_asset')
    need(e['segment_F9'][2] == 0 and inv[path] == {'kind': 'preserved-empty-failed-segment', 'F9': e['segment_F9']} and (inv[root]['entries'] == ['range']) and (inv[range_ + '/segments']['entries'] == [leaf]) and (inv[sock]['kind'] == 'retained-prior-socket'), 'known_empty_exact_zero_no_receipt_no_extra_segment')
    names = inv[range_]['entries']
    need({'intent.json', 'initial-kernel-unit.json', 'owned-cleanup.json', 'failed.json', 'segments'} <= set(names) and len(names) <= 256 and all((n in EMPTY_REGULAR | ARCHIVE_DIRS | {'segments'} or re.fullmatch('dns-route-[0-9a-f]{32}\\.json', n) for n in names)), 'known_empty_consumer_closed_original_failure_names')
    paths = {root, range_, sock, path}
    for name in names:
        p = range_ + '/' + name
        paths.add(p)
        if name in ARCHIVE_DIRS:
            need(inv[p]['kind'] == 'directory' and inv[p]['entries'] == [], 'known_empty_no_daemon_or_import')
        elif name != 'segments':
            need(inv[p]['kind'] == 'preserved-source-diagnostic' and inv[p]['F9'][2] <= 64 * 1024 ** 2, 'known_empty_metadata_only_diagnostic')
    for a, p in ((e['receipt_absence'], path + '.json'), (e['daemon_absence'], range_ + '/containerd.sock')):
        need(a['path'] == p and a['errno'] == 2 and (a['parent']['path'] == str(Path(p).parent)) and (Path(p).name not in a['parent']['entries']), 'known_empty_positive_absence')
    need(type(frame) in (tuple, list) and len(frame) == 2 and all((type(x) in (int, float) for x in frame)) and (frame[0] <= frame[1]), 'known_empty_actual_A_observation_frame')
    first = e['kernel_original']
    second = e['kernel_recheck_original']
    for k in (first, second):
        kernel.validate_failed_kernel(k, u['Id'], int(u['ExecMainPID']), policy['boot_id'], frame[0])
        need(k['finished_at'] <= frame[1], 'known_empty_both_kernel_within_actual_A_frame')
    need(first['finished_at'] <= second['started_at'], 'known_empty_two_independent_ordered_kernel_observations')
    need(t['scope']['boot_id'] == policy['boot_id'], 'known_empty_historical_worker_same_A_boot')
    return paths

def recheck(first, second):
    """Keep both fresh kernel originals while comparing immutable asset facts.
 Caller owns these collector-local dictionaries; no approved service global is
 changed. Each full kernel frame is independently validated by validate().
 """

    def facts(v):
        out = dict(v)
        if 'empty_failures' in v:
            out['empty_failures'] = {stage: {key: value for key, value in row.items() if key != 'kernel_original'} for stage, row in v['empty_failures'].items()}
        return out
    need(facts(first) == facts(second), 'known_empty_second_full_inventory_source_receipt_unchanged')
    for stage, row in first.get('empty_failures', {}).items():
        need('kernel_recheck_original' not in row and 'kernel_recheck_original' not in second['empty_failures'][stage], 'known_empty_exactly_two_fresh_kernel_observations')
    for stage, row in first.get('empty_failures', {}).items():
        row['kernel_recheck_original'] = second['empty_failures'][stage]['kernel_original']
    return True

def reader_path_root():
    return str(Path(old_bound()['qualified_original']['path']).parent)

def sealed_old_row(stage, row):
    h = old_bound()
    need(stage in h['actors'], 'known_prior_sealed_old_member_only')
    a = h['actors'][stage]
    z = row.get('sealed_old_origin')
    root = reader_path_root()
    need(a['state'] == row['terminal_state'] == 'FAILED_REGISTRY_QUIESCENT' and row['terminal_sha256'] == a['terminal_sha256'] and (z == {'snapshot_sha256': h['snapshot_sha256'], 'PC_terminal_path': root + '/asset-terminals/' + stage + '.json', 'PC_clock_path': root + '/asset-terminal-clocks/' + stage + '/received.json'}), 'known_prior_exact_sealed_old_domain_origin')
    need(row['completed_original'] == {'sha256': a['completed_sha256'], 'F9': a['original_refs']['completed.json']['F9']} and row['fence_original'] == {'sha256': a['fence_sha256'], 'F9': a['original_refs']['fence-released.json']['F9']}, 'known_prior_sealed_old_completed_fence')
    return h

def _prefile_actor(stage, current):
    a = dict(old_bound()['actors'][stage])
    a.pop('state')
    return {'failed_ancestors': {stage: a}, 'current': current}

def _collect_prefile(policy, stage, row, t, base, directory, before, end, current):
    import old_failed_kernel as kernel
    old_terminal_matches(t, stage, current)
    root = base / 'stages' / stage
    directory(root, ['range'])
    ranged = root / 'range'
    d = directory(ranged, sorted(prefile_APPROVED_HISTORY['entries']))
    fd = os.open(ranged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        d['children'] = {n: f9(os.stat(n, dir_fd=fd, follow_symlinks=False)) for n in d['entries']}
        need(d['F9'] == f9(os.fstat(fd)) == f9(ranged.lstat()) and sorted(os.listdir(fd)) == d['entries'], 'known_prefile_complete_metadata_held_named')
    finally:
        os.close(fd)
    for n in d['entries']:
        if n in ARCHIVE_DIRS:
            directory(ranged / n, [])
        else:
            f = metadata(ranged / n)
            need(f[2] <= 64 * 1024 ** 2, 'known_prefile_bounded_diagnostic')
            before[str(ranged / n)] = {'kind': 'preserved-source-diagnostic', 'F9': f}
    sock = base / 'sockets' / (stage + '.sock')
    sf = metadata(sock, socket=True)
    before[str(sock)] = {'kind': 'retained-prior-socket', 'F9': sf}
    ar = _prefile_actor(stage, current)
    proof = {'terminal_ref': {'path': policy['source_root'] + '/stages/' + stage + '/terminal-qualified.json', 'sha256': row['terminal_sha256'], 'F9': row['A_terminal_F9']}, 'pre_file_absence': prefile_capture(stage, ar, policy, d, {str(ranged): d}, encode(t), row['A_terminal_F9'], primitives.data_absence), 'daemon_socket_absence': primitives.data_absence({'data_root': str(ranged / 'containerd.sock')}), 'retained_socket': {'path': str(sock), 'F9': sf}}
    prefile_validate(proof, stage, ar, policy, {str(ranged): d})
    u = t['scope']['unit']
    kernel.ALLOWED_UNIT = u['Id']
    k = kernel.kernel_after_stop(u['Id'], int(u['ExecMainPID']), policy['boot_id'], end)
    return {'schema': 'known-prior-preserved-prefile-failure/v1', 'proof': proof, 'directory': d, 'kernel_original': k, 'accepted_bytes': 0, 'failure_relabelled_success': False}

def _validate_prefile(e, policy, stage, row, t, current, inv, frame):
    import old_failed_kernel as kernel
    need(set(e) == {'schema', 'proof', 'directory', 'kernel_original', 'kernel_recheck_original', 'accepted_bytes', 'failure_relabelled_success'} and e['schema'] == 'known-prior-preserved-prefile-failure/v1' and (type(e['accepted_bytes']) is int) and (e['accepted_bytes'] == 0) and (e['failure_relabelled_success'] is False), 'known_prefile_explicit_failed_preservation_type')
    old_terminal_matches(t, stage, current)
    root = policy['data_root'] + '/stages/' + stage
    ranged = root + '/range'
    sock = policy['data_root'] + '/sockets/' + stage + '.sock'
    d = e['directory']
    p = e['proof']
    prefile_validate(p, stage, _prefile_actor(stage, current), policy, {ranged: d})
    need(p['terminal_ref'] == {'path': policy['source_root'] + '/stages/' + stage + '/terminal-qualified.json', 'sha256': row['terminal_sha256'], 'F9': row['A_terminal_F9']} and inv[root]['entries'] == ['range'] and (inv[ranged] == {'kind': 'directory', 'F9': d['F9'], 'entries': d['entries']}) and (inv[sock] == {'kind': 'retained-prior-socket', 'F9': p['retained_socket']['F9']}), 'known_prefile_exact_inventory_and_origins')
    missing = p['daemon_socket_absence']
    need(missing['path'] == ranged + '/containerd.sock' and missing['errno'] == 2 and (missing['parent']['path'] == ranged) and (missing['parent']['F9'] == d['F9']) and (missing['parent']['entries'] == d['entries']), 'known_prefile_fresh_daemon_positive_absence')
    paths = {root, ranged, sock}
    for n in d['entries']:
        path = ranged + '/' + n
        paths.add(path)
        z = inv[path]
        need(z['F9'] == d['children'][n], 'known_prefile_full_child_metadata')
        if n in ARCHIVE_DIRS:
            need(z['kind'] == 'directory' and z['entries'] == [], 'known_prefile_archive_empty')
        else:
            need(z['kind'] == 'preserved-source-diagnostic' and z['F9'][2] <= 64 * 1024 ** 2, 'known_prefile_diagnostic_only')
    need(type(frame) in (tuple, list) and len(frame) == 2 and (frame[0] <= frame[1]), 'known_prefile_actual_A_frame')
    u = t['scope']['unit']
    first = e['kernel_original']
    second = e['kernel_recheck_original']
    for k in (first, second):
        kernel.validate_failed_kernel(k, u['Id'], int(u['ExecMainPID']), policy['boot_id'], frame[0])
        need(k['finished_at'] <= frame[1], 'known_prefile_two_actual_kernels_within_outer_frame')
    need(first['finished_at'] <= second['started_at'] and t['scope']['boot_id'] == policy['boot_id'], 'known_prefile_same_boot_ordered_kernel')
    return paths
