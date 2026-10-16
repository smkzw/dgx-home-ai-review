# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Publish only a complete parent-bound pair; receipt sources are trusted, immutable metadata."""
import hashlib
import os
from pathlib import Path
import re
import stat
from G7_INTEGRATION_CANDIDATE_R1 import cache_checks as checks
from .durable import need, publish_exclusive, private_dir, digest
KINDS = {'model', 'engram', 'kit', 'engine', 'python'}

def load_receipt(path, expected_sha):
    p = Path(path)
    for q in (p, *p.parents):
        need(not q.is_symlink(), 'receipt_symlink')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and (not before.st_mode & 18) and (before.st_size <= 1048576), 'root_readonly_receipt')
        raw = f.read(1048577)
        need(checks.identity(before) == checks.identity(os.fstat(f.fileno())) == checks.identity(p.stat()), 'receipt_changed')
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'actual_receipt_SHA')
    return checks.strict(raw)

def validate_rank(v, *, node, run_id, generation, input_identity):
    need(isinstance(v, dict) and v.get('schema') == 'g7-native-rank-verification-r2/v1' and (v.get('verified') is True), 'actual_rank_receipt_required')
    from G7_INTEGRATION_CANDIDATE_R1.compiler import paths
    need(node in ('spark-a', 'spark-b'), 'only_AB_node')
    rank = 0 if node == 'spark-a' else 1
    fixed = paths(run_id, node)
    need(all((v.get(k) == fixed[j] for k, j in (('model_path', 'model'), ('cache_path', 'rank_cache'), ('engram_path', 'engram')))), 'fixed_native_tool_paths')
    need(v.get('node') == node and type(v.get('rank')) is int and (v['rank'] == rank) and (v.get('run_id') == run_id), 'exact_node_rank_run')
    need(v.get('owner') == 'dgx-hx-service' and type(v.get('generation')) is int and (v['generation'] == generation), 'exact_owner_generation')
    need(v.get('input_identity') == input_identity, 'exact_full_input_identity')
    need(v.get('local_stopped_fence_before') == v.get('local_stopped_fence_after') and isinstance(v.get('local_stopped_fence_before'), dict), 'same_stopped_fence')
    fence = v['local_stopped_fence_before']
    need(fence.get('profile') == 'deepseek-cacheprep-ab' and fence.get('owner') == 'dgx-hx-service' and (type(fence.get('generation')) is int) and (fence['generation'] == generation) and (fence.get('state') == 'STOPPED'), 'actual_stopped_identity')
    need(v.get('gpu_empty_before') is True and v.get('gpu_empty_after') is True, 'complete_actual_GPU_clear')
    inputs = v.get('inputs')
    need(isinstance(inputs, dict) and set(inputs) == KINDS, 'all_full_input_sets')
    expected_keys = {'model': 'model_manifest_sha256', 'engram': 'engram_manifest_sha256', 'kit': 'kit_manifest_sha256', 'python': 'python_source_sha256', 'engine': 'engine_acceptance_sha256'}
    for kind in sorted(KINDS):
        r = inputs[kind]
        need(isinstance(r, dict) and r.get('manifest_sha256') == input_identity[expected_keys[kind]] and (r.get('all_full_sha_verified') is True) and (r.get('immutable_root_owned') is True), 'complete_full_input_verification')
        rows = r.get('files')
        need(isinstance(rows, list) and rows and (len(rows) <= 5000), 'bounded_complete_input_rows')
        names = set()
        for row in rows:
            need(set(row) == {'path', 'size', 'sha256', 'mtime_ns', 'ctime_ns', 'dev', 'inode', 'mode', 'uid'}, 'held_input_identity_fields')
            need(isinstance(row['path'], str) and row['path'] not in names and (not Path(row['path']).is_absolute()) and ('..' not in Path(row['path']).parts), 'unique_relative_input')
            names.add(row['path'])
            need(type(row['size']) is int and row['size'] >= 0 and re.fullmatch('[0-9a-f]{64}', row['sha256']) and (type(row['uid']) is int) and (row['uid'] == 0) and (type(row['mode']) is int) and (not row['mode'] & 146), 'immutable_full_input_row')
            need(all((type(row[k]) is int and row[k] >= 0 for k in ('mtime_ns', 'ctime_ns', 'dev', 'inode'))), 'actual_input_stat')
        need(r.get('files_digest') == digest(rows), 'full_input_rows_digest')
    need(len(inputs['engine']['files']) == 34 and len(inputs['python']['files']) == 1014 and (len(inputs['kit']['files']) == 222) and (len(inputs['model']['files']) == 49) and (len(inputs['engram']['files']) == 4), 'fixed_complete_file_counts')
    from .source_inputs import verify_rows
    for kind in ('model', 'engram', 'kit', 'python'):
        verify_rows(kind, inputs[kind]['files'])
        need(inputs[kind].get('official_Gitblob_LFS_identity_verified') is True, 'official_nonLFS_Gitblob_verification_required')
    from G7_INTEGRATION_CANDIDATE_R1.compiler import copy_plan
    actual = {r['path']: (r['size'], r['sha256']) for r in copy_plan()['files']}
    need({r['path']: (r['size'], r['sha256']) for r in inputs['engine']['files']} == actual, 'all_actual_34_engine_files')
    e = {x['path']: x['sha256'] for x in inputs['engine']['files']}
    need(e.get('native/bin/tensorfold-native') == 'c4c8343a42638d81a54b60c4d3cc28155e9e2b9fa745b7237775639d4095059c' and e.get('bin/tf-dsv41-check') == checks.CHECK_SHA, 'actual_native_engine_and_checker')
    cache = v.get('cache')
    need(isinstance(cache, dict) and re.fullmatch('rank' + str(rank) + 'of2-[0-9a-f]{20}\\.bin', cache.get('file', '')) and (cache.get('immutable_root_owned') is True) and re.fullmatch('[0-9a-f]{64}', cache.get('sha256', '')), 'sealed_complete_cache')
    need(type(cache.get('size')) is int and 16 <= cache['size'] <= checks.MAX_CACHE and (type(cache.get('entries')) is int) and (cache['entries'] > 0) and (type(cache.get('bytes')) is int) and (0 < cache['bytes'] < cache['size']) and (type(cache.get('index_at')) is int) and (cache['index_at'] == cache['bytes']), 'cache_bounds')
    tm = v.get('token_map')
    need(isinstance(tm, dict) and tm.get('sha256') == checks.TOKEN_SHA == input_identity['token_map_sha256'] and (tm.get('length') == 129280) and (tm.get('immutable_root_owned') is True) and (tm.get('config_vocab_matched') is True), 'actual_fixed_map_and_config_vocab')
    checks.verify_native_check(v['native_check'], cache, rank, checks.CHECK_SHA, v['model_path'], v['cache_path'])
    engram = v.get('native_engram_check')
    need(isinstance(engram, dict) and engram.get('rc') == 0 and (type(engram['rc']) is int) and (engram.get('binary_sha256') == e.get('bin/tf-dsv41-engram-check')) and (engram.get('argv') == [v['engram_path']]), 'exact_engram_native_check')
    raw = engram.get('stdout')
    need(isinstance(raw, str) and len(raw.encode()) <= 65536, 'bounded_engram_JSONL')
    lines = [checks.strict(line) for line in raw.splitlines() if line.strip()]
    need(len(lines) == 3 and lines[-1].get('layers') == 2 and (lines[-1].get('all_equal') is True), 'actual_engram_summary')
    need(all((type(r.get('layer')) is int for r in lines[:2])) and {r.get('layer') for r in lines[:2]} == {1, 14}, 'actual_engram_layers')
    for row in lines[:2]:
        need(all((type(row.get(k)) is int and row[k] > 0 for k in ('row_w', 'row_s'))), 'actual_engram_row_shape')
        need(row.get('rows') == 4096 and row.get('direct_equal') is True and (row.get('aio_equal') is True) and (row.get('direct_fds') is True), 'actual_engram_three_path_consistency')
        need(all((type(row.get(k)) in (int, float) and __import__('math').isfinite(row[k]) and (row[k] >= 0) for k in ('buffered_ms', 'direct_ms', 'aio_ms'))), 'actual_engram_timings')
    return v

def publish(config, generation, *, held_guard, loader=load_receipt):
    held_guard()
    receipts = {n: validate_rank(loader(r['path'], r['sha256']), node=n, run_id=config['run_id'], generation=generation, input_identity=config['input_identity']) for n, r in config['rank_receipts'].items()}
    need(set(receipts) == {'spark-a', 'spark-b'}, 'two_rank_pair')
    need(receipts['spark-a']['token_map']['sha256'] == receipts['spark-b']['token_map']['sha256'], 'same_RO_map')
    held_guard()
    root = private_dir(config['publication_root'])
    target = root / (config['run_id'] + '.json')
    result = {'schema': 'g7-accepted-cache-pair-r2/v1', 'run_id': config['run_id'], 'owner': 'dgx-hx-service', 'generation': generation, 'input_identity': config['input_identity'], 'rank_receipt_sha256': {n: r['sha256'] for n, r in config['rank_receipts'].items()}, 'ranks': receipts, 'cache_accepted': True, 'serving_accepted': False}
    h = publish_exclusive(target, result)
    return {'pair_receipt_sha256': h, 'pair_receipt': str(target), 'cache_accepted': True, 'serving_accepted': False}
