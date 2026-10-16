# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Service-readable Root qualification of FULL frozen ancestor oldcfg/oldPID originals.
Root producer executes both original epoch.consume and consume_negative before
publishing this archive. Service never impersonates Root to read private scopes.
"""
from pathlib import Path
from managed_scope import positive
from contract import need, sha, strict, encode, PC_ROOT, CPU_ROOT, LEASE, ANCESTOR_SPEC, HISTORY_UNIT
APPROVED_ANCESTOR_SHA = 'd424bc57057ee10ae9e65717e7bad254e562bc9a5e5222f6463cd39d2d174de5'
APPROVED_ANCESTOR_PRODUCER_SHA = 'aa6d7c1b4455111158dfe4614fac0dd649c078df8ed2faa282d98c19f2459abd'
APPROVED_ANCESTOR_SCOPE_SHA = None
HISTORICAL_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26')
INDEX = HISTORICAL_ROOT / 'historical/qualified.json'
DONE = HISTORICAL_ROOT / 'historical/completed.json'

def root(read, path, cap=4194304):
    raw, f9 = read(path, limit=cap)
    need(type(f9) is list and len(f9) == 9 and (f9[2] == len(raw)) and (f9[3:7] == [0, 989, 33056, 1]), 'held_Root_readable_ancestor_raw_F9')
    return (raw, f9)

def consume(read, oldcfg_raw, old_identity, now):
    need(APPROVED_ANCESTOR_SHA is not None and APPROVED_ANCESTOR_PRODUCER_SHA is not None and (APPROVED_ANCESTOR_SCOPE_SHA is not None), 'real_frozen_ancestor_qualification_pending')
    raw, st = root(read, INDEX)
    done, ds = root(read, DONE)
    q, c = (strict(raw), strict(done))
    need(sha(raw) == APPROVED_ANCESTOR_SHA and q['schema'] == 'registry-R26-historical-qualified/v1' and (c['schema'] == 'registry-R26-historical-completed/v1') and (c['qualified_sha256'] == sha(raw)) and (q['producer_sha256'] == c['producer_sha256'] == APPROVED_ANCESTOR_PRODUCER_SHA), 'actual_fixed_ancestor_source_qualified')
    need(q['old_config_sha256'] == sha(oldcfg_raw) and q['old_manager_identity'] == old_identity and (q['old_source118'] == strict(oldcfg_raw)['PC_source_pins']) and (len(q['old_source118']) == 118) and (q['negative_state'] == 'NEGATIVE_RELEASED') and (q['CPU_success'] is False) and (ANCESTOR_SPEC is not None) and (q['ancestor_epoch_schema'] == ANCESTOR_SPEC['epoch_schema']) and (q['ancestor_root'] == ANCESTOR_SPEC['epoch_root']) and (q['physical_lease'] == LEASE) and (q['old_failures_preserved'] is True), 'old_ancestor_not_NEW_source_or_PID')
    need(q['observed_at'] <= c['observed_at'] <= now, 'ancestor_history_nonfuture_no_refresh')
    positive(q['actual_readonly_scope'], q['returned_original'], APPROVED_ANCESTOR_SCOPE_SHA, unit=HISTORY_UNIT, operation='d150ba0068787c05e4d8877442840d9f')
    need(q['returned_original']['result']['qualified_body_sha256'] == q['qualified_body_sha256'], 'actual_readonly_worker_result_bound')
    required = {'ancestor-epoch', 'ancestor-epoch-completed', 'negative', 'negative-completed', 'old-config'}
    need(required <= set(q['originals']) and len(q['originals']) <= 128, 'complete_bounded_ancestor_originals')
    total = 0
    for name, item in q['originals'].items():
        need('/' not in name and name not in ('.', '..'), 'archive_fixed_leaf_name')
        body, meta = root(read, HISTORICAL_ROOT / 'historical/raw' / name)
        total += len(body)
        need(total <= 32 * 1024 ** 2, 'bounded_historical_raw_total')
        need(sha(body) == item['sha256'] and meta == item['mirror_F9'] and (len(item['origin_F9']) == 9) and (item['origin_F9'][2] == len(body)) and (item['origin_F9'][6] == 1), 'original_raw_and_actual_mirror_F9_not_origin_substitution')
    need(q['originals']['old-config']['sha256'] == sha(oldcfg_raw), 'actual_old_config_archive_source')
    return {'state': 'NEGATIVE_RELEASED', 'CPU_success': False, 'historical_only': True, 'requires_caller_fresh_current_idle': True, 'old_config_sha256': sha(oldcfg_raw), 'old_manager_identity': old_identity, 'old_source118': q['old_source118'], 'ancestor_sha256': sha(raw), 'receipt_sha256': q['originals']['negative']['sha256'], 'qualified_F9': st, 'completed_F9': ds}
