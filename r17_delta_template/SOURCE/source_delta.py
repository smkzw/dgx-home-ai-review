# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure explicit existing-leaf CAS contract; no IO, authority or cached verdicts."""
import re
from pathlib import Path
from contract import need, sha, strict, CONFIG
SCHEMA = 'registry-explicit-source-delta/v1'
INSTALLED = 'registry-R26-PC-installed-unqualified/v2'
QUALIFIED = 'registry-R26-current118-source-qualified/v2'
COMPLETED = 'registry-R26-current118-qualified-completed/v2'

def f9(v):
    need(type(v) is list and len(v) == 9 and all((type(x) is int for x in v)), 'delta_full_F9_type')
    need(v[0] >= 0 and v[1] > 0 and (v[2] >= 0) and (v[3] == 0) and (v[6] == 1) and (v[5] & 61440 == 32768) and (v[5] & 18 == 0), 'delta_root_regular_not_writable')
    return v

def descriptor(v):
    need(type(v) is dict and set(v) == {'path', 'old_sha256', 'old_stat', 'new_sha256'}, 'delta_exact_descriptor')
    need(type(v['path']) is str and str(Path(v['path'])) == v['path'] and Path(v['path']).is_absolute() and ('..' not in Path(v['path']).parts), 'delta_canonical_existing_path')
    need(all((type(v[k]) is str and re.fullmatch('[0-9a-f]{64}', v[k]) for k in ('old_sha256', 'new_sha256'))) and v['old_sha256'] != v['new_sha256'], 'delta_real_sha_change')
    f9(v['old_stat'])
    return v

def checked(p, approved):
    need(approved is not None, 'explicit_delta_SOURCE_pending')
    d = p['source_delta']
    need(type(d) is dict and set(d) == {'schema', 'sources', 'config'} and (d['schema'] == SCHEMA) and (d == approved), 'exact_source_approved_delta_not_body_authority')
    need(type(d['sources']) is list and 1 <= len(d['sources']) <= 118, 'delta_finite_existing_sources')
    rows = [descriptor(x) for x in d['sources']]
    names = [x['path'] for x in rows]
    need(names == sorted(set(names)) and d['config']['path'] == str(CONFIG) and (str(CONFIG) not in names), 'delta_order_unique_config_last')
    descriptor(d['config'])
    old, new = (p['oldmap'], p['newmap'])
    need(type(old) is dict and type(new) is dict and (len(old) == len(new) == 118) and (set(old) == set(new)), 'delta_same_complete118')
    need({k for k in old if old[k] != new[k]} == set(names), 'delta_exact_newmap_difference')
    payload = p['changed_source_raw_utf8']
    need(type(payload) is dict and set(payload) == set(names), 'delta_exact_payload_set')
    for row in rows:
        name = row['path']
        need(old[name] == row['old_sha256'] and new[name] == row['new_sha256'] and (type(payload[name]) is str) and (sha(payload[name].encode()) == row['new_sha256']), 'delta_source_bytes_pins')
    c = d['config']
    need(c['old_sha256'] == sha(p['old_config_raw_utf8'].encode()) and c['new_sha256'] == sha(p['new_config_raw_utf8'].encode()), 'delta_exact_config_bytes')
    need(strict(p['old_config_raw_utf8'])['PC_source_pins'] == old and strict(p['new_config_raw_utf8'])['PC_source_pins'] == new, 'delta_config_fullmaps')
    return d

def targets(p, approved):
    d = checked(p, approved)
    return [(Path(x['path']), p['changed_source_raw_utf8'][x['path']].encode(), x) for x in d['sources']] + [(CONFIG, p['new_config_raw_utf8'].encode(), d['config'])]

def before_matches(before, d):
    need(set(before['source_files']) == set(before['current_source118']) and len(before['source_files']) == 118, 'delta_before_full118')
    for name, pin in before['current_source118'].items():
        need(before['source_files'][name]['sha256'] == pin, 'delta_before_all_SHA')
    for row in d['sources']:
        need(before['source_files'][row['path']] == {'sha256': row['old_sha256'], 'stat': row['old_stat']}, 'delta_old_source_exact_SHA_F9')
    need(before['config_sha256'] == d['config']['old_sha256'] and before['config_stat'] == d['config']['old_stat'], 'delta_old_config_exact_SHA_F9')

def transition(before, after, d):
    need(d is not None, 'explicit_delta_transition_pending')
    before_matches(before, d)
    changed = {x['path']: x for x in d['sources']}
    old = before['current_source118']
    new = dict(old, **{k: x['new_sha256'] for k, x in changed.items()})
    need(after['current_source118'] == new and set(after['source_files']) == set(old), 'delta_after_complete118')
    for name, pin in new.items():
        leaf = after['source_files'][name]
        need(set(leaf) == {'sha256', 'stat'} and leaf['sha256'] == pin, 'delta_new_source_SHA')
        if name not in changed:
            need(leaf == before['source_files'][name], 'delta_full_complement_F9')
        else:
            f9(leaf['stat'])
            need(leaf['stat'][3:7] == changed[name]['old_stat'][3:7] and leaf['stat'][:2] != changed[name]['old_stat'][:2], 'delta_changed_atomic_identity_preserve_permissions')
    f9(after['config_stat'])
    need(after['config_sha256'] == d['config']['new_sha256'] and after['config_stat'][3:7] == d['config']['old_stat'][3:7] and (after['config_stat'][:2] != d['config']['old_stat'][:2]), 'delta_new_config_identity_permissions')
    return len(old) - len(changed)

def verify_installed(inst, approved):
    need(approved is not None and inst['schema'] == INSTALLED and (inst['source_delta'] == approved), 'delta_installed_v2_exact_static_contract')
    d = inst['source_delta']
    before, after = (inst['before'], inst['current'])
    count = transition(before, after, d)
    rows = d['sources'] + [d['config']]
    need(type(inst['CAS_calls']) is int and inst['CAS_calls'] == len(rows) and (inst['unchanged_source_count'] == count) and ('other117_metadata_unchanged' not in inst), 'delta_actual_counts_no_legacy_boolean')
    expected = []
    for row in rows:
        newstat = after['config_stat'] if row['path'] == str(CONFIG) else after['source_files'][row['path']]['stat']
        expected.append(dict(row, new_stat=newstat))
    need(inst['cas_originals'] == expected, 'delta_all_actual_CAS_originals_order_F9')
    need(inst['normal_stop_calls'] == inst['normal_start_calls'] == 1 and type(inst['normal_stop_calls']) is int and (type(inst['normal_start_calls']) is int) and (type(inst['socket_unlink_calls']) is int) and (inst['socket_unlink_calls'] in (0, 1)) and (inst['models_started'] == 0), 'delta_preserved_finite_stop_start_no_model')
    return count
