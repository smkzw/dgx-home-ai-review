# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Internal service config adapter; no RPC/caller supplied delta authority."""
import re
import source_delta
from contract import need, sha, encode, strict, CONFIG, APPROVED_DELTA_POLICY

def approved_from_internal_config(internal_config):
    p = APPROVED_DELTA_POLICY
    need(p is not None, 'service_delta_policy_SOURCE_pending')
    need(type(internal_config) is dict and type(internal_config.get('_config_sha256')) is str and re.fullmatch('[0-9a-f]{64}', internal_config['_config_sha256']), 'internal_Root_loaded_config_identity_required')
    new = {k: v for k, v in internal_config.items() if k != '_config_sha256'}
    old = p['old_config']
    newmap = new['PC_source_pins']
    oldmap = old['PC_source_pins']
    need(set(new) == set(old) and {k for k in new if new[k] != old[k]} == {'PC_source_pins', 'review_sha256'} and (new['review_sha256'] == p['review_sha256']), 'internal_config_scope_only_pins_review')
    need(type(newmap) is dict and set(newmap) == set(oldmap) and (len(newmap) == 118) and ({k for k in oldmap if oldmap[k] != newmap[k]} == set(p['changed_paths'])), 'service_exact_changed6_complement112')
    for path, pin in p['fixed_five_new_sha256'].items():
        need(newmap[path] == pin, 'service_fixed_five_accepted_bytes')
    need(all((type(x) is str and re.fullmatch('[0-9a-f]{64}', x) for x in newmap.values())), 'service_full118_SHA_types')
    sources = [dict(row, new_sha256=newmap[row['path']]) for row in p['old_sources']]
    return {'schema': source_delta.SCHEMA, 'sources': sources, 'config': dict(p['old_config_leaf'], new_sha256=internal_config['_config_sha256'])}

def verify_installed(installed, internal_config):
    approved = approved_from_internal_config(internal_config)
    need(installed['before']['current_source118'] == APPROVED_DELTA_POLICY['old_config']['PC_source_pins'], 'service_old118_exact_static_policy')
    need(installed['current']['current_source118'] == internal_config['PC_source_pins'] and installed['current']['config_sha256'] == internal_config['_config_sha256'], 'service_current_config_Root_binding')
    return source_delta.verify_installed(installed, approved)
