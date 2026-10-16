# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict additional root-0440 config; no production schema or registry expansion."""
import re
from pathlib import Path
from deployment_integrations.composition import _read_trusted_json
from .durable import need, digest
SCHEMA = 'g7-private-maintenance-r2/v1'
KEYS = {'schema', 'enabled', 'caller_owner', 'run_id', 'run_root', 'publication_root', 'binding', 'rank_receipts', 'input_identity'}

def validate(v):
    need(isinstance(v, dict) and set(v) == KEYS and (v['schema'] == SCHEMA), 'maintenance_config_schema')
    need(type(v['enabled']) is bool, 'explicit_enable')
    need(isinstance(v['caller_owner'], str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', v['caller_owner']), 'fixed_caller_owner')
    need(isinstance(v['run_id'], str) and re.fullmatch('[0-9a-f]{32}', v['run_id']), 'fixed_run_id')
    for name in ('run_root', 'publication_root'):
        p = Path(v[name])
        need(p.is_absolute() and '..' not in p.parts and str(p).startswith('/srv/dgx-home-ai/runtime/hx-service-state/g7/'), 'existing_unit_RW_state_root_only')
    need(isinstance(v['binding'], dict) and isinstance(v['input_identity'], dict), 'bound_qualification_and_full_input_identity')
    need(set(v['rank_receipts']) == {'spark-a', 'spark-b'}, 'both_rank_receipts')
    for r in v['rank_receipts'].values():
        need(isinstance(r, dict) and set(r) == {'path', 'sha256'}, 'rank_receipt_binding')
        need(isinstance(r['path'], str) and Path(r['path']).is_absolute() and ('..' not in Path(r['path']).parts), 'absolute_receipt')
        need(isinstance(r['sha256'], str) and re.fullmatch('[0-9a-f]{64}', r['sha256']), 'actual_receipt_SHA_required')
    required = {'engine_acceptance_sha256', 'python_source_sha256', 'model_manifest_sha256', 'engram_manifest_sha256', 'kit_manifest_sha256', 'environment_receipt_sha256', 'calibration_receipt_sha256', 'token_map_sha256', 'rdma_receipt_sha256', 'copy_receipts_sha256'}
    need(set(v['input_identity']) == required, 'exact_complete_input_identity')
    for k, h in v['input_identity'].items():
        if k == 'copy_receipts_sha256':
            need(isinstance(h, dict) and set(h) == {'spark-a', 'spark-b'} and all((isinstance(x, str) and re.fullmatch('[0-9a-f]{64}', x) for x in h.values())), 'actual_AB_copy_receipts')
        else:
            need(isinstance(h, str) and re.fullmatch('[0-9a-f]{64}', h), 'actual_input_receipt_SHA')
    from G7_INTEGRATION_CANDIDATE_R1.cache_checks import TOKEN_SHA
    need(v['input_identity']['token_map_sha256'] == TOKEN_SHA, 'fixed_actual_map_raw_SHA')
    need(v['input_identity']['engine_acceptance_sha256'] == 'b1f0aa8e42e9bf7bcf053f5a09cdfe4a7dbd4e44dc8bf819f994ff1a0a232fac', 'fixed_actual_R8b_acceptance')
    need(v['input_identity']['python_source_sha256'] == '24c99a85bccbc9364e59f3687c721eacd9964bf9f3def6c5638053c59c5977f2', 'fixed_official_Python_source')
    return v

def load(path):
    return validate(_read_trusted_json(Path(path), 'private G7 maintenance config'))
