# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root-controlled evidence config; no request-supplied path/threshold/receipt."""
from pathlib import Path
import re
from deployment_integrations.composition import _read_trusted_json
from G7_INTEGRATION_CANDIDATE_R2.durable import need
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
PATH = Path('/etc/dgx-home-ai/g7-qualification-verification.json')
KEYS = {'schema', 'enabled', 'parent_accepted', 'caller_owner', 'run_id', 'run_root', 'qualification_run_root', 'publication_root', 'permit_sha256', 'input_identity', 'rank_receipts'}

def validate(v):
    need(type(v) is dict and set(v) == KEYS and (v['schema'] == 'g7-private-qualification-verification-qv1/v1'), 'verification_config_schema')
    need(type(v['enabled']) is bool and type(v['parent_accepted']) is bool, 'explicit_source_native_gates')
    need(type(v['caller_owner']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', v['caller_owner']), 'fixed_authenticated_owner')
    run = v['run_id']
    need(type(run) is str and re.fullmatch('[0-9a-f]{32}', run), 'fixed_run')
    base = Path('/srv/dgx-home-ai/runtime/hx-service-state/g7')
    for k, prefix in [('run_root', 'qualification-verification'), ('qualification_run_root', 'qualification'), ('publication_root', 'qualified-cache-pairs')]:
        need(type(v[k]) is str and Path(v[k]) == base / prefix / run, 'fixed_existing_unit_RW_namespace')
    qp.sha(v['permit_sha256'])
    need(type(v['input_identity']) is dict and set(v['input_identity']) == qp.INPUTS, 'qualification_inputs_without_fake_calibration')
    for k, h in v['input_identity'].items():
        if k == 'copy_receipts_sha256':
            need(type(h) is dict and set(h) == set(qp.c.NODES), 'AB_copy_receipts')
            for x in h.values():
                qp.sha(x)
        else:
            qp.sha(h)
    need(type(v['rank_receipts']) is dict and set(v['rank_receipts']) == set(qp.c.NODES), 'AB_result_bindings')
    for r in v['rank_receipts'].values():
        need(type(r) is dict and set(r) == {'path', 'sha256'}, 'actual_root_rank_result_binding')
        qp.sha(r['sha256'])
        p = Path(r['path'])
        need(p.parent.parent == Path('/srv/dgx-home-ai/runtime/hx-service-state/g7/root-receipts') and p.name == 'result.json' and re.fullmatch('[0-9a-f]{32}', p.parent.name), 'fixed_HX_root_readonly_receipt_namespace')
    return v

def load():
    return validate(_read_trusted_json(PATH, 'private qualification verification config'))
