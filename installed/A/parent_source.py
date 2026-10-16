# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Current PC typed Root-qualified originals; never use oldnegative as newPID."""
import base64
import plan
from root_io import sha
APPROVED_PC_QUALIFIER_SHA = '217a5cb2fd3970678f98da5feaa934aa53d249ec372a2db946914b4d75df0a1e'
APPROVED_PC_WORKER_SHA = '9dfad7bd5c531ce5ddc05b57383f43c4b282a05a954cf975df190eb06a487350'
APPROVED_RPC_SOURCE_SHA = None

def qualified_PC(value, c, review=None):
    plan.need(review is not None and c['review_sha256'] == review, 'current_PC_Source_None')
    qualifier = value['qualifier_source']
    worker = value['worker_source']
    plan.need(APPROVED_PC_QUALIFIER_SHA is not None and APPROVED_PC_WORKER_SHA is not None and (qualifier['sha256'] == APPROVED_PC_QUALIFIER_SHA) and (worker['sha256'] == APPROVED_PC_WORKER_SHA), 'fixed_actual_PC_epoch_qualification_producer')
    plan.need(qualifier['stat'][3:7] == [0, 989, 33056, 1] or qualifier['stat'][3:7] == [0, 0, 33152, 1], 'Root_qualifier_source_origin')
    plan.need(worker['stat'][3:7] in ([0, 989, 33056, 1], [0, 0, 33152, 1]), 'Root_worker_source_origin')
    raw = base64.b64decode(value['qualified_raw_b64'], validate=True)
    done = base64.b64decode(value['completed_raw_b64'], validate=True)
    cfg = base64.b64decode(value['config_raw_b64'], validate=True)
    v, d = (plan.strict(raw), plan.strict(done))
    plan.need(sha(raw) == value['qualified_sha256'] and sha(done) == value['completed_sha256'] and (value['qualified_F9'][2] == len(raw)) and (value['qualified_F9'][3:7] == [0, 989, 33056, 1]) and (value['completed_F9'][3:7] == [0, 989, 33056, 1]), 'true_Root_current_origins_not_usercopy')
    plan.need(plan.strict(cfg)['review_sha256'] == review and v['schema'] == 'registry-R26-current118-source-qualified/v1' and (d['schema'] == 'registry-R26-current118-qualified-completed/v1') and (v['qualifier_sha256'] == d['qualifier_sha256'] == qualifier['sha256']) and (d['receipt_sha256'] == sha(raw)), 'new_PC_qualification_exact_source_and_result')
    plan.need(v['current']['manager_identity'] == d['manager_identity'] == value['manager_identity'] == c['manager_identity'] and v['current']['current_source118'] == c['current_PC_source118'] == plan.strict(cfg)['PC_source_pins'] and (v['current']['config_sha256'] == c['PC_config_sha256'] == sha(cfg)) and (v['current']['lease_dev_inode'] == [2096, 69257]) and (value['RPC_source_sha256'] == c['PC_root_rpc_source_sha256'] == value['RPC_source_sha256']), 'independent_newsource_sole_owner_originallease')
    from pc_managed_scope import positive
    positive(v['actual_installer_scope'], v['returned_original'], worker['sha256'])
    plan.need(v['observed_at'] <= d['observed_at'] <= value['observed_at'], 'historical_real_qualification_times_not_refreshed')
    return v
