# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact v2 integration, private actor validator from the one late factory."""
from source_io import base, bind, sha, need, load_source, HERE
import policy as P
import integrate_current
import component_source, history_binding

def derive_prebind(raw):
    s = raw.decode()
    a = 'import current_negative as negative\n'
    need(s.count(a) == 1, 'one_current_prebind_contract_import')
    s = s.replace(a, a + 'from contract import OPERATION\n', 1)
    a = "'operation':negative.OPERATION"
    need(s.count(a) == 1, 'one_internal_request_source_operation')
    s = s.replace(a, "'operation':OPERATION", 1)
    a = ';negative.actor(encode(v),c);'
    b = ';_late().actor_validator(g).actor(encode(v),c);'
    need(s.count(a) == 1, 'one_private_actor_validation')
    s = s.replace(a, b, 1)
    a = ";negative.checked_request(encode(request),a['current']);"
    b = ";_late().actor_validator(g).checked_request(encode(request),a['current']);"
    need(s.count(a) == 1, 'one_private_request_validation')
    s = s.replace(a, b, 1)
    a = '  root=os.open(base.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain.parent_fd);child=None\n'
    b = "  need(os.getuid()==os.geteuid()==999 and base.name=='asset-prebind-requests-'+OPERATION and str(base.parent)=='/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d','current_prebind_fixed_service_request_root')\n  try:root=os.open(base.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain.parent_fd)\n  except FileNotFoundError as error:\n   need(error.errno==2,'current_prebind_request_root_exact_ENOENT');os.mkdir(base.name,0o700,dir_fd=chain.parent_fd);root=os.open(base.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain.parent_fd);os.fchmod(root,0o700);os.fsync(root);os.fsync(chain.parent_fd)\n  child=None\n"
    need(s.count(a) == 1, 'one_service_request_parent_open')
    s = s.replace(a, b, 1)
    out = s.encode()
    compile(out, 'private_current_prebind', 'exec')
    return out

def extend(helpers, names, review, late_context):
    h = dict(helpers)
    order = list(names)
    extra = ('known_prior_assets.py', 'current_negative.py', 'current_prebind.py')
    at = order.index('asset_stage.py')
    order[at:at] = extra
    h['known_prior_assets.py'] = component_source.current_known('PC', P.PC_ROOT + '/asset-terminals')
    h['current_negative.py'] = integrate_current.current_negative()
    h['current_prebind.py'] = bind(derive_prebind(base('CURRENT/current_prebind.py')), {'APPROVED_REVIEW': review, 'REQUEST_ROOT': '/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/asset-prebind-requests-' + P.ASSET_OPERATION, 'QUALIFIED_ROOT': P.PC_ROOT + '/current-prebind-readonly', 'APPROVED_NONCE_POLICY': 'active-stage-operation/v1', 'APPROVED_LATE_CONTEXT_PATH': P.PC_ROOT + '/service/late_scope_context.py', 'APPROVED_LATE_CONTEXT_SHA': sha(late_context)})
    h['history_reader.py'] = history_binding.history_reader_source()
    h['asset_stage.py'] = bind(component_source.raw('SOURCE/asset_stage.py'), {'APPROVED_REVIEW': review})
    h['empty_range_repair.py'] = component_source.raw('SOURCE/empty_range_repair.py')
    order.insert(order.index('asset_stage.py'), 'empty_range_repair.py')
    return (h, tuple(order))
