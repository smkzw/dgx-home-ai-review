# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure additive compiler. Never writes live config, claims resources or launches."""
from copy import deepcopy
from pathlib import Path
import json
import re
from G7_PROFILE_CANDIDATE_R1.deepseek_profile import plan as serving
PREP = 'deepseek-cacheprep-ab'
PREP_MODEL = 'DeepSeek-V4.1-Flash-TF-CachePrep'
PY_REV = '90b68e063a0b8bba59aaf13340ef16619e751195'
ROOT = '/srv/dgx-home-ai'
ENGINE = ROOT + '/runtime/g7/engine/' + serving.ENGINE_REV + '-r8b-9d020065064941bd9bfdc0dd0be431d5'
PYTHON = ROOT + '/runtime/g7/python/' + PY_REV
CANDIDATE = ROOT + '/runtime/g7/integration/r1'
MIA = ROOT + '/models/G7-staged/Mia-AiLab--DeepSeek-V4.1-Flash-EXL3-2.9bpw/64ba41b6c916a587db06eae2e19b7845f7be6e6b'
ENGRAM = ROOT + '/models/G7-staged/deepseek-ai--DeepSeek-V4.1-Flash/2cba9e42aa026125f3ed06c6d98c1db82f7ca027'
KIT = ROOT + '/models/G7-staged/bertholomus--DeepSeek-V4.1-Flash-TensorFold-TP2-2xGB10/' + serving.KIT_REV + '/kit'
NODES = ('spark-a', 'spark-b')

class Pending(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Pending(why)

def run_token(run):
    need(isinstance(run, str) and re.fullmatch('[0-9a-f]{32}', run), 'fixed_private_run_id_required')
    return run

def paths(run, node):
    run_token(run)
    need(node in NODES, 'only_AB')
    cache = ROOT + '/runtime/g7/cache-preparation/' + run + '/' + node
    return {'model': MIA, 'engram': ENGRAM, 'kit': KIT, 'build': ENGINE, 'rank_cache': cache + '/tf-ds-rank', 'token_map': ROOT + '/runtime/g7/token-maps/' + run + '/dsv41_token_map.json'}

def budget():
    return {'source_bytes': 414418301113, 'rank_cache_budget_bytes': 120000000000, 'build_image_session_budget_bytes': 115000000000, 'minimum_additional_free_reserve_bytes': 250000000000, 'total_bytes': 899418301113, 'rank_cache_source_free_guard_bytes': 117978000140, 'free_guard_margin_within_cache_line_bytes': 2021999860, 'fresh_disk_free_required': True, 'old_accepted_cache_retention_must_fit': True, 'actual_admitted': False}

def prep_plan(node, run):
    p = paths(run, node)
    wire = serving.BINDINGS[node]
    cache = p['rank_cache'].rsplit('/', 1)[0]
    args = ['--user', '1000:1000', '--gpus', 'all', '--network', 'host', '--ipc', 'host', '--cap-drop', 'ALL', '--cap-add', 'IPC_LOCK', '--security-opt', 'no-new-privileges', '--device', '/dev/infiniband', '--ulimit', 'memlock=-1', '--ulimit', 'stack=67108864', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=2g']
    for src, dst, rw in [(MIA, '/model', False), (ENGRAM, '/engram', False), (KIT, '/kit', False), (PYTHON, '/python-source', False), (CANDIDATE, '/integration', False), (p['token_map'], '/token-map.json', False), (cache, '/prep', True)]:
        args += ['--mount', f'type=bind,src={src},dst={dst}' + ('' if rw else ',readonly')]
    args += ['--entrypoint', '/usr/bin/python3']
    env = {'TF_DS_REPLAY': '1', 'TF_DS_PREFILL_CHUNK': '2048', 'TF_DS_RANK_CACHE': '/prep/tf-ds-rank', 'TF_DS_RANK_CACHE_READERS': '32', 'TF_DS_TOKEN_MAP': '/token-map.json', 'TF_DS_ENGRAM': '/engram', 'TORCH_EXTENSIONS_DIR': '/prep/torch_extensions', 'HOME': '/prep', 'XDG_CACHE_HOME': '/prep/cache', 'NCCL_IB_HCA': wire['hca'], 'NCCL_IB_GID_INDEX': '3', 'NCCL_SOCKET_IFNAME': wire['iface'], 'TF_RDMA_DEVICES': wire['hca'], 'TF_RDMA_GID_INDEX': '3', 'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1'}
    plan = {'image': serving.IMAGE, 'model_id': PREP_MODEL, 'nodes': list(NODES), 'roles': dict(serving.ROLES), 'docker_run_args': args, 'container_args': ['-I', '-B', '/integration/prep_launcher.py', str(wire['rank'])], 'container_env': env, 'launch_enabled': False}
    if node == 'spark-a':
        plan['api'] = {'host': '127.0.0.1', 'port': 18892, 'path': '/v1/models'}
    return plan

def additive(original, name, spec):
    need(isinstance(original, dict) and isinstance(original.get('profiles'), dict), 'actual_original_profile_document_required')
    out = deepcopy(original)
    need(name not in out['profiles'], 'existing_profile_refused')
    out['profiles'][name] = deepcopy(spec)
    return out

def compile_disabled(originals, run):
    """Require exact current original documents supplied by parent; preserve them."""
    need(set(originals) == {'nodes', 'core', 'adapter', 'service'}, 'exact_original_documents_required')
    need(set(originals['nodes']) == set(NODES), 'both_actual_AB_node_manifests_required')
    result = {'nodes': {}, 'core': deepcopy(originals['core']), 'adapter': deepcopy(originals['adapter']), 'service': deepcopy(originals['service']), 'budget': budget(), 'parent_accepted': False, 'environment_accepted': False, 'serving_accepted': False, 'cache_accepted': False}
    for node in NODES:
        old = originals['nodes'][node]
        need(old.get('node') == node, 'node_identity')
        sp = serving.node_plan(node, paths(run, node))
        sp['launch_enabled'] = False
        result['nodes'][node] = additive(additive(old, serving.PROFILE, sp), PREP, prep_plan(node, run))
    for name, model, port, role in [(serving.PROFILE, serving.MODEL, 18891, 'on-demand-after-G7'), (PREP, PREP_MODEL, 18892, 'parent-maintenance-only')]:
        result['core'] = additive(result['core'], name, {'nodes': list(NODES), 'source': PY_REV if name == PREP else serving.ENGINE_REV, 'role': role, 'hardware_validated': False, 'min_start_available_gib': None, 'runtime_floor_gib': None})
        result['adapter'] = additive(result['adapter'], name, {'nodes': list(NODES), 'model_id': model, 'api_host': '127.0.0.1', 'api_port': port, 'api_path': '/v1/models', 'roles': dict(serving.ROLES)})
        result.setdefault('pending_service_deltas', {})[name] = {'enabled': False, 'active_work_path': '/_dgx/active_work' if name == serving.PROFILE else ''}
    return result

def copy_plan():
    manifest = json.loads((Path(__file__).parent / 'ENGINE_OUTPUTS.json').read_bytes())
    return {'nodes': list(NODES), 'destination': ENGINE, 'files': manifest['all34_files'], 'terminal_acceptance_sha256': manifest['terminal_acceptance_sha256'], 'actual_evidence_sha256': manifest['actual_evidence_sha256'], 'owner': 'root:root', 'mode': 'immutable-readable', 'source_copy_on_A_and_B': 'parent supplies accepted R8b source path; copy then full held-file SHA verify', 'new_destination_only': True, 'replace_existing': False, 'root_allowlist_install': 'disabled additive only', 'python_source_destination': PYTHON, 'python_source_commit': PY_REV, 'python_source_files': 'G7_PYTHON_PREP_CANDIDATE_R1/SOURCE_FILES.json', 'kit_destination': KIT, 'kit_payloads': 221, 'image': serving.IMAGE, 'image_prep_runtime_accepted': False, 'actual_copied': False}

def compile_guard_policy(original, new_manifest):
    """Keep original calibrated rows; new disabled rows explicitly pending."""
    need(isinstance(original, dict) and isinstance(original.get('profiles'), dict), 'actual_original_guard_policy_required')
    out = deepcopy(original)
    for name in (PREP, serving.PROFILE):
        need(new_manifest['profiles'][name].get('launch_enabled') is False, 'disabled_launch_plan_required')
        out = additive(out, name, {'enabled': False, 'calibration_pending': True, 'image_config_id': serving.IMAGE})
    from .node_guard_candidate import parse_policy
    parse_policy(out, new_manifest)
    return out
