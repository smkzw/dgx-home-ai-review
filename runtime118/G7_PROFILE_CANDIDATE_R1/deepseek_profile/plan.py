# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure candidate configuration compiler. Never writes configs, starts or enables.

Only parent-bound artifact paths are rendered; every result remains disabled and
uncalibrated. Actual full-weight/cache/build/kit/RDMA proofs are still required.
"""
from copy import deepcopy
from pathlib import PurePosixPath
import re
from .adapter import PROFILE, MODEL, NODES, ROLES
ENGINE_REV = '4e80f05ecba89a4e90d16375ade2eddbdc0a10c4'
RECIPE_REV = '5e90ec9302149049e8f019ea035827cb24c206f8'
KIT_REV = '789625a7081e91643cb61ceafd15f588850c511a'
IMAGE = 'sha256:9b00719301e859f7b790b5c4d80ab1e49ef64bef63d3e7af2f3829cfc32cfee1'
GID_PATCH_SHA = '181c967eacf4030441f7853b54bd76f0e2fb2bc72b74450ab0e4b13320eaa63d'
BINDINGS = {'spark-a': {'rank': 0, 'hca': 'roceP2p1s0f1', 'iface': 'enP2p1s0f1np1', 'ip': '192.0.2.10'}, 'spark-b': {'rank': 1, 'hca': 'roceP2p1s0f0', 'iface': 'enP2p1s0f0np0', 'ip': '192.0.2.10'}}
KEYS = frozenset(('model', 'engram', 'kit', 'build', 'rank_cache', 'token_map'))

class Pending(ValueError):
    pass

def path(value):
    if not isinstance(value, str) or not re.fullmatch('/srv/dgx-home-ai/[A-Za-z0-9_./-]{1,180}', value):
        raise Pending('parent_bound_local_NVMe_path_required')
    p = PurePosixPath(value)
    if '..' in p.parts or str(p) != value:
        raise Pending('canonical_NVMe_path_required')
    return value

def node_plan(node, paths):
    if node not in BINDINGS or not isinstance(paths, dict) or set(paths) != KEYS:
        raise Pending('exact_parent_AB_artifact_paths_required')
    paths = {k: path(v) for k, v in paths.items()}
    destinations = {'model': '/model', 'engram': '/engram', 'kit': '/kit', 'build': '/engine', 'rank_cache': '/rank-cache', 'token_map': '/token-map.json'}
    wire = BINDINGS[node]
    env = {'TF_DS_REPLAY_FLOOR': '1', 'TF_RDMA_GID_INDEX': '3', 'NCCL_IB_GID_INDEX': '3', 'NCCL_IB_HCA': wire['hca'], 'NCCL_SOCKET_IFNAME': wire['iface']}
    args = ['--gpus', 'all', '--network', 'host', '--ipc', 'host', '--cap-drop', 'ALL', '--cap-add', 'IPC_LOCK', '--security-opt', 'no-new-privileges', '--device', '/dev/infiniband', '--ulimit', 'memlock=-1', '--ulimit', 'stack=67108864', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=2g']
    for key in sorted(paths):
        args += ['--mount', f'type=bind,src={paths[key]},dst={destinations[key]},readonly']
    pool = '131072'
    if node == 'spark-a':
        env.update(TF_TP_WORLD='2', TF_TP_MASTER='192.0.2.10', TF_TP_PORT='29620', TF_DS_RANK_CACHE='/rank-cache', TF_DS_KIT='/kit', TENSORFOLD_CUDA_KERNELS='/kit/aot', TF_DS_ENGRAM='/engram', TF_DS_TOKEN_MAP='/token-map.json', TF_RDMA_DEVICES=wire['hca'], TF_DS_GRAPHS='1', TF_DS_HC_SIDE='1', TF_DS_L2_PREFETCH='1', TF_DS_ENGRAM_AIO='1')
        args += ['--entrypoint', '/engine/native/bin/tensorfold-native']
        command = ['serve', '/model', '--host', '127.0.0.1', '--port', '18891', '--name', MODEL, '--context', pool, '--parallel', '4', '--thinking', '--reasoning-effort', 'xhigh', '--max-tokens', '32768', '--temperature', '1.0', '--top-p', '0.95', '--top-k', '20', '--backend', 'cuda', '--dashboard']
    else:
        args += ['--entrypoint', '/engine/bin/tf-dsv41-lanes']
        command = ['/model', '/rank-cache', '1', '2', '192.0.2.10', '29620', '/kit', '--engram', '/engram', '--token-map', '/token-map.json', '--pool', pool, '--rdma', wire['hca'], '--rdma-gid-index', '3', '--graphs', '1', '--side', '1', '--prefetch', '1', '--aio', '1']
    plan = {'image': IMAGE, 'model_id': MODEL, 'nodes': list(NODES), 'roles': dict(ROLES), 'docker_run_args': args, 'container_args': command, 'container_env': env}
    if node == 'spark-a':
        plan['api'] = {'host': '127.0.0.1', 'port': 18891, 'path': '/v1/models'}
    return plan

def disabled_deltas(parent_paths):
    if not isinstance(parent_paths, dict) or set(parent_paths) != set(NODES):
        raise Pending('both_AB_artifact_paths_required')
    return {'node_manifests': {n: {'schema': 'dgx-v4-node-v1-manifest', 'node': n, 'state_db': '/var/lib/dgx-v4/node-fence/state.sqlite3', 'lock_file': '/var/lib/dgx-v4/node-fence/resource.lock', 'runtime_guard_required': True, 'launch_enabled': False, 'profiles': {PROFILE: node_plan(n, parent_paths[n])}} for n in NODES}, 'node_adapter_profile': {'nodes': list(NODES), 'model_id': MODEL, 'api_host': '127.0.0.1', 'api_port': 18891, 'api_path': '/v1/models', 'roles': dict(ROLES)}, 'core_profile': {'nodes': list(NODES), 'source': 'deepseek_recipe', 'role': 'on-demand-after-G7', 'hardware_validated': False, 'min_start_available_gib': None, 'runtime_floor_gib': None}, 'service_profile': {'enabled': False, 'active_work_path': '/_dgx/active_work'}, 'gateway_model': {'profile': PROFILE, 'capabilities': {k: False for k in ('stream', 'tools', 'response_format', 'response_format_json_schema', 'response_format_strict', 'parallel_tool_calls')}}, 'engine_context_candidate': 131072, 'initial_admission_concurrency': 1, 'backend_front_tunnel': None, 'backend_auth_file': None, 'parent_accepted': False, 'pending': ['exact output manifests/ELF/fatbins on AB', 'complete weights/Engram/kit byte verification', 'sealed per-rank cache/token maps', 'fresh native GID3/RDMA and memory calibration', 'parent bind ports/tunnel/private auth; native loopback is behind authenticated front', 'highest reasoning+JSON/tools/vision serving acceptance; capabilities remain false']}

def merge_profile(document, profile_spec):
    """Add this profile in memory only, preserving every existing unrelated value."""
    result = deepcopy(document)
    if PROFILE in result['profiles'] and result['profiles'][PROFILE] != profile_spec:
        raise Pending('existing_DS_profile_requires_explicit_parent_review')
    result['profiles'][PROFILE] = deepcopy(profile_spec)
    return result
