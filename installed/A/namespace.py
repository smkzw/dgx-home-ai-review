# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Seven exact merged-config path slots; every other source value remains pinned."""
import copy, hashlib, json
from pathlib import Path
OLD_ROOT = '/var/lib/dgx-v4/mimo-registry-native-r26'
ROOT = '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14'
BASE_SHA = '6bb755798fafa04c6a66bc7dca67688f6a3102b8f39c370d4461db6737f35676'
SLOTS = ((('root',), '/containerd-data'), (('state',), '/containerd-exec'), (('temp',), '/tmp'), (('grpc', 'address'), '/containerd.sock'), (('ttrpc', 'address'), '/containerd.sock.ttrpc'), (('plugins', 'io.containerd.internal.v1.opt', 'path'), '/private-opt'), (('plugins', 'io.containerd.snapshotter.v1.overlayfs', 'root_path'), '/private-overlay'))

class Refused(ValueError):
    pass

def need(v, c):
    if not v:
        raise Refused(c)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def relocate(source_raw, root=ROOT):
    need(type(source_raw) is bytes and len(source_raw) <= 65536 and (sha(source_raw) == BASE_SHA), 'official_merged_exact_source')
    need(root == ROOT, 'only_exact_candidate_namespace')
    source = json.loads(source_raw)
    out = copy.deepcopy(source)
    for path, suffix in SLOTS:
        parent = out
        for key in path[:-1]:
            need(type(parent) is dict and key in parent, 'complete_explicit_merged_path')
            parent = parent[key]
        need(type(parent) is dict and path[-1] in parent and (type(parent[path[-1]]) is str) and (parent[path[-1]] == OLD_ROOT + suffix), 'exact_old_official_path_slot')
        parent[path[-1]] = root + suffix
    return out

def expected_bytes(root=ROOT):
    return encode(relocate(Path(__file__).with_name('OFFICIAL_MERGED_BASELINE.json').read_bytes(), root))

def expected(raw, root=ROOT):
    need(type(raw) is bytes and raw == expected_bytes(root), 'exact_relocated_expected_data')
    return json.loads(raw)
