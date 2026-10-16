# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact selected frozen component bytes; no recursive catalogue or CPU copy."""
import json
from source_io import HERE, sha, need, bind
ROOT = HERE.parent / 'COMPONENT'

def raw(name):
    p = json.loads((ROOT / 'PINS.json').read_bytes())
    need(p['manifest_sha256'] == 'a971fbc0e7d558489ef452e169707ae6390b1b48ba5d3ddade1cedf79cdbe104', 'R15_exact_frozen_colocation_manifest')
    r = p['files'][name]
    b = (ROOT / name).read_bytes()
    need(sha(b) == r['sha256'] and len(b) == r['bytes'], 'R15_complete_component_physical_source')
    return b

def renderer():
    from history_binding import require_data
    import policy as P
    v = require_data()
    return bind(raw('SOURCE/renderer.py'), {'PC_ROOT': P.PC_ROOT, 'APPROVED_PREFILE_HISTORY': v['prefile_history'], 'APPROVED_ANCESTOR_HISTORY': v['old_domain']})

def current_known(role, PC_root=None):
    from history_binding import require_data
    v = require_data()
    return bind((HERE.parent / 'known_prior_assets_r15.py').read_bytes(), {'ROLE': role, 'PC_TERMINAL_ROOT': PC_root, 'old_APPROVED_HISTORY': v['old_domain'], 'prefile_APPROVED_HISTORY': v['prefile_history']})
