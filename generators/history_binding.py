# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Offline data-before-code DAG. No synthetic Root F9 or permission defaults."""
import json
from source_io import HERE, sha, need, bind
STATE = HERE.parent / 'HISTORY_INPUTS.json'

def descriptor(v, path=None):
    need(type(v) is dict and set(v) == {'path', 'sha256', 'F9'}, 'R15_actual_history_Root_descriptor_None')
    p = v['path']
    f = v['F9']
    need(type(p) is str and p.startswith('/opt/dgx-v4/hx/mimo-registry-r15-history/') and ('..' not in p.split('/')) and (path is None or p == path), 'R15_fixed_independent_history_Root_path')
    need(type(v['sha256']) is str and len(v['sha256']) == 64 and (type(f) is list) and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[3:7] == [0, 989, 33056, 1]) and (f[2] <= 2097152), 'R15_actual_history_Root_fullF9_leaf_cap')
    return v

def require_data():
    v = json.loads(STATE.read_bytes())
    need(type(v) is dict and set(v) == {'schema', 'component', 'bridge_binding', 'normal_history', 'old_domain', 'prefile_history'} and (v['schema'] == 'R15-data-before-code-inputs/v1'), 'R15_closed_history_DAG_inputs')
    need(type(v['component']) is dict and type(v['bridge_binding']) is dict and (set(v['bridge_binding']) == {'snapshot', 'source_bundle', 'old_metadata'}), 'R15_frozen_component_and_actual_binding_pending')
    for k in ('snapshot', 'source_bundle'):
        descriptor(v['bridge_binding'][k])
    r = descriptor(v['normal_history'], '/opt/dgx-v4/hx/mimo-registry-r15-history/normal-history.json')
    path = HERE.parent / 'DATA/normal-history.json'
    raw = path.read_bytes()
    need(len(raw) == r['F9'][2] and sha(raw) == r['sha256'], 'R15_complete_normal_history_bytes_Root_pinned')
    return dict(v, normal_history_raw=raw, normal_history_ref=r)

def history_reader_source():
    v = require_data()
    component = v['component']
    need(set(component) == {'manifest_sha256', 'files'} and type(component['files']) is dict, 'R15_exact_frozen_component_pins')
    row = component['files']['SOURCE/history_reader.py']
    raw = (HERE.parent / 'COMPONENT/SOURCE/history_reader.py').read_bytes()
    need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'R15_held_old_domain_complete_source')
    old = json.loads((HERE.parent / 'COMPONENT/OLD_EPOCH.json').read_bytes())
    pins = json.loads((HERE.parent / 'COMPONENT/OLD_SOURCE_PINS.json').read_bytes())
    return bind(raw, {'epoch_OLD_EPOCH': old, 'epoch_OLD_SOURCE_PINS': pins, 'epoch_APPROVED_BINDING': v['bridge_binding']})
