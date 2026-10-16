# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same proven cold Root RPC bootstrap, bound only to actual R12 originals.
No transport or Manager construction; source-context remains a read-only RPC.
"""
import base64
import json
import re
from pathlib import Path
from emission import need, sha, encode, checked_graph, PC_ROOT, EPOCH, SOURCE_EPOCH, PACKAGE_ROOT
HERE = Path(__file__).resolve().parent
BOOTSTRAP_SHA = '7c4a9c0225c4b071cc9079f497b1051dadafc09c8a3c729665666214c38289e7'
ACTIONS = frozenset(('activate-registry-source', 'begin-asset-entry-clock', 'begin-asset-terminal-clock', 'finish-asset-stage', 'finish-failed-asset-stage', 'finish-not-launched-asset-stage', 'prepare-empty-asset-range-repair', 'prepare-not-launched-asset-stage', 'publish-asset-entry-clock', 'publish-asset-plan', 'publish-asset-terminal', 'publish-empty-asset-range-repair-contract', 'pulse-asset-stage', 'reserve-asset-stage', 'source-context', 'status-asset-stage', 'status-registry-source'))

def bootstrap():
    raw = (HERE / 'cold_bootstrap_fixed.py').read_bytes()
    need(sha(raw) == BOOTSTRAP_SHA, 'exact_previously_actual_cold_bootstrap')
    return raw

def policy_template(graph):
    pc = checked_graph(graph)
    idx = json.loads(pc['epoch-index.json'])
    extra = {n: sha(b) for n, b in pc.items() if n not in idx['files'] and n != 'epoch-index.json'}
    return {'PC_ROOT': PC_ROOT, 'config_path': '/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json', 'config_sha256': sha(graph['config']), 'review_sha256': graph['packet']['review_sha256'], 'index_sha256': sha(pc['epoch-index.json']), 'index_count': len(idx['files']), 'extra_sources': extra, 'RPC_sha256': sha(pc['parent-root-rpc.py']), 'operation': SOURCE_EPOCH}

def capture_policy_command(graph):
    """Fresh actual Root F9 plus actual RPC.current, no operator request or write."""
    p = policy_template(graph)
    package = {PACKAGE_ROOT + n: graph['packet']['newmap'][PACKAGE_ROOT + n] for n in ('__init__.py', 'common.py', 'collector.py')}
    code = 'import types,json,base64\nraw=' + repr(bootstrap()) + ";b=types.ModuleType('same_proven_Root_RPC_bootstrap');exec(compile(raw,'<fixed-cold-bootstrap>','exec'),b.__dict__);p=" + repr(p) + '\n'
    code += "cfg,cs=b.held(p['config_path'],p['config_sha256']);idx,ix=b.held(p['PC_ROOT']+'/epoch-index.json',p['index_sha256']);p['config_stat']=cs;p['index_stat']=ix;p['package']={}\n"
    code += 'for path,pin in ' + repr(package) + ".items():\n raw,f=b.held(path,pin);p['package'][path]={'sha256':pin,'stat':f}\n"
    code += "b.POLICY=p;current=b.main('current-only')\n"
    code += "from B_OWNER_RECOVERY_R25_WIRING.common import protected_read\nq,qf=protected_read(p['PC_ROOT']+'/current-source-qualified.json',limit=2097152);d,df=protected_read(p['PC_ROOT']+'/current-qualification-completed.json',limit=2097152);v=b.strict(q);done=b.strict(d);b.need(v['current']['manager_identity']==current['manager_identity'] and v['current']['config_sha256']==p['config_sha256'] and v['current']['current_source118']==current['current_source118'] and done['receipt_sha256']==b.sha(q),'actual_qualification_current_bound')\nprint(json.dumps({'schema':'R12-parent-actual-RPC-policy/v1','policy':p,'current':current,'qualified_original':{'raw_b64':base64.b64encode(q).decode(),'sha256':b.sha(q),'F9':qf},'completed_original':{'raw_b64':base64.b64encode(d).decode(),'sha256':b.sha(d),'F9':df},'requests_sent':0,'controls':0},allow_nan=False))\n"
    compile(code, 'R12_actual_policy_capture', 'exec')
    return code

def validate_policy(graph, original):
    need(type(original) is dict and original.get('schema') == 'R12-parent-actual-RPC-policy/v1' and (original['requests_sent'] == original['controls'] == 0), 'actual_policy_capture_required')
    p = original['policy']
    fixed = policy_template(graph)
    need(all((p[n] == v for n, v in fixed.items())) and set(p) == set(fixed) | {'config_stat', 'index_stat', 'package'}, 'actual_same_R12_policy_domain')
    need(len(original['current']['current_source118']) == 118 and original['current']['current_source118'] == graph['packet']['newmap'], 'actual_new_source118')
    for path, row in p['package'].items():
        need(row['sha256'] == graph['packet']['newmap'][path] and len(row['stat']) == 9 and (row['stat'][3] == 0) and (row['stat'][6] == 1), 'actual_unchanged_protected_package_F9')
    need(set(p['package']) == {PACKAGE_ROOT + n for n in ('__init__.py', 'common.py', 'collector.py')}, 'actual_package_exact_three')
    qrow, drow = (original['qualified_original'], original['completed_original'])
    qraw = base64.b64decode(qrow['raw_b64'], validate=True)
    draw = base64.b64decode(drow['raw_b64'], validate=True)
    q, d = (json.loads(qraw), json.loads(draw))
    need(sha(qraw) == qrow['sha256'] and sha(draw) == drow['sha256'] and (d['receipt_sha256'] == sha(qraw)), 'full_actual_qualification_completion_originals')
    need(q['current']['manager_identity'] == original['current']['manager_identity'] and q['current']['current_source118'] == graph['packet']['newmap'] and (q['current']['config_sha256'] == p['config_sha256']), 'actual_qualification_not_historical_owner')
    return p

def command(graph, original, action, nonce, payload):
    p = validate_policy(graph, original)
    need(action in ACTIONS and re.fullmatch('[0-9a-f]{32}', nonce) is not None and (type(payload) is dict), 'closed_Root_RPC_action_and_new_nonce')
    frame = encode({'action': action, 'operation': SOURCE_EPOCH if action == 'activate-registry-source' else EPOCH, 'nonce': nonce, 'payload': payload})
    need(len(frame) <= 1048576, 'unchanged_private_input_cap')
    code = 'import types,sys,io\nraw=' + repr(bootstrap()) + ";b=types.ModuleType('same_proven_Root_RPC_bootstrap');exec(compile(raw,'<fixed-cold-bootstrap>','exec'),b.__dict__);b.POLICY=" + repr(p) + ';sys.stdin=io.TextIOWrapper(io.BytesIO(' + repr(frame) + '),encoding="utf-8");b.main()\n'
    compile(code, 'R12_same_proven_Root_RPC', 'exec')
    return code
