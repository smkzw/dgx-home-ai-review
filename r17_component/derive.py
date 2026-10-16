# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact copied R16 source transforms. No epoch, namespace or actual slot binding."""
import ast
import hashlib
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1/FINAL_GRAPH/PC'
PINS = {'service/grant.py': '5ddec1dc173999fe76fe08dbbb4c88719b5695c3dc88e6e2f05e50e1c3bf69e2', 'service/prelaunch_recovery.py': '6bd659dcaaef0769fb2ce95b6619676a5747e1cc96128c41d7112c47d523040b', 'service/current_epoch.py': 'a0607d40dd0535199068d72091fed15ee5dd1dbe32413baf476b11d3e94ced12', 'pc/r11-gate/gate_loader.py': 'b0851a274412b2cad18c23980868beade79ae18a34168b23e305bb305a671533', 'pc/r11-gate/phase_history.py': '912e56a54f2f08cfe98527847ab4c694b0fe35514bda664c45f34b3b19acbbf3', 'service/history_reader.py': '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8', 'service/asset_stage.py': '8960088fa6cea502c52db75ece7aa1969c3b255cc988e0169cc8c7effdb7850c'}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def need(value, reason):
    if not value:
        raise ValueError(reason)

def original(path):
    raw = (BASE / path).read_bytes()
    need(sha(raw) == PINS[path], 'R17_exact_frozen_preimage:' + path)
    return raw

def replace_once(text, old, new):
    need(text.count(old) == 1, 'R17_exact_one_transform:' + old[:80])
    return text.replace(old, new, 1)

def replace_definition(raw, name, source):
    tree = ast.parse(raw)
    node = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name))
    lines = raw.decode().splitlines(True)
    lines[node.lineno - 1:node.end_lineno] = [source.rstrip() + '\n']
    out = ''.join(lines).encode()
    compile(out, name, 'exec')
    return out

def function(raw, name):
    node = next((n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name))
    return ast.get_source_segment(raw.decode(), node)

def phase_history(raw):
    historical = function(raw, 'consume').replace('def consume(installed,phase):', 'def consume_event_history(installed,phase):', 1)
    historical = replace_once(historical, " holder=installed['current']['manager_identity']['pid'];gate.actor_parent(holder)", ' # Actual actor/lease observations are checked by the separate live consumer.')
    return raw + b'\n\n' + historical.encode() + b'\n'

def gate_loader(raw):
    old = function(raw, 'verify_installed')
    out = raw
    text = out.decode()
    text = replace_once(text, 'def load(phase):', 'def load(phase, *, input_read=None):')
    text = replace_once(text, ' from B_OWNER_RECOVERY_R25_WIRING.common import protected_read\n # Each call', ' from B_OWNER_RECOVERY_R25_WIRING.common import protected_read\n if input_read is not None:protected_read=input_read\n # Each call')
    text = replace_once(text, " if common is None or getattr(common,'__file__',None)!=common_path:raise ImportError('R11_gate_protected_common_origin')", " if common is None or getattr(common,'__file__',None)!=common_path:raise ImportError('R11_gate_protected_common_origin')\n if input_read is not None:\n  view=types.ModuleType(common.__name__);view.__dict__.update(common.__dict__);view.protected_read=input_read;common=view")
    out = text.encode()
    historical = old.replace('def verify_installed(installed):', 'def verify_installed_history(installed):', 1)
    historical = replace_once(historical, "mods['phase_history'].consume(installed,phase)", "mods['phase_history'].consume_event_history(installed,phase)")
    dynamic = "def verify_current_owner(identity, *, actual_identity, input_read=None, prepared_history=None):\n if not callable(actual_identity):raise RuntimeError('R17_private_internal_identity_callback')\n if identity != actual_identity():raise RuntimeError('R17_actual_internal_current_identity')\n mods,old,held=load('before-stop',input_read=input_read)\n try:\n  if prepared_history is not None:prepared_history(mods)\n  value=mods['pc_gate'].actor_parent(identity['pid'])\n  from B_OWNER_RECOVERY_R25_WIRING.common import protected_read\n  if input_read is not None:protected_read=input_read\n  if any(protected_read(path,limit=2097152)!=pair for path,pair in held.items()):raise RuntimeError('R17_current_actor_source_fullF9_after')\n  if identity != actual_identity():raise RuntimeError('R17_actual_identity_stable_after_actor')\n  return value\n finally:restore(old)\n"
    return out + b'\n' + historical.encode() + b'\n\n' + dynamic.encode()

def current_epoch(raw):
    old = function(raw, 'consume_initial')
    new = replace_once(old, 'def consume_initial(read,config,identity,now):', 'def consume_initial(read,config,identity,now,*,phase_verify=None):')
    new = replace_once(new, 'phase_gate.verify_installed(v)', 'phase_gate.verify_installed_history(v)if phase_verify is None else phase_verify(v)')
    out = replace_definition(raw, 'consume_initial', new)
    dynamic = "def current_owner(read, identity, prepared=None):\n raw,meta=root(read,PC_ROOT/'pc/r11-gate/gate_loader.py')\n need(sha(raw)==APPROVED_PHASE_GATE_SHA,'R17_current_owner_exact_gate_source')\n from asset_stage import identity as actual_identity\n if prepared is not None:return prepared.current_owner(read,identity,actual_identity)\n import types\n gate=types.ModuleType('R17_private_current_owner_gate')\n gate.__file__=str(PC_ROOT/'pc/r11-gate/gate_loader.py')\n exec(compile(raw,gate.__file__,'exec'),gate.__dict__)\n from asset_stage import identity as actual_identity\n return gate.verify_current_owner(identity,actual_identity=actual_identity)\n"
    source = "def consume(read,config,identity,now,*,prepared=None):\n installation=consume_installation(read,config,now)if prepared is None else prepared.installation(read,config)\n if identity==installation['initial_identity']:\n  value=installation\n else:\n  value=renew(read,config,identity,now,installation)\n # New sole qualification must be accepted before current owner checks. Original\n # installation/PID remains unchanged in its historical evidence.\n current_owner(read,identity,prepared)\n return value\n"
    return replace_definition(out, 'consume', source) + b'\n' + dynamic.encode()

def clock_delta(raw):
    """New v2 functions only; v1 original event consumers remain byte-exact."""
    replacements = {}
    for name in ('owner_permit', 'owner_begin', 'owner_finish', 'owner_fresh', 'owner_checked_A'):
        text = function(raw, name).replace('def ' + name + '(', 'def ' + name + '_v2(', 1)
        text = text.replace('failed-owner-terminal-release-permit/v1', 'failed-owner-terminal-release-permit/v2')
        text = text.replace('failed-owner-terminal-PC-send/v1', 'failed-owner-terminal-PC-send/v2')
        text = text.replace('failed-owner-terminal-fresh-qualified/v1', 'failed-owner-terminal-fresh-qualified/v2')
        text = text.replace('failed-owner-terminal-release-eligibility/v1', 'failed-owner-terminal-release-eligibility/v2')
        text = text.replace('failed-owner-terminal-A-readonly/v1', 'failed-owner-terminal-A-readonly/v2')
        text = text.replace('failed-owner-terminal-PC-received/v1', 'failed-owner-terminal-PC-received/v2')
        if name in ('owner_finish', 'owner_fresh'):
            text = text.replace('owner_checked_A(', 'owner_checked_A_v2(')
        if name == 'owner_permit':
            text = replace_once(text, "'PC_issued_at': now,", "'PC_boot_id': current['manager_identity']['boot_id'], 'PC_issued_at': now,")
        elif name == 'owner_begin':
            text = replace_once(text, "'PC_sent_at': owner_time.time(),", "'PC_boot_id': v['PC_boot_id'], 'PC_sent_at': owner_time.time(),")
        elif name == 'owner_finish':
            text = replace_once(text, "'PC_received_at': now,", "'PC_boot_id': moment['PC_boot_id'], 'PC_received_at': now,")
            text = replace_once(text, "    owner_need(owner_number(duration) and 0 <= duration <= 30 and (0 <= now - moment['PC_sent_at'] <= 30), 'owner_finish_PC_original_whole30')", "    r17_owner_clock(moment,pv,owner_Path('/proc/sys/kernel/random/boot_id').read_text().strip(),owner_time.monotonic(),now)")
        elif name == 'owner_checked_A':
            text = replace_once(text, "bm['schema'] == 'failed-owner-terminal-PC-send/v2' and bm['request_original']", "bm['schema'] == 'failed-owner-terminal-PC-send/v2' and bm['PC_boot_id']==request['new_current']['manager_identity']['boot_id'] and bm['request_original']")
        elif name == 'owner_fresh':
            text = replace_once(text, "'old_plan', 'PC_issued_at'", "'old_plan', 'PC_boot_id', 'PC_issued_at'")
            text = replace_once(text, "'PC_sent_at', 'PC_monotonic_sent'}", "'PC_boot_id', 'PC_sent_at', 'PC_monotonic_sent'}")
            text = replace_once(text, "'scope_sha256', 'PC_received_at',", "'scope_sha256', 'PC_boot_id', 'PC_received_at',")
            text = replace_once(text, "and received['schema'] == 'failed-owner-terminal-PC-received/v2'", "and received['schema'] == 'failed-owner-terminal-PC-received/v2' and received['PC_boot_id']==moment['PC_boot_id']==permit['PC_boot_id']==current['manager_identity']['boot_id']")
            old = "    owner_need(historical or (permit['PC_monotonic_origin'] <= g.clock() < permit['PC_deadline_monotonic'] and 0 <= now - permit['PC_issued_at'] <= permit['duration_seconds'] and (0 <= now - received['PC_received_at']) and (received['PC_monotonic_elapsed'] + now - received['PC_received_at'] <= 30)), 'owner_release_new_PC_final_whole30')"
            new = "    if not historical:r17_owner_clock(moment, permit, __import__('asset_stage', fromlist=['identity']).identity()['boot_id'], g.clock(), now)"
            text = replace_once(text, old, new)
            text = replace_once(text, "'PC_release_clock': {'received_at':", "'PC_release_clock': {'PC_boot_id': moment['PC_boot_id'], 'PC_monotonic_sent': moment['PC_monotonic_sent'], 'PC_sent_at': moment['PC_sent_at'], 'received_at':")
        replacements[name + '_v2'] = text
    kernel = ast.parse((HERE / 'SOURCE/owner_clock.py').read_bytes())
    mapping = {'math': 'r17_math', 'ClockRefused': 'r17_ClockRefused', 'number': 'r17_clock_number', 'require': 'r17_clock_require', 'check': 'r17_owner_clock'}

    class Prefix(ast.NodeTransformer):

        def visit_Name(self, node):
            node.id = mapping.get(node.id, node.id)
            return node

        def visit_FunctionDef(self, node):
            node.name = mapping.get(node.name, node.name)
            return self.generic_visit(node)

        def visit_ClassDef(self, node):
            node.name = mapping.get(node.name, node.name)
            return self.generic_visit(node)

        def visit_Import(self, node):
            for item in node.names:
                if item.name == 'math':
                    item.asname = 'r17_math'
            return node
    kernel = ast.unparse(Prefix().visit(kernel))
    final = "def owner_final_clock_v2(eligibility,g):\n c=eligibility['PC_release_clock']\n moment={k:c[k]for k in ('PC_boot_id','PC_monotonic_sent','PC_sent_at')}\n permit={'PC_boot_id':c['PC_boot_id'],'PC_issued_at':c['permit_wall'],\n         'PC_monotonic_origin':c['permit_monotonic_origin'],\n         'PC_deadline_monotonic':c['permit_monotonic_deadline'],\n         'duration_seconds':c['permit_seconds']}\n current=__import__('asset_stage',fromlist=['identity']).identity()\n return r17_owner_clock(moment,permit,current['boot_id'],g.clock(),g.runtime.manager._now())\n"
    return (kernel + '\n\n' + '\n\n'.join(replacements.values()) + '\n' + final).encode()

def stages(raw):
    text = raw.decode()
    marker = "    entries={p.name for p in sub.iterdir()};done=sub/'fence-released.json'"
    extra = "    if sub.name==epoch_asset_history_bridge.owner_policy()['stage'] and epoch_asset_history_bridge.owner_converged_cold(self):continue\n"
    return replace_once(text, marker, extra + marker).encode()

def recovery(raw):
    text = raw.decode()
    need(text.rstrip().endswith('self.root.mkdir(mode=0o700);os.chmod(self.root,0o700)'), 'R17_exact_Recovery_class_tail')
    return (text + '\n def owner_decision_cold(self,stages):\n  import history_reader\n  return history_reader.owner_restore_decision_cold(self,stages)\n').encode()

def grant(raw):
    return replace_once(raw.decode(), '        self.prelaunch_recovery=Recovery(self)\n        self.asset_stages=Stages(self,operator._asset_terminal)', '        with self.s._lock:\n            try:\n                self.prelaunch_recovery=Recovery(self)\n                self.asset_stages=Stages(self,operator._asset_terminal)\n            except BaseException:\n                self.s.restore_operator_block()\n                raise').encode()

def owner_history_dispatch(raw):
    old = function(raw, 'owner_history')
    added = replace_once(old, '    p = owner_policy()', "    if owner_strict(rows['completed.json']).get('schema')=='fixed-image-finite-stage-owner-recovered/v2':\n        return owner_committed_history_v2(stages,stage,rows)\n    p = owner_policy()")
    return replace_definition(raw, 'owner_history', added)

def materialize():
    result = {}
    raw = original('pc/r11-gate/phase_history.py')
    result['pc/r11-gate/phase_history.py'] = phase_history(raw)
    raw = original('pc/r11-gate/gate_loader.py')
    result['pc/r11-gate/gate_loader.py'] = gate_loader(raw)
    raw = original('service/current_epoch.py')
    result['service/current_epoch.py'] = current_epoch(raw)
    result['owner_history_clock_delta.py'] = clock_delta(original('service/history_reader.py'))
    result['service/asset_stage.py'] = stages(original('service/asset_stage.py'))
    result['owner_cold_delta.py'] = (HERE / 'SOURCE/owner_cold.py').read_bytes()
    result['owner_state_delta.py'] = (HERE / 'SOURCE/owner_state.py').read_bytes()
    result['service/prelaunch_recovery.py'] = recovery(original('service/prelaunch_recovery.py'))
    result['service/grant.py'] = grant(original('service/grant.py'))
    result['owner_history_dispatch.py'] = function(owner_history_dispatch(original('service/history_reader.py')), 'owner_history').encode() + b'\n'
    for name, source in result.items():
        compile(source, name, 'exec')
    return result
if __name__ == '__main__':
    target = HERE / 'CANDIDATE'
    target.mkdir(exist_ok=True)
    rows = {}
    for name, raw in materialize().items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        rows[name] = {'sha256': sha(raw), 'bytes': len(raw)}
    (HERE / 'CANDIDATE_PINS.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'files': len(rows), 'native_eligible': False, 'actual_slots': None}))
