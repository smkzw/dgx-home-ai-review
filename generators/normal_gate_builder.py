# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""R16 typed held failed-owner normal entry; ordinary idle gate stays frozen."""
import ast, json
from source_io import base, bind, sha, need, encode, HERE, replace_definition, expression
import policy as P
import history_binding
ACTOR_PARENT = None

def build(review, contract_raw, plan_raw, oldpolicy, packedpins):
    data = history_binding.require_data()
    extra = json.loads((HERE.parent / 'R16_NORMAL_INPUT.json').read_bytes())
    normalref = extra['ref']
    historyraw = (HERE.parent / 'DATA/R16-normal-history.json').read_bytes()
    need(type(normalref) is dict and normalref['path'] == '/opt/dgx-v4/hx/mimo-registry-r16-history/normal-history.json' and (normalref['sha256'] == sha(historyraw)) and (normalref['F9'][2] == len(historyraw)), 'R16_actual_static_normal_data_None')
    small = {'schema': 'R16-held-failed-owner-normal-policy/v1', 'history_sha256': sha(historyraw), 'new_source_root': P.A_ROOT}
    immutable = json.loads((HERE.parent / 'R16_BASELINE_IMMUTABLE.json').read_bytes())
    baseline = {k: immutable[k] for k in ('manager_identity', 'current_source118', 'config_sha256', 'config_stat', 'source_files', 'lease_full_F9', 'Cleaf', 'commands')}
    common = {n + '.py': base('PC/service/' + n + '.py') for n in ('root_io', 'bounded_process', 'observer', 'old_failed_kernel', 'proc_lifetime', 'receipt_codec', 'ready_history', 'legacy_actor', 'history_namespace')}
    common['plan.py'] = plan_raw
    common['history_reader.py'] = history_binding.history_reader_source()
    common['pc_recovery.py'] = bind((HERE.parent / 'phase_histories_r16.py').read_bytes(), {'APPROVED_ROOT': P.PC_ROOT, 'APPROVED_REVIEW': review, 'APPROVED_NORMAL_HISTORY': normalref, 'APPROVED_PRIOR_NORMAL': data['normal_history_ref']})
    common['prelaunch_negative.py'] = bind((HERE.parent / 'normal_negative_r16.py').read_bytes(), {'APPROVED_POLICY': small, 'APPROVED_REVIEW': review, 'OPERATION': P.EPOCH})
    common['prelaunch_stop.py'] = base('PC/service/prelaunch_stop.py')
    roots = {'before-stop': '/opt/dgx-v4/r16-normal-before', 'after-stop': '/opt/dgx-v4/r16-normal-after'}
    common['gate_protocol.py'] = bind(base('NORMAL_GATE/gate_protocol.py'), {'OPERATION': P.EPOCH, 'PHASES': tuple(roots), 'ROOTS': roots})
    protocol = common['gate_protocol.py'].decode()
    need(protocol.count("negative.APPROVED_POLICY['A_history_sha256']") == 1, 'R16_single_normal_history_producer')
    common['gate_protocol.py'] = protocol.replace("negative.APPROVED_POLICY['A_history_sha256']", "negative.APPROVED_POLICY['history_sha256']", 1).encode()
    common['scope_receipt.py'] = base('NORMAL_GATE/scope_receipt.py')
    orderA = ('plan', 'root_io', 'bounded_process', 'observer', 'old_failed_kernel', 'proc_lifetime', 'receipt_codec', 'ready_history', 'prelaunch_negative', 'gate_protocol', 'scope_receipt')
    phases = {}
    for phase, root in roots.items():
        files = {n + '.py': common[n + '.py'] for n in orderA}
        files['prelaunch_negative.py'] = expression(common['prelaunch_negative.py'], 'ROOT', 'Path(' + repr(root) + ')')
        worker = bind(base('NORMAL_GATE/worker.py'), {'APPROVED_REVIEW': review, 'PHASE': phase, 'ORDER': orderA, 'APPROVED_INPUTS': {n: sha(b) for n, b in files.items()}})
        files['worker.py'] = worker
        scope = bind(base('NORMAL_GATE/scope.py'), {'APPROVED_FILES': {n: sha(b) for n, b in files.items()}, 'APPROVED_WORKER_SHA': sha(worker), 'PHASE': phase, 'OPERATION': P.EPOCH})
        files['scope.py'] = expression(scope, 'STAGE', 'Path(' + repr(root) + ')')
        files['historical-MAC-original.json'] = historyraw
        need(sum(map(len, files.values())) <= 4194304 and all((len(b) <= 2097152 for b in files.values())), 'R16_normal_A_caps')
        phases[phase] = {'root': root, 'files': files, 'pins': {n: sha(b) for n, b in files.items()}, 'worker_sha256': sha(worker), 'scope_sha256': sha(files['scope.py']), 'history_data_root': None, 'source_review': review}
    raw = replace_definition(base('NORMAL_GATE/pc_gate.py'), ACTOR_PARENT.encode(), 'actor_parent')
    text = raw.decode()
    before = "need(classification==previous['classification'],'R11_original_strict_EXIT0_or_Code2_not_relabel')"
    need(text.count(before) == 1, 'R16_normal_original_classification_slot')
    text = text.replace(before, "need(classification==previous['classification']and classification['state']=='OLD_OWNER_FAILED_SHUTDOWN_PRESERVED_NO_ENGINE'and classification['actual_exit_code']==2,'R16_typed_held_original_Code2_not_arbitrary_failure')", 1)
    before = "  context={'owner_state':'LIVE','snapshot':s,'private_status_original':status}"
    need(text.count(before) == 1, 'R16_normal_live_context_slot')
    text = text.replace(before, "  asset=native.current_failed_owner_status(end);av=strict(asset['reply_raw_utf8'].encode());need(av['ok']is True,'R16_actual_failed_owner_status_reply')\n  pending=recovery.history_reader.owner_normal_before(protected_read,recovery.history_reader.owner_policy(),v['current'],av['result'],asset['observed_at'])\n  context={'owner_state':'LIVE','snapshot':s,'private_status_original':status,'private_asset_status_original':asset,'failed_owner_descriptor':{k:x for k,x in pending['failed_owner'].items()if k!='original_terminal'}}", 1)
    start = text.index(' packed,_=recovery.packed_histories(protected_read,Path(APPROVED_ROOT));history=')
    end = text.index(' return current,context\n', start)
    text = text[:start] + " holder=original['manager_identity']['pid']if phase=='before-stop'else native.pid()\n parent_original=actor_parent(holder);need(actor_parent(holder)==parent_original,'R16_normal_four_actor_metadata_after_history');context['retained_actor_directory']=parent_original\n" + text[end:]
    common['pc_gate.py'] = bind(text.encode(), {'APPROVED_ROOT': P.PC_ROOT, 'APPROVED_BASELINE': baseline, 'APPROVED_PHASES': {n: {k: v for k, v in q.items() if k not in ('files', 'pins')} for n, q in phases.items()}})
    ph = base('NORMAL/phase_history.py').decode()
    before = "stopped.classify(s['raw_utf8'].encode(),s['journal_raw_utf8'].encode(),before['manager_identity'],s['composition_sha256'])==s['classification']"
    need(ph.count(before) == 1, 'R16_normal_historical_stop_slot')
    ph = ph.replace(before, before + "and s['classification']['state']=='OLD_OWNER_FAILED_SHUTDOWN_PRESERVED_NO_ENGINE'and s['classification']['actual_exit_code']==2", 1)
    ph = ph.replace(" return {'phase':phase,'qualified_sha256':sha(raw)", " holder=installed['current']['manager_identity']['pid'];gate.actor_parent(holder)\n return {'phase':phase,'qualified_sha256':sha(raw)", 1)
    common['phase_history.py'] = ph.encode()
    orderPC = orderA[:8] + ('legacy_actor', 'history_namespace', 'history_reader', 'prelaunch_negative', 'pc_recovery', 'prelaunch_stop') + orderA[-2:] + ('pc_gate', 'phase_history')
    common['gate_loader.py'] = bind(base('TOOLS/module_closure_source/gate_loader.py'), {'ROOT': P.PC_ROOT + '/pc/r11-gate', 'ORDER': orderPC, 'PHASES': tuple(roots), 'APPROVED_FILES': {n: sha(b) for n, b in common.items()}, 'APPROVED_CONTRACT_SHA': sha(contract_raw)})
    for n, b in common.items():
        compile(b, n, 'exec')
    return {'PC_files': {'pc/r11-gate/' + n: b for n, b in common.items()}, 'PC_pins': {n: sha(b) for n, b in common.items()}, 'phases': phases, 'actual_clock': None, 'native_eligible': False}

def final_reader(gate, raw):
    files = dict(gate['PC_files'])
    files['pc/r11-gate/history_reader.py'] = raw
    loader = bind(files['pc/r11-gate/gate_loader.py'], {'APPROVED_FILES': {p.rsplit('/', 1)[1]: sha(b) for p, b in files.items() if not p.endswith('/gate_loader.py')}})
    files['pc/r11-gate/gate_loader.py'] = loader
    return dict(gate, PC_files=files, PC_pins={p.rsplit('/', 1)[1]: sha(b) for p, b in files.items()})
