# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Complete deterministic final-byte assembly; no runtime or native invocation."""
import ast, json, re
from source_io import base, bind, expression, sha, encode, need, literal, HERE
import policy as P
from owner_native import owner_native
import operation_domains
import builder, a_builder, normal_gate_builder, helper_builder, history_data, scope_builder, current_builder, integrate_current
ROOT_ORDER = ('contract.py', 'pc/managed_scope.py', 'pc/ancestor.py', 'pc/ancestor_producer.py', 'pc/bounded_process.py', 'pc/prelaunch_stop.py', 'pc/prelaunch_barrier.py', 'pc/current_reader.py', 'pc/native.py', 'pc/epoch_transaction.py', 'pc/qualifier.py')

def deduplicate_gate(gate, helpers):
    """Exact identical source bodies share physical immutable leaves, not aliases.
 Private import namespace and per-call source/FD/F9 verification remain intact.
 """
    files = dict(gate['PC_files'])
    loader = files.pop('pc/r11-gate/gate_loader.py')
    mapping = {}
    dedup = {}
    for path, raw in files.items():
        same = next(('service/' + n for n, b in helpers.items() if b == raw), None) or next((n for n, b in dedup.items() if b == raw), None)
        mapping[path.rsplit('/', 1)[1]] = same or path
        if same is None:
            dedup[path] = raw
    old = " for n in ORDER:one(n,Path(ROOT)/(n+'.py'),APPROVED_FILES[n+'.py'])"
    need(loader.decode().count(old) == 1, 'one_closed_gate_source_path_table')
    loader = loader.decode().replace(old, " for n in ORDER:one(n,Path(ROOT).parent.parent/APPROVED_SOURCE_PATHS[n+'.py'],APPROVED_FILES[n+'.py'])", 1)
    loader += '\nAPPROVED_SOURCE_PATHS=' + repr(mapping) + '\n'
    loader = loader.encode()
    compile(loader, 'deduplicated_private_gate', 'exec')
    dedup['pc/r11-gate/gate_loader.py'] = loader
    return dict(gate, PC_files=dedup, PC_pins=dict(gate['PC_pins'], **{'gate_loader.py': sha(loader)}), loader_sha256=sha(loader), source_paths=mapping)

def assemble(review, entry_nonce, *, current=None):
    need(re.fullmatch('[0-9a-f]{64}', review) and re.fullmatch('[0-9a-f]{32}', entry_nonce) and (entry_nonce != '0' * 32), 'explicit_SOURCE_review_nonce_data')
    facts = builder.actual_baseline()
    old = facts['config']
    cold = builder.C_context(review).cold_transform(facts['wire_raw'], review)
    contract = builder.normal_contract(review)
    worker = bind(base('TOOLS/templates/pc/scope_worker.py'), {'ROLE': 'epoch', 'APPROVED_REVIEW': review})
    qualifier = bind(base('NORMAL/templates/pc/qualifier.py'), {'APPROVED_REVIEW': review, 'APPROVED_WORKER_SHA': sha(worker)})
    A = a_builder.build(review, entry_nonce, contract, qualifier, worker)
    packed, packedpins = history_data.materialize()
    oldpolicy = json.loads(base('INPUTS/zero-history-policy.json'))
    gate = normal_gate_builder.build(review, contract, A['files']['plan.py'], oldpolicy, packedpins)
    helpers, names = helper_builder.base_helpers(review, contract, A, qualifier, worker, gate)
    reader = base('PC/pc/current_reader.py')
    scope = scope_builder.build(A, oldpolicy, packedpins, reader, current=current)
    helpers['late_scope_context.py'] = operation_domains.late_context(scope['late_context'])
    if current is not None:
        helpers, names = current_builder.extend(helpers, names, review, helpers['late_scope_context.py'])
    import owner_builder
    helpers, names = owner_builder.extend(helpers, names, review, entry_nonce, qualifier)
    gate = normal_gate_builder.final_reader(gate, helpers['history_reader.py'])
    gate = deduplicate_gate(gate, helpers)
    helpers['current_epoch.py'] = bind(helpers['current_epoch.py'], {'APPROVED_PHASE_GATE_SHA': gate['loader_sha256']})
    basepc = {n.removeprefix('PC/'): base(n) for n in json.loads((HERE / 'BASE_PINS.json').read_bytes()) if n.startswith('PC/')}
    keep = set(ROOT_ORDER) | {'pc/inputs/io_utils.py', 'pc/inputs/old_installer_helpers.py', 'pc/stopped_nodes.py', 'pc/negative_contract.py', 'pc/scope_observer.py', 'pc/AB_source_barrier.py', 'pc/stopped_live_idle.py', 'pc/C_renewal_receiver.py', 'pc/root_renewal.py', 'C_renewal_interface.py', 'renewal-worker.py', 'service/manifest-original.json', 'service/config-original.json'}
    pc = {n: basepc[n] for n in keep}
    pc.update(cold['stage_files'])
    pc.update(gate['PC_files'])
    pc.update(scope['files'])
    pc['A-origin-publisher.py'] = bind((HERE / 'a_origin.py').read_bytes(), {'ROOT': P.A_ROOT, 'PC_ROOT': P.PC_ROOT, 'APPROVED': {'operation': P.EPOCH, 'review': review, 'source_pins': A['pins'], 'source_sizes': {n: len(b) for n, b in A['files'].items()}}})
    pc['contract.py'] = contract
    pc['pc/qualifier.py'] = qualifier
    tx = base('NORMAL/pc/epoch_transaction.py')
    pc['pc/epoch_transaction.py'] = tx
    pc['C_renewal_interface.py'] = bind(pc['C_renewal_interface.py'], {'APPROVED_R26_REVIEW': review, 'PC_ROOT': P.PC_ROOT + '/c-arm-r26/renewals'})
    pc['pc/C_renewal_receiver.py'] = bind(pc['pc/C_renewal_receiver.py'], {'APPROVED_INTERFACE_SHA': sha(pc['C_renewal_interface.py']), 'APPROVED_REVIEW': review})
    renewal_worker = expression(bind(base('TOOLS/templates/pc/renewal_worker.py'), {'APPROVED_REVIEW': review}), 'ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    pc['renewal-worker.py'] = renewal_worker
    helpers['restart_qualification.py'] = bind(helpers['restart_qualification.py'], {'APPROVED_RENEWAL_WORKER_SHA': sha(renewal_worker), 'APPROVED_C_RENEWAL_CONSUMER_SHA': sha(pc['pc/C_renewal_receiver.py'])})
    helpers['entry_clock_store.py'] = bind(helpers['entry_clock_store.py'], {'NONCE': entry_nonce})
    helpers['safe_error.py'] = bind(helpers['safe_error.py'], {'APPROVED_TRACE_FILES': tuple(sorted(set(old['PC_source_pins']) | {P.PC_ROOT + '/service/' + n for n in names} | {P.PC_ROOT + '/parent-root-rpc.py'} | {P.PC_ROOT + '/' + n for n in gate['PC_files'] if n.endswith('.py')}))})
    codes = set()
    for raw in tuple(helpers.values()) + tuple(gate['PC_files'].values()):
        for n in ast.walk(ast.parse(raw)):
            if isinstance(n, ast.Call) and len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and (type(n.args[1].value) is str) and (getattr(n.func, 'id', None) in ('need', 'epoch_need', 'old_need', 'prefile_need', 'owner_need') or getattr(n.func, 'attr', None) == 'need'):
                codes.add(n.args[1].value)
    oldcodes = next((n.value for n in ast.parse(helpers['safe_error.py']).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'CODES' for t in n.targets))))
    codes.update(ast.literal_eval(oldcodes.args[0]) if isinstance(oldcodes, ast.Call) else ast.literal_eval(oldcodes))
    helpers['safe_error.py'] = bind(helpers['safe_error.py'], {'CODES': tuple(sorted(codes))})
    safe_text = helpers['safe_error.py'].decode()
    before = "name=='Refused'"
    need(safe_text.count(before) == 1, 'R16_exact_fixed_owner_refusal_predicate')
    safe_text = safe_text.replace(before, "name in ('Refused','owner_Refused')", 1)
    before = "('Refused','ValueError','TimeoutError','OSError','FileNotFoundError','PermissionError')"
    need(safe_text.count(before) == 1, 'R16_exact_fixed_owner_error_type')
    safe_text = safe_text.replace(before, "('Refused','owner_Refused','ValueError','TimeoutError','OSError','FileNotFoundError','PermissionError')", 1)
    helpers['safe_error.py'] = safe_text.encode()
    if current is not None:
        node = next((n.value for n in ast.parse(helpers['safe_error.py']).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'READONLY' for t in n.targets))))
        allowed = ast.literal_eval(node.args[0])
        helpers['safe_error.py'] = expression(helpers['safe_error.py'], 'READONLY', 'frozenset(' + repr(tuple(allowed) + ('activate-registry-source', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage', 'prepare-empty-asset-range-repair')) + ')')
    hp = {n: sha(b) for n, b in helpers.items()}
    wire = helper_builder.wire(cold['wire_raw'], helpers, names, review)
    if current is not None:
        actions = next((n.value for n in ast.parse(wire).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'REGISTRY_ACTIONS' for t in n.targets))))
        actions = ast.literal_eval(actions.args[0]) if isinstance(actions, ast.Call) else ast.literal_eval(actions)
        wire = expression(wire, 'REGISTRY_ACTIONS', 'frozenset(' + repr(tuple(actions) + ('prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage', 'prepare-empty-asset-range-repair')) + ')')
    newmap = dict(old['PC_source_pins'])
    wirepath = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py'
    newmap[wirepath] = sha(wire)
    cfg = encode(dict(old, PC_source_pins=newmap, review_sha256=review))
    pc.update({'service/' + n: b for n, b in helpers.items()})
    probe = expression(bind(basepc['prestart-helper-check.py'], {'APPROVED_HELPERS': hp, 'APPROVED_REVIEW': review, 'ORDER': names}), 'ROOT', 'Path(' + repr(P.PC_ROOT + '/service') + ')')
    pc['prestart-helper-check.py'] = probe
    pc['pc/stopped_live_idle.py'] = bind(pc['pc/stopped_live_idle.py'], {'APPROVED_LIVE_IDLE_SHA': hp['live_idle.py']})
    for leaf, mapping in (('pc-nodes-readonly.py', old['PC_source_pins']), ('pc-nodes-readonly-new.py', newmap)):
        pc[leaf] = expression(bind(basepc[leaf], {'APPROVED_RELEASE': review, 'SOURCE_PINS': mapping, 'CONFIG_SHA': old['PC_source_pins']['/etc/dgx-home-ai/node-adapter.json'], 'APPROVED_LIVE_IDLE_SHA': hp['live_idle.py'], 'APPROVED_HELPER_PINS': {n: hp[n] for n in ('contract.py', 'prelaunch_stop.py', 'live_idle.py')}}), 'PC_ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    inp = {n: sha(pc['pc/' + n]) for n in ('inputs/io_utils.py', 'inputs/old_installer_helpers.py', 'current_reader.py', 'negative_contract.py', 'stopped_nodes.py', 'AB_source_barrier.py', 'C_renewal_receiver.py', 'prelaunch_stop.py', 'prelaunch_barrier.py')}
    inp.update({n: sha(pc[n]) for n in ('pc-nodes-readonly.py', 'pc-nodes-readonly-new.py', 'C_renewal_interface.py')})
    inp.update(service_helpers=hp, service_order=names, cold_stage=cold['stage_pins'], prelaunch_policy_sha256=literal(basepc['pc/native.py'], 'APPROVED_INPUT_PINS')['prelaunch_policy_sha256'])
    inp['r11-gate/gate_loader.py'] = gate['loader_sha256']
    native_text = pc['pc/native.py'].decode()
    for prior_slot, new_slot in (("PC_ROOT/'c-arm-r26/before_start.py'", "PC_ROOT/'c-arm-r30/before_start.py'"), ("['cold_stage']['c-arm-r26/before_start.py']", "['cold_stage']['c-arm-r30/before_start.py']"), ("p['entry_phase']=='LIVE_RESERVED_STAGE'", "p['entry_phase']==ENTRY_PHASE")):
        need(native_text.count(prior_slot) == 1, 'R13_one_current_native_slot:' + prior_slot)
        native_text = native_text.replace(prior_slot, new_slot, 1)
    native_text = owner_native(native_text)
    pc['pc/native.py'] = native_text.encode()
    native = bind(pc['pc/native.py'], {'APPROVED_INPUT_PINS': inp, 'APPROVED_OLD_CONFIG_SHA': sha(facts['config_raw']), 'APPROVED_NEW_CONFIG_SHA': sha(cfg), 'APPROVED_STOPPED_LIVE_IDLE_SHA': sha(pc['pc/stopped_live_idle.py']), 'APPROVED_PRESTART_PROBE_SHA': sha(probe)})
    pc['pc/native.py'] = native
    oldpacket = json.loads(base('PC/epoch-packet.json'))
    packet = {'entry_phase': P.ENTRY_PHASE, 'review_sha256': review, 'operation': P.EPOCH, 'grant_operation': P.ASSET_OPERATION, 'oldmap': old['PC_source_pins'], 'newmap': newmap, 'old_identity': facts['identity'], 'old_config_raw_utf8': facts['config_raw'].decode(), 'new_config_raw_utf8': cfg.decode(), 'wire_raw_utf8': wire.decode(), 'helpers': hp, 'input_pins': inp, 'historical_ancestor_sha256': oldpacket['historical_ancestor_sha256'], 'historical_oldmap': oldpacket['historical_oldmap'], 'old_grant_operation': P.OLD_GRANT_OPERATION}
    packetraw = encode(packet)
    pc['epoch-packet.json'] = packetraw
    pc['pc/epoch_transaction.py'] = bind(tx, {'APPROVED_PACKET_SHA': sha(packetraw)})
    pc['epoch-scope/worker.py'] = worker
    rootpins = {n: sha(pc[n]) for n in ROOT_ORDER}
    for mode, leaf in (('epoch', 'epoch-scope/loader.py'), ('epoch-finalize', 'epoch-finalize.py')):
        pc[leaf] = bind(base('TOOLS/templates/pc/loader.py'), {'MODE': mode, 'APPROVED_REVIEW': review, 'APPROVED_PACKET_SHA': sha(packetraw), 'APPROVED_MODULE_PINS': rootpins, 'MODULE_ORDER': ROOT_ORDER})
    pc['renewal-loader.py'] = expression(bind(base('TOOLS/templates/pc/renewal_loader.py'), {'ORDER': names, 'APPROVED_REVIEW': review, 'APPROVED_PACKET_SHA': sha(packetraw), 'APPROVED_SERVICE_PINS': hp, 'APPROVED_ROOT_PINS': {n: sha(pc[n]) for n in ('pc/native.py', 'pc/current_reader.py', 'pc/bounded_process.py', 'pc/managed_scope.py', 'pc/root_renewal.py')}, 'APPROVED_C_RENEWAL_MODULE_SHA': sha(pc['pc/C_renewal_receiver.py'])}), 'ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    rpc = expression(bind(base('TOOLS/templates/pc_rpc.py'), {'APPROVED_PC_RPC': {'review_sha256': review, 'helper_pins': hp, 'entry_producer_sha256': A['agent_sha256'], 'terminal_producer_sha256': sha(A['files']['fetch/entry.py']), 'entry_nonce': entry_nonce, 'renewal_loader_sha256': sha(pc['renewal-loader.py'])}}), 'PC_ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    rpc = integrate_current.transformed(rpc, 'rpc') if current is not None else rpc
    if current is not None:
        text = rpc.decode()
        marker = "'status-asset-stage'"
        need(text.count(marker) == 2, 'R13_exact_Root_RPC_closed_asset_action_tables')
        text = text.replace(marker, marker + ",'prepare-empty-asset-range-repair'")
        before = " if p['action'] in ASSET_ACTIONS:\n"
        need(text.count(before) == 1, 'R13_exact_Root_repair_publication_dispatch')
        text = text.replace(before, " if p['action']=='publish-empty-asset-range-repair-contract':\n  import empty_range_repair\n  cfg,identity=current();return empty_range_repair.publish_contract(cfg,identity,p['payload'])\n" + before, 1)
        before = 'ACTIONS=ASSET_ACTIONS|'
        need(text.count(before) == 1, 'R13_closed_Root_only_repair_publisher')
        text = text.replace(before, "ACTIONS={'publish-empty-asset-range-repair-contract'}|ASSET_ACTIONS|", 1)
        rpc = text.encode()
    rpc = operation_domains.rpc(rpc)
    pc['parent-root-rpc.py'] = rpc
    identity = {'schema': 'R12-normal-source-identity/v1', 'review_sha256': review, 'operation': P.EPOCH, 'business_operation': P.BUSINESS, 'old_identity': facts['identity'], 'old_config_sha256': sha(facts['config_raw']), 'new_config_sha256': sha(cfg), 'normal_stop_calls_planned': 1, 'prior_stop_calls': 0, 'new_start_calls_planned': 1, 'actual_native_intent': None}
    pc['identity-contract.json'] = encode(identity)
    index = {'schema': 'registry-R26-final-source-index/v1', 'operation': P.EPOCH, 'review_sha256': review, 'role': 'epoch', 'files': {n: sha(b) for n, b in sorted(pc.items())}}
    indexraw = encode(index)
    pc['epoch-index.json'] = indexraw
    for mode in ('launch', 'finalize-stop'):
        pc['epoch-' + mode + '.py'] = bind(base('TOOLS/templates/pc/source_entry.py'), {'ROLE': 'epoch', 'MODE': mode, 'APPROVED_REVIEW': review, 'APPROVED_FINAL_INDEX_SHA': sha(indexraw)})
        pc['renewal-' + mode + '.py'] = expression(bind(base('TOOLS/templates/pc/renewal_entry.py'), {'MODE': mode, 'APPROVED_REVIEW': review, 'APPROVED_INDEX_SHA': sha(indexraw)}), 'ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    for n, b in pc.items():
        if n.endswith('.py'):
            compile(b, n, 'exec')
        need(len(b) <= 2097152, 'final_PC_leaf2MiB')
    import owner_scope_builder
    owner_scope = owner_scope_builder.build(entry_nonce)
    return {'owner_scope': owner_scope, 'PC': pc, 'A': A, 'normal_gate': gate, 'readonly_scope': scope, 'PC_data': packed, 'C_static9': builder.C_context(review).context(review, P.PC_ROOT)['static9'], 'packet': packet, 'wire': wire, 'config': cfg, 'helper_order': names, 'PC_bytes': sum(map(len, pc.values())), 'PC_files': len(pc), 'pending': [] if current is not None else ['current_v2_frozen_source_and_new_actions'], 'actual_intent': None, 'native_eligible': False}
