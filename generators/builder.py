# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""R12 phased offline graph. Pending inputs cannot create an executable packet."""
import ast, json, pathlib, types
from source_io import need, sha, encode, base, bind, expression, replace_definition, load_source, HERE
import policy as P
APPROVED_SOURCE_REVIEW = None
APPROVED_COMPONENTS = None

def components():
    return {'R12': {'state': 'frozen_accepted_baseline_not_replayed'}, 'C27': {'state': 'SOURCE_implemented_actual_pending', 'actual': None}, 'normal_R13_phases': {'state': 'SOURCE_implemented_actual_pending', 'actual': None}, 'retired_R12_history': {'state': 'historical_original_event_consumption_only', 'actual': None}, 'empty_range_repair': {'state': 'SOURCE_explicit_finite_0B_only_actual_pending', 'actual': None}}

def actual_baseline():
    cfg = base('INPUTS/actual-old-config.raw')
    wire = base('INPUTS/actual-old-wire.raw')
    v = json.loads(cfg)
    need(v['operation'] == P.BUSINESS and sha(cfg) == '2ff3afad2450db95f757cf44630f69fa7326128753f4308aa393998eb6554659' and (sha(wire) == v['PC_source_pins']['/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py']), 'complete_actual_current_D3_not_old_failed_baseline')
    return {'config_raw': cfg, 'wire_raw': wire, 'config': v, 'identity': json.loads((HERE.parent / 'R16_BASELINE_IMMUTABLE.json').read_bytes())['manager_identity']}

def C_context(review):
    path = HERE.parent / 'C30/interface.py'
    m = load_source(path.read_bytes(), 'R13_fixed_C27_interface', path)
    pins = json.loads((HERE.parent / 'C30_DERIVATION.json').read_bytes())['files']
    m.APPROVED_STATIC_PINS = {n: x['sha256'] for n, x in pins.items() if n.startswith(('C30_SOURCE/', 'pc_templates/'))}
    m.OPERATION = P.BUSINESS
    m.EPOCH_IDENTITY = {'operation': P.EPOCH, 'PC_root': P.PC_ROOT, 'review_sha256': review}
    m.RECEIPT_ROOT_IDENTITY = P.PC_ROOT + '/c-arm-r30'
    return m

def normal_contract(review):
    raw = base('PC/contract.py')
    facts = actual_baseline()
    raw = bind(raw, {'APPROVED_REVIEW': review, 'OPERATION': P.ASSET_OPERATION, 'EPOCH_OPERATION': P.EPOCH, 'ENTRY_PHASE': P.ENTRY_PHASE, 'SCOPE_UNIT': P.PC_UNIT, 'APPROVED_PREDECESSOR_IDENTITY': facts['identity'], 'APPROVED_PREDECESSOR_CONFIG_SHA': sha(facts['config_raw']), 'RELEASE_STATE': 'FAILED_ASSET_STAGE_NOT_LAUNCHED_QUIESCENT', 'FIRST_ACTIVATION_RELEASED': False, 'FIRST_ACTIVATION_HISTORICAL_ONLY': True})
    raw = expression(raw, 'PC_ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    raw = expression(raw, 'PARENT_SOURCE_BUNDLE', 'Path(' + repr('/home/REDACTED_USER/dgx-r26-r16-source-bundle.json') + ')')
    return raw

def partial(review):
    need(type(review) is str and len(review) == 64, 'offline_review_hash_not_permission')
    facts = actual_baseline()
    cm = C_context(review)
    cold = cm.cold_transform(facts['wire_raw'], review)
    pc = {n.removeprefix('PC/'): base(n) for n in json.loads((HERE / 'BASE_PINS.json').read_bytes()) if n.startswith('PC/')}
    for n in ('epoch-packet.json', 'epoch-index.json', 'identity-contract.json', 'epoch-launch.py', 'epoch-finalize-stop.py', 'epoch-scope/loader.py', 'renewal-launch.py', 'renewal-finalize-stop.py', 'r11-release-loader.py', 'r11-release-publication.py'):
        pc.pop(n, None)
    for n in tuple(pc):
        if n.startswith('c-arm-r26/'):
            pc.pop(n)
    pc.update(cold['stage_files'])
    contract = normal_contract(review)
    pc['contract.py'] = contract
    pc['service/contract.py'] = contract
    tx = base('NORMAL/pc/epoch_transaction.py')
    tx = bind(tx, {'APPROVED_PACKET_SHA': None})
    pc['pc/epoch_transaction.py'] = tx
    pc['pc/qualifier.py'] = base('NORMAL/templates/pc/qualifier.py')
    pc['service/current_epoch.py'] = base('NORMAL/templates/service/current_epoch.py')
    for n in json.loads((HERE / 'BASE_PINS.json').read_bytes()):
        if n.startswith('H5/PC/service/'):
            rel = n.removeprefix('H5/PC/')
            pc[rel] = base(n)
    pc['service/history_bootstrap.py'] = bind(pc['service/history_bootstrap.py'], {'APPROVED_NEW_REVIEW': review})
    pc['service/stage_naming.py'] = bind(pc['service/stage_naming.py'], {'FAMILY': P.FAMILY})
    pc['service/asset_stage.py'] = bind(pc['service/asset_stage.py'], {'APPROVED_REVIEW': review})
    pc['service/asset_stage.py'] = expression(pc['service/asset_stage.py'], 'STATE_ROOT', 'OPERATOR/' + repr('fixed-image-asset-stages-' + P.FAMILY))
    pc['service/zero_recovery.py'] = bind(pc['service/zero_recovery.py'], {'RECOVERY_ROOT': '/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/zero-launch-' + P.EPOCH, 'QUALIFIED_ROOT': P.PC_ROOT, 'APPROVED_REVIEW': review})
    edges = [{'from': 'static SOURCE pins', 'to': 'review'}, {'from': 'review + old complete wire', 'to': 'C26 cold static13'}, {'from': 'normal contract final bytes', 'to': 'phase private loader'}, {'from': 'A final source/index', 'to': 'service final producer pins'}, {'from': 'service full helper pins', 'to': 'wire'}, {'from': 'wire', 'to': 'config PC118 (other117 exact)'}, {'from': 'packet/root modules', 'to': 'epoch index and source entry'}, {'from': 'actual new qualified current', 'to': 'fresh readonly zero request/policy'}, {'from': 'Root PC30 qualified receipt', 'to': 'sameRuntime single activate/zero release'}]
    for n, b in pc.items():
        if n.endswith('.py'):
            compile(b, n, 'exec')
        need(len(b) <= 2097152, 'partial_singleleaf_cap')
    return {'PC': pc, 'C_static9': cm.context(review, P.PC_ROOT)['static9'], 'cold_wire': cold['wire_raw'], 'components': components(), 'hash_DAG': edges, 'open_edges': ['normal phase root/A emitters final binding', 'A full final wrappers/index and producer pins', 'future prebind component', 'oldcfg ffc2 historical adapter', 'trusted late scope context', 'all helper/root/packet/index hashes'], 'native_eligible': False, 'runnable_packet': None, 'actual_intent': None}

def write_partial(destination, review):
    out = pathlib.Path(destination)
    need(not out.exists() and out.parent == HERE, 'unique_local_partial_destination')
    g = partial(review)
    out.mkdir(mode=448)
    index = {}
    for role in ('PC', 'C_static9'):
        for n, b in g[role].items():
            path = out / role / n
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b)
            index[role + '/' + n] = {'sha256': sha(b), 'bytes': len(b)}
    report = {k: v for k, v in g.items() if k not in ('PC', 'C_static9', 'cold_wire')}
    report['physical_pins'] = index
    report['PC_fragment_bytes'] = sum((len(b) for b in g['PC'].values()))
    report['PC_fragment_files'] = len(g['PC'])
    (out / 'PARTIAL_GRAPH.json').write_bytes(encode(report))
    return report
PRODUCTION_SOURCE_FILES = ('source_io.py', 'policy.py', 'builder.py', 'a_builder.py', 'helper_builder.py', 'operation_domains.py', 'history_binding.py', 'component_source.py', 'normal_gate_builder.py', 'phase_histories.py', 'history_data.py', 'late_scope_context.py', 'integrate_emitter.py', 'scope_builder.py', 'integrate_current.py', 'current_builder.py', 'final_graph.py', 'a_origin.py', 'origin_emitters.py', 'empty_protocol.py', 'owner_builder.py', 'owner_native.py', 'owner_scope_builder.py', 'owner_parent.py')

def source_pins():
    pins = {name: sha((HERE / name).read_bytes()) for name in PRODUCTION_SOURCE_FILES}
    for name, row in json.loads((HERE / 'BASE_PINS.json').read_bytes()).items():
        raw = base(name)
        pins['BASE/' + name] = sha(raw)
    for name in ('SOURCE_CONTRACT.json', 'R15_BASELINE_IMMUTABLE.json', 'R12_RETIRED_POLICY.json', 'NORMAL_PHASE_POLICY.json', 'NORMAL_PHASE_HISTORY.raw', 'normal_negative.py', 'phase_histories_r14.py', 'role_context_candidate.py', 'source_pending.py', 'SOURCE_PENDING_POLICY.json', 'retired_family.py', 'CANDIDATE_DIAGNOSTICS.json', 'empty_range_repair.py', 'empty_repair_negative.py', 'empty_repair_transform.py', 'known_prior_assets_r13.py', 'KNOWN_PRIOR_EMPTY_DERIVATION.json', 'derive_known_prior.py', 'known_empty_tail.py'):
        pins['R13/' + name] = sha((HERE.parent / name).read_bytes())
    for name, row in json.loads((HERE.parent / 'C30_DERIVATION.json').read_bytes())['files'].items():
        raw = (HERE.parent / 'C30' / name).read_bytes()
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'R13_exact_derived_C27_SOURCE')
        pins['C27/' + name] = sha(raw)
    for name in ('range_http.py', 'diagnostics.py', 'range_diagnostic.py'):
        pins['CANDIDATE/A/' + name] = sha((HERE.parent / 'CANDIDATE/A' / name).read_bytes())
    for name in ('HISTORY_INPUTS.json', 'PARENT_CONTRACT.json', 'normal_negative_r15.py', 'phase_histories_r15.py', 'known_prior_assets_r15.py', 'DATA/normal-history.json', 'DATA/old-domain-descriptor.json', 'PARALLEL_COMPONENT.json'):
        pins['R15/' + name] = sha((HERE.parent / name).read_bytes())
    for name, row in json.loads((HERE.parent / 'COMPONENT/PINS.json').read_bytes())['files'].items():
        raw = (HERE.parent / 'COMPONENT' / name).read_bytes()
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'R15_exact_component_selected_SOURCE')
        pins['COMPONENT/' + name] = sha(raw)
    for name in ('R16_CONTRACT.json', 'R16_BASELINE_IMMUTABLE.json', 'OWNER_POLICY.unbound.json', 'R16_NORMAL_INPUT.json', 'DATA/R16-normal-history.json', 'owner_readonly_worker.py', 'owner_worker_main.py', 'owner_scope_run.py', 'phase_histories_r16.py', 'normal_negative_r16.py', 'INPUTS/R15-current-config.raw', 'INPUTS/R15-current-wire.raw'):
        pins['R16/' + name] = sha((HERE.parent / name).read_bytes())
    for name in ('CANDIDATE/history_reader.py', 'CANDIDATE/asset_stage.py', 'CANDIDATE/prelaunch_recovery.py', 'SOURCE/owner_terminal_context.py', 'SOURCE/owner_terminal_recovery.py', 'SOURCE/owner_terminal_producer.py'):
        pins['OWNER/' + name] = sha((HERE.parent / 'OWNER' / name).read_bytes())
    pins['PARALLEL/live_idle.py'] = sha((HERE.parent / 'CANDIDATE/PC/live_idle.py').read_bytes())
    return dict(sorted(pins.items()))

def source_review():
    return {'schema': 'R12-minimal-joint-source-review/v1', 'sourceepoch': P.EPOCH, 'business_operation': P.BUSINESS, 'source_pins': source_pins(), 'readonly_sealer': {'preimage_sha256': sha(base('ZERO_EMITTER/SOURCE/seal.py')), 'derived_sha256': sha(__import__('empty_protocol').seal(base('ZERO_EMITTER/SOURCE/seal.py')))}, 'actual_issue': None, 'actual_window': None, 'actual_permit': None, 'native_eligible': False, 'authority_from_JSON': False, 'code_limit': 4194304, 'data_limit': 4194304, 'leaf_limit': 2097152, 'index_limit': 128}

def materialize(review_raw, entry_nonce):
    need(type(review_raw) is bytes and strict_review(review_raw) == source_review(), 'exact_complete_source_review_not_permission')
    import final_graph, integrate_current
    graph = final_graph.assemble(sha(review_raw), entry_nonce, current=integrate_current.template_table())
    need(graph['PC_files'] <= 128 and graph['PC_bytes'] <= 4194304, 'final_code_caps')
    import base64
    serialized = encode({'role': 'epoch', 'review_sha256': graph['packet']['review_sha256'], 'files': {n: base64.b64encode(b).decode() for n, b in graph['PC'].items()}, 'index': json.loads(graph['PC']['epoch-index.json'])})
    need(len(serialized) <= 4194304, 'R15_complete_serialized_PC_bundle_original4MiB')
    graph['serialized_PC_source_bundle_bytes'] = len(serialized)
    return graph

def strict_review(raw):

    def pairs(items):
        v = {}
        for k, x in items:
            need(k not in v, 'duplicate_review_key')
            v[k] = x
        return v
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_review'))
if __name__ == '__main__':
    raise SystemExit('offline_SOURCE_only_use_explicit_partial_no_native')
