# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite pure offline existing-leaf binder. No IO/native authority on import."""
import ast, base64, builtins, dataclasses, hashlib, json, pathlib, sys, types
HERE = pathlib.Path(__file__).resolve().parent
CONFIG = '/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json'
WIRE = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py'
LEAF = 2097152
BUNDLE = 4194304
ACTUAL_CONTEXT = None

def need(v, r):
    if not v:
        raise ValueError(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(b):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_key')
            d[k] = v
        return d
    return json.loads(b, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite'))

def inputs():
    refs = strict((HERE / 'SOURCE_INPUTS.json').read_bytes())
    out = {}
    for ref in refs.values():
        if ref['copy']:
            b = (HERE / ref['copy']).read_bytes()
            need(sha(b) == ref['sha256'] and len(b) == ref['bytes'], 'fixed_input_bytes')
            out[ref['copy'].removeprefix('INPUTS/')] = b
    return out

def source_tools(raw):
    t = ast.parse(raw)
    selected = [n for n in t.body if isinstance(n, ast.FunctionDef) and n.name in ('bind', 'expression', 'encode')]
    ns = {'ast': ast, 'json': json, 'need': need}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<exact_R16_source_io_functions>', 'exec'), ns)
    return ns

def private_load(table, order):
    """Fresh exact source module dictionaries, no sys.modules/ambient overrides."""
    need(set(table) == set(order), 'private_complete_exact_order')
    mods = {}
    for name in order:
        raw, pin = table[name]
        need(type(raw) is bytes and sha(raw) == pin, 'private_full_source_SHA')

        def imp(n, g=None, l=None, fromlist=(), level=0):
            if not level and n in table:
                need(n in mods, 'private_dependency_order')
                return mods[n]
            need(not level and n.split('.')[0] in sys.stdlib_module_names, 'private_unknown_import')
            return builtins.__import__(n, g, l, fromlist, level)
        m = types.ModuleType('_delta_binder_' + name)
        m.__file__ = '/SOURCE/' + name + '.py'
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imp)
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        mods[name] = m
    return mods

@dataclasses.dataclass(frozen=True)
class ServiceDomain:
    contract: bytes
    policy_source: bytes
    delta_source: bytes
    policy_raw: bytes
    old_config_raw: bytes
    old_files_raw: bytes
    old_config_stat_raw: bytes
    runtime: tuple

def service_domain(*, old_config_raw, old_source_files, old_config_stat, runtime_five, contract_values):
    src = inputs()
    tools = source_tools(src['recipe__source_io.py'])
    accepted = strict(src['accepted-five.json'])['source_delta']
    old = strict(old_config_raw)
    oldmap = old['PC_source_pins']
    need(set(runtime_five) == {r['native_path'] for r in accepted} and set(old_source_files) == set(oldmap) and (len(oldmap) == 118), 'complete_old118_exact_five_payloads')
    for path, pin in oldmap.items():
        need(old_source_files[path]['sha256'] == pin and set(old_source_files[path]) == {'sha256', 'stat'}, 'old118_exact_rows')
    check = private_load({'contract': (src['delta__contract.py'], sha(src['delta__contract.py'])), 'source_delta': (src['delta__source_delta.py'], sha(src['delta__source_delta.py']))}, ('contract', 'source_delta'))['source_delta']
    for row in accepted:
        b = runtime_five[row['native_path']]
        need(type(b) is bytes and len(b) == row['bytes'] and (sha(b) == row['new_sha256']) and (oldmap[row['native_path']] == row['old_sha256']), 'exact_parent_accepted_five_bytes')
        compile(b, row['native_path'], 'exec')
    need(WIRE in oldmap and WIRE not in runtime_five and (CONFIG not in oldmap), 'fixed_wire_and_config_separate')
    for x in old_source_files.values():
        check.f9(x['stat'])
    check.f9(old_config_stat)
    required = {'APPROVED_REVIEW', 'APPROVED_PREDECESSOR_IDENTITY', 'APPROVED_PREDECESSOR_CONFIG_SHA', 'OPERATION', 'EPOCH_OPERATION', 'ENTRY_PHASE', 'SCOPE_UNIT', 'PC_ROOT', 'PARENT_SOURCE_BUNDLE'}
    need(set(contract_values) == required and contract_values['APPROVED_PREDECESSOR_CONFIG_SHA'] == sha(old_config_raw) and (type(contract_values['APPROVED_REVIEW']) is str) and (len(contract_values['APPROVED_REVIEW']) == 64), 'explicit_main_contract_context_no_generated_identity')
    values = dict(contract_values)
    paths = {n: values.pop(n) for n in ('PC_ROOT', 'PARENT_SOURCE_BUNDLE')}
    need(all((type(v) is str and pathlib.PurePosixPath(v).is_absolute() and (str(pathlib.PurePosixPath(v)) == v) and ('..' not in pathlib.PurePosixPath(v).parts) for v in paths.values())), 'explicit_main_source_paths')
    contract = tools['bind'](src['delta__contract.py'], values)
    for name, value in paths.items():
        contract = tools['expression'](contract, name, 'Path(' + repr(value) + ')')
    changed = sorted(set(runtime_five) | {WIRE})
    policy = {'schema': 'R17-service-explicit-delta-policy/v1', 'review_sha256': contract_values['APPROVED_REVIEW'], 'old_config': old, 'changed_paths': changed, 'fixed_five_new_sha256': {r['native_path']: r['new_sha256'] for r in accepted}, 'old_sources': [{'path': p, 'old_sha256': oldmap[p], 'old_stat': old_source_files[p]['stat']} for p in changed], 'old_config_leaf': {'path': CONFIG, 'old_sha256': sha(old_config_raw), 'old_stat': old_config_stat}}
    contract += b'\nAPPROVED_OLD_SOURCE_FILES=' + repr(old_source_files).encode() + b'\n'
    contract += b'\nAPPROVED_DELTA_POLICY=' + repr(policy).encode() + b'\n'
    delta_source = src['delta__source_delta.py'].replace(b'from contract import need,sha,strict,CONFIG', b'from contract import need,sha,strict,CONFIG,APPROVED_OLD_SOURCE_FILES', 1)
    before = b'def before_matches(before,d):\n'
    need(delta_source.count(before) == 1, 'one_exact_before_baseline_seam')
    delta_source = delta_source.replace(before, before + None, 1)
    payload_old = None
    payload_new = None
    need(delta_source.count(payload_old) == 1, 'one_exact_payload_getter_seam')
    delta_source = delta_source.replace(payload_old, payload_new, 1)
    return ServiceDomain(contract, (HERE / 'service_delta_policy.py').read_bytes(), delta_source, encode(policy), old_config_raw, encode(old_source_files), encode(old_config_stat), tuple(sorted(runtime_five.items())))

def bind_root(domain, *, final_wire, final_config, qualifier, worker, native_values, packet_fields):
    need(type(domain) is ServiceDomain, 'only_internal_pre_wire_domain')
    src = inputs()
    tools = source_tools(src['recipe__source_io.py'])
    policy = strict(domain.policy_raw)
    old = strict(domain.old_config_raw)
    cfg = strict(final_config)
    runtime = dict(domain.runtime)
    runtime[WIRE] = final_wire
    need(type(final_wire) is bytes and type(final_config) is bytes and (type(worker) is bytes) and (type(qualifier) is bytes), 'final_bytes_required')
    newmap = dict(old['PC_source_pins'], **{p: sha(b) for p, b in runtime.items()})
    need(cfg['PC_source_pins'] == newmap and cfg['review_sha256'] == policy['review_sha256'] and (set(cfg) == set(old)) and ({k for k in cfg if cfg[k] != old[k]} == {'PC_source_pins', 'review_sha256'}), 'exact_final_config_six_delta_only')
    expected_worker = tools['bind'](src['R16__worker.py'], {'ROLE': 'epoch', 'APPROVED_REVIEW': policy['review_sha256']})
    need(worker == expected_worker, 'worker_exact_generic_template_no_late_delta')
    expected_qualifier = tools['bind'](src['delta__qualifier.py'], {'APPROVED_REVIEW': policy['review_sha256'], 'APPROVED_WORKER_SHA': sha(worker)})
    need(qualifier == expected_qualifier, 'qualifier_exact_non_delta_template_worker_review_only')
    delta = {'schema': 'registry-explicit-source-delta/v1', 'sources': [dict(x, new_sha256=newmap[x['path']]) for x in policy['old_sources']], 'config': dict(policy['old_config_leaf'], new_sha256=sha(final_config))}
    root_contract = tools['bind'](domain.contract, {'APPROVED_SOURCE_DELTA': delta})
    n = next((n for n in ast.parse(root_contract).body if isinstance(n, ast.Assign) and any((isinstance(x, ast.Name) and x.id == 'APPROVED_DELTA_POLICY' for x in n.targets))))
    lines = root_contract.decode().splitlines(True)
    lines[n.lineno - 1:n.end_lineno] = []
    root_contract = ''.join(lines).encode()
    supplied = {'entry_phase', 'operation', 'grant_operation', 'old_identity', 'helpers', 'input_pins', 'historical_ancestor_sha256', 'historical_oldmap', 'old_grant_operation'}
    need(set(packet_fields) == supplied, 'exact_main_packet_fields_no_wire_duplicate_or_override')
    packet = dict(packet_fields, review_sha256=policy['review_sha256'], oldmap=old['PC_source_pins'], newmap=newmap, old_config_raw_utf8=domain.old_config_raw.decode(), new_config_raw_utf8=final_config.decode(), changed_source_raw_utf8={p: b.decode() for p, b in runtime.items()}, source_delta=delta)
    packet_raw = encode(packet)
    modules = private_load({'contract': (root_contract, sha(root_contract)), 'source_delta': (domain.delta_source, sha(domain.delta_source))}, ('contract', 'source_delta'))
    modules['contract'].fixed_packet(packet)
    required = {'APPROVED_INPUT_PINS', 'APPROVED_OLD_CONFIG_SHA', 'APPROVED_NEW_CONFIG_SHA', 'APPROVED_STOPPED_LIVE_IDLE_SHA', 'APPROVED_PRESTART_PROBE_SHA'}
    need(set(native_values) == required and native_values['APPROVED_OLD_CONFIG_SHA'] == sha(domain.old_config_raw) and (native_values['APPROVED_NEW_CONFIG_SHA'] == sha(final_config)), 'exact_main_native_context')
    native = tools['bind'](src['delta__native.py'], native_values)
    tx = tools['bind'](src['delta__epoch_transaction.py'], {'APPROVED_PACKET_SHA': sha(packet_raw)})
    logical = {'contract.py': root_contract, 'pc/source_delta.py': domain.delta_source, 'pc/current_reader.py': src['delta__current_reader.py'], 'pc/native.py': native, 'pc/epoch_transaction.py': tx, 'pc/qualifier.py': qualifier, 'epoch-scope/worker.py': worker, 'epoch-packet.json': packet_raw}
    need('wire_raw_utf8' not in packet and len(delta['sources']) == 6, 'seven_CAS_no_wire_duplicate')
    for name, b in logical.items():
        if name.endswith('.py'):
            compile(b, name, 'exec')
    order = ('contract.py', 'pc/source_delta.py', 'pc/current_reader.py', 'pc/native.py', 'pc/epoch_transaction.py', 'pc/qualifier.py')
    tree = ast.parse(src['recipe__final_graph.py'])
    root_order = ast.literal_eval(next((n.value for n in tree.body if isinstance(n, ast.Assign) and any((isinstance(x, ast.Name) and x.id == 'ROOT_ORDER' for x in n.targets)))))
    need(root_order[0] == 'contract.py' and 'pc/source_delta.py' not in root_order, 'exact_R16_Root_order_insert')
    private_order = (root_order[0], 'pc/source_delta.py', *root_order[1:])
    return {'Root': logical, 'service': {'service/contract.py': domain.contract, 'service/source_delta.py': domain.delta_source, 'service/service_delta_policy.py': domain.policy_source}, 'Root_component_order': order, 'Root_private_order': private_order, 'Root_external_logical_sources': tuple((n for n in private_order if n not in logical)), 'Root_component_pins': {n: sha(logical[n]) for n in order}, 'service_component_order': ('contract.py', 'source_delta.py', 'service_delta_policy.py'), 'phase_contract_ref': {'path': 'service/contract.py', 'sha256': sha(domain.contract)}, 'packet': packet, 'source_delta': delta, 'unchanged_count': 112, 'native_eligible': False, 'actual_slots': None}

def measure(full_logical_sources):
    """Exact R16 builder.materialize serialization expression, complete input only."""
    need(type(full_logical_sources) is dict and 'epoch-index.json' in full_logical_sources and ('epoch-packet.json' in full_logical_sources), 'complete_bundle_metadata_required')
    need(all((type(n) is str and type(b) is bytes and (len(b) <= LEAF) for n, b in full_logical_sources.items())), 'source_leaf2MiB')
    graph = {'PC': full_logical_sources, 'packet': strict(full_logical_sources['epoch-packet.json'])}
    tree = ast.parse(inputs()['recipe__builder.py'])
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'materialize'))
    node = next((n for n in fn.body if isinstance(n, ast.Assign) and any((isinstance(x, ast.Name) and x.id == 'serialized' for x in n.targets))))
    serialized = eval(compile(ast.Expression(node.value), '<exact_R16_serialized_bundle>', 'eval'), {'encode': source_tools(inputs()['recipe__source_io.py'])['encode'], 'base64': base64, 'json': json, 'graph': graph})
    code_bytes = sum(map(len, full_logical_sources.values()))
    need(code_bytes <= BUNDLE and len(serialized) <= BUNDLE, 'complete_source_and_serialized4MiB')
    return {'logical_files': len(full_logical_sources), 'all_source_bytes': code_bytes, 'serialized_PC_source_bundle_bytes': len(serialized), 'serialized_sha256': sha(serialized), 'metadata_counted': True, 'physical128_acceptance': 'PENDING_MAIN_DEDUP_FULL_GRAPH'}
