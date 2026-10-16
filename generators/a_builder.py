# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Derive once from exact installed A53. Explicit live slots, no prefix replace."""
import ast, json
from source_io import base, bind, expression, encode, sha, need, load_source, HERE
import policy as P

def relocate(raw, slots):
    s = raw.decode()
    lines = s.splitlines(True)
    nodes = [n for n in ast.walk(ast.parse(s)) if isinstance(n, ast.Constant) and type(n.value) is str and (n.value in slots)]
    for n in sorted(nodes, key=lambda x: (x.lineno, x.col_offset), reverse=True):
        need(n.lineno == n.end_lineno, 'single_line_live_slot')
        line = lines[n.lineno - 1]
        lines[n.lineno - 1] = line[:n.col_offset] + repr(slots[n.value]) + line[n.end_col_offset:]
    raw = ''.join(lines).encode()
    compile(raw, 'explicit_live_slot', 'exec')
    return raw

def metadata_answer_receipt(raw):
    """Match the existing Root agent ABI: A reception stamp is pulse-only."""
    text = raw.decode()
    old = "answer=dict(data['answer']);answer['A_received_at']=time.time();return exchange"
    new = "answer=dict(data['answer']);\n  if type(answer)is dict and 'original_raw_b64' in answer:answer['A_received_at']=time.time()\n  return exchange"
    need(text.count(old) == 1, 'one_exact_unconditional_asset_answer_stamp')
    out = text.replace(old, new, 1).encode()
    compile(out, 'source_held_pulse_only_receipt', 'exec')
    return out

def build(review, nonce, contract_raw, qualifier_raw, worker_raw):
    pins = json.loads((HERE / 'BASE_PINS.json').read_bytes())
    body = {n.removeprefix('A/'): base(n) for n in json.loads((HERE.parents[2] / 'runtime/R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12/FINAL_GRAPH_D/PHYSICAL_PINS.json').read_bytes()) if n.startswith('A/')}
    oldindex = json.loads(body['source-index.json'])
    for n, pin in oldindex['files'].items():
        need(sha(body[n]) == pin, 'installed_A53_inner_source_exact')
    for n in ('qualification.py', 'point_clock.py', 'segment_agent.py'):
        body[n] = base('H5/A/' + n)
    body['segment_agent.py'] = metadata_answer_receipt(body['segment_agent.py'])
    slots = {P.OLD_A: P.A_ROOT, P.OLD_DATA: P.A_DATA, P.OLD_A + '/entry-state': P.A_ROOT + '/entry-state', P.OLD_A + '/root_agent.py': P.A_ROOT + '/root_agent.py', P.OLD_PC: P.PC_ROOT, P.OLD_DATA + '/parent-metadata.sock': P.A_DATA + '/parent-metadata.sock', 'dgx-v4-mimo-registry-native-prestart-r11.service': P.A_ENTRY_UNIT, 'mimo-registry-prestart-r11-owned': 'mimo-registry-' + P.FAMILY + '-owned', 'dgx-v4-mimo-registry-prestart-r11-index': 'dgx-v4-mimo-registry-' + P.FAMILY + '-index'}
    for n in ('asset_segments.py', 'fetch/supervision.py', 'old_failed_kernel.py', 'plan.py', 'private_config.py', 'segment_runtime.py'):
        body[n] = relocate(body[n], slots)
    body['namespace.py'] = bind(body['namespace.py'], {'ROOT': P.A_DATA})
    body['stage_naming.py'] = bind(body['stage_naming.py'], {'FAMILY': P.FAMILY})
    body['plan.py'] = bind(body['plan.py'], {'OPERATION': P.ASSET_OPERATION, 'UNIT': P.A_ENTRY_UNIT, 'ROOT': P.A_DATA, 'STAGE': P.A_ROOT, 'PC_STAGE': P.PC_ROOT, 'SOCKET': P.A_DATA + '/parent-metadata.sock', 'ENTRY_UNIT': 'dgx-v4-mimo-registry-a-entry-' + P.FAMILY + '-' + nonce + '.service', 'ENTRY_STATE': P.A_ROOT + '/entry-state', 'NAMESPACE': 'mimo-registry-' + P.FAMILY + '-owned', 'INDEX_NAME': 'dgx-v4-mimo-registry-' + P.FAMILY + '-index', 'AGENT': P.A_ROOT + '/root_agent.py'})
    need('EPOCH_OPERATION' not in {n.targets[0].id for n in ast.parse(body['plan.py']).body if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}, 'R15_plan_new_epoch_slot_not_rebind_business')
    body['plan.py'] += ('\nEPOCH_OPERATION=' + repr(P.EPOCH) + '\n').encode()
    body['asset_segments.py'] = bind(body['asset_segments.py'], {'APPROVED_REVIEW': review})
    body['pc_contract.py'] = contract_raw
    body['pc_managed_scope.py'] = base('PC/pc/managed_scope.py').replace(b'from contract import', b'from pc_contract import', 1)
    body['parent_source.py'] = bind(body['parent_source.py'], {'APPROVED_PC_QUALIFIER_SHA': sha(qualifier_raw), 'APPROVED_PC_WORKER_SHA': sha(worker_raw)})
    naming = load_source(body['namespace.py'], 'pure_fixed_namespace', HERE / 'namespace.py')
    need(naming.OLD_ROOT == '/var/lib/dgx-v4/mimo-registry-native-r26' and naming.BASE_SHA == sha(body['OFFICIAL_MERGED_BASELINE.json']), 'official_baseline_opaque_unchanged')
    config = load_source(body['private_config.py'], 'pure_fixed_config', HERE / 'private_config.py')
    body['containerd.candidate.toml'] = config.config_bytes(P.A_DATA)
    body['EXPECTED_DUMP.json'] = encode(naming.relocate(body['OFFICIAL_MERGED_BASELINE.json'], P.A_DATA))
    body['range_http.py'] = (HERE.parent / 'CANDIDATE/A/range_http.py').read_bytes()
    body['diagnostics.py'] = (HERE.parent / 'CANDIDATE/A/diagnostics.py').read_bytes()
    body['range_diagnostic.py'] = (HERE.parent / 'range_diagnostic.py').read_bytes()
    body['diagnostics.py'] = bind(body['diagnostics.py'], {'APPROVED_TRACE_FILES': tuple((P.A_ROOT + '/' + n for n in sorted(body) if n.endswith('.py')))})
    excludes = ('source-index.json', 'root_agent.py', 'entry_worker.py', 'root_loader.py', 'segment_runtime.py', 'segment_ready_worker.py')
    index = dict(oldindex, operation=P.ASSET_OPERATION, review_sha256=review, files={n: sha(raw) for n, raw in sorted(body.items()) if n not in excludes})
    iraw = encode(index)
    body['source-index.json'] = iraw
    body['segment_runtime.py'] = bind(body['segment_runtime.py'], {'APPROVED': {'index_sha256': sha(iraw), 'review_sha256': review}, 'BASE_DATA': P.A_DATA})
    for n in ('entry_worker.py', 'segment_ready_worker.py'):
        body[n] = bind(body[n], {'APPROVED_ENTRY': {'index_sha256': sha(iraw), 'review_sha256': review}})
    agent = ast.literal_eval(next((n.value for n in ast.parse(body['root_agent.py']).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'APPROVED_AGENT' for t in n.targets)))))
    agent.update(index_sha256=sha(iraw), review_sha256=review, entry_worker_sha256=sha(body['entry_worker.py']), root_worker_sha256=sha(body['root_worker.py']), ready_worker_sha256=sha(body['segment_ready_worker.py']), worker_sha256=sha(body['segment_worker.py']), segment_wrappers={n: sha(body[n]) for n in ('segment_runtime.py', 'segment_ready_worker.py')})
    agent['stage_clock_policy'].update(operation=P.ASSET_OPERATION, source_review_sha256=review, worker_sha256=agent['ready_worker_sha256'], source_index_sha256=sha(iraw))
    body['root_agent.py'] = bind(body['root_agent.py'], {'APPROVED_AGENT': agent})
    body['root_loader.py'] = bind(body['root_loader.py'], {'APPROVED_LITERAL': {'source_index_sha256': sha(iraw), 'review_sha256': review, 'context_producer_sha256': sha(body['root_agent.py'])}})
    for n, b in body.items():
        if n.endswith('.py'):
            compile(b, n, 'exec')
        need(len(b) <= 2097152, 'A_final_singleleaf_cap')
    need(sum(map(len, body.values())) <= 4194304, 'A_final_code_stage4MiB')
    need(len((P.A_DATA + '/sockets/' + 'a' * 32 + '.sock').encode()) < 108, 'A_future_UNIX_socket_cap')
    return {'files': body, 'pins': {n: sha(b) for n, b in sorted(body.items())}, 'source_index_sha256': sha(iraw), 'agent_sha256': sha(body['root_agent.py']), 'entry_worker_sha256': sha(body['entry_worker.py']), 'ready_worker_sha256': sha(body['segment_ready_worker.py']), 'segment_worker_sha256': sha(body['segment_worker.py']), 'segment_terminal_producer_sha256': sha(body['segment_terminal_producer.py']), 'actual_intent': None}
