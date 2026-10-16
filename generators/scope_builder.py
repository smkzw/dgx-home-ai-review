# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One immutable renderer/source-table shared by parent and service late binding."""
import base64, json
from source_io import base, bind, sha, encode, need, load_source, HERE
import policy as P
import empty_protocol
import component_source, history_binding
from integrate_emitter import renderer as derive_renderer

def templates(A, *, current=None):
    pins = json.loads(base('ZERO_EMITTER/PRODUCTION_PINS.json'))['files']
    out = {n.removeprefix('external:'): base('ZERO_EMITTER/external/' + n.removeprefix('external:') + '.py') for n in pins if n.startswith('external:')}
    for name in ('current_clock', 'current_negative', 'current_scope', 'current_qualified', 'stage_naming'):
        out.pop(name, None)
    out['plan'] = A['files']['plan.py']
    out['zero_runtime'] = empty_protocol.runtime(base('ZERO_EMITTER/SOURCE/runtime.py'))
    if current is not None:
        need(set(current) == {'current_clock', 'current_negative', 'current_scope', 'current_qualified', 'known_prior_assets'}, 'complete_current_v2_template_table')
        out.update(current)
        out['stage_naming'] = A['files']['stage_naming.py']
    return out

def build(A, oldpolicy, packedpins, reader_raw, *, current=None):
    renderer = component_source.renderer()
    text = renderer.decode()
    old = "bindings['known_prior_assets']={'ROLE':role,'PC_TERMINAL_ROOT':PC_ROOT+'/asset-terminals' if role=='PC' else None}"
    new = "bindings['known_prior_assets']={'ROLE':role,'PC_TERMINAL_ROOT':PC_ROOT+'/asset-terminals' if role=='PC' else None,'old_APPROVED_HISTORY':APPROVED_ANCESTOR_HISTORY,'prefile_APPROVED_HISTORY':APPROVED_PREFILE_HISTORY}"
    need(text.count(old) == 1, 'R15_one_known_prior_private_source_context')
    renderer = text.replace(old, new, 1).encode()
    loader = empty_protocol.loader(base('ZERO_EMITTER/SOURCE/held_loader.py'))
    tables = {'historical-fixed': templates(A)}
    if current is not None:
        tables['current-stage-prebind'] = templates(A, current=current)
        table = templates(A, current=current)
        table.pop('known_prior_assets')
        table.update(empty_protocol.templates())
        table['current_negative'] = component_source.raw('SOURCE/current_negative.py')
        table['current_qualified'] = component_source.raw('SOURCE/current_qualified.py')
        tables[empty_protocol.MODE] = table
    allsource = {}
    keys = {}
    for mode, table in tables.items():
        keys[mode] = {}
        for name, raw in table.items():
            key = name if name not in allsource or allsource[name] == raw else mode + ':' + name
            need(key not in allsource or allsource[key] == raw, 'scope_one_closed_bundle_key_one_body')
            allsource[key] = raw
            keys[mode][name] = key
    bundle = encode({'schema': 'R12-readonly-template-source/v1', 'files': {n: {'source_bytes_base64': base64.b64encode(b).decode(), 'sha256': sha(b), 'source_bytes': len(b)} for n, b in sorted(allsource.items())}})
    files = {'readonly-renderer.py': renderer, 'readonly-held-loader.py': loader, 'readonly-template-source.json': bundle}
    root = P.PC_ROOT
    static = {mode: {'policy': oldpolicy, 'packed_pins': packedpins if mode == 'historical-fixed' else None, 'publication_operation': P.EPOCH if mode == 'historical-fixed' else None} for mode in tables}
    slots = {'APPROVED_RENDERER': {'path': root + '/readonly-renderer.py', 'sha256': sha(renderer)}, 'APPROVED_LOADER': {'path': root + '/readonly-held-loader.py', 'sha256': sha(loader)}, 'APPROVED_TEMPLATES': {mode: {n: {'path': root + '/readonly-template-source.json', 'bundle_sha256': sha(bundle), 'bundle_key': keys[mode][n], 'sha256': sha(b)} for n, b in table.items()} for mode, table in tables.items()}, 'APPROVED_STATIC': static, 'APPROVED_CURRENT_READER_SHA': sha(reader_raw), 'APPROVED_A_ORIGIN': {'source_root': P.A_ROOT, 'data_root': P.A_DATA, 'source_pins': A['pins'], 'source_sizes': {n: len(b) for n, b in A['files'].items()}, 'index_sha256': A['source_index_sha256'], 'ready_worker_sha256': A['ready_worker_sha256']}}
    bound = bind((HERE / 'late_scope_context.py').read_bytes(), slots)
    need(all((len(b) <= 2097152 for b in files.values())), 'scope_source_table_singleleaf2MiB')
    return {'files': files, 'late_context': bound, 'templates': tables, 'renderer_raw': renderer, 'loader_raw': loader, 'sealer_raw': empty_protocol.seal(base('ZERO_EMITTER/SOURCE/seal.py')), 'static': static, 'slots': slots, 'component_pending': None if current is not None else 'current_v2_frozen_source', 'actual_scope': None}

def render(graph, mode, current, nonce, actor_raw, reader_raw, input_pins):
    need(mode in graph['templates'], 'closed_bound_scope_mode')
    m = load_source(graph['renderer_raw'], 'offline_R12_single_renderer', HERE / 'readonly-renderer.py')
    static = graph['static'][mode]
    return m.render_plan(current, nonce, actor_raw, approved={'mode': mode, 'review': current['review_sha256'], 'policy': static['policy'], 'operation': P.ASSET_OPERATION, 'current_reader_sha256': sha(reader_raw), 'current_reader_input_pins': input_pins, 'packed_pins': static['packed_pins'], 'publication_operation': static['publication_operation']}, templates=graph['templates'][mode], loader=graph['loader_raw'])
