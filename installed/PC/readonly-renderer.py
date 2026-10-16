# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Single pure protected renderer. No filesystem, Runtime, authority or IO.
The service supplies only internal held/pinned templates and static bindings.
"""
import hashlib, json, re
APPROVED_PREFILE_HISTORY = {'download_failed_original': None, 'entries': {'blobs': [66306, 55189573, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'containerd-data': [66306, 55189567, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'containerd-exec': [66306, 55189568, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'download-failed.json': [66306, 55189580, 395, 0, 0, 33152, 1, 1792132947392628289, 1792132947392628289], 'failed.json': [66306, 55189581, 1186, 0, 0, 33152, 1, 1792132947506628308, 1792132947506628308], 'home': [66306, 55189572, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'initial-kernel-unit.json': [66306, 55189575, 19346, 0, 0, 33152, 1, 1792132917302623837, 1792132917302623837], 'intent.json': [66306, 55189574, 414276, 0, 0, 33152, 1, 1792132917273623833, 1792132917273623833], 'owned-cleanup.json': [66306, 55189582, 1962, 0, 0, 33152, 1, 1792132947562628317, 1792132947562628317], 'private-opt': [66306, 55189569, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'private-overlay': [66306, 55189570, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833], 'segment-resources.jsonl': [66306, 55189579, 0, 0, 0, 33152, 1, 1792132917389623848, 1792132917389623848], 'segments.stderr': [66306, 55189578, 427, 0, 0, 33152, 1, 1792132947491840050, 1792132947491840050], 'segments.stdout': [66306, 55189577, 0, 0, 0, 33152, 1, 1792132917315623839, 1792132917315623839], 'tmp': [66306, 55189571, 4096, 0, 0, 16832, 2, 1792132917272623833, 1792132917272623833]}, 'failed_original': None, 'failure_location': {'function': 'sample', 'line': 143, 'source': '/opt/dgx-v4/mimo-registry-native-r26-role-context-r14/fetch/supervision.py'}, 'failure_observed_at': 1792132947.3933606, 'metadata_sha256': '06d23b3b05f372fb1fa662a6e8ed113e674f6c2f85515c89227d8fec1e8e14bc', 'producer_sources': {'fetch/supervision.py': '0b4b24b13250bafb38d41e5ef6fe079b725665bf7fbe8f9ca2d96ad2ab5fbbdf', 'segment_download_worker.py': '452d0e1e07e63218b8b12f843b3e1545e17c9e9fb8fa3f438aa11f242bdd0411', 'topology.py': '411036bf0b9b5fe3e419ff4a3ca6663151f086beb06f37962e3fc1c29aaadaac'}, 'range_F9': [66306, 55189566, 4096, 0, 0, 16832, 9, 1792132947562628317, 1792132947562628317], 'result_observed_at': 1792132947.506779, 'root_chain_F9': {'/var': [66306, 1441794, 4096, 0, 0, 16877, 13, 1762332498664000000, 1762332498664000000], '/var/lib': [66306, 1442040, 4096, 0, 0, 16877, 84, 1791724570084815877, 1791724570084815877], '/var/lib/dgx-v4': [66306, 3286406, 4096, 0, 0, 16877, 17, 1792132917184623822, 1792132917184623822], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14': [66306, 55189561, 4096, 0, 0, 16832, 4, 1792132917198623824, 1792132917198623824], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14/stages': [66306, 55189562, 4096, 0, 0, 16832, 3, 1792132917193623823, 1792132917193623823], '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14/stages/b7a518bbefa903b6c43c44b9a2f6f6cf': [66306, 55189563, 4096, 0, 0, 16832, 3, 1792132917272623833, 1792132917272623833]}, 'schema': 'failed-range-prefile-absence-static-history/v1', 'stage_operation': 'b7a518bbefa903b6c43c44b9a2f6f6cf', 'terminal_sha256': '3dcc5a38505ce24a79b9076ca39e1a3813a4f1f7e05a7e04089bf086a0681ecd'}
APPROVED_ANCESTOR_HISTORY = {'A_source': {'boot_id': 'redacted-32c02e882269', 'data_root': '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14', 'index_sha256': '9b9cc0a2c97ec234482aa20a2f195024651f9f821d2f78480ca75f04d7958256', 'ready_worker_sha256': 'cf565910ef8430c8b4bcec8c1a3805e9e3e58a262592f18856631dbd9aebb746', 'source_root': '/opt/dgx-v4/mimo-registry-native-r26-role-context-r14', 'sources': {'EXPECTED_DUMP.json': None, 'OFFICIAL_MERGED_BASELINE.json': None, 'asset_segments.py': None, 'bounded_process.py': None, 'broker.py': None, 'config-original.json': None, 'containerd.candidate.toml': None, 'diagnostics.py': None, 'download_worker.py': None, 'entry_clock.py': None, 'entry_worker.py': None, 'failed_terminal.py': None, 'fetch/config-original.json': None, 'fetch/contract.py': None, 'fetch/entry.py': None, 'fetch/fetch.py': None, 'fetch/manifest-original.json': None, 'fetch/oci.py': None, 'fetch/supervision.py': None, 'fetch/transport.py': None, 'manifest-original.json': None, 'namespace.py': None, 'native.py': None, 'observer.py': None, 'old_failed_kernel.py': None, 'parent_metadata.py': None, 'parent_source.py': None, 'pc_contract.py': None, 'pc_managed_scope.py': None, 'plan.py': None, 'point_clock.py': None, 'private_config.py': None, 'qualification.py': None, 'range_catalog.py': None, 'range_component.py': None, 'range_diagnostic.py': None, 'range_fetch.py': None, 'range_http.py': None, 'range_transport.py': None, 'root_agent.py': None, 'root_io.py': None, 'root_loader.py': None, 'root_worker.py': None, 'segment_agent.py': None, 'segment_download_worker.py': None, 'segment_ready.py': None, 'segment_ready_worker.py': None, 'segment_runtime.py': None, 'segment_terminal_producer.py': None, 'segment_worker.py': None, 'source-index.json': None, 'stage_entry_clock.py': None, 'stage_naming.py': None, 'terminal.py': None, 'topology.py': None}}, 'actors': {'b7a518bbefa903b6c43c44b9a2f6f6cf': None, '69b0a7b8356ae276839c3cc43044096c': None}, 'old_current': None, 'operation': 'ed7021db9df4c839d02f3271361924de', 'qualification_completed_original': None, 'qualification_summary': {'Core_generations': {'glm-ab': 14, 'image-turbo-c': 1, 'qwen-a-c': 11}, 'historical_only': True, 'initial_identity': {'boot_id': 'redacted-2606f3e07a03', 'invocation_id': '69c59077d950b1dff986304287b2fa6c', 'pid': 2023335, 'start_ticks': '34798009'}, 'source_qualified_sha256': 'deb0365552c06e04acd864d3fbb8cc06d5d826ea26e44dc6f32a35b1752036d7'}, 'qualified_original': None, 'schema': 'R14B-sealed-old-domain/v1', 'snapshot_result': {'actors': {'b7a518bbefa903b6c43c44b9a2f6f6cf': {'historical_only': True, 'retry_authorized': False, 'state': 'FAILED_REGISTRY_QUIESCENT', 'terminal_sha256': '3dcc5a38505ce24a79b9076ca39e1a3813a4f1f7e05a7e04089bf086a0681ecd'}, '69b0a7b8356ae276839c3cc43044096c': {'historical_only': True, 'retry_authorized': False, 'state': 'FAILED_REGISTRY_QUIESCENT', 'terminal_sha256': '455e0b3b131f3ecd92ce86d01fecec4985747c45981e94dc155b25875cf29e5b'}}, 'historical_only': True, 'resource_authorized': False, 'retry_authorized': False, 'schema': 'R14B-finite-epoch-historical-only/v1', 'source_activation_authorized': False, 'used': [{'count': 462849, 'digest': '2ed23d91404d4701b704d1bde211c59a2a564a31c315f05871a6e9403bc19945', 'start': 6291456}, {'count': 376792, 'digest': 'b69841cb303ccedcf38d7b88ef5624621de9afac92f991bd9493046493af0459', 'start': 0}], 'used_sha256': 'dd582c52b50eaed32a8a63812473abde289ee85d82ae93fc673bfd6c403b5fbd'}, 'snapshot_sha256': '17875f46f0529747493cfac1de59bc4e2c36f5715fdad9bf69d812f6e2196d0c'}
PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'
BOOTSTRAP_ROOT_HELD = None

def need(v, r):
    if not v:
        raise ValueError(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_zero_key')
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_zero'))

def entry(root, spec_sha, loader_pin, mode, extra=None):
    code = BOOTSTRAP_ROOT_HELD + '\nimport types,json,base64;\nroot=Path(' + repr(root) + ");p=root/'held_loader.py';raw,loader_f9=held(p," + repr(loader_pin) + ");m=types.ModuleType('actual_zero_held_loader');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);ctx=m.load(root," + repr(spec_sha) + ");runtime=ctx.module('zero_runtime');\n"
    if mode == 'collector':
        code += 'import sys;sys.stdout.buffer.write(runtime.collector(ctx))\n'
    elif mode == 'worker':
        code += 'runtime.worker(ctx,' + repr(extra) + ",root/'worker.py')\n"
    elif mode == 'launch':
        code += 'result=runtime.launch_capture(ctx,' + repr(extra['scope_policy']) + ',' + repr(extra['PC_BEGIN_original']) + ');print(json.dumps(result,allow_nan=False))\n'
    elif mode == 'begin':
        code += 'print(json.dumps(runtime.pc_begin(ctx),allow_nan=False))\n'
    elif mode == 'ack':
        code += 'print(json.dumps(runtime.pc_ack(ctx,' + repr(extra) + '),allow_nan=False))\n'
    elif mode == 'finish':
        code += 'print(json.dumps(runtime.pc_finish(ctx,' + repr(extra) + '),allow_nan=False))\n'
    else:
        need(False, 'closed_zero_entry_mode')
    compile(code, 'zero_emitted_' + mode, 'exec')
    return code.encode()

def render_plan(current, nonce, actor_raw, *, approved, templates, loader):
    """Pure renderer for same protected SOURCE held by parent/service. No IO or authority.
 Caller must independently hold/hash the fixed source table and static approved
 bindings; this seam never consumes caller JSON as permission and never runs IO.
 """
    need(type(PC_ROOT) is str and PC_ROOT.startswith('/opt/dgx-v4/hx/') and ('..' not in PC_ROOT.split('/')), 'prefile_future_PC_root_None')
    need(type(approved) is dict and set(approved) == {'mode', 'review', 'policy', 'operation', 'current_reader_sha256', 'current_reader_input_pins', 'packed_pins', 'publication_operation'}, 'zero_exact_internal_render_bindings')
    APPROVED_MODE = approved['mode']
    APPROVED_REVIEW = approved['review']
    APPROVED_POLICY = approved['policy']
    APPROVED_OPERATION = approved['operation']
    APPROVED_CURRENT_READER_INPUT_PINS = approved['current_reader_input_pins']
    APPROVED_PACKED_PINS = approved['packed_pins']
    APPROVED_PUBLICATION_OPERATION = approved['publication_operation']
    APPROVED_CURRENT = current
    APPROVED_ACTOR_RAW = actor_raw
    need(APPROVED_MODE in ('historical-fixed', 'current-stage-prebind', 'failed-empty-range-repair') and type(current) is dict and (current.get('review_sha256') == APPROVED_REVIEW) and (type(APPROVED_REVIEW) is str) and re.fullmatch('[0-9a-f]{64}', APPROVED_REVIEW) and (type(APPROVED_OPERATION) is str) and re.fullmatch('[0-9a-f]{32}', APPROVED_OPERATION) and (type(nonce) is str) and re.fullmatch('[0-9a-f]{32}', nonce) and (type(APPROVED_POLICY) is dict) and (type(loader) is bytes), 'zero_render_unbound_None_harddeny')
    need(type(templates) is dict and set(templates) == {'B_OWNER_RECOVERY_R25_WIRING.common', 'bounded_process', 'history_publication', 'history_reader_a', 'history_reader_pc', 'not_launched_history', 'observer', 'old_failed_kernel', 'plan', 'proc_lifetime', 'publication_fs_a', 'publication_fs_pc', 'ready_history', 'receipt_codec', 'root_io', 'zero_negative', 'zero_pc_clock', 'zero_qualified', 'zero_scope', 'zero_runtime'} | ({'current_negative', 'current_scope', 'current_clock', 'current_qualified', 'stage_naming'} | ({'known_prior_assets'} if type(actor_raw) is bytes and strict(actor_raw).get('schema') == 'current-stage-prebind-actor/v2' else set()) if APPROVED_MODE in ('current-stage-prebind', 'failed-empty-range-repair') else set()) and all((type(k) is str and type(v) is bytes for k, v in templates.items())), 'zero_held_complete_source_bytes')
    need(APPROVED_MODE == 'historical-fixed' and type(APPROVED_PACKED_PINS) is dict and (APPROVED_PUBLICATION_OPERATION is not None) and (actor_raw is None) or (APPROVED_MODE in ('current-stage-prebind', 'failed-empty-range-repair') and type(actor_raw) is bytes), 'zero_closed_history_or_actor_domain')
    if APPROVED_MODE == 'failed-empty-range-repair':
        need(type(APPROVED_ANCESTOR_HISTORY) is dict and APPROVED_OPERATION == APPROVED_ANCESTOR_HISTORY['operation'] == 'ed7021db9df4c839d02f3271361924de' and (APPROVED_POLICY['source_root'] == '/opt/dgx-v4/mimo-registry-r15') and (APPROVED_POLICY['data_root'] == APPROVED_ANCESTOR_HISTORY['A_source']['data_root'] == '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14') and (current['review_sha256'] != APPROVED_ANCESTOR_HISTORY['old_current']['review_sha256']), 'R15_same_family_shared_BASE_independent_new_source')
    historical = APPROVED_MODE == 'historical-fixed'
    label = 'asset-zero-readonly' if historical else 'asset-empty-repair-readonly' if APPROVED_MODE == 'failed-empty-range-repair' else 'asset-current-prebind-readonly'
    A = '/opt/dgx-v4/' + label + '-r14-' + nonce
    PC = PC_ROOT + ('/zero-readonly/' + nonce if historical else ('/asset-empty-repairs/' if APPROVED_MODE == 'failed-empty-range-repair' else '/current-prebind-readonly/') + strict(APPROVED_ACTOR_RAW)['stage_operation'])
    unit = 'dgx-v4-' + label + '-r14-' + nonce + '.service'
    if historical:
        request = encode({'schema': 'stage-not-launched-request/v1', 'operation': APPROVED_OPERATION, 'nonce': nonce, 'current': APPROVED_CURRENT, 'history_sha256': APPROVED_POLICY['A_history_sha256']})
    else:
        actor = strict(APPROVED_ACTOR_RAW)
        need(nonce == actor['stage_operation'], 'zero_current_nonce_is_internal_active_stage_operation')
        request = encode({'schema': 'failed-empty-range-repair-request/v1' if APPROVED_MODE == 'failed-empty-range-repair' else 'current-stage-prebind-request/v1', 'operation': APPROVED_OPERATION, 'nonce': nonce, 'current': APPROVED_CURRENT, 'actor_sha256': sha(APPROVED_ACTOR_RAW), 'stage_operation': actor['stage_operation']})
    source = dict(templates)
    out = {}
    for role, root in (('A', A), ('PC', PC)):
        selected = {n: b for n, b in source.items() if not (role == 'A' and n in ('B_OWNER_RECOVERY_R25_WIRING.common', 'zero_qualified', 'zero_pc_clock'))}
        reader = 'history_reader_a' if role == 'A' else 'history_reader_pc'
        selected['history_reader'] = source[reader]
        selected.pop('history_reader_a', None)
        selected.pop('history_reader_pc', None)
        selected['publication_fs'] = source['publication_fs_a' if role == 'A' else 'publication_fs_pc']
        selected.pop('publication_fs_a', None)
        selected.pop('publication_fs_pc', None)
        bindings = {'plan': {'UNIT': unit, 'ENTRY_UNIT': unit}, 'not_launched_history': {'HISTORY_ROOT': root + '/history-data', 'APPROVED_POLICY': APPROVED_POLICY, 'APPROVED_PACKED_PINS': {n: r['packed_sha256'] for n, r in (APPROVED_PACKED_PINS or {}).items()}, 'APPROVED_PUBLICATION_OPERATION': APPROVED_PUBLICATION_OPERATION}, 'zero_negative': {'APPROVED_POLICY': APPROVED_POLICY, 'APPROVED_REVIEW': APPROVED_REVIEW, 'ROOT': A, 'UNIT': unit, 'OPERATION': APPROVED_OPERATION}, 'history_publication': {'ROOT': root + '/history-data', 'OPERATION': APPROVED_PUBLICATION_OPERATION, 'OWNER': [0, 0, 33152, 1] if role == 'A' else [0, 989, 33056, 1], 'APPROVED_INPUTS': APPROVED_PACKED_PINS}}
        if APPROVED_MODE == 'failed-empty-range-repair':
            need(type(APPROVED_PREFILE_HISTORY) is dict, 'prefile_history_None_harddeny')
            need(type(APPROVED_ANCESTOR_HISTORY) is dict, 'ancestor_history_None_harddeny')
            bindings['current_negative'] = {'prefile_APPROVED_HISTORY': APPROVED_PREFILE_HISTORY, 'old_APPROVED_HISTORY': APPROVED_ANCESTOR_HISTORY}
        if not historical and 'known_prior_assets' in selected:
            bindings['known_prior_assets'] = {'ROLE': role, 'PC_TERMINAL_ROOT': PC_ROOT + '/asset-terminals' if role == 'PC' else None, 'old_APPROVED_HISTORY': APPROVED_ANCESTOR_HISTORY, 'prefile_APPROVED_HISTORY': APPROVED_PREFILE_HISTORY}
        spec = {'schema': 'asset-zero-readonly-spec/v1', 'role': role, 'mode': APPROVED_MODE, 'actor_sha256': None if historical else sha(APPROVED_ACTOR_RAW), 'operation': APPROVED_OPERATION, 'nonce': nonce, 'review': APPROVED_REVIEW, 'current': APPROVED_CURRENT, 'policy': APPROVED_POLICY, 'unit': unit, 'A_root': A, 'PC_root': PC_ROOT, 'request_sha256': sha(request), 'current_reader_sha256': approved['current_reader_sha256'], 'current_reader_input_pins': APPROVED_CURRENT_READER_INPUT_PINS, 'sources': {n: {'file': n.replace('.', '_') + '.py', 'sha256': sha(raw)} for n, raw in selected.items()}, 'bindings': bindings}
        if not historical:
            bindings.setdefault('current_negative', {}).update({'APPROVED_POLICY': APPROVED_POLICY, 'APPROVED_REVIEW': APPROVED_REVIEW, 'ROOT': A if APPROVED_MODE == 'failed-empty-range-repair' else root, 'OPERATION': APPROVED_OPERATION})
        if role == 'PC':
            scope = out['scope_policy']
            spec['A_file_pins'] = out['A']['pins']
            spec['A_file_sizes'] = {n: len(b) for n, b in out['A']['files'].items()}
            bindings['zero_scope' if historical else 'current_scope'] = {'APPROVED_SCOPE': scope}
            bindings['zero_pc_clock' if historical else 'current_clock'] = {'APPROVED_REVIEW': APPROVED_REVIEW}
            bindings['zero_qualified' if historical else 'current_qualified'] = {'APPROVED_REVIEW': APPROVED_REVIEW, 'APPROVED_ROOT': PC, 'APPROVED_POLICY': APPROVED_POLICY}
        specraw = encode(spec)
        files = {'held_loader.py': loader, 'spec.json': specraw, 'request.json': request, 'current-context.json': encode(APPROVED_CURRENT), **{'src/' + spec['sources'][n]['file']: b for n, b in selected.items()}}
        specpin = sha(specraw)
        if not historical:
            files['actor.json'] = APPROVED_ACTOR_RAW
        if role == 'A':
            files['collector.py'] = entry(A, specpin, sha(loader), 'collector')
            files['worker.py'] = entry(A, specpin, sha(loader), 'worker', sha(files['collector.py']))
            scope = {'unit': unit, 'worker_sha256': sha(files['worker.py']), 'worker_path': A + '/worker.py', 'operation': APPROVED_OPERATION, 'nonce': nonce}
            out['scope_policy'] = scope
            out['A_entry'] = {'spec_sha256': specpin, 'loader_sha256': sha(loader)}
            out['launch_command'] = entry(A, specpin, sha(loader), 'launch', {'scope_policy': scope, 'PC_BEGIN_original': None}).decode()
        else:
            out['PC_entry'] = {'spec_sha256': specpin, 'loader_sha256': sha(loader)}
        need(len(files) <= 128 and all((len(b) <= 2097152 for b in files.values())) and (sum(map(len, files.values())) <= 4194304), 'zero_code_index128_leaf2MiB_total4MiB')
        out[role] = {'root': root, 'role': role, 'files': files, 'pins': {n: sha(b) for n, b in files.items()}, 'native_eligible': False}
    return out
