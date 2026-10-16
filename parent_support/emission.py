# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure R12 parent command assembly. This module never runs a transport.

Consumes the single joint graph; actual package F9/current/BEGIN are late data.
Candidate commands are not native admission or evidence of their execution.
"""
import ast
import base64
import hashlib
import json
import types
from pathlib import Path
PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'
EPOCH = 'ed7021db9df4c839d02f3271361924de'
SOURCE_EPOCH = '2b9e9b631cebc13ae6b1550ee59c13ed'
PACKAGE_ROOT = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/'

def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def checked_graph(graph):
    pc = graph['PC']
    p = graph['packet']
    need(p['operation'] == SOURCE_EPOCH and p['grant_operation'] == EPOCH and (p['entry_phase'] == 'LIVE_IDLE_FAILED_TERMINAL_HELD'), 'parent_exact_source_operation')
    need(json.loads(graph['config'])['operation'] == '17d8f5ea0cc8db181c5b341f6ffb38ce', 'parent_business_domain')
    need(len(pc) <= 128 and sum(map(len, pc.values())) <= 4194304, 'parent_final_code_cap')
    need(all((type(b) is bytes and len(b) <= 2097152 for b in pc.values())), 'parent_full_source_leaves')
    index = json.loads(pc['epoch-index.json'])
    need(all((sha(pc[n]) == h for n, h in index['files'].items())), 'parent_actual_physical_index')
    need(p['helpers'] == {n: sha(pc['service/' + n]) for n in graph['helper_order']}, 'parent_complete_helper_set')
    return pc

def module(raw, name, path):
    result = types.ModuleType(name)
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result

def rootwrap(code, seconds):
    raw = code.encode() if isinstance(code, str) else code
    need(type(raw) is bytes and 0 < seconds <= 120, 'parent_bounded_existing_sudo_channel')
    out = "import subprocess,base64,sys\np=subprocess.run(['/usr/bin/sudo','-k','-n','/usr/bin/python3','-I','-B','-'],input=base64.b64decode(" + repr(base64.b64encode(raw).decode()) + '),capture_output=True,timeout=' + repr(seconds) + ')\nsys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr);raise SystemExit(p.returncode)\n'
    compile(out, 'parent_existing_Root_stdin', 'exec')
    return out

def closed_inline(sources, body):
    """Complete fixed source bodies, private importer, no ambient application imports."""
    need(sources and all((type(b) is bytes and len(b) <= 2097152 for b in sources.values())), 'parent_inline_source_cap')
    need(sum(map(len, sources.values())) <= 4194304, 'parent_inline_batch_cap')
    out = 'import builtins,sys,types,hashlib,json\n_sources=' + repr(sources) + '\n_pins=' + repr({n: sha(b) for n, b in sources.items()}) + '\n_mods={}\n'
    out += "def _imports(name,globals=None,locals=None,fromlist=(),level=0):\n assert not level\n if name in _mods:return _mods[name]\n if name in _sources:raise ImportError('closed_source_order_'+name)\n if name=='B_OWNER_RECOVERY_R25_WIRING.common' or name.split('.')[0] in sys.stdlib_module_names:return builtins.__import__(name,globals,locals,fromlist,level)\n raise ImportError('closed_parent_unknown_import_'+name)\n"
    out += "for _name,_raw in _sources.items():\n assert hashlib.sha256(_raw).hexdigest()==_pins[_name]\n _m=types.ModuleType(_name);_m.__file__='<parent-held-source>/'+_name+'.py';_m.__dict__['__builtins__']=dict(vars(builtins),__import__=_imports);exec(compile(_raw,_m.__file__,'exec'),_m.__dict__);_mods[_name]=_m\n"
    out += body + '\n'
    compile(out, 'R12_closed_parent_source', 'exec')
    return out

class Emission:

    def __init__(self, graph, package, *, base_source):
        self.graph = graph
        self.pc = checked_graph(graph)
        self.base_source = Path(base_source)
        self.package = package
        need(set(package) == {PACKAGE_ROOT + n for n in ('__init__.py', 'common.py', 'collector.py')}, 'parent_actual_package_three')
        for path, row in package.items():
            need(set(row) == {'sha256', 'stat'} and row['sha256'] == graph['packet']['oldmap'][path] == graph['packet']['newmap'][path], 'parent_unchanged_package_source_pin')
            f = row['stat']
            need(type(f) is list and len(f) == 9 and all((type(v) is int for v in f)) and (f[3] == 0) and (f[6] == 1), 'parent_actual_package_full_F9')
        raw = (self.base_source / 'TOOLS/gate_commands.py').read_bytes()
        self.gate = module(raw, 'R12_private_parent_gate', self.base_source / 'TOOLS/gate_commands.py')
        descriptor = dict(graph['normal_gate'], PC_root=PC_ROOT)
        descriptor['PC_pins'] = dict(descriptor['PC_pins'], **{'gate_loader.py': sha(self.pc['pc/r11-gate/gate_loader.py'])})
        self.normal = descriptor
        self.gate.APPROVED_GRAPH = {'PC_pins': descriptor['PC_pins'], 'A_phase_pins': {p: v['pins'] for p, v in descriptor['phases'].items()}}
        self.gate.APPROVED_PC_ENTRY = {'epoch_loader_sha256': sha(self.pc['epoch-scope/loader.py']), 'packet_sha256': sha(self.pc['epoch-packet.json']), 'package': package, 'contract_sha256': sha(self.pc['contract.py'])}

    def pc_package(self, body):
        return self.gate.package_entry(body)

    def normal_seal(self, phase):
        return self.gate.seal(self.normal, phase)

    def epoch(self, mode):
        need(mode in ('launch', 'finalize-stop'), 'parent_two_once_epoch_modes')
        name = 'epoch-' + mode + '.py'
        code = 'import types,pathlib,json\nfrom B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha\np=pathlib.Path(' + repr(PC_ROOT + '/' + name) + ');raw,f=protected_read(p,limit=2097152);need(sha(raw)==' + repr(sha(self.pc[name])) + ",'exact_final_epoch_entry_before_effect');m=types.ModuleType('fixed_R12_epoch_entry');m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);print(json.dumps({'entry_rc':m.main()}))\n"
        return self.pc_package(code)

    def normal_await(self, phase):
        return self.gate.awaiting(self.normal, phase)

    def normal_A_run(self, phase, request_raw):
        return self.gate.A_run(self.normal, phase, request_raw)

    def normal_PC_finish(self, phase, compact):
        return self.gate.publisher_entry(self.normal, phase, compact)

    def C30_PC(self, mode, nonce, value=None):
        need(mode in ('prestage-request', 'prestage-ack', 'prepare', 'begin', 'finish-publish'), 'parent_C30_closed_phase')
        need(type(nonce) is str and len(nonce) == 32 and all((c in '0123456789abcdef' for c in nonce)), 'parent_new_C30_nonce')
        root = PC_ROOT + '/c-arm-r30'
        code = 'import pathlib,types,json\nfrom B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha,strict\nroot=pathlib.Path(' + repr(root) + ')\n'
        sources = {n.removeprefix('c-arm-r30/'): sha(b) for n, b in self.pc.items() if n.startswith('c-arm-r30/')}
        code += '_pins=' + repr(sources) + "\ndef held_module(name):\n raw,f=protected_read(root/name,limit=2097152);need(sha(raw)==_pins[name],'actual_C30_complete_source');m=types.ModuleType('parent_fixed_C30_'+name);m.__file__=str(root/name);exec(compile(raw,m.__file__,'exec'),m.__dict__);return m\n"
        code += "cfgraw,cf=protected_read('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json');need(sha(cfgraw)==" + repr(sha(self.graph['config'])) + ",'actual_C30_new_config');raw,f=protected_read(pathlib.Path(" + repr(PC_ROOT + '/pc/inputs/io_utils.py') + '));need(sha(raw)==' + repr(sha(self.pc['pc/inputs/io_utils.py'])) + ",'actual_C30_Root_IO');io=types.ModuleType('parent_fixed_C30_IO');exec(compile(raw,'<held-Root-IO>','exec'),io.__dict__);c=held_module('C_clock.py');nonce=" + repr(nonce) + '\n'
        if mode == 'prestage-ack':
            need(type(value) is dict, 'parent_actual_C30_prestage_original')
            code += 'result=c.prestage_ack(nonce,' + repr(value) + ',io)\n'
        elif mode == 'finish-publish':
            need(type(value) is dict, 'parent_actual_C30_complete_lossless_receipt')
            code += "clock=c.finish(nonce,io);codec=held_module('receipt_codec.py');raw=codec.unpack(" + repr(value) + ");m=held_module('current_C_consumer.py');cfg=strict(cfgraw);cfg['_config_sha256']=sha(cfgraw);result=m.publish(cfg,raw,io)\n"
        else:
            code += 'result=c.' + mode.replace('prestage-request', 'prestage_request') + '(nonce,io)\n'
        code += 'print(json.dumps(result,allow_nan=False))\n'
        return self.pc_package(code)

    def C30_plan(self, request_raw):
        source = self.graph['C_static9']
        request = json.loads(request_raw)
        need(request['PC_config_sha256'] == sha(self.graph['config']), 'parent_actual_C30_request_config')
        review_raw = encode({'schema': 'c-unarmed-before-PC-r27-readonly-source-review/v1', 'source_pins': {n: sha(b) for n, b in source.items()}, 'native_pending': True})
        build = module(source['build.py'], 'parent_fixed_C30_materializer', '<fixed-C30-build>')
        return build.materialize(review_raw, request_raw, source)

    def C30_Spark(self, plan, mode):
        need(plan['root'] == '/opt/dgx-v4/runtime/g8-clock-probe-c30-mimo-registry-r16' and mode in ('seal', 'request', 'launch', 'observe', 'capture-owned-stop'), 'parent_fixed_C30_namespace_modes')
        if mode == 'seal':
            return closed_inline({'sealer': plan['sealer']}, "print(json.dumps(_mods['sealer'].seal(),allow_nan=False))")
        bootstrap = module(self.graph['readonly_scope']['renderer_raw'], 'parent_C30_held_bootstrap', '<same-Root-renderer>').BOOTSTRAP_ROOT_HELD
        path = plan['root'] + '/launch-and-capture.py'
        code = bootstrap + '\nimport types,json\np=' + repr(path) + ';raw,f=held(p,' + repr(plan['file_pins']['launch-and-capture.py']) + ",mode=0o600);m=types.ModuleType('parent_fixed_C30_launcher');m.__file__=p;exec(compile(raw,p,'exec'),m.__dict__);m.context()\n"
        if mode == 'request':
            code += 'raw=' + repr(plan['request_raw']) + ";m.need(m.sha(raw)==m.REQUEST_SHA,'actual_PC_C30_request_original');m.fresh(m.Path(m.ROOT)/'request.json',raw);result={'request_sha256':m.sha(raw),'clock_started':False}\n"
        else:
            method = {'launch': 'launch', 'observe': 'observe', 'capture-owned-stop': 'capture_then_stop'}[mode]
            code += 'result=m.' + method + '()\n'
        code += 'print(json.dumps(result,allow_nan=False))\n'
        compile(code, 'parent_C30_held_Spark_entry', 'exec')
        return code

    def A_origin(self, emitter_api):
        result = emitter_api.a_command(self.graph)
        need(result['source_sha256'] == sha(result['code'].encode()), 'parent_A_origin_source_pin')
        return result['code']

    def PC_origin(self, emitter_api, A_original):
        raw = encode(A_original)
        need(len(raw) <= 2097152, 'parent_full_A_origin_cap')
        result = emitter_api.pc_command(self.graph)
        need(result['requires_protected_package3_bootstrap'] is True and result['source_sha256'] == sha(result['code'].encode()), 'parent_PC_origin_exact_source')
        prefix = 'import io,sys\nsys.stdin=io.TextIOWrapper(io.BytesIO(' + repr(raw) + '),encoding="utf-8")\n'
        return self.pc_package(prefix + result['code'])

    def history_publish(self, root, role):
        """Separate full lossless packed data publication, before any BEGIN."""
        need(role in ('A', 'PC'), 'parent_closed_history_role')
        if role == 'PC':
            need(root == PC_ROOT + '-data', 'parent_fixed_PC_history_data_root')
        else:
            need(root in {d['history_data_root'] for d in self.normal['phases'].values()}, 'parent_fixed_A_normal_history_root')
        bodies = self.graph['PC_data']
        fixed = self.graph['readonly_scope']['static']['historical-fixed']['packed_pins']
        pub = (self.base_source / 'H5/PC-publisher/history_publication.py').read_bytes()
        fs = (self.base_source / ('H5/PC-publisher/publication_fs.py' if role == 'PC' else 'H5/A-prestage/publication_fs.py')).read_bytes()
        source = {}
        if role == 'A':
            phase = next((d for d in self.normal['phases'].values() if d['history_data_root'] == root))
            source.update({'plan': phase['files']['plan.py'], 'root_io': phase['files']['root_io.py']})
        source.update({'publication_fs': fs, 'receipt_codec': self.pc['service/receipt_codec.py'], 'history_publication': pub})
        body = "m=_mods['history_publication'];m.ROOT=" + repr(root) + ';m.OPERATION=' + repr(EPOCH) + ';m.OWNER=' + repr([0, 989, 33056, 1] if role == 'PC' else [0, 0, 33152, 1]) + ';m.APPROVED_INPUTS=' + repr(fixed) + ';print(json.dumps(m.publish(' + repr(bodies) + '),allow_nan=False))'
        code = closed_inline(source, body)
        return self.pc_package(code) if role == 'PC' else code

    def readonly_plan(self, mode, current, nonce, actor_raw=None, *, current_policy=None):
        scope = self.graph['readonly_scope']
        need(mode in scope['templates'] and current['source118'] == self.graph['packet']['newmap'] and (current['config_sha256'] == sha(self.graph['config'])) and (current['review_sha256'] == self.graph['packet']['review_sha256']), 'parent_actual_new_current_context')
        if mode == 'historical-fixed':
            need(actor_raw is None and current_policy is None, 'parent_fixed_old_actor_not_caller')
            policy = scope['static'][mode]['policy']
        else:
            need(type(actor_raw) is bytes and type(current_policy) is dict and (json.loads(actor_raw)['stage_operation'] == nonce), 'parent_actual_owned_stage_actor_and_nonce')
            policy = current_policy
        static = scope['static'][mode]
        renderer = module(scope['renderer_raw'], 'R12_parent_same_renderer', '<same-Root-renderer>')
        approved = {'mode': mode, 'review': current['review_sha256'], 'policy': policy, 'operation': EPOCH, 'current_reader_sha256': sha(self.pc['pc/current_reader.py']), 'current_reader_input_pins': self.graph['packet']['input_pins'], 'packed_pins': static['packed_pins'], 'publication_operation': static['publication_operation']}
        return renderer.render_plan(current, nonce, actor_raw, approved=approved, templates=scope['templates'][mode], loader=scope['loader_raw'])

    def readonly_stage(self, plan, role):
        need(role in ('PC', 'A'), 'parent_scope_stage_fixed_role')
        packed = self.graph['PC_data'] if json.loads(plan[role]['files']['spec.json'])['mode'] == 'historical-fixed' else None
        raw = self.graph['readonly_scope']['sealer_raw']
        code = closed_inline({'sealer': raw}, "print(json.dumps(_mods['sealer'].stage(" + repr(plan[role]) + ',' + repr(packed) + '),allow_nan=False))')
        return self.pc_package(code) if role == 'PC' else code

    def readonly_command(self, plan, mode, payload=None):
        need(mode in ('ack', 'begin', 'finish', 'A-launch'), 'parent_closed_readonly_phase')
        renderer = module(self.graph['readonly_scope']['renderer_raw'], 'R12_parent_entry_renderer', '<same-Root-renderer>')
        if mode == 'A-launch':
            need(type(payload) is bytes, 'parent_actual_PC_BEGIN_original_required')
            d = plan['A_entry']
            return renderer.entry(plan['A']['root'], d['spec_sha256'], d['loader_sha256'], 'launch', {'scope_policy': plan['scope_policy'], 'PC_BEGIN_original': payload}).decode()
        need(mode == 'begin' or type(payload) is bytes, 'parent_complete_original_phase_payload')
        d = plan['PC_entry']
        return renderer.entry(plan['PC']['root'], d['spec_sha256'], d['loader_sha256'], mode, payload).decode()

    def historical_qualified_mirror(self, plan, qualified_raw):
        """Fixed Root leaf required by original zero Recovery; no timestamp change."""
        root = plan['PC']['root']
        need(root.startswith(PC_ROOT + '/zero-readonly/') and type(qualified_raw) is bytes, 'parent_fixed_zero_proof_namespace')
        pin = sha(qualified_raw)
        code = 'from B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha\nimport pathlib,types,json\n'
        code += 'raw,st=protected_read(pathlib.Path(' + repr(root + '/not-launched-qualified.json') + '),limit=2097152);need(sha(raw)==' + repr(pin) + ",'actual_zero_qualified_original_full_SHA')\n"
        code += 'source,ss=protected_read(pathlib.Path(' + repr(PC_ROOT + '/pc/inputs/io_utils.py') + '));need(sha(source)==' + repr(sha(self.pc['pc/inputs/io_utils.py'])) + ",'Root_fixed_IO_source');io=types.ModuleType('R12_fixed_zero_publication_IO');exec(compile(source,'<held-Root-IO>','exec'),io.__dict__);target=pathlib.Path(" + repr(PC_ROOT + '/not-launched-qualified.json') + ");io.fresh(target,raw,mode=0o440,gid=989);after,f=protected_read(target,limit=2097152);need(after==raw and f[3:7]==[0,989,0o100440,1],'zero_mirror_exact_raw_separate_current_F9');print(json.dumps({'sha256':sha(after),'F9':f,'original_child_F9':st,'source_path':" + repr(root + '/not-launched-qualified.json') + ",'path':str(target),'raw_bytes_preserved':True}))\n"
        return self.pc_package(code)

def run_normal_phase(once, emitted, phase):
    """Once.actual owns durable attempts. No retries, repeat stop or catch-and-resend."""
    waiting = once.actual('R12-' + phase + '-PC-await', emitted.normal_await(phase), timeout=175)
    raw = base64.b64decode(waiting['awaiting_raw_b64'], validate=True)
    request = base64.b64decode(json.loads(raw)['request_raw_b64'], validate=True)
    receipt = once.actual('R12-' + phase + '-A-run', rootwrap(emitted.normal_A_run(phase, request), 27), node='spark-a', timeout=29)
    return once.actual('R12-' + phase + '-PC-publish', emitted.normal_PC_finish(phase, receipt), timeout=20)

def run_readonly(once, emitted, plan, *, tag, deadline=None):
    """Publication occurs before BEGIN; one exact BEGIN is carried to A and PC."""
    import time
    end = time.monotonic() + 90 if deadline is None else deadline

    def call(name, code, node='pc', timeout=30):
        remaining = end - time.monotonic()
        need(remaining > 0, 'parent_readonly_original90_no_extension')
        return once.actual(tag + '-' + name, code, node=node, timeout=min(timeout, remaining))
    call('PC-prestage', emitted.readonly_stage(plan, 'PC'))
    ack = call('A-prestage', rootwrap(emitted.readonly_stage(plan, 'A'), 30), node='spark-a', timeout=35)
    call('PC-ack', emitted.readonly_command(plan, 'ack', encode(ack)))
    begin = call('PC-BEGIN', emitted.readonly_command(plan, 'begin'))
    proof = call('A-run', rootwrap(emitted.readonly_command(plan, 'A-launch', encode(begin)), 90), node='spark-a', timeout=90)
    return call('PC-finish', emitted.readonly_command(plan, 'finish', encode(proof)))
