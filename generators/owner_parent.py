# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure fixed Root data commands and one same-process finish/activation tail."""
import ast, json, re
from source_io import sha, need, encode
import policy as P

def known_names(graph):
    return tuple((n[:-3] for n in graph['helper_order'])) + ('B_OWNER_RECOVERY_R25_WIRING', 'B_OWNER_RECOVERY_R25_WIRING.common', 'B_OWNER_RECOVERY_R25_WIRING.collector', 'control_plane', 'control_plane.errors', 'node_adapter', 'node_adapter.protocol', 'node_adapter.client')

def pc_command(graph, late, original, phase, input_raw=b''):
    need(phase in ('permit', 'begin', 'finish') and type(input_raw) is bytes and (len(input_raw) <= 2097152), 'R16_owner_closed_Root_data_phase')
    p = late.validate_policy(graph, original)
    names = known_names(graph)
    code = "import builtins,types,sys,json,base64,os\nroot='" + P.PC_ROOT + "'\n"
    code += 'before_modules={n:sys.modules.get(n)for n in ' + repr(names) + '};before_path=list(sys.path);before_finders=list(sys.meta_path)\ntry:\n'
    lines = 'raw=' + repr(late.bootstrap()) + ";b=types.ModuleType('R16_exact_7c4_Root');exec(compile(raw,'<exact-7c4-bootstrap>','exec'),b.__dict__);b.POLICY=" + repr(p) + ";current=b.main('current-only')\nimport history_reader as h\nraw,f=b.held(root+'/pc/inputs/io_utils.py'," + repr(sha(graph['PC']['pc/inputs/io_utils.py'])) + ");io=types.ModuleType('R16_actual_Root_IO');exec(compile(raw,root+'/pc/inputs/io_utils.py','exec'),io.__dict__)\n"
    lines += 'cfg=b.strict(b.held(' + repr(p['config_path']) + ',' + repr(p['config_sha256']) + ',' + repr(p['config_stat']) + ")[0]);cfg['_config_sha256']=" + repr(p['config_sha256']) + '\n'
    if phase == 'permit':
        lines += "target=h.owner_Path(h.owner_policy()['permit_path']).parent\nif not target.exists():\n target.mkdir(mode=0o750);os.chown(target,0,989);os.chmod(target,0o750)\nelse:raise RuntimeError('R16_owner_new_release_namespace_OEXCL')\nresult=h.owner_permit(h.read,io.fresh,cfg,current['manager_identity'])\n"
    elif phase == 'begin':
        lines += 'result=h.owner_begin(h.read,io.fresh)\n'
    else:
        lines += 'v=h.owner_strict(' + repr(input_raw) + ");h.owner_need(type(v)is dict and set(v)=={'A_original','scope'},'R16_owner_complete_A_scope_input');result=h.owner_finish(h.read,io.fresh,v['A_original'],v['scope'])\n"
    code += ''.join((' ' + line + '\n' for line in lines.splitlines()))
    code += 'finally:\n for n,old in before_modules.items():\n  if old is None:sys.modules.pop(n,None)\n  else:sys.modules[n]=old\n sys.path[:]=before_path;sys.meta_path[:]=before_finders\n'
    code += "print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))\n"
    compile(code, 'R16_actual_owner_Root_' + phase, 'exec')
    need(len(code.encode()) <= 4194304, 'R16_owner_Root_command_cap4MiB')
    return code

def A_run(graph, begin):
    """Project the original four-field Root producer reply into the closed A ABI."""
    import base64
    import owner_scope_builder
    need(type(begin) is dict and set(begin) == {'PC_begin_original', 'request_original', 'request_raw_b64', 'send_moment_original'}, 'R16_owner_full_BEGIN_producer_reply')
    br = begin['PC_begin_original']
    rr = begin['request_original']
    mr = begin['send_moment_original']
    need(set(br) == {'raw_b64', 'sha256', 'F9'} and set(rr) == set(mr) == {'path', 'sha256', 'F9'}, 'R16_owner_BEGIN_complete_original_refs')
    request = base64.b64decode(begin['request_raw_b64'], validate=True)
    raw = base64.b64decode(br['raw_b64'], validate=True)
    moment = json.loads(raw)
    need(sha(raw) == br['sha256'] == mr['sha256'] and br['F9'] == mr['F9'] and (moment['request_original'] == rr) and (sha(request) == rr['sha256']) and (rr['F9'][2] == len(request)) and (mr['F9'][2] == len(raw)) and (rr['F9'][3:7] == mr['F9'][3:7] == [0, 989, 33056, 1]), 'R16_owner_BEGIN_exact_request_send_raw_F9')
    return owner_scope_builder.A_run(graph['owner_scope'], encode({'request_raw_b64': begin['request_raw_b64'], 'PC_begin_original': br}))

def finish_activate(graph, late, original, A_raw, activation_nonce):
    need(type(activation_nonce) is str and re.fullmatch('[0-9a-f]{32}', activation_nonce), 'R16_owner_new_activation_nonce')
    finish = pc_command(graph, late, original, 'finish', A_raw)
    rpc = late.command(graph, original, 'activate-registry-source', activation_nonce, {})
    source = 'import builtins,contextlib,io,json,sys,traceback,base64\n'
    source += 'def capture(source):\n out=io.BytesIO();err=io.BytesIO();ot=io.TextIOWrapper(out,encoding="utf-8",write_through=True);et=io.TextIOWrapper(err,encoding="utf-8",write_through=True);rc=0\n try:\n  with contextlib.redirect_stdout(ot),contextlib.redirect_stderr(et):exec(compile(source,"<R16-finite-owner-continuation>","exec"),{"__name__":"__main__","__builtins__":dict(vars(builtins))})\n except SystemExit as e:\n  rc=0 if e.code is None else e.code if type(e.code)is int else 1\n except BaseException:\n  rc=1\n  with contextlib.redirect_stderr(et):traceback.print_exc(limit=20)\n ot.flush();et.flush();a=out.getvalue();b=err.getvalue();ot.detach();et.detach();assert len(a)+len(b)<=4194304;return {"rc":rc,"stdout_raw_b64":base64.b64encode(a).decode(),"stderr_raw_b64":base64.b64encode(b).decode()}\n'
    source += 'finish=capture(' + repr(finish) + ')\nif finish["rc"]!=0:\n print(json.dumps({"finish":finish,"activation":None}));raise SystemExit(1)\nactivation=capture(' + repr(rpc) + ')\nprint(json.dumps({"finish":finish,"activation":activation},sort_keys=True,separators=(",",":")))\nraise SystemExit(activation["rc"])\n'
    compile(source, 'R16_owner_finish_actual_cold_RootRPC_continuation', 'exec')
    need(len(source.encode()) <= 4194304, 'R16_owner_combined_source_cap4MiB')
    return source
