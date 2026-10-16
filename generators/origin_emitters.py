# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Two fixed SOURCE emitters. Never executes transport or consumes permission."""
from source_io import need, sha
from pathlib import Path
import policy as P

def a_command(graph):
    from scope_builder import render
    from source_io import load_source, HERE
    renderer = load_source(graph['readonly_scope']['renderer_raw'], 'fixed_origin_bootstrap', HERE / 'readonly-renderer.py')
    b = renderer.BOOTSTRAP_ROOT_HELD
    pin = {'plan': sha(graph['A']['files']['plan.py']), 'root_io': sha(graph['A']['files']['root_io.py'])}
    origin = graph['PC']['A-origin-publisher.py']
    code = b + "\nimport builtins,sys,types,json;mods={}\nbase_import=builtins.__import__\ndef fixed_import(name,globals=None,locals=None,fromlist=(),level=0):\n if name in mods and not level:return mods[name]\n need(not level and name.split('.')[0]in sys.stdlib_module_names,'A_origin_closed_import')\n return base_import(name,globals,locals,fromlist,level)\n"
    for name in ('plan', 'root_io'):
        path = P.A_ROOT + '/' + name + '.py'
        code += 'raw,f=held(' + repr(path) + ',' + repr(pin[name]) + ',mode=0o600);m=types.ModuleType(' + repr(name) + ');m.__file__=' + repr(path) + ";m.__dict__['__builtins__']=dict(vars(builtins),__import__=fixed_import);mods[" + repr(name) + "]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__)\n"
    code += 'raw=' + repr(origin) + ';need(sha(raw)==' + repr(sha(origin)) + ",'A_origin_publisher_source');m=types.ModuleType('fixed_A_origin_publisher');m.__dict__['__builtins__']=dict(vars(builtins),__import__=fixed_import);exec(compile(raw,'<fixed_A_origin_publisher>','exec'),m.__dict__);sys.stdout.buffer.write(mods['plan'].encode(m.collect()))\n"
    compile(code, 'A_origin_fixed_emitter', 'exec')
    return {'code': code, 'source_sha256': sha(code.encode()), 'A_pins': pin, 'publisher_sha256': sha(origin), 'input_bytes': None, 'effects': 'one new source-origin receipt only; no scope/model/data/GET'}

def pc_command(graph):
    """Parent feeds the exact returned A original as bounded stdin. Current is
 collected internally by the full installed Root reader, never caller JSON.
 The caller supplies protected package3/contract bootstrap before this suffix;
 this is explicit and cannot be called as a standalone ambient file.
 """
    pc = graph['PC']
    need(len(pc) <= 128 and graph['PC_bytes'] <= 4194304, 'final_PC_caps_before_origin_emission')
    code = 'import sys,types,json,time\nfrom pathlib import Path\nfrom B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha,strict,encode\n'
    code += 'root=Path(' + repr(P.PC_ROOT) + ");contract_raw,contract_f9=protected_read(root/'contract.py',limit=2097152);need(sha(contract_raw)==" + repr(sha(pc['contract.py'])) + ",'origin_final_contract');oldcontract=sys.modules.get('contract');c=types.ModuleType('contract');c.__file__=str(root/'contract.py');sys.modules['contract']=c;exec(compile(contract_raw,c.__file__,'exec'),c.__dict__)\nprevious=None\ntry:\n"
    code += " raw,st=protected_read(root/'epoch-scope/loader.py',limit=2097152);need(sha(raw)==" + repr(sha(pc['epoch-scope/loader.py'])) + ",'origin_final_Root_loader');lm=types.ModuleType('origin_loader');lm.__file__=str(root/'epoch-scope/loader.py');exec(compile(raw,lm.__file__,'exec'),lm.__dict__);mods,previous=lm.load_modules(root);packetraw,pf=protected_read(root/'epoch-packet.json',limit=2097152);need(sha(packetraw)==" + repr(sha(pc['epoch-packet.json'])) + ",'origin_final_packet');p=strict(packetraw);native=mods['native'].RootNative(p,old=False);s=native.capture(time.monotonic()+30,old=False);current={'review_sha256':p['review_sha256'],'config_sha256':s['config_sha256'],'manager_identity':s['manager_identity'],'source118':s['current_source118']}\n"
    code += " qraw,qf=protected_read(root/'current-source-qualified.json',limit=2097152);q=strict(qraw);need(q['current']['manager_identity']==current['manager_identity'] and q['current']['current_source118']==current['source118'] and q['current']['config_sha256']==current['config_sha256'] and q['review_sha256']==current['review_sha256'],'origin_independent_current_qualification')\n"
    code += " import builtins\n local={}\n def fixed_import(name,globals=None,locals=None,fromlist=(),level=0):\n  if not level and name in local:return local[name]\n  need(not level and name.split('.')[0]in sys.stdlib_module_names,'PC_origin_closed_import')\n  return builtins.__import__(name,globals,locals,fromlist,level)\n planraw,plf=protected_read(root/'service/plan.py',limit=2097152);need(sha(planraw)==" + repr(sha(pc['service/plan.py'])) + ",'origin_protected_plan');pm=types.ModuleType('plan');pm.__dict__['__builtins__']=dict(vars(builtins),__import__=fixed_import);exec(compile(planraw,str(root/'service/plan.py'),'exec'),pm.__dict__);local['plan']=pm\n raw,rf=protected_read(root/'service/root_io.py',limit=2097152);need(sha(raw)==" + repr(sha(pc['service/root_io.py'])) + ",'origin_protected_root_io');r=types.ModuleType('root_io');r.__dict__['__builtins__']=dict(vars(builtins),__import__=fixed_import);exec(compile(raw,str(root/'service/root_io.py'),'exec'),r.__dict__);local['root_io']=r\n"
    code += " raw,of=protected_read(root/'A-origin-publisher.py',limit=2097152);need(sha(raw)==" + repr(sha(pc['A-origin-publisher.py'])) + ",'origin_protected_publisher');m=types.ModuleType('origin_publisher');m.__dict__['__builtins__']=dict(vars(builtins),__import__=fixed_import);exec(compile(raw,str(root/'A-origin-publisher.py'),'exec'),m.__dict__);incoming=sys.stdin.buffer.read(2097153);need(0<len(incoming)<=2097152,'origin_actual_A_original_cap');result=m.publish(strict(incoming),current);sys.stdout.buffer.write(encode(result))\nfinally:\n if previous is not None:lm.restore_modules(previous)\n if oldcontract is None:sys.modules.pop('contract',None)\n else:sys.modules['contract']=oldcontract\n"
    compile(code, 'PC_origin_fixed_emitter', 'exec')
    return {'code': code, 'source_sha256': sha(code.encode()), 'requires_protected_package3_bootstrap': True, 'stdin': 'exact A original envelope JSON, <=2MiB', 'effects': 'one new PC Root0440 source-origin mirror only'}
