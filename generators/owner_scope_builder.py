# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Small fixed A readonly packet; reuses complete original observer/kernel."""
import ast
from source_io import HERE, base, bind, sha, need, expression, literal
import owner_builder
import policy as P

def build(nonce):
    root = '/opt/dgx-v4/r16-owner-readonly-' + nonce
    unit = 'dgx-v4-prelaunch-release-' + nonce + '.service'
    files = owner_builder.readonly_modules(nonce)
    files['observer.py'] = base('PC/service/observer.py')
    files['ready_history.py'] = base('PC/service/ready_history.py')
    files['worker.py'] = owner_builder.readonly_worker(nonce)
    raw = base('NORMAL_GATE/scope.py')
    tree = ast.parse(raw)
    functions = [ast.get_source_segment(raw.decode(), n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name not in ('argv', 'run')]
    prefix = 'import errno,base64,hashlib,json,os,re,stat,subprocess,sys,time\nfrom pathlib import Path\nimport observer,ready_history\n'
    props = literal(raw, 'PROPS')
    fields = literal(raw, 'FIELDS')
    prefix += 'PROPS=' + repr(props) + '\nFIELDS=' + repr(fields) + '\n'
    argv = next((ast.get_source_segment(raw.decode(), n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'argv'))
    need(argv.count('RuntimeMaxSec=120') == 1 and argv.count(",'--worker'") == 1, 'R16_owner_scope_original_argv')
    argv = argv.replace('RuntimeMaxSec=120', 'RuntimeMaxSec=90').replace(",'--worker'", '')
    run = (HERE.parent / 'owner_scope_run.py').read_bytes()
    scope = (prefix + '\n\n'.join(functions) + '\n' + argv + '\n').encode() + run
    scope = bind(scope, {'APPROVED_FILES': {n: sha(b) for n, b in files.items()}, 'APPROVED_WORKER_SHA': sha(files['worker.py']), 'APPROVED_UNIT': unit, 'APPROVED_OPERATION': P.EPOCH, 'STAGE': None})
    scope = expression(scope, 'STAGE', 'Path(' + repr(root) + ')')
    compile(scope, 'owner_scope_complete_original_primitives', 'exec')
    files['scope.py'] = scope
    return {'root': root, 'unit': unit, 'files': files, 'pins': {n: sha(b) for n, b in files.items()}, 'worker_sha256': sha(files['worker.py']), 'body_sha256': sha(owner_builder.readonly_body(nonce)), 'actual': None, 'native_eligible': False}

def root_bootstrap():
    return literal(base('ZERO_EMITTER/SOURCE/renderer.py'), 'BOOTSTRAP_ROOT_HELD')

def A_seal(plan):
    need(sum(map(len, plan['files'].values())) <= 4194304 and len(plan['files']) <= 128 and all((len(b) <= 2097152 for b in plan['files'].values())), 'R16_owner_scope_seal_original_caps')
    code = root_bootstrap() + 'import base64,json\nroot=Path(' + repr(plan['root']) + ');values=' + repr(plan['files']) + ';pins=' + repr(plan['pins']) + "\nneed(os.getuid()==os.geteuid()==0 and not root.exists()and not root.is_symlink(),'R16_owner_scope_unique_unused')\n"
    code += "for ancestor in root.parents:\n z=ancestor.lstat();need(stat.S_ISDIR(z.st_mode)and z.st_uid==0 and not z.st_mode&0o022,'R16_owner_scope_Root_parent')\nroot.mkdir(mode=0o700);os.chmod(root,0o700)\n"
    code += "for n,b in values.items():\n need(n and '/'not in n and n not in('.','..')and sha(b)==pins[n],'R16_owner_scope_closed_leaf');fd=os.open(root/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n try:\n  os.fchmod(fd,0o600);view=memoryview(b)\n  while view:\n   count=os.write(fd,view);need(count>0,'R16_owner_scope_write_progress');view=view[count:]\n  os.fsync(fd)\n finally:os.close(fd)\n need(held(root/n,pins[n],cap=2097152,mode=0o600)[0]==b,'R16_owner_scope_full_readback')\n"
    code += "directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\ntry:os.fsync(directory)\nfinally:os.close(directory)\nprint(json.dumps({'root':str(root),'sources':{n:{'sha256':pins[n],'F9':held(root/n,pins[n],cap=2097152,mode=0o600)[1]}for n in values},'clock_started':False,'units_launched':0}))\n"
    compile(code, 'owner_A_OEXCL_source_seal', 'exec')
    return code

def A_run(plan, begin):
    import json
    need(type(begin) is bytes and len(begin) <= 2097152, 'R16_owner_actual_BEGIN_bytes')
    code = root_bootstrap() + 'import builtins,types,sys,json\nroot=Path(' + repr(plan['root']) + ');pins=' + repr(plan['pins']) + ';saved={n:held(root/n,pin,cap=2097152,mode=0o600)for n,pin in pins.items()};modules={}\n'
    code += "def imports(n,g=None,l=None,fromlist=(),level=0):\n need(not level,'R16_owner_scope_no_relative_import')\n if n in modules:return modules[n]\n need(n.split('.')[0]in sys.stdlib_module_names,'R16_owner_scope_no_ambient_import');return builtins.__import__(n,g,l,fromlist,0)\n"
    code += "for n in ('plan','root_io','bounded_process','old_failed_kernel','observer','ready_history','scope'):\n m=types.ModuleType('_R16_owner_scope_'+n);m.__file__=str(root/(n+'.py'));m.__dict__['__builtins__']=dict(vars(builtins),__import__=imports);modules[n]=m;exec(compile(saved[n+'.py'][0],m.__file__,'exec'),m.__dict__)\nresult=modules['scope'].run(" + repr(begin) + ");need(all(held(root/n,pins[n],cap=2097152,mode=0o600)==row for n,row in saved.items()),'R16_owner_source_F9_after_scope_entry');print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))\n"
    compile(code, 'owner_A_actual_scope', 'exec')
    return code
