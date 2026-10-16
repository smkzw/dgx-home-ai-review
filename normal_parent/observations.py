# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure new-epoch readonly barriers; never launch, stop, qualify or request.
Caller retains the original epoch900. New C30 PCwhole10 has not begun here.
"""
from pathlib import Path
import types
import hashlib
import json
PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'
EPOCH = '2b9e9b631cebc13ae6b1550ee59c13ed'
PARENT = Path(__file__).resolve().parent.parent / 'r12-parent-emission-source-r2'
PARENT_MANIFEST = '632a8a5ca40498445c1c0b540d330b84d4bc0b0e564ed5228c53784d35cff39a'
R14_EMISSION = None
SPECS = {'C30-prestage': ('awaiting-C30-prestage.json', 'C30-unclocked-source-prestage-request/v1', 'review_sha256'), 'C30-current': ('awaiting-current-C30.json', 'R26-current-C-start-barrier/v1', 'release_sha256')}

def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def parent():
    need(R14_EMISSION is not None and R14_EMISSION.PC_ROOT == PC_ROOT and (R14_EMISSION.SOURCE_EPOCH == EPOCH) and (R14_EMISSION.EPOCH == 'ed7021db9df4c839d02f3271361924de'), 'exact_R13_parent_emitter_injected_before_observation')
    return R14_EMISSION

def barrier(emitted, phase):
    """A successful read returns full original bytes/F9 and fixed identity fields.
    Worker failure returns its complete raw evidence, never a made-up success.
    """
    need(phase in SPECS, 'only_two_C30_barriers')
    leaf, schema, review_key = SPECS[phase]
    p = emitted.graph['packet']
    need(p['operation'] == EPOCH, 'new_epoch_not_old_current')
    body = 'import pathlib,time,json,base64,re\nfrom B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha,strict\n'
    body += 'root=pathlib.Path(' + repr(PC_ROOT) + ");marker=root/'c-arm-r30'/" + repr(leaf) + ";failed=root/'epoch-scope/once/failed.json';end=time.monotonic()+175\n"
    body += "def original(path):\n raw,f=protected_read(path,limit=2097152);return {'raw_b64':base64.b64encode(raw).decode(),'sha256':sha(raw),'F9':f}\n"
    body += "while True:\n if failed.exists():\n  row=original(failed)\n  if not base64.b64decode(row['raw_b64'],validate=True).endswith(b'\\n'):\n   need(time.monotonic()<end,'new_epoch_barrier_original_bounded_wait');time.sleep(.1);continue\n  print(json.dumps({'worker_failed':True,'failure':row,'barrier':" + repr(phase) + "}));break\n if marker.exists():\n  row=original(marker)\n  if not base64.b64decode(row['raw_b64'],validate=True).endswith(b'\\n'):\n   need(time.monotonic()<end,'new_epoch_barrier_original_bounded_wait');time.sleep(.1);continue\n  v=strict(base64.b64decode(row['raw_b64'],validate=True));need(v['schema']==" + repr(schema) + ' and v[' + repr(review_key) + ']==' + repr(p['review_sha256']) + " and v['config_sha256']==" + repr(sha(emitted.graph['config'])) + ",'actual_new_C30_barrier_domain');need(type(v['request_nonce'])is str and re.fullmatch('[0-9a-f]{32}',v['request_nonce'])is not None and type(v['worker_pid'])is int and v['worker_pid']>0,'actual_C30_worker_nonce')\n"
    if phase == 'C30-current':
        body += "  need(v['operation']==" + repr(EPOCH) + " and v['normal_start_calls']==0 and v['automatic_retry']is False,'actual_C30_before_original_start')\n"
    else:
        body += "  need(v['clock_started']is False,'actual_C30_unclocked_prestage')\n"
    body += "  print(json.dumps({'worker_failed':False,'barrier':" + repr(phase) + ",'original':row,'value':v}));break\n need(time.monotonic()<end,'new_epoch_barrier_original_bounded_wait');time.sleep(.1)\n"
    compile(body, 'new_epoch_' + phase, 'exec')
    return emitted.pc_package(body)

def terminal(emitted):
    """Wait for the actual new scope before the single finalize-stop action.
    Full retained state and both originals are losslessly packed for transport.
    """
    e = parent()
    e.checked_graph(emitted.graph)
    pc = emitted.graph['PC']
    sources = {'contract': pc['contract.py'], 'bounded_process': pc['pc/bounded_process.py'], 'scope_observer': pc['pc/scope_observer.py'], 'receipt_codec': pc['service/receipt_codec.py']}
    body = 'import pathlib,time,base64\nfrom B_OWNER_RECOVERY_R25_WIRING.common import protected_read,need,sha,strict,encode\nroot=pathlib.Path(' + repr(PC_ROOT) + ');end=time.monotonic()+55\n'
    body += "while True:\n observed=_mods['scope_observer'].observe('epoch')\n if observed['unit']['MainPID']=='0':break\n need(time.monotonic()<end,'new_epoch_terminal_bounded_wait_no_replay');time.sleep(.2)\n"
    body += "def maybe(path):\n if not path.exists():return None\n raw,f=protected_read(path,limit=4194304);return {'raw_b64':base64.b64encode(raw).decode(),'sha256':sha(raw),'F9':f}\n"
    body += "returned=maybe(root/'epoch-scope/once/returned-zero.json');installed=maybe(root/'epoch-private/installed-unqualified.json');failed=maybe(root/'epoch-scope/once/failed.json');u=observed['unit'];ready=(u['LoadState']=='loaded' and u['ExecMainCode']=='1' and u['ExecMainStatus']=='0' and u['Result']=='success' and observed['cgroup_procs']==[] and returned is not None and installed is not None and failed is None)\n"
    body += "value={'scope':observed,'returned':returned,'installed':installed,'failed':failed,'ready_for_single_finalize':ready,'qualifier_called':False,'owned_stop_calls':0};print(json.dumps(_mods['receipt_codec'].pack(encode(value))))\n"
    return emitted.pc_package(e.closed_inline(sources, body))
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_readonly_emitters_no_native')
