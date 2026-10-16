# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure reusable renewal interface. Root execution remains parent-owned."""
import ast, types, base64, hashlib, json, stat
from pathlib import Path
APPROVED_SOURCE_BODIES = {'readonly_once.py': None, 'validate.py': None, 'ANCHORS.json': None, 'Root_C_pins.json': None, 'old_three.json': None, 'worker.py': None, 'seal.py': None, 'build.py': None, 'consumer.py': None}
APPROVED_SOURCE_REVIEW_RAW = None
APPROVED_R26_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r26/renewals'

def need(v, r):
    if not v:
        raise ValueError(r)

def strict(raw):
    import json

    def pairs(xs):
        out = {}
        for k, v in xs:
            need(k not in out, 'duplicate_renewal_key')
            out[k] = v
        return out
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite'))
    json.dumps(v, allow_nan=False)
    return v

def materialize_C_renewal(request_raw):
    need(APPROVED_SOURCE_BODIES is not None and APPROVED_SOURCE_REVIEW_RAW is not None and (APPROVED_R26_REVIEW is not None), 'renewal_SOURCE_pending')
    m = types.ModuleType('held_renewal_build')
    m.__file__ = 'held_renewal/build.py'
    exec(compile(APPROVED_SOURCE_BODIES['build.py'], m.__file__, 'exec'), m.__dict__)
    return m.materialize(APPROVED_SOURCE_REVIEW_RAW, request_raw, APPROVED_SOURCE_BODIES)

def consume_current_C(receipt_raw, receipt_stat, clock, actualcfgcopy, now):
    need(APPROVED_SOURCE_BODIES is not None and APPROVED_SOURCE_REVIEW_RAW is not None and (APPROVED_R26_REVIEW is not None), 'renewal_SOURCE_pending')
    m = types.ModuleType('held_renewal_consumer')
    m.__file__ = 'held_renewal/consumer.py'
    exec(compile(APPROVED_SOURCE_BODIES['consumer.py'], m.__file__, 'exec'), m.__dict__)
    m.APPROVED_C_SOURCE_BODIES = APPROVED_SOURCE_BODIES
    m.APPROVED_C_REVIEW_RAW = APPROVED_SOURCE_REVIEW_RAW
    m.APPROVED_R26_REVIEW = APPROVED_R26_REVIEW
    return m.consume_current_C(receipt_raw, receipt_stat, clock, actualcfgcopy, now)

def origin_readback(launcher, plan, receipt):
    """Read actual archived origin after true retained EXIT0 and owned stop."""
    root = Path(plan['root'])
    raw, meta = launcher.read(root / 'readonly-qualified.json', 4194304)
    need(raw == launcher.encoded(receipt) and len(meta) == 9 and all((type(x) is int for x in meta)) and (meta[2] == len(raw)) and (meta[3:7] == [0, 0, stat.S_IFREG | 384, 1]), 'actual_Spark_origin_raw_F9_not_PC_mirror')
    originals = {}
    for name in ('owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'):
        body, st = launcher.read(root / name, 4194304)
        need(len(st) == 9 and all((type(x) is int for x in st)) and (st[2] == len(body)) and (st[3:7] == [0, 0, stat.S_IFREG | 384, 1]), 'actual_owned_stop_original_Root_F9')
        originals[name] = {'path': str(root / name), 'raw_b64': base64.b64encode(body).decode(), 'sha256': hashlib.sha256(body).hexdigest(), 'stat': st}
    intent = strict(base64.b64decode(originals['owned-stop-intent.json']['raw_b64']))
    result = strict(base64.b64decode(originals['owned-stop-result.json']['raw_b64']))
    after = strict(base64.b64decode(originals['owned-stop-observed.json']['raw_b64']))
    need(intent['unit'] == plan['unit'] and intent['invocation_id'] == receipt['intent']['invocation_id'] and (intent['owned_scope_stop_calls'] == 1) and (result['rc'] == 0) and (base64.b64decode(result['stderr_b64']) == b'') and (after['unit']['MainPID'] == '0') and (after['unit']['ActiveState'] == 'inactive') and (after['cgroup_procs'] == []) and (after['boot_id'] == receipt['actual_retained_EXIT0']['boot_id']), 'actual_owned_stop_not_pending_flag_rewrite')
    need(receipt['observed_at'] <= intent['issued_at'] <= result['observed_at'] <= after['observed_at'], 'original_owned_stop_time_order')
    return {'schema': 'C-renewal-origin-readback/v1', 'receipt_path': str(root / 'readonly-qualified.json'), 'receipt_raw_b64': base64.b64encode(raw).decode(), 'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'receipt_stat': meta, 'owned_stop_originals': originals}

def C_single_transport_command(plan):
    nonce = strict(plan['request_raw'])['nonce']
    root = '/opt/dgx-v4/c-unarmed-renewal-r26-' + nonce
    unit = 'dgx-v4-c-unarmed-renewal-r26-' + nonce + '.service'
    need(plan['root'] == root and plan['unit'] == unit and (len(plan['files']) == 8) and (plan['native_called'] is False), 'new_renewal_fixed_once')
    prefix = 'import json,os,time,types,pathlib,sys,base64,hashlib,stat;from pathlib import Path;\ndef need(v,r):\n if not v:raise RuntimeError(r)\n'
    bootstrap = "s=types.ModuleType('fixed_renewal_seal');s.__file__=" + repr(root + '/sealer.py') + ";s.__dict__['__name__']='fixed_renewal_seal';exec(compile(" + repr(plan['sealer']) + ",s.__file__,'exec'),s.__dict__);sealed=s.seal(); "
    code = prefix + 'import io,contextlib; out=io.StringIO();\nwith contextlib.redirect_stdout(out):\n ' + bootstrap + '\n'
    code += '\n' + None + '\n'
    code += 'root=pathlib.Path(' + repr(root) + ");raw=(root/'launch-and-capture.py').read_bytes();m=types.ModuleType('fixed_renewal_launcher');m.__file__=str(root/'launch-and-capture.py');exec(compile(raw,m.__file__,'exec'),m.__dict__);m.context(); strict=m.strict; m.fresh(root/'request.json'," + repr(plan['request_raw']) + "); launched=m.launch(); end=time.monotonic()+15\nwhile True:\n o=m.observe()\n if o['unit']['MainPID']=='0':break\n need(time.monotonic()<end,'finite_renewal_terminal_wait');time.sleep(.025)\nresult=m.capture_then_stop();origin=origin_readback(m," + repr({'root': root, 'unit': unit}) + ',result);print(json.dumps(origin,allow_nan=False))\n'
    compile(code, 'renewal-one-transport', 'exec')
    return code
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_no_native')
