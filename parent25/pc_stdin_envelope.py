# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""PC parent transport only: exact request bytes, held bootstrap over bounded stdin."""
import base64, hashlib, json, zlib
CAP = 4194304
RAW_BOOT_CAP = 16384
SCHEMA = 'fixed-PC-cold-stdin/v1'
DECODER = "import sys,json,base64,zlib,hashlib,io\nb=sys.stdin.buffer.read(4194305);assert len(b)<=4194304\ndef P(p):\n d=dict(p);assert len(d)==len(p);return d\nv=json.loads(b,object_pairs_hook=P)\nassert type(v)is dict and set(v)=={'schema','bootstrap','request','request_sha256'} and v['schema']=='fixed-PC-cold-stdin/v1' and all(type(x)is str for x in v.values())\nc=base64.b64decode(v['bootstrap'],validate=True);d=zlib.decompressobj();s=d.decompress(c,16385)\nassert len(s)<=16384 and d.eof and not d.unused_data and not d.unconsumed_tail and hashlib.sha256(s).hexdigest()=='BOOT_SHA'\nr=base64.b64decode(v['request'],validate=True)\nassert len(r)<=4194304 and hashlib.sha256(r).hexdigest()==v['request_sha256']\nsys.stdin=io.TextIOWrapper(io.BytesIO(r),encoding='utf-8');exec(compile(s,'<fixed-PC-cold-bootstrap>','exec'))\n"

def short_code(bootstrap):
    import ast
    body = DECODER.replace('BOOT_SHA', hashlib.sha256(bootstrap).hexdigest())
    compile(body, 'fixed-stdin-decoder', 'exec')
    compressed = base64.b64encode(zlib.compress(body.encode(), 9)).decode()
    return 'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(' + repr(compressed) + ")),'<fixed-PC-stdin-decoder>','exec'))"

def encode(request, bootstrap):
    if type(request) is not bytes or type(bootstrap) is not bytes or len(request) > CAP or (len(bootstrap) > RAW_BOOT_CAP):
        raise ValueError('bounded_exact_PC_stdin')
    v = {'schema': SCHEMA, 'bootstrap': base64.b64encode(zlib.compress(bootstrap, 9)).decode(), 'request': base64.b64encode(request).decode(), 'request_sha256': hashlib.sha256(request).hexdigest()}
    b = (json.dumps(v, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(b) > CAP:
        raise ValueError('bounded_PC_stdin_envelope')
    return b
