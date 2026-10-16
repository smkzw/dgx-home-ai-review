# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import sys, io, json, types
raw = sys.stdin.buffer.read(4194305)
assert 0 < len(raw) <= 4194304

def pairs(xs):
    v = {}
    for k, x in xs:
        assert k not in v
        v[k] = x
    return v
v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
assert type(v) is dict and set(v) == {'schema', 'bootstrap', 'request'} and (v['schema'] == 'reserved-parent-compact-input/v1')
c = types.ModuleType('fixed_bounded_compact_codec')
exec(compile(CODEC, '<reviewed_lossless_codec>', 'exec'), c.__dict__)
source = c.unpack(v['bootstrap'])
request = c.unpack(v['request'])
assert len(source) <= 16384 and c.sha(source) == BOOT_SHA
sys.stdin = io.TextIOWrapper(io.BytesIO(request), encoding='utf-8')
d = types.ModuleType('fixed_safe_diagnostic')
exec(compile(DIAG, '<fixed_safe_diagnostic>', 'exec'), d.__dict__)
target = json.loads(request, object_pairs_hook=pairs)
traced = None
trace0 = sys.gettrace()
traced, diagnosis = d.capture(SOURCE_PATHS, target, DOMAIN)
sys.settrace(traced)

class BoundedBuffer(io.BytesIO):

    def write(self, b):
        assert self.tell() + len(b) <= 4194304
        return super().write(b)
out = io.TextIOWrapper(BoundedBuffer(), encoding='utf-8')
saved = sys.stdout
sys.stdout = out
rc = 0
try:
    exec(compile(source, '<fixed_protected_RPC_bootstrap>', 'exec'), {'__name__': '__main__'})
except SystemExit as e:
    assert type(e.code) is int and e.code in (0, 1)
    rc = e.code
except BaseException:
    rc = 1
finally:
    out.flush()
    sys.stdout = saved
    sys.settrace(trace0)
original = out.buffer.getvalue()
if not original:
    original = b'{"reason_code":"protected_RPC_cold_failed_no_retry"}' + bytes([10])
    rc = 1
sys.stdout.buffer.write((json.dumps({'schema': 'reserved-parent-RPC-output/v1', 'original': c.pack(original), 'diagnostic': diagnosis if rc else None}, sort_keys=True, separators=(',', ':')) + chr(10)).encode())
raise SystemExit(rc)
