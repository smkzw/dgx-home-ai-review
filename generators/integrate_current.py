# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Copy the exact frozen v2 closed aliases. No mutable component acceptance."""
import json
from source_io import HERE, sha, encode, need, base, load_source, bind
B = HERE.parent / 'R26_CURRENT_STAGE_PREBIND_TERMINAL_SOURCE_R1'
MANIFEST = 'dbf2e40f212497de3eadbf5b94f422f68a49065e35ea9747b7ef5faddef07e51'

def snapshot():
    mr = (B / 'SOURCE_MANIFEST.json').read_bytes()
    need(sha(mr) == MANIFEST, 'current_v2_frozen_manifest')
    copy = (B / 'COPYLIST.json').read_bytes()
    need(sha(copy) == '0a133715e4d575d2f8918d581648a54256a0f54615bbe0e3eeb0e8a47fca2b99', 'current_v2_copylist')
    v = json.loads(copy)
    selected = {'SOURCE_MANIFEST.baseline.json': (mr, B / 'SOURCE_MANIFEST.json'), 'COPYLIST.json': (copy, B / 'COPYLIST.json')}
    for name, row in v['module_aliases'].items():
        p = B / row['source']
        r = p.read_bytes()
        need(sha(r) == row['sha256'] and len(r) == row['bytes'], 'current_v2_exact_alias')
        selected[name + '.py'] = (r, p)
    for name, row in v['transforms'].items():
        p = B / name
        r = p.read_bytes()
        need(sha(r) == row['sha256'], 'current_v2_exact_transform')
        selected[name] = (r, p)
    pins = json.loads((HERE / 'BASE_PINS.json').read_bytes())
    orig = json.loads((HERE / 'COPY_ORIGINS.json').read_bytes())
    for name, (raw, p) in selected.items():
        key = 'CURRENT/' + name
        dest = HERE / 'BASE' / key
        if key in pins:
            need(dest.read_bytes() == raw and pins[key] == {'sha256': sha(raw), 'bytes': len(raw)}, 'current_never_overwrite')
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            pins[key] = {'sha256': sha(raw), 'bytes': len(raw)}
            orig[key] = {'path': str(p), 'sha256': sha(raw), 'bytes': len(raw)}
    (HERE / 'BASE_PINS.json').write_bytes(encode(pins))
    (HERE / 'COPY_ORIGINS.json').write_bytes(encode(orig))
    return len(selected)

def transformed(raw, kind):
    t = load_source(base('CURRENT/' + kind + '_transform.py'), 'closed_current_' + kind, HERE / (kind + '_transform.py'))
    t.APPROVED_ORIGINAL_SHA = sha(raw)
    return t.transform(raw)

def current_negative():
    raw = base('CURRENT/current_negative.py')
    s = raw.decode()
    a = 'known_prior_assets.collect(p,a,current,end)==absence'
    b = 'known_prior_assets.recheck(absence,known_prior_assets.collect(p,a,current,end))'
    need(s.count(a) == 1, 'one_second_full_known_prior_scan')
    s = s.replace(a, b, 1)
    a = "known_prior_assets.validate(v['data_absence'],p,a,current)"
    b = "known_prior_assets.validate(v['data_absence'],p,a,current,(v['started_at'],v['finished_at']))"
    need(s.count(a) == 1, 'one_outer_actual_A_frame_consumer')
    s = s.replace(a, b, 1)
    out = s.encode()
    compile(out, 'R13_current_negative_full_recheck', 'exec')
    return out

def template_table():
    return {n: (HERE.parent / 'known_prior_assets_r15.py').read_bytes() if n == 'known_prior_assets' else current_negative() if n == 'current_negative' else base('CURRENT/' + n + '.py') for n in ('current_clock', 'current_negative', 'current_scope', 'current_qualified', 'known_prior_assets')}
