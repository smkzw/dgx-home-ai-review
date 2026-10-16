# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit frozen emitter snapshot and two-slot successor derivation only."""
import json, pathlib
from source_io import HERE, sha, encode, need
E = HERE.parent / 'R26_ASSET_ZERO_SCOPE_EMITTER_SOURCE_R1'
MANIFEST = '67462c82aaffcecbd2dda07d2fce42d9846ea26fc1c0884ebe9a0cf8cd102f3f'

def snapshot():
    raw = (E / 'SOURCE_MANIFEST.json').read_bytes()
    need(sha(raw) == MANIFEST, 'frozen_scope_emitter_manifest')
    pins = json.loads((E / 'PRODUCTION_PINS.json').read_bytes())
    allpins = json.loads((HERE / 'BASE_PINS.json').read_bytes())
    orig = json.loads((HERE / 'COPY_ORIGINS.json').read_bytes())
    selected = {'SOURCE_MANIFEST.baseline.json': (E / 'SOURCE_MANIFEST.json', MANIFEST), 'PRODUCTION_PINS.json': (E / 'PRODUCTION_PINS.json', None)}
    for name, row in pins['files'].items():
        selected['external/' + name.removeprefix('external:') + '.py' if name.startswith('external:') else name] = (pathlib.Path(row['path']), row['sha256'])
    for name, (p, pin) in selected.items():
        b = p.read_bytes()
        need(pin is None or sha(b) == pin, 'scope_full_input_pin')
        key = 'ZERO_EMITTER/' + name
        out = HERE / 'BASE' / key
        if key in allpins:
            need(out.read_bytes() == b and allpins[key] == {'sha256': sha(b), 'bytes': len(b)}, 'snapshot_never_overwrite')
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(b)
            allpins[key] = {'sha256': sha(b), 'bytes': len(b)}
            orig[key] = {'path': str(p), 'sha256': sha(b), 'bytes': len(b)}
    (HERE / 'BASE_PINS.json').write_bytes(encode(allpins))
    (HERE / 'COPY_ORIGINS.json').write_bytes(encode(orig))
    return len(selected)

def renderer(raw):
    old = "  spec={'schema':'asset-zero-readonly-spec/v1'"
    need(raw.decode().count(old) == 1, 'one_renderer_role_slot')
    insert = "  if not historical and 'known_prior_assets' in selected:\n   bindings['known_prior_assets']={'ROLE':role,'PC_TERMINAL_ROOT':PC_ROOT+'/asset-terminals' if role=='PC' else None}\n"
    out = raw.decode().replace(old, insert + old, 1).encode()
    compile(out, 'R12_derived_single_renderer', 'exec')
    return out
if __name__ == '__main__':
    print(snapshot())
