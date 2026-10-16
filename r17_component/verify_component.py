# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit component-only verifier. No epoch, native, network or Runtime.
Default verifies frozen source only. --cold LABEL replays the saved CPU event
through the new cold/history slice; it does not rerun the original scope.
"""
import argparse, hashlib, json, pathlib, re, subprocess, sys
H = pathlib.Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--cold')
args = p.parse_args()
manifest = json.loads((H / 'COMPONENT_MANIFEST.json').read_bytes())
for kind in ('own', 'external'):
    for name, ref in manifest[kind].items():
        path = H / name if kind == 'own' else pathlib.Path(name)
        raw = path.read_bytes()
        assert len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256'], (kind, name)
        if kind == 'own' and path.suffix == '.py':
            compile(raw, str(path), 'exec')
assert manifest['actual_slots'] is None and manifest['native_eligible'] is False
if args.cold:
    assert re.fullmatch('[A-Za-z0-9_]{1,48}', args.cold)
    assert sys.version_info[:2] == (3, 11)
    subprocess.run([sys.executable, '-I', '-B', str(H / 'tests/verify_v2_cold.py'), args.cold], check=True, timeout=900)
    subprocess.run([sys.executable, '-I', '-B', str(H / 'tests/verify_v2_history.py'), 'HISTORY_' + args.cold, args.cold], check=True, timeout=360)
print(json.dumps({'component_pins': 'PASS', 'Python_compile': 'PASS', 'native': 0, 'full_Runtime': 'not claimed', 'actual_slots': None}, sort_keys=True))
