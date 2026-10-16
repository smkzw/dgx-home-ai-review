# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Saved complete cold output: service/Root historical reader only, no barrier.
No new journal, projection, finish, scope, Runtime, Manager or resource grant.
"""
import pathlib, sys
H = pathlib.Path(__file__).resolve().parents[1]
source = (H / 'tests/verify_v2_cold.py').read_text().split("config=ev['config'];results=[];finishes=[]")[0]
ns = {'__file__': str(H / 'tests/verify_v2_cold.py'), '__name__': 'R17_v2_history_seed'}
exec(compile(source, '<exact v2 readonly history definition seed>', 'exec'), ns)
hr, fs, pr, j, role, w, RootPath = (ns[k] for k in ('hr', 'fs', 'pr', 'j', 'role', 'w', 'RootPath'))
folder = H / ('CPU_V2_COLD_' + (sys.argv[2] if len(sys.argv) > 2 else 'THIRD')) / 'complete'
p = hr.owner_policy()
root = ns['root']
stage = p['stage']
ev = ns['ev']
ns['private_roots'].append(str(folder))
for prefix, target in ((root + '/' + stage, folder / 'actor'), (p['activation_root'], folder / 'source-base'), (hr.owner_DECISION_POLICY['parent'], folder / 'journal-parent')):
    for key in list(fs.mapping):
        if key == prefix or key.startswith(prefix + '/'):
            fs.mapping.pop(key)
    fs.mapping[prefix] = target
for name, row in ns['old']['rows'].items():
    fs.expected[str(folder / 'actor' / name)] = row['F9']
g = ns['types'].SimpleNamespace(same=lambda: ns['lx']['lease_same'](ev['current']['pid']), runtime=None)
view = ns['types'].SimpleNamespace(g=g, root=RootPath(root), read=w.read, used=[])
paths = [folder / 'actor' / n for n in set(p['old_records']) | pr.ACTOR_NAMES] + [folder / 'source-base' / ev['current']['invocation_id'] / n for n in pr.SOURCE_NAMES] + [folder / 'journal-parent' / p['probe_nonce'] / n for n in j.NAMES if (folder / 'journal-parent' / p['probe_nonce'] / n).exists()]
before = {str(x): [getattr(x.stat(), n) for n in pr.FIELDS] for x in paths}
results = []
for name, osrole in (('service', role), ('Root', fs)):
    hr.owner_os = osrole
    j.os = osrole
    pr.os = osrole
    view.used = []
    rows, stats = hr.owner_actor_snapshot(view, stage)
    value = hr.owner_committed_history_v2(view, stage, rows)
    assert value['state'] == 'FAILED_REGISTRY_QUIESCENT' and len(view.used) == 1
    results.append({'role': name, 'historical_only': True, 'used': len(view.used), 'source_authority': False})
assert before == {str(x): [getattr(x.stat(), n) for n in pr.FIELDS] for x in paths}
report = {'cases': results, 'actual_full_v2_eligibility_and_actual_projection_F9': True, 'canonical_old_event_unchanged': True, 'writes': 0, 'barriers': 0, 'physical_finish': 0, 'scope_reruns': 0, 'native': 0}
(H / 'V2_HISTORY_RESULT.json').write_bytes(w.common.encode(report))
print(ns['json'].dumps(report, sort_keys=True))
