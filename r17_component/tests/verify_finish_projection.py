# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import importlib.util, json, pathlib
H = pathlib.Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location('projection', H / 'SOURCE/owner_projection.py')
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
v = json.loads((H / 'CPU_V2_SCOPE_FIRST/V2_ORIGINALS.json').read_bytes())
e = v['eligibility']
clock = dict(v['final_clock'])
clock['PC_wall_observed'] += 0.001
terminal = m.encode({'state': 'FAILED_REGISTRY_QUIESCENT'})
e = dict(e, old_terminal_sha256=m.sha(terminal))
r = {'schema': 'owner-projection-recipe/v2', 'operation': '1' * 32, 'stage': e['stage_operation'], 'old_terminal': {'sha256': m.sha(terminal)}, 'original_deadline_monotonic': e['original_deadline_monotonic'], 'release_clock': v['final_clock'], 'request': {'request_nonce': e['activation_request_nonce']}, 'qualification': {}, 'prior': {}, 'legacy_original': {}, 'eligibility': e, 'current': {}, 'recorded_at': e['observed_at']}
x = m.render(r, terminal, clock)
a = json.loads(x['actor']['completed.json'])
b = json.loads(x['source']['intent.json'])
c = json.loads(x['source']['fence-released.json'])
assert a['finished_at'] == c['observed_at'] == clock['PC_wall_observed'] and b['observed_at'] == r['recorded_at'] and (b['release_commit_clock'] == clock)
wrong = dict(clock, PC_wall_observed=r['recorded_at'] - 1)
try:
    m.render(r, terminal, wrong)
except m.ProjectionRefused as err:
    assert str(err) == 'owner_projection_original_postfinish_clock'
else:
    raise AssertionError('preintent finish accepted')
report = {'same_verified_witness_finish_clock': True, 'no_new_stamp_or_fallback': True, 'preintent_finish_refused': True, 'native': 0}
(H / 'FINISH_PROJECTION_RESULT.json').write_bytes(m.encode(report))
print(json.dumps(report, sort_keys=True))
