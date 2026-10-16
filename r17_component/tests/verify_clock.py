# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import ast, json, math, pathlib, sys, types
H = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(H))
import derive
raw = (H / 'SOURCE/owner_clock.py').read_bytes()
c = types.ModuleType('r17_clock')
exec(compile(raw, '<r17 clock>', 'exec'), c.__dict__)
m = {'PC_boot_id': 'boot', 'PC_sent_at': 1000.0, 'PC_monotonic_sent': 100.0}
p = {'PC_boot_id': 'boot', 'PC_issued_at': 990.0, 'PC_monotonic_origin': 90.0, 'PC_deadline_monotonic': 210.0, 'duration_seconds': 120}
assert c.check(m, p, 'boot', 129.0, 1029.0)['PC_whole30_remaining'] == 1
assert c.check(m, p, 'boot', 130.0, 1030.0)['PC_whole30_remaining'] == 0
negatives = []
for name, begin, permit, boot, mono, wall, reason in (('rollback5', m, p, 'boot', 134.0, 1029.0, 'owner_clock_original_BEGIN_whole30'), ('forward5', m, p, 'boot', 129.0, 1034.0, None), ('late', m, p, 'boot', math.nextafter(130.0, math.inf), 1030.0, 'owner_clock_original_BEGIN_whole30'), ('changed_boot', m, p, 'newboot', 120.0, 1020.0, 'owner_clock_same_boot'), ('nan', m, p, 'boot', math.nan, 1020.0, 'owner_clock_finite_original_domain'), ('infinite', m, p, 'boot', math.inf, 1020.0, 'owner_clock_finite_original_domain'), ('bool', m, p, 'boot', True, 1020.0, 'owner_clock_finite_original_domain'), ('negative_elapsed', m, p, 'boot', 99.0, 1000.0, 'owner_clock_original_permit_monotonic'), ('permit_expired', dict(m, PC_monotonic_sent=205.0, PC_sent_at=1105.0), p, 'boot', 210.0, 1110.0, 'owner_clock_original_permit_monotonic')):
    if reason is None:
        assert c.check(begin, permit, boot, mono, wall)
        continue
    try:
        c.check(begin, permit, boot, mono, wall)
    except c.ClockRefused as e:
        assert str(e) == reason
        negatives.append({'name': name, 'reason': str(e)})
    else:
        raise AssertionError(name + ' accepted')
for origin in (100.0, 368000.123456789, 2.0 ** 30 - 1e-06, 2.0 ** 40 + 0.125):
    permit = dict(p, PC_monotonic_origin=origin, PC_deadline_monotonic=origin + 120.0)
    begin = dict(m, PC_monotonic_sent=origin + 1.0)
    assert c.check(begin, permit, 'boot', origin + 2.0, 1001.0)
    for direction in (-math.inf, math.inf):
        altered = dict(permit, PC_deadline_monotonic=math.nextafter(permit['PC_deadline_monotonic'], direction))
        try:
            c.check(begin, altered, 'boot', origin + 2.0, 1001.0)
        except c.ClockRefused as e:
            assert str(e) == 'owner_clock_original_permit_formula'
        else:
            raise AssertionError('wrong one ULP deadline accepted')
delta = derive.clock_delta(derive.original('service/history_reader.py'))
compile(delta, 'clock delta', 'exec')
text = delta.decode()
assert 'PC_boot_id' in derive.function(delta, 'owner_begin_v2') and 'PC_boot_id' in derive.function(delta, 'owner_permit_v2')
assert 'r17_owner_clock(' in derive.function(delta, 'owner_fresh_v2')
assert 'PC_monotonic_sent' in derive.function(delta, 'owner_final_clock_v2')
result = {'sameboot_original_monotonic30': True, 'wall_rollback_cannot_hide_late': True, 'negatives': negatives, 'exact_producer_deadlines': 4, 'wrong_ULP_refusals': 8, 'v1_unchanged_v2_explicit': True, 'native': 0}
(H / 'CLOCK_RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps({'negative_cases': len(negatives) + 8, 'native': 0}))
