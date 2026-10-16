# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed C qualification transaction on the existing Store/schema only."""
import json
from .permit import cc, PROFILE, NODENAME, OWNER

def reserve(store, document):
    v = document.value
    with store._tx() as conn:
        p = conn.execute('SELECT * FROM profiles WHERE name=?', (PROFILE,)).fetchone()
        n = conn.execute('SELECT * FROM nodes WHERE name=?', (NODENAME,)).fetchone()
        cc.need(p is not None and n is not None, 'existing_C_rows_required')
        cc.need(json.loads(p['nodes_json']) == [NODENAME] and p['source'] == 'qwen_image_turbo', 'fixed_existing_C_profile')
        cc.need(not p['hardware_validated'] and p['min_start_available_json'] is None and (p['runtime_floor_json'] is None), 'C_remains_uncalibrated')
        cc.need(p['state'] == 'STOPPED' and p['owner'] is None and (p['generation'] + 1 == v['generation']), 'exact_next_C_generation')
        cc.need(n['hold_profile'] is None and (not n['quarantine']), 'C_free_not_uncertain')
        now = store._clock()
        conn.execute("UPDATE nodes SET hold_profile=?,hold_owner=?,hold_generation=?,hold_operation='qualification',held_at=? WHERE name=?", (PROFILE, OWNER, v['generation'], now, NODENAME))
        conn.execute("UPDATE profiles SET generation=?,owner=?,state='STARTING',reason='C first trial: qualification_pending' WHERE name=?", (v['generation'], OWNER, PROFILE))
        store._audit_conn(conn, 'g8_firsttrial_reserve', actor=OWNER, profile=PROFILE, generation=v['generation'], reason='experiment, not calibration', detail='run=' + v['run_id'] + ' permit=' + document.sha256)
    return store.profile_view(PROFILE)
