# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Read-only terminal root and original Manager evidence; no SQL mutation."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from G7_INTEGRATION_CANDIDATE_R2.durable import need, digest
from G7_INTEGRATION_CANDIDATE_R1 import cache_checks as checks
from G7_INTEGRATION_CANDIDATE_R1.compiler import PREP, PREP_MODEL, NODES
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
from G7_QUALIFICATION_IMPLEMENTATION_R1 import node_wrapper as node
from G7_QUALIFICATION_IMPLEMENTATION_R1 import node_guard as guard
DB = Path('/var/lib/dgx-v4/node-fence/state.sqlite3')
LOCK = Path('/var/lib/dgx-v4/node-fence/resource.lock')
GUARD_DIR = Path('/var/lib/dgx-v4/node-runtime-guard')

def read_private_json(path, *, uid=0, mode=384, limit=1048576):
    p = Path(path)
    for q in (p, *p.parents):
        need(not q.is_symlink(), 'private_proof_symlink')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == uid and (stat.S_IMODE(s.st_mode) == mode) and (s.st_nlink == 1) and (s.st_size <= limit), 'private_single_proof_file')
        raw = f.read(limit + 1)
        need(len(raw) == s.st_size and checks.identity(s) == checks.identity(os.fstat(f.fileno())) == checks.identity(p.lstat()), 'private_proof_changed')
    return (checks.strict(raw), hashlib.sha256(raw).hexdigest())

def validate_ticket(t):
    need(type(t) is dict and t.get('schema') == 'g7-qualification-verification-ticket-qv1/v1', 'qualification_ticket_schema')
    need(t.get('profile') == PREP and t.get('owner') == qp.c.OWNER and (type(t.get('generation')) is int) and (t['generation'] > 0), 'exact_qualification_ticket_identity')
    need(t.get('GPU_lifecycle_permission') is False and t.get('hardware_validated') is False and (t.get('calibration_published') is False) and (t.get('core_state') == 'STOPPED') and (t.get('hold_operation') == 'qualification'), 'never_calibrated_or_lifecycle_ticket')
    qp.sha(t.get('permit_sha256'))
    qp.sha(t.get('completion_sha256'))
    qp.c.number(t.get('issued_at'))
    v = t.get('completion')
    need(type(v) is dict and v.get('schema') == 'g7-live-prep-completion-qv1/v1', 'actual_saved_prep_completion')
    raw = json.dumps(v, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
    need(hashlib.sha256(raw).hexdigest() == t['completion_sha256'], 'actual_completion_raw_SHA')
    need(all((v.get(k) == t.get(k) for k in ('run_id', 'profile', 'owner', 'generation', 'permit_sha256', 'manager_pid', 'lease_dev_inode', 'input_identity'))), 'exact_completion_ticket_binding')
    need(v.get('ready_published') is False and v.get('hardware_validated') is False and (v.get('probe_ready', {}).get('healthy') is True) and (v['probe_ready'].get('model_id') == PREP_MODEL), 'actual_completion_no_READY')
    need(type(v.get('live_guards')) is dict and set(v['live_guards']) == set(NODES), 'saved_AB_live_guard_completion')
    for item in v['live_guards'].values():
        need(item.get('verified') is True and item.get('guard_state') == 'ACTIVE' and (item.get('reason_code') in ('active', 'active_warning')), 'saved_actual_ACTIVE_guards')
    ids = v.get('container_ids')
    need(type(ids) is dict and set(ids) == set(NODES), 'exact_AB_completion_CIDs')
    for cid in ids.values():
        need(type(cid) is str and __import__('re').fullmatch('[0-9a-f]{64}', cid), 'full_completion_CID')
    need(t.get('explicit_stop', {}).get('stopped') is True and t['explicit_stop'].get('confirmed') is True, 'durable_original_explicit_stop_required')
    return t

def explicit_stop(run_root, v, permit_sha256):
    path = Path(run_root) / 'commands.sqlite3'
    need(not path.is_symlink(), 'stop_ledger_symlink')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and (stat.S_IMODE(s.st_mode) == 384), 'actual_original_private_ledger')
    with contextlib.closing(sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        row = db.execute('SELECT phase,generation,identity FROM run WHERE id=?', (v['run_id'],)).fetchone()
        need(row is not None and row[:2] == ('STOPPED_HELD', v['generation']) and (row[2] == digest({'run_id': v['run_id'], 'profile': v['profile'], 'owner': v['owner'], 'generation': v['generation'], 'permit_sha256': permit_sha256})), 'original_command_STOPPED_held')
        rows = db.execute("SELECT result FROM commands WHERE action='stop' AND state='FINISHED'").fetchall()
    matches = []
    for raw, in rows:
        r = checks.strict(raw)
        if r.get('stopped') is True and r.get('confirmed') is True and (r.get('generation') == v['generation']) and (r.get('profile') == v['profile']):
            matches.append(r)
    need(len(matches) == 1, 'one_actual_original_owned_stop_ack')
    return matches[0]

def local_record(ticket, *, db_path=DB, node_name=None):
    validate_ticket(ticket)
    with contextlib.closing(sqlite3.connect('file:' + str(db_path) + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        r = db.execute('SELECT * FROM node_state WHERE id=1').fetchone()
        need(r is not None, 'actual_node_record')
        v = dict(r)
        admission = db.execute('SELECT * FROM g7_qualification_runs WHERE run_id=?', (ticket['run_id'],)).fetchone()
        need(admission is not None and all((admission[k] == ticket[k] for k in ('profile', 'owner', 'generation', 'permit_sha256'))) and (admission['start_intent_at'] is not None), 'actual_root_consumed_launch_intent')
    need(v.get('state') == 'CLEAR' and all((v.get(k) == ticket[k] for k in ('profile', 'owner', 'generation'))) and (v.get('quarantine_reason') is None), 'actual_confirmed_CLEAR_identity')
    released = qp.c.number(v.get('released_at'))
    updated = qp.c.number(v.get('updated_at'))
    need(released == updated and released > 0, 'actual_confirm_stop_clearance_time')
    if node_name is not None:
        need(v.get('container_id') == ticket['completion']['container_ids'][node_name], 'same_stopped_prep_CID')
    return v

def terminal_values(ticket, node_name, record, status, state, proof, events, now):
    validate_ticket(ticket)
    need(status.get('schema') == guard.STATUS_SCHEMA and status.get('node') == node_name and (type(status.get('guard_pid')) is int) and (status['guard_pid'] > 1), 'actual_root_guard_terminal_identity')
    need(status.get('state') == 'IDLE_HOLD_RETAINED' and status.get('reason_code') == 'idle_db_clear' and all((status.get(k) is None for k in ('profile', 'owner', 'generation', 'container_id', 'image'))), 'actual_root_clear_idle_not_fake_STOPPED')
    stamp = qp.c.number(status.get('observed_at'))
    pstamp = qp.c.number(proof.get('observed_at'))
    need(record['updated_at'] <= stamp <= pstamp <= now and now - stamp <= 10, 'fresh_guard_after_confirmed_CLEAR')
    need(proof.get('schema') == 'g7-qualification-guard-proof/v1' and proof.get('node') == node_name and (proof.get('guard_pid') == status['guard_pid']) and (proof.get('permit_sha256') == ticket['permit_sha256']), 'same_armed_root_guard_permit')
    need(state.get('schema') == guard.STATE_SCHEMA and state.get('phase') == 'IDLE_HOLD_RETAINED' and (state.get('clear_authorized') is True) and (state.get('tracked') is None) and (state.get('terminal') is None) and (state.get('retained_unknown') is False), 'guard_consumed_exact_CLEAR')
    need(state.get('last_record') == guard._record_snapshot(record), 'guard_same_actual_CLEAR_record')
    relevant = []
    for row in events:
        guard._validate_event(row)
        if all((row.get(k) == ticket[k] for k in ('profile', 'owner', 'generation'))):
            need(row.get('node') == node_name and row.get('image') in (None, qp.c.PINS['image']), 'same_root_event_node_image')
            need(row.get('container_id') in (None, record['container_id']), 'guard_event_foreign_CID')
            relevant.append(row)
            if row['event'] == 'terminal' or row['state'] in ('QUARANTINED_HOLD_RETAINED', 'STOPPED_HOLD_RETAINED'):
                need(row.get('reason') == 'container_exited_without_clearance', 'guard_failed_trial_cannot_accept_cache')
    need(relevant, 'actual_guard_event_history_required')
    return {'status': status, 'state_last_record': state['last_record'], 'permit_sha256': proof['permit_sha256'], 'relevant_events': relevant, 'full_events_sha256': digest(events), 'terminal_verified': True}

def root_terminal(ticket, node_name, record):
    status = node.load_runtime_guard_status()
    stable_status, _sha = read_private_json(GUARD_DIR / 'status.json', limit=8192)
    need(stable_status == status, 'guard_status_changed_retry_fresh_read')
    state = guard.StateStore(GUARD_DIR).load_state()
    proof = node.load_qualification_guard_proof()
    p = GUARD_DIR / 'events.jsonl'
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and (stat.S_IMODE(s.st_mode) == 384) and (s.st_nlink == 1) and (s.st_size <= 8 * 1024 ** 2), 'bounded_complete_root_events')
        raw = f.read(8 * 1024 ** 2 + 1)
        need(len(raw) == s.st_size and checks.identity(s) == checks.identity(os.fstat(f.fileno())) == checks.identity(p.lstat()), 'root_events_changed_retry_fresh_read')
    events = [checks.strict(line) for line in raw.splitlines() if line]
    return terminal_values(ticket, node_name, record, status, state, proof, events, time.time())

@contextlib.contextmanager
def artifact_lock(ticket, node_name, *, base=Path('/var/lib/dgx-v4/g7-qualification-verifier')):
    for p in (base, *base.parents):
        s = p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and (not s.st_mode & 18), 'parent_provisioned_artifact_lock_root')
    path = base / (ticket['run_id'] + '-' + node_name + '.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 384)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and (stat.S_IMODE(s.st_mode) == 384) and (s.st_nlink == 1), 'root_single_artifact_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
        need(checks.identity(s) == checks.identity(os.fstat(fd)) == checks.identity(path.lstat()), 'artifact_lock_inode_changed')
    finally:
        os.close(fd)

def snapshot(ticket, node_name):
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        document = qp.load(qp.NODE_PATH)
        document.check(now=time.time())
        need(document.sha256 == ticket['permit_sha256'] and all((document.value[k] == ticket[k] for k in ('run_id', 'profile', 'owner', 'generation', 'input_identity', 'manager_pid', 'lease_dev_inode'))), 'actual_root_permit_ticket_binding')
        record = local_record(ticket, node_name=node_name)
        result = node.enumerate_gpu(node.CommandRunner(node.DEFAULT_BINARIES), record=record)
        need(result.complete and (not result.truncated) and result.gpu_empty, 'actual_complete_GPU_clear')
        terminal = root_terminal(ticket, node_name, record)
        return (record, terminal)
    finally:
        os.close(fd)

@contextlib.contextmanager
def mutation_fence(ticket, node_name, before):
    """Only bounded permission changes; never hash/cache/native tools inside."""
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(local_record(ticket, node_name=node_name) == before, 'seal_owner_changed_before_mutation')
        yield
        need(local_record(ticket, node_name=node_name) == before, 'seal_owner_changed_during_mutation')
    finally:
        os.close(fd)
