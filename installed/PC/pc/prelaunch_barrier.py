# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root-local nonce/pairedclock request→fresh A readonly scope→typed receiver."""
import base64, os, secrets, time, types, stat
from pathlib import Path
from contract import PC_ROOT, need, sha, encode, strict
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
APPROVED_POLICY_SHA = 'a34013d0240718a6f188682c9da36dbcff88ba48f0d5ce8179da6fd821a4f0f4'
APPROVED_A_WORKER_SHA = '93902c66a9607efc03b8abbc66321d942a8b5bcd0b54c1f3f03a46e0f1b21791'
BASE = PC_ROOT / 'prelaunch-readonly'

def archive_before(candidate, observation, scope):
    item = scope['body_original']
    raw = base64.b64decode(item['raw_b64'], validate=True)
    need(sha(raw) == item['sha256'] and item['F9'][2] == len(raw), 'archive_scope_full_original_SHA_F9')
    body = strict(raw)
    need(scope['A_original'] == body['A'] == observation['A'], 'archive_derived_A_mirror_exact')
    return {'candidate': candidate, 'observation': observation, 'A_scope': {k: v for k, v in scope.items() if k != 'A_original'}}

def shared_dir(p):
    need(not p.exists() and (not p.is_symlink()), 'new_readonly_phase_namespace')
    p.mkdir(mode=488)
    os.chown(p, 0, 989)
    os.chmod(p, 488)

def await_A(native, p, before, phase, end):
    need(phase in ('before-stop', 'after-stop', 'after-current') and APPROVED_POLICY_SHA is not None and (APPROVED_A_WORKER_SHA is not None), 'fixed_prelaunch_phase_source_pending')
    if not BASE.exists():
        shared_dir(BASE)
    else:
        meta = BASE.lstat()
        need(not BASE.is_symlink() and stat.S_ISDIR(meta.st_mode) and ((meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) == (0, 989, 488)), 'fixed_shared_readonly_parent_identity')
    root = BASE / phase
    shared_dir(root)
    nonce = secrets.token_hex(16)
    req = {'schema': 'registry-prelaunch-fresh-A-request/v1', 'phase': phase, 'request_nonce': nonce, 'operation': p['grant_operation'], 'policy_sha256': APPROVED_POLICY_SHA, 'source_review_sha256': p['review_sha256'], 'PC_manager_identity': before['manager_identity'], 'PC_config_sha256': native.current.config['_config_sha256'], 'A_worker_sha256': APPROVED_A_WORKER_SHA}
    raw = encode(req)
    native.current.io.fresh(root / 'request.json', raw, mode=288, gid=989)
    sent = native.wall()
    mono = time.monotonic()
    native.current.io.fresh(root / 'sent.json', encode({'request_sha256': sha(raw), 'PC_sent_at': sent, 'PC_monotonic_sent': mono, 'PC_boot_id': before['manager_identity']['boot_id']}), mode=288, gid=989)
    native.current.io.fresh(root / 'awaiting.json', encode({'request': req, 'request_raw_utf8': raw.decode(), 'PC_sent_at': sent, 'PC_monotonic_sent': mono}), mode=288, gid=989)
    receiver = root / 'received.json'
    limit = min(end, mono + 30)
    while not receiver.exists():
        need(time.monotonic() < limit, 'fresh_A_readonly_whole30_no_retry')
        time.sleep(0.02)
    received, rs = protected_read(receiver, limit=4194304)
    out = strict(received)
    elapsed = time.monotonic() - mono
    now = native.wall()
    need(0 <= elapsed <= 30 and 0 <= now - sent <= 30 and (abs(now - sent - elapsed) <= 30) and (out['request_sha256'] == sha(raw)) and (out['request_nonce'] == nonce) and (out['phase'] == phase), 'true_PC_nonce_whole30_not_remote_retime')
    from managed_scope import positive
    source, st = protected_read(PC_ROOT / 'prelaunch-A-worker.py')
    need(sha(source) == APPROVED_A_WORKER_SHA, 'new_actual_readonly_worker_complete_source')
    positive(out['actual_scope'], out['returned_original'], APPROVED_A_WORKER_SHA, unit=out['unit'], operation=req['operation'], runtime_seconds=120)
    need(out['unit'] == 'dgx-v4-prelaunch-' + phase + '-' + nonce + '.service' and out['actual_scope']['cgroup_procs'] == [] and (out['actual_scope']['unit']['ExecMainStatus'] == '0'), 'new_retained_readonly_EXIT0')
    body_raw = base64.b64decode(out['body_original']['raw_b64'], validate=True)
    need(sha(body_raw) == out['body_original']['sha256'] and out['body_original']['F9'][2] == len(body_raw), 'whole_original_A_readonly_body_SHA_F9')
    body = strict(body_raw)
    need(body['request'] == req and body['policy_sha256'] == APPROVED_POLICY_SHA and (body['worker_sha256'] == APPROVED_A_WORKER_SHA) and (body['A']['process_scan']['complete'] is True) and (body['A']['process_scan']['matches'] == []), 'actual_same_nonce_A_noengine')
    need(sent - 30 <= body['A']['started_at'] <= body['A']['observed_at'] <= now + 30, 'remote_A_clock_only_configured_audit_bound')
    return {'phase': phase, 'request': req, 'request_sha256': sha(raw), 'body_original': out['body_original'], 'actual_scope': out['actual_scope'], 'returned_original': out['returned_original'], 'owned_stop_originals': out['owned_stop_originals'], 'scope_actual_EXIT0': True, 'target_matches': [], 'source34': body['A']['A34'], 'A_original': body['A'], 'PC_started_at': sent, 'PC_finished_at': now, 'PC_monotonic_elapsed': elapsed, 'PC_monotonic_started': mono, 'receiver_ref': {'path': str(receiver), 'sha256': sha(received), 'stat': rs}}
