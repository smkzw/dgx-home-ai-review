# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed root permit, never client-provided thresholds or calibration."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from G8_C_FIRSTTRIAL_CANDIDATE_R1 import contract as cc
HX = Path('/etc/dgx-home-ai/g8-c-firsttrial.json')
NODE = Path('/etc/dgx-v4/g8-c-firsttrial.json')
PROFILE, NODENAME, OWNER, IMAGE = (cc.PROFILE, cc.NODE, cc.OWNER, cc.IMAGE)
COMMIT = 'b0b743566f65daafc423b4fea8a2fbda94b3384a'
FIELDS = {'schema', 'approved_experiment', 'run_id', 'profile', 'node', 'owner', 'caller_owner', 'generation', 'manager_pid', 'lease_dev_inode', 'issued_at', 'expires_at', 'host_facts', 'policy', 'node_plan_sha256', 'input_receipt_sha256', 'source_closure_sha256', 'approval_receipt_sha256'}

def policy(total_bytes, cpu_count):
    """Candidate experiment protection only. Native parent approval is required.

    112GiB is the existing C idle/preflight envelope, not Comfy calibration.
    Reserve follows the documented OS-reserve precedent, not Qwen measured RAM.
    These values never populate min_start_available_gib/runtime_floor_gib.
    """
    cc.need(type(total_bytes) is int and total_bytes > 112 * 2 ** 30 and (type(cpu_count) is int) and (cpu_count >= 3), 'actual_C_host_facts_required')
    reserve = max(4.0, total_bytes / 2 ** 30 * 0.1)
    floor = max(14.5, reserve + 2)
    return {'id': 'g8-c-firsttrial-experimental-r1', 'measured_calibration': False, 'initial_available_gib': 112.0, 'sample_count': 3, 'max_age_s': 10.0, 'sample_interval_s': 2.0, 'emergency_gib': reserve, 'sustained_floor_gib': floor, 'warning_gib': floor + 1.5, 'sustained_count': 1, 'startup_grace_s': 180.0, 'deadline_s': 1800.0, 'cpu_limit': cpu_count - 2}

def validate(v, *, now, starting=False):
    cc.need(type(v) is dict and set(v) == FIELDS and (v['schema'] == 'g8-c-firsttrial-permit/v1'), 'exact_C_permit_fields')
    cc.need(v['approved_experiment'] is True, 'root_parent_experiment_approval_required')
    cc.need((v['profile'], v['node'], v['owner']) == (PROFILE, NODENAME, OWNER), 'fixed_C_profile_owner_node')
    cc.need(type(v['run_id']) is str and re.fullmatch('[0-9a-f]{32}', v['run_id']), 'fixed_C_run')
    cc.need(type(v['caller_owner']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', v['caller_owner']), 'fixed_registry_caller')
    for k in ('generation', 'manager_pid'):
        cc.need(type(v[k]) is int and v[k] > 0, 'actual_C_positive_identity')
    cc.need(type(v['lease_dev_inode']) is list and len(v['lease_dev_inode']) == 2 and all((type(x) is int and x > 0 for x in v['lease_dev_inode'])), 'actual_physical_lease_identity')
    for k in ('issued_at', 'expires_at'):
        cc.need(type(v[k]) in (int, float) and math.isfinite(v[k]), 'finite_C_permit_time')
    cc.need(v['issued_at'] <= now and 0 < v['expires_at'] - v['issued_at'] <= 1800.0, 'finite_C_trial_window')
    if starting:
        cc.need(now < v['expires_at'], 'C_trial_permit_expired')
    facts = v['host_facts']
    cc.need(type(facts) is dict and set(facts) == {'total_bytes', 'cpu_count'}, 'exact_C_host_facts')
    cc.need(cc.canonical(v['policy']) == cc.canonical(policy(**facts)), 'fixed_C_experimental_policy_no_threshold_input')
    for k in ('node_plan_sha256', 'input_receipt_sha256', 'source_closure_sha256', 'approval_receipt_sha256'):
        cc.need(cc.digest(v[k]), 'actual_C_trusted_receipt_SHA_required')
    return v

class Document:

    def __init__(self, v, sha):
        self.value = copy.deepcopy(v)
        self.sha256 = sha
        self._snapshot = cc.canonical(v)

    def check(self, *, now, starting=False):
        cc.need(cc.canonical(self.value) == self._snapshot, 'C_permit_mutated')
        validate(self.value, now=now, starting=starting)
        return self

def load(path, *, uid=0, mode=288):
    p = Path(path)
    for ancestor in p.parents:
        s = ancestor.lstat()
        cc.need(stat.S_ISDIR(s.st_mode) and (not stat.S_ISLNK(s.st_mode)) and (s.st_uid == uid) and (not s.st_mode & 18), 'protected_C_permit_ancestors')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        cc.need(stat.S_ISREG(before.st_mode) and before.st_uid == uid and (stat.S_IMODE(before.st_mode) == mode) and (before.st_nlink == 1) and (before.st_size <= 65536), 'root_C_permit_file')
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        named = p.lstat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        cc.need(len(raw) == before.st_size and all((getattr(before, k) == getattr(after, k) == getattr(named, k) for k in fields)), 'held_C_permit_changed')
        return Document(cc.loads(raw), hashlib.sha256(raw).hexdigest())
    finally:
        os.close(fd)

def request(body, run):
    cc.need(type(body) is dict and set(body) == {'action', 'run_id', 'key'} and (body['run_id'] == run), 'fixed_C_test_body')
    cc.need(type(body['action']) is str and body['action'] in ('start', 'schema', 'submit', 'status', 'trace', 'result', 'stop', 'cleanup'), 'fixed_C_test_actions_no_generic_release')
    cc.need(type(body['key']) is str and re.fullmatch('[0-9a-f]{32}', body['key']), 'fixed_C_test_idempotency_key')
    return body
