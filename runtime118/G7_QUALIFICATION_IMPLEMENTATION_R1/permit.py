# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One root-controlled, identity-bound trial permit; no executable config values."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from dataclasses import dataclass, field

def sibling(name):
    path = Path(__file__).resolve().with_name(name + '.py')
    alias = 'g7_qualification_frozen_' + name
    if alias in sys.modules:
        m = sys.modules[alias]
        if Path(m.__file__).resolve() != path:
            raise ValueError('frozen_module_identity_mismatch')
        return m
    spec = importlib.util.spec_from_file_location(alias, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[alias] = m
    try:
        spec.loader.exec_module(m)
    except BaseException:
        sys.modules.pop(alias, None)
        raise
    return m
c = sibling('contract')
NODE_PATH = Path('/etc/dgx-v4/g7-qualification.json')
HX_PATH = Path('/etc/dgx-home-ai/g7-qualification.json')
MAX_BYTES = 65536
FIELDS = {'schema', 'run_id', 'profile', 'owner', 'generation', 'image', 'pins', 'host_facts', 'plan_sha256', 'input_identity', 'manager_pid', 'lease_dev_inode', 'issued_at', 'expires_at'}
INPUTS = {'model_manifest_sha256', 'engram_manifest_sha256', 'kit_manifest_sha256', 'python_source_sha256', 'engine_acceptance_sha256', 'environment_receipt_sha256', 'token_map_sha256', 'rdma_receipt_sha256', 'copy_receipts_sha256'}

def digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def unique(pairs):
    out = {}
    for k, v in pairs:
        c.need(k not in out, 'duplicate_JSON_key')
        out[k] = v
    return out

def sha(v):
    c.need(type(v) is str and re.fullmatch('[0-9a-f]{64}', v), 'full_SHA_required')

def validate(v):
    c.need(type(v) is dict and set(v) == FIELDS and (v['schema'] == 'g7-one-shot-qualification/v1'), 'permit_schema')
    c.need(type(v['run_id']) is str and re.fullmatch('[0-9a-f]{32}', v['run_id']), 'fixed_run_id')
    c.need(v['profile'] in c.PROFILES and v['owner'] == c.OWNER, 'fixed_profile_owner')
    c.need(type(v['generation']) is int and v['generation'] > 0, 'actual_next_generation')
    c.need(v['pins'] == c.PINS and v['image'] == c.PINS['image'], 'exact_source_image_pins')
    c.need(type(v['manager_pid']) is int and v['manager_pid'] > 1, 'actual_sole_manager_pid')
    c.need(type(v['lease_dev_inode']) is list and len(v['lease_dev_inode']) == 2 and all((type(x) is int and x > 0 for x in v['lease_dev_inode'])), 'actual_physical_lease')
    c.number(v['issued_at'])
    c.number(v['expires_at'])
    c.need(v['expires_at'] - v['issued_at'] == 1800, 'fixed_absolute_trial_deadline')
    for k in ('host_facts', 'plan_sha256'):
        c.need(type(v[k]) is dict and set(v[k]) == set(c.NODES), 'exact_AB_' + k)
    for n in c.NODES:
        f = v['host_facts'][n]
        c.need(type(f) is dict and set(f) == {'total_bytes', 'cpu_count'}, 'fixed_actual_host_facts')
        c.policy(**f)
        sha(v['plan_sha256'][n])
    ins = v['input_identity']
    c.need(type(ins) is dict and set(ins) == INPUTS, 'complete_fixed_input_identity')
    for k, h in ins.items():
        if k == 'copy_receipts_sha256':
            c.need(type(h) is dict and set(h) == set(c.NODES), 'both_copy_receipts')
            for x in h.values():
                sha(x)
        else:
            sha(h)
    c.need(ins['python_source_sha256'] == '24c99a85bccbc9364e59f3687c721eacd9964bf9f3def6c5638053c59c5977f2', 'fixed_Python_source_receipt')
    c.need(ins['engine_acceptance_sha256'] == 'b1f0aa8e42e9bf7bcf053f5a09cdfe4a7dbd4e44dc8bf819f994ff1a0a232fac', 'fixed_R8b_engine_receipt')
    c.need(ins['token_map_sha256'] == 'de40bcdd71f24430ba82752ef385093be962adbf845a1c97db39161597d5dc28', 'fixed_token_map')
    return v

@dataclass(frozen=True)
class Document:
    value: dict
    sha256: str
    _value_digest: str = field(init=False, repr=False)

    def __post_init__(self):
        validate(self.value)
        sha(self.sha256)
        object.__setattr__(self, '_value_digest', digest(self.value))

    def check(self, *, now, identity=None, manifest=None, node=None, starting=False):
        validate(self.value)
        c.number(now)
        c.need(digest(self.value) == self._value_digest, 'permit_object_mutated')
        v = self.value
        if starting:
            c.need(v['issued_at'] <= now < v['expires_at'], 'permit_time_window')
        if identity:
            c.need(all((identity.get(k) == v[k] and type(identity.get(k)) is type(v[k]) for k in ('profile', 'owner', 'generation'))), 'permit_identity_mismatch')
        if manifest is not None:
            c.need(manifest.get('runtime_guard_required') is True, 'mandatory_runtime_guard')
            node = node or manifest['node']
            c.need(node in c.NODES and manifest['node'] == node, 'permit_node')
            plan = manifest['profiles'].get(v['profile'])
            c.need(type(plan) is dict, 'permit_plan_missing')
            c.need(plan.get('launch_enabled') is False and plan.get('image') == v['image'] and (plan.get('nodes') == list(c.NODES)), 'disabled_fixed_AB_plan_required')
            c.need(digest(plan) == v['plan_sha256'][node], 'exact_root_plan_SHA')
            args = plan.get('docker_run_args', [])
            limit = c.policy(**v['host_facts'][node])['container_cpu_limit']
            c.need(args.count('--cpus') == 1 and args[args.index('--cpus') + 1] == str(limit), 'fixed_trial_CPU_quota')
        return self

def load(path, *, require_root=True):
    path = Path(path)
    if require_root:
        for ancestor in path.absolute().parents:
            s = ancestor.lstat()
            c.need(stat.S_ISDIR(s.st_mode) and (not stat.S_ISLNK(s.st_mode)) and (s.st_uid == 0) and (not s.st_mode & 18), 'root_permit_ancestor')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        c.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and (before.st_size <= MAX_BYTES), 'bounded_regular_permit')
        if require_root:
            c.need(before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 288, 'root0440_permit_required')
        raw = bytearray()
        while len(raw) <= MAX_BYTES:
            b = os.read(fd, min(65536, MAX_BYTES + 1 - len(raw)))
            if not b:
                break
            raw.extend(b)
        after = os.fstat(fd)
        named = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        c.need(all((getattr(before, k) == getattr(after, k) == getattr(named, k) for k in fields)), 'permit_changed_during_read')
        c.need(len(raw) <= MAX_BYTES, 'permit_too_large')
        v = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda s: (_ for _ in ()).throw(c.Refusal('nonfinite_JSON')))
        return Document(validate(v), hashlib.sha256(raw).hexdigest())
    finally:
        os.close(fd)

def optional_node():
    try:
        return load(NODE_PATH)
    except FileNotFoundError:
        return None

def node_facts(text, cpu_count):
    counts = {}
    for line in (text or '').splitlines():
        k, sep, tail = line.partition(':')
        if k not in ('MemTotal', 'MemAvailable'):
            continue
        fields = tail.split()
        c.need(sep and len(fields) == 2 and (fields[1] == 'kB') and fields[0].isdigit() and (k not in counts), 'strict_meminfo')
        counts[k] = int(fields[0]) * 1024
    c.need(set(counts) == {'MemTotal', 'MemAvailable'} and 0 <= counts['MemAvailable'] <= counts['MemTotal'], 'complete_actual_meminfo')
    return ({'total_bytes': counts['MemTotal'], 'cpu_count': cpu_count}, counts['MemAvailable'] / c.GIB)
