# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import contextlib
import fcntl
import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
import importlib.util
import hashlib
_q_spec = importlib.util.spec_from_file_location('g7_qualification_root_permit', Path(__file__).with_name('permit.py'))
qp = importlib.util.module_from_spec(_q_spec)
sys.modules[_q_spec.name] = qp
_q_spec.loader.exec_module(qp)
QUALIFICATION_PROOF_PATH = Path('/var/lib/dgx-v4/node-runtime-guard/qualification-proof.json')

def load_qualification_guard_proof():
    for directory in QUALIFICATION_PROOF_PATH.parents:
        st = directory.lstat()
        qp.c.need(stat.S_ISDIR(st.st_mode) and (not stat.S_ISLNK(st.st_mode)) and (st.st_uid == 0) and (not st.st_mode & 18), 'qualification_proof_directory')
    fd = os.open(QUALIFICATION_PROOF_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        qp.c.need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and (stat.S_IMODE(st.st_mode) == 384) and (st.st_size <= 8192), 'qualification_guard_proof_file')
        raw = os.read(fd, 8193)
        qp.c.need(len(raw) <= 8192 and len(raw) == st.st_size, 'qualification_proof_incomplete_or_too_large')
        after = os.fstat(fd)
        named = QUALIFICATION_PROOF_PATH.lstat()
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        qp.c.need(st.st_nlink == 1 and all((getattr(st, k) == getattr(after, k) == getattr(named, k) for k in fields)), 'qualification_proof_changed')
        return json.loads(raw, object_pairs_hook=qp.unique)
    finally:
        os.close(fd)

def qualification_document(runtime, request, *, starting):
    plan = runtime.manifest.get('profiles', {}).get(request.get('profile'), {})
    if plan.get('launch_enabled', True) is not False:
        return None
    if request.get('profile') not in qp.c.PROFILES:
        return None
    document = runtime.qualification_reader()
    qp.c.need(document is not None, 'qualification_permit_missing')
    document.check(now=runtime.clock(), identity=request, manifest=runtime.manifest, starting=starting)
    facts, free = qp.node_facts(runtime.meminfo(), runtime.cpu_count())
    qp.c.need(facts == document.value['host_facts'][runtime.manifest['node']], 'actual_local_host_facts_changed')
    if starting:
        qp.c.need(free >= 110.0, 'qualification_local_RAM_admission')
    return document

def qualification_record(connection, document):
    v = document.value
    row = connection.execute('SELECT * FROM g7_qualification_runs WHERE run_id=?', (v['run_id'],)).fetchone()
    if row is not None:
        qp.c.need(all((row[k] == v[k] for k in ('profile', 'owner', 'generation'))) and row['permit_sha256'] == document.sha256, 'qualification_fence_binding_changed')
    return row
SCHEMA = 'dgx-v4-node-v1'
SSH_COMMAND = 'dgx-v4-node-v1'
MANIFEST_SCHEMA = 'dgx-v4-node-v1-manifest'
DEFAULT_MANIFEST_PATH = '/etc/dgx-v4/node-manifest.json'
DEFAULT_MEMINFO_PATH = '/proc/meminfo'
GUARD_STATUS_PATH = Path('/var/lib/dgx-v4/node-runtime-guard/status.json')
GUARD_ENTRYPOINT = '/opt/dgx-v4/bin/node-guard-bootstrap.py'
GUARD_MAX_AGE_SECONDS = 10.0
DEFAULT_BINARIES: dict[str, str] = {'nvidia-smi': '/usr/bin/nvidia-smi', 'docker': '/usr/bin/docker'}
MAX_REQUEST_BYTES = 65536
MAX_REPLY_BYTES = 262144
MAX_MANIFEST_BYTES = 65536
MAX_API_BYTES = 65536
CMD_TIMEOUT_SECONDS = 20.0
CMD_OUTPUT_CAP = 262144
FENCE_LOCK_WAIT_SECONDS = 2.0
NSMI_ARGV = ('nvidia-smi', '--query-compute-apps=pid,process_name,used_memory', '--format=csv,noheader,nounits')
DOCKER_PS_ARGV = ('docker', 'ps', '--all', '--quiet', '--no-trunc')
DOCKER_INSPECT_ALL_TEMPLATE = '{{.Id}}\t{{.Config.Image}}\t{{.HostConfig.Runtime}}\t{{json .HostConfig.DeviceRequests}}\t{{json .HostConfig.Devices}}\t{{json .Config.Labels}}\t{{.State.Running}}\t{{.State.Status}}'
DOCKER_INSPECT_OWN_TEMPLATE = '{{.Id}}\t{{json .Config.Labels}}\t{{.State.Running}}\t{{.State.Status}}\t{{.HostConfig.RestartPolicy.Name}}'
DOCKER_INSPECT_IMAGE_TEMPLATE = '{{.Config.Image}}'
LABEL_NODE = 'dgx-v4.node'
LABEL_PROFILE = 'dgx-v4.profile'
LABEL_OWNER = 'dgx-v4.owner'
LABEL_GENERATION = 'dgx-v4.generation'
STATE_CLEAR = 'CLEAR'
STATE_CLAIMED = 'CLAIMED'
STATE_RUNNING = 'RUNNING'
STATE_QUARANTINED = 'QUARANTINED'
ACTIVE_CONTAINER_STATES = frozenset({'running', 'paused', 'restarting'})
INACTIVE_CONTAINER_STATES = frozenset({'created', 'exited', 'dead'})
WIRE_ACTIONS = ('probe', 'preflight', 'claim', 'start', 'probe_ready', 'stop', 'confirm_stop', 'reconcile', 'release')
TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
REQUEST_ID_RE = re.compile('[0-9a-f]{16,64}')
CONTAINER_ID_RE = re.compile('[0-9a-f]{12,64}')
IMAGE_RE = re.compile('(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64})')
CONTAINER_CGROUP_ID_RE = re.compile('(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')
MODEL_ID_RE = re.compile('[A-Za-z0-9][A-Za-z0-9._/-]{0,199}')
ENV_NAME_RE = re.compile('[A-Za-z_][A-Za-z0-9_]{0,63}')
FORBIDDEN_PLAN_ARG_RE = re.compile('^(--label|--label-file|--restart|--name|--detach|-d|--rm|--privileged)(=|$)')
ROLE_API_LEADER = 'api_leader'
ROLE_WORKER = 'worker'
PROFILE_ROLES = frozenset({ROLE_API_LEADER, ROLE_WORKER})
REASON_MAX = 200
MAX_PROCESS_ROWS = 128
MAX_CONTAINER_ROWS = 64

class ProtocolError(ValueError):

    def __init__(self, reason_code: str, message: str=''):
        super().__init__(message or reason_code)
        self.reason_code = reason_code

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ProtocolError('duplicate_key', f'duplicate JSON key: {key!r}')
        seen.add(key)
    return dict(pairs)

def _reject_constant(name: str) -> Any:
    raise ProtocolError('nonfinite_number', f'JSON constant {name!r} is not accepted')

def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ProtocolError('nonfinite_number', 'non-finite JSON number is not accepted')
    return value

def strict_json_loads(raw: Any, *, max_bytes: int) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        if len(data) > max_bytes:
            raise ProtocolError('oversize_payload', f'payload exceeds {max_bytes} bytes')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ProtocolError('invalid_utf8', 'payload is not valid UTF-8') from exc
    elif isinstance(raw, str):
        text = raw
        if len(text.encode('utf-8')) > max_bytes:
            raise ProtocolError('oversize_payload', f'payload exceeds {max_bytes} bytes')
    else:
        raise ProtocolError('invalid_type', 'payload must be bytes or str')
    if not text.strip():
        raise ProtocolError('empty_payload', 'empty payload')
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant, parse_float=_finite_float)
    except ProtocolError:
        raise
    except RecursionError as exc:
        raise ProtocolError('too_deep', 'payload nesting exceeds the parser limit') from exc
    except ValueError as exc:
        raise ProtocolError('invalid_json', 'payload is not a single valid JSON value') from exc

def require_token(value: Any, name: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ProtocolError('bad_field', f'{name} must match {TOKEN_RE.pattern}')
    return value

def require_generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProtocolError('bad_field', 'generation must be a positive integer')
    return int(value)

def _clean_str(value: Any, name: str, *, max_len: int, allow_empty: bool=False) -> str:
    if not isinstance(value, str):
        raise ProtocolError('bad_field', f'{name} must be a string')
    if not value and (not allow_empty):
        raise ProtocolError('bad_field', f'{name} must be non-empty')
    if len(value) > max_len:
        raise ProtocolError('bad_field', f'{name} exceeds {max_len} characters')
    for ch in value:
        if ch < ' ' or ch == '\x7f':
            raise ProtocolError('bad_field', f'{name} must be printable')
    return value

def same_identity(record: Mapping[str, Any] | None, profile: str, owner: str, generation: int) -> bool:
    return bool(record is not None and record.get('profile') == profile and (record.get('owner') == owner) and (int(record.get('generation') or 0) == int(generation)))

@dataclass
class CommandResult:
    argv: tuple[str, ...]
    ok: bool
    returncode: int | None = None
    stdout: str = ''
    stderr: str = ''
    timed_out: bool = False
    reason: str | None = None

class CommandRunner:
    """Fixed-argv executor over pinned absolute binaries. Never a shell."""

    def __init__(self, binaries: Mapping[str, str], *, timeout: float=CMD_TIMEOUT_SECONDS, cap: int=CMD_OUTPUT_CAP):
        self.binaries = dict(binaries)
        self.timeout = float(timeout)
        self.cap = int(cap)

    def _env(self) -> dict[str, str]:
        try:
            import pwd
            home = pwd.getpwuid(os.getuid()).pw_dir
        except Exception:
            home = '/'
        return {'PATH': '/usr/bin:/bin', 'HOME': home, 'LC_ALL': 'C'}

    def run(self, argv: Sequence[str]) -> CommandResult:
        argv = tuple((str(item) for item in argv))
        if not argv:
            return CommandResult(argv=argv, ok=False, reason='empty_argv')
        binary = argv[0]
        path = self.binaries.get(binary)
        if path is None:
            return CommandResult(argv=argv, ok=False, reason='unmapped_command')
        try:
            proc = subprocess.run([path, *argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, env=self._env(), close_fds=True)
        except subprocess.TimeoutExpired:
            return CommandResult(argv=argv, ok=False, timed_out=True, reason='timeout')
        except OSError as exc:
            return CommandResult(argv=argv, ok=False, reason=f'spawn_error:{type(exc).__name__}')
        if len(proc.stdout) > self.cap or len(proc.stderr) > self.cap:
            return CommandResult(argv=argv, ok=False, reason='output_oversize')
        try:
            stdout = proc.stdout.decode('utf-8')
            stderr = proc.stderr.decode('utf-8')
        except UnicodeDecodeError:
            return CommandResult(argv=argv, ok=False, reason='undecodable_output')
        ok = proc.returncode == 0
        return CommandResult(argv=argv, ok=ok, returncode=proc.returncode, stdout=stdout, stderr=stderr, reason=None if ok else f'exit_{proc.returncode}')

class ManifestError(Exception):

    def __init__(self, reason_code: str, message: str=''):
        super().__init__(message or reason_code)
        self.reason_code = reason_code

def load_manifest(path: str | Path, *, require_root_owner: bool=True) -> dict:
    """Load and strictly validate the frozen root-owned manifest."""
    manifest_path = Path(path)
    try:
        info = os.lstat(manifest_path)
    except OSError as exc:
        raise ManifestError('manifest_missing', f'manifest not readable: {type(exc).__name__}') from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ManifestError('manifest_not_regular', 'manifest must be a regular file, not a symlink')
    if require_root_owner and info.st_uid != 0:
        raise ManifestError('manifest_not_root_owned', 'manifest must be owned by root')
    if info.st_mode & 18:
        raise ManifestError('manifest_writable', 'manifest must not be group/world writable')
    raw = manifest_path.read_bytes()
    try:
        value = strict_json_loads(raw, max_bytes=MAX_MANIFEST_BYTES)
    except ProtocolError as exc:
        raise ManifestError(f'manifest_{exc.reason_code}', 'manifest is not valid strict JSON') from exc
    return validate_manifest(value)

def validate_manifest(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ManifestError('manifest_bad_shape', 'manifest must be an object')
    allowed = {'schema', 'node', 'state_db', 'lock_file', 'launch_enabled', 'profiles', 'runtime_guard_required'}
    unknown = sorted((str(k) for k in value if k not in allowed))
    if unknown:
        raise ManifestError('manifest_unknown_field', f"unknown manifest keys: {', '.join(unknown)}")
    if value.get('schema') != MANIFEST_SCHEMA:
        raise ManifestError('manifest_bad_schema', f'schema must be {MANIFEST_SCHEMA!r}')
    if 'runtime_guard_required' in value and type(value['runtime_guard_required']) is not bool:
        raise ManifestError('manifest_bad_guard_flag', 'runtime_guard_required must be a boolean')
    node = value.get('node')
    if not isinstance(node, str) or not TOKEN_RE.fullmatch(node):
        raise ManifestError('manifest_bad_node', 'node must be a plain token')
    for key in ('state_db', 'lock_file'):
        path = value.get(key)
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ManifestError('manifest_bad_path', f'{key} must be an absolute path')
        for ch in path:
            if ch < ' ' or ch == '\x7f':
                raise ManifestError('manifest_bad_path', f'{key} must not contain control characters')
    if value['state_db'] == value['lock_file']:
        raise ManifestError('manifest_bad_path', 'state_db and lock_file must differ')
    launch_enabled = value.get('launch_enabled')
    if not isinstance(launch_enabled, bool):
        raise ManifestError('manifest_bad_launch_flag', 'launch_enabled must be a boolean')
    profiles = value.get('profiles')
    if not isinstance(profiles, dict):
        raise ManifestError('manifest_bad_profiles', 'profiles must be an object')
    for name, plan in profiles.items():
        if not isinstance(name, str) or not TOKEN_RE.fullmatch(name):
            raise ManifestError('manifest_bad_profile_name', f'invalid profile name: {name!r}')
        validate_plan(plan, node=node, profile=name)
        if value.get('runtime_guard_required') is True and (not re.fullmatch('sha256:[0-9a-f]{64}', plan['image'])):
            raise ManifestError('manifest_bad_guard_image', 'guarded plans pin exact local image configuration IDs')
    return value

def validate_plan(plan: Any, *, node: str, profile: str) -> dict:
    if not isinstance(plan, dict):
        raise ManifestError('manifest_bad_plan', f'profiles[{profile}] must be an object')
    allowed = {'image', 'model_id', 'nodes', 'api', 'roles', 'docker_run_args', 'container_args', 'container_env', 'launch_enabled'}
    unknown = sorted((str(k) for k in plan if k not in allowed))
    if unknown:
        raise ManifestError('manifest_bad_plan', f"profiles[{profile}] unknown keys: {', '.join(unknown)}")
    if 'launch_enabled' in plan and type(plan['launch_enabled']) is not bool:
        raise ManifestError('manifest_bad_profile_launch_flag', 'profile launch_enabled must be bool')
    image = plan.get('image')
    if not isinstance(image, str) or not IMAGE_RE.fullmatch(image):
        raise ManifestError('manifest_bad_image', f'profiles[{profile}].image must be repo@sha256:<64hex> or exact local sha256:<64hex>')
    model_id = plan.get('model_id')
    if not isinstance(model_id, str) or not MODEL_ID_RE.fullmatch(model_id):
        raise ManifestError('manifest_bad_model_id', f'profiles[{profile}].model_id is invalid')
    nodes = plan.get('nodes')
    if not isinstance(nodes, list) or not nodes or any((not isinstance(n, str) or not TOKEN_RE.fullmatch(n) for n in nodes)) or (len(set(nodes)) != len(nodes)):
        raise ManifestError('manifest_bad_nodes', f'profiles[{profile}].nodes must be a unique token list')
    if node not in nodes:
        raise ManifestError('manifest_bad_nodes', f'profiles[{profile}] does not include this node {node!r}')
    roles: dict[str, str] | None = None
    node_role: str | None = None
    if 'roles' in plan:
        roles_raw = plan['roles']
        if not isinstance(roles_raw, dict) or set(roles_raw) != set(nodes) or any((not isinstance(role, str) or role not in PROFILE_ROLES for role in roles_raw.values())) or (sum((role == ROLE_API_LEADER for role in roles_raw.values())) != 1) or (sum((role == ROLE_WORKER for role in roles_raw.values())) < 1):
            raise ManifestError('manifest_bad_roles', f'profiles[{profile}].roles must map every node to exactly one api_leader and at least one worker')
        roles = dict(roles_raw)
        node_role = roles[node]
    if node_role == ROLE_WORKER:
        if 'api' in plan:
            raise ManifestError('manifest_bad_api', f'profiles[{profile}] worker must not declare an API target')
        api = None
    else:
        api = plan.get('api')
        if not isinstance(api, dict) or set(api) != {'host', 'port', 'path'}:
            raise ManifestError('manifest_bad_api', f'profiles[{profile}].api must be exactly host/port/path')
    if api is not None:
        if api.get('host') not in ('127.0.0.1', '::1'):
            raise ManifestError('manifest_bad_api', f'profiles[{profile}].api.host must be a loopback literal')
        port = api.get('port')
        if isinstance(port, bool) or not isinstance(port, int) or (not 1 <= port <= 65535):
            raise ManifestError('manifest_bad_api', f'profiles[{profile}].api.port is invalid')
        path = api.get('path')
        _clean_str(path, f'profiles[{profile}].api.path', max_len=128)
        if not path.startswith('/') or '..' in path or ' ' in path:
            raise ManifestError('manifest_bad_api', f'profiles[{profile}].api.path must be a clean absolute path')
    for key in ('docker_run_args', 'container_args'):
        args = plan.get(key, [])
        if not isinstance(args, list):
            raise ManifestError('manifest_bad_args', f'profiles[{profile}].{key} must be a list of strings')
        for arg in args:
            text = _clean_str(arg, f'profiles[{profile}].{key}[]', max_len=256)
            if key == 'docker_run_args' and FORBIDDEN_PLAN_ARG_RE.match(text):
                raise ManifestError('manifest_bad_args', f'profiles[{profile}].{key} must not override safety-critical docker flags')
    container_env = plan.get('container_env', {})
    if not isinstance(container_env, dict) or len(container_env) > 32:
        raise ManifestError('manifest_bad_env', f'profiles[{profile}].container_env must be an object of <=32 entries')
    for key, value in container_env.items():
        if not isinstance(key, str) or not ENV_NAME_RE.fullmatch(key):
            raise ManifestError('manifest_bad_env', f'profiles[{profile}].container_env has an invalid name')
        _clean_str(value, f'profiles[{profile}].container_env[{key}]', max_len=1024, allow_empty=True)
    return plan

class FenceUnavailable(Exception):
    pass

class FenceBusy(Exception):
    pass
FENCE_SCHEMA_SQL = '\nCREATE TABLE IF NOT EXISTS g7_qualification_runs (\n run_id TEXT PRIMARY KEY,profile TEXT NOT NULL,owner TEXT NOT NULL,generation INTEGER NOT NULL,\n permit_sha256 TEXT NOT NULL,claimed_at REAL NOT NULL,start_intent_at REAL,\n UNIQUE(profile,generation)\n);\nCREATE TABLE IF NOT EXISTS node_state (\n    id INTEGER PRIMARY KEY CHECK (id = 1),\n    state TEXT NOT NULL,\n    profile TEXT,\n    owner TEXT,\n    generation INTEGER,\n    container_id TEXT,\n    claimed_at REAL,\n    updated_at REAL,\n    released_at REAL,\n    quarantine_reason TEXT,\n    note TEXT\n);\n'
RECORD_COLUMNS = ('state', 'profile', 'owner', 'generation', 'container_id', 'claimed_at', 'updated_at', 'released_at', 'quarantine_reason', 'note')

class Fence:
    """One SQLite record per node, guarded by an exclusive ``flock``.

    Every lifecycle action (read or mutate) runs inside :meth:`locked`, so all
    mutations are serialized against each other and against observations.
    """

    def __init__(self, db_path: str | Path, lock_path: str | Path, *, wait_seconds: float=FENCE_LOCK_WAIT_SECONDS, clock: Callable[[], float]=time.time):
        self.db_path = Path(db_path)
        self.lock_path = Path(lock_path)
        self.wait_seconds = float(wait_seconds)
        self.clock = clock

    def _check_paths(self) -> None:
        for path in (self.db_path, self.lock_path):
            parent = path.parent
            if not parent.is_dir() or parent.is_symlink():
                raise FenceUnavailable(f'fence directory unavailable for {path.name}')
            if parent.stat().st_mode & 2:
                raise FenceUnavailable(f'fence directory is world writable for {path.name}')
            if path.exists() or path.is_symlink():
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise FenceUnavailable(f'fence path {path.name} must be a regular file')
                if info.st_uid != os.geteuid():
                    raise FenceUnavailable(f'fence path {path.name} must be owned by the service user')
                if info.st_mode & 18:
                    raise FenceUnavailable(f'fence path {path.name} must not be group/world writable')

    @contextlib.contextmanager
    def locked(self):
        self._check_paths()
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 384)
        connection = None
        try:
            deadline = time.monotonic() + self.wait_seconds
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise FenceBusy('fence busy') from None
                    time.sleep(0.05)
            try:
                connection = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
                connection.row_factory = sqlite3.Row
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA synchronous=FULL')
                connection.execute('PRAGMA busy_timeout=5000')
                connection.executescript(FENCE_SCHEMA_SQL)
            except sqlite3.Error as exc:
                with contextlib.suppress(Exception):
                    if connection is not None:
                        connection.close()
                connection = None
                raise FenceUnavailable(f'fence database unavailable: {type(exc).__name__}') from exc
            yield connection
        finally:
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close()
            with contextlib.suppress(Exception):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

def read_record(connection: sqlite3.Connection) -> dict[str, Any] | None:
    row = connection.execute('SELECT * FROM node_state WHERE id=1').fetchone()
    if row is None:
        return None
    return {key: row[key] for key in RECORD_COLUMNS}

def save_record(connection: sqlite3.Connection, record: Mapping[str, Any]) -> None:
    connection.execute('BEGIN IMMEDIATE')
    try:
        connection.execute('INSERT INTO node_state(id, state, profile, owner, generation, container_id,\n                   claimed_at, updated_at, released_at, quarantine_reason, note)\n               VALUES(1, :state, :profile, :owner, :generation, :container_id,\n                   :claimed_at, :updated_at, :released_at, :quarantine_reason, :note)\n               ON CONFLICT(id) DO UPDATE SET\n                   state=excluded.state, profile=excluded.profile, owner=excluded.owner,\n                   generation=excluded.generation, container_id=excluded.container_id,\n                   claimed_at=excluded.claimed_at, updated_at=excluded.updated_at,\n                   released_at=excluded.released_at, quarantine_reason=excluded.quarantine_reason,\n                   note=excluded.note', {'state': record['state'], 'profile': record.get('profile'), 'owner': record.get('owner'), 'generation': record.get('generation'), 'container_id': record.get('container_id'), 'claimed_at': record.get('claimed_at'), 'updated_at': record.get('updated_at'), 'released_at': record.get('released_at'), 'quarantine_reason': record.get('quarantine_reason'), 'note': record.get('note')})
    except BaseException:
        connection.execute('ROLLBACK')
        raise
    else:
        connection.execute('COMMIT')

def _new_record(state: str, *, profile: str, owner: str, generation: int, now: float, **extra: Any) -> dict[str, Any]:
    record = {'state': state, 'profile': profile, 'owner': owner, 'generation': int(generation), 'container_id': None, 'claimed_at': now, 'updated_at': now, 'released_at': None, 'quarantine_reason': None, 'note': None}
    record.update(extra)
    return record

@dataclass
class GpuSnapshot:
    complete: bool
    reasons: list[str]
    processes: list[dict[str, Any]]
    containers: list[dict[str, Any]]
    truncated: bool = False

    @property
    def gpu_empty(self) -> bool:
        return self.complete and (not self.truncated) and (not self.processes) and (not self.containers)

def _parse_compute_processes(result: CommandResult) -> tuple[list[dict[str, Any]] | None, str | None]:
    if not result.ok:
        return (None, f"nvidia_smi_{result.reason or 'failed'}")
    processes: list[dict[str, Any]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split(',')]
        if len(parts) < 2:
            return (None, 'nvidia_smi_unparseable')
        try:
            pid = int(parts[0])
        except ValueError:
            return (None, 'nvidia_smi_unparseable')
        entry: dict[str, Any] = {'pid': pid, 'process_name': parts[1][:128]}
        if len(parts) >= 3 and parts[2]:
            with contextlib.suppress(ValueError):
                entry['used_memory_mib'] = int(float(parts[2]))
        processes.append(entry)
    return (processes, None)

def _container_is_gpu(device_requests: Any, runtime: Any, devices: Any) -> bool:
    if isinstance(device_requests, list) and device_requests:
        return True
    if isinstance(runtime, str) and 'nvidia' in runtime.lower():
        return True
    if isinstance(devices, list) and devices:
        return True
    return False

def _json_field(value: str) -> Any:
    text = value.strip()
    if not text or text == '<no value>':
        return None
    try:
        return json.loads(text)
    except ValueError:
        return '<unparseable>'

def enumerate_gpu(runner: CommandRunner, *, record: Mapping[str, Any] | None=None) -> GpuSnapshot:
    """Enumerate compute processes and every Docker container that can hold GPU work."""
    reasons: list[str] = []
    processes: list[dict[str, Any]] = []
    containers: list[dict[str, Any]] = []
    complete = True
    parsed, reason = _parse_compute_processes(runner.run(NSMI_ARGV))
    if parsed is None:
        complete = False
        reasons.append(reason or 'nvidia_smi_failed')
    else:
        processes = parsed
    ps = runner.run(DOCKER_PS_ARGV)
    if not ps.ok:
        complete = False
        reasons.append(f"docker_ps_{ps.reason or 'failed'}")
    else:
        ids: list[str] = []
        seen_ids: set[str] = set()
        for raw_line in ps.stdout.splitlines():
            candidate = raw_line.strip()
            if not candidate:
                continue
            if not CONTAINER_ID_RE.fullmatch(candidate) or candidate in seen_ids:
                complete = False
                reasons.append('docker_ps_unparseable')
                break
            ids.append(candidate)
            seen_ids.add(candidate)
        if complete and ids:
            inspect = runner.run(('docker', 'inspect', '--format', DOCKER_INSPECT_ALL_TEMPLATE, *ids))
            if not inspect.ok:
                complete = False
                reasons.append(f"docker_inspect_{inspect.reason or 'failed'}")
            else:
                inspected_ids: set[str] = set()
                for raw_line in inspect.stdout.splitlines():
                    line = raw_line.strip('\n')
                    if not line:
                        continue
                    fields = line.split('\t')
                    if len(fields) != 8:
                        complete = False
                        reasons.append('docker_inspect_unparseable')
                        break
                    container_id, image, runtime, device_requests_raw, devices_raw, labels_raw, running_raw, status_raw = fields
                    if not CONTAINER_ID_RE.fullmatch(container_id) or container_id not in seen_ids or container_id in inspected_ids or (running_raw.strip().lower() not in ('true', 'false')):
                        complete = False
                        reasons.append('docker_inspect_unparseable')
                        break
                    device_requests = _json_field(device_requests_raw)
                    devices = _json_field(devices_raw)
                    labels = _json_field(labels_raw)
                    if '<unparseable>' in (device_requests, devices, labels) or (device_requests is not None and (not isinstance(device_requests, list))) or (devices is not None and (not isinstance(devices, list))) or (labels is not None and (not isinstance(labels, dict))):
                        complete = False
                        reasons.append('docker_inspect_unparseable')
                        break
                    status = status_raw.strip().lower()
                    if status not in ACTIVE_CONTAINER_STATES and status not in INACTIVE_CONTAINER_STATES:
                        complete = False
                        reasons.append('docker_inspect_unknown_state')
                        break
                    inspected_ids.add(container_id)
                    if status not in ACTIVE_CONTAINER_STATES:
                        continue
                    if not _container_is_gpu(device_requests, runtime, devices):
                        continue
                    label_map = labels or {}
                    entry: dict[str, Any] = {'id': container_id, 'short_id': container_id[:12], 'image': image[:200], 'runtime': runtime[:64], 'status': status, 'device_requests_present': bool(device_requests), 'nvidia_runtime': 'nvidia' in runtime.lower(), 'devices_present': bool(devices), 'labels_present': any((label in label_map for label in (LABEL_PROFILE, LABEL_OWNER, LABEL_GENERATION))), 'owner': label_map.get(LABEL_OWNER) if isinstance(label_map.get(LABEL_OWNER), str) else None, 'generation': label_map.get(LABEL_GENERATION) if isinstance(label_map.get(LABEL_GENERATION), str) else None, 'mapped': bool(record is not None and record.get('container_id') == container_id and (label_map.get(LABEL_PROFILE) == record.get('profile')) and (label_map.get(LABEL_OWNER) == record.get('owner')) and (label_map.get(LABEL_GENERATION) == str(record.get('generation'))) and (record.get('node') is None or label_map.get(LABEL_NODE) == record.get('node')))}
                    containers.append(entry)
                if complete and inspected_ids != seen_ids:
                    complete = False
                    reasons.append('docker_inspect_incomplete')
    truncated = len(processes) > MAX_PROCESS_ROWS or len(containers) > MAX_CONTAINER_ROWS
    if truncated:
        reasons.append('enumeration_truncated')
    return GpuSnapshot(complete=complete, reasons=reasons[:8], processes=processes[:MAX_PROCESS_ROWS], containers=containers[:MAX_CONTAINER_ROWS], truncated=truncated)

def default_process_container_id(pid: int) -> str | None:
    """Return one exact Docker cgroup ID for a host GPU PID; unknown fails closed."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        text = (Path('/proc') / str(pid) / 'cgroup').read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return None
    matches = set(CONTAINER_CGROUP_ID_RE.findall(text))
    return next(iter(matches)) if len(matches) == 1 else None

def gpu_summary(snapshot: GpuSnapshot) -> dict[str, Any]:
    return {'enumeration': 'complete' if snapshot.complete and (not snapshot.truncated) else 'unknown', 'reasons': list(snapshot.reasons), 'truncated': snapshot.truncated, 'process_count': len(snapshot.processes), 'gpu_container_count': len(snapshot.containers), 'empty': snapshot.gpu_empty, 'processes': [{'pid': item['pid'], 'process_name': item.get('process_name', '')[:64]} for item in snapshot.processes[:16]], 'containers': [{'short_id': item.get('short_id'), 'status': item.get('status'), 'image': item.get('image'), 'owner': item.get('owner'), 'generation': item.get('generation'), 'mapped': item.get('mapped')} for item in snapshot.containers[:16]]}

@dataclass
class InspectResult:
    exists: bool | None
    data: dict[str, Any] | None
    reason: str | None = None

def _inspect_not_found(result: CommandResult) -> bool:
    text = (result.stderr or '').lower()
    return 'no such' in text or 'not found' in text

def inspect_own_container(runner: CommandRunner, container_id: str) -> InspectResult:
    result = runner.run(('docker', 'inspect', '--format', DOCKER_INSPECT_OWN_TEMPLATE, container_id))
    if not result.ok:
        if result.returncode not in (0, None) and _inspect_not_found(result):
            return InspectResult(exists=False, data=None, reason='not_found')
        return InspectResult(exists=None, data=None, reason=f"inspect_{result.reason or 'failed'}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return InspectResult(exists=None, data=None, reason='inspect_unparseable')
    fields = lines[0].split('\t')
    if len(fields) != 5:
        return InspectResult(exists=None, data=None, reason='inspect_unparseable')
    raw_id, labels_raw, running_raw, status_raw, restart_raw = fields
    labels = _json_field(labels_raw)
    running_text = running_raw.strip().lower()
    status = status_raw.strip().lower()
    if not CONTAINER_ID_RE.fullmatch(raw_id) or labels == '<unparseable>' or (labels is not None and (not isinstance(labels, dict))) or (running_text not in ('true', 'false')):
        return InspectResult(exists=None, data=None, reason='inspect_unparseable')
    if status not in ACTIVE_CONTAINER_STATES and status not in INACTIVE_CONTAINER_STATES:
        return InspectResult(exists=None, data=None, reason='inspect_unknown_state')
    data = {'id': raw_id, 'labels': labels or {}, 'running': running_text == 'true', 'status': status, 'restart_policy': restart_raw.strip()[:32]}
    return InspectResult(exists=True, data=data, reason=None)

def inspect_container_image(runner: CommandRunner, container_id: str) -> str | None:
    result = runner.run(('docker', 'inspect', '--format', DOCKER_INSPECT_IMAGE_TEMPLATE, container_id))
    if not result.ok:
        return None
    lines = result.stdout.splitlines()
    if len(lines) != 1 or not lines[0]:
        return None
    return lines[0]

def container_is_active(data: Mapping[str, Any]) -> bool:
    return data.get('status') in ACTIVE_CONTAINER_STATES

def labels_match_identity(data: Mapping[str, Any], *, node: str, profile: str, owner: str, generation: int) -> bool:
    labels = data.get('labels') or {}
    return bool(labels.get(LABEL_NODE) == node and labels.get(LABEL_PROFILE) == profile and (labels.get(LABEL_OWNER) == owner) and (labels.get(LABEL_GENERATION) == str(int(generation))))

def find_container_by_name(runner: CommandRunner, name: str) -> str | None:
    result = runner.run(('docker', 'ps', '--quiet', '--no-trunc', '--filter', f'name=^/{name}$'))
    if not result.ok:
        return None
    for raw_line in result.stdout.splitlines():
        candidate = raw_line.strip()
        if CONTAINER_ID_RE.fullmatch(candidate):
            return candidate
    return None

def container_name(profile: str, generation: int, node: str) -> str:
    return f'dgx-v4-{profile}-g{int(generation)}-{node}'

def docker_run_argv(plan: Mapping[str, Any], *, node: str, profile: str, owner: str, generation: int) -> list[str]:
    argv = ['docker', 'run', '--detach', '--name', container_name(profile, generation, node), '--restart=no', '--label', f'{LABEL_NODE}={node}', '--label', f'{LABEL_PROFILE}={profile}', '--label', f'{LABEL_OWNER}={owner}', '--label', f'{LABEL_GENERATION}={int(generation)}']
    for key in sorted(plan.get('container_env', {})):
        argv.extend(['--env', f"{key}={plan['container_env'][key]}"])
    argv.extend(plan.get('docker_run_args', []))
    argv.append(plan['image'])
    argv.extend(plan.get('container_args', []))
    return argv

class _NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def default_api_get(url: str) -> tuple[int | None, bytes]:
    """Loopback model-API probe. No proxies, bounded body, never logs the body."""
    request = urllib.request.Request(url, method='GET', headers={'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=5.0) as response:
            return (int(response.status), response.read(MAX_API_BYTES + 1))
    except urllib.error.HTTPError as exc:
        body: bytes = b''
        with contextlib.suppress(Exception):
            body = exc.read(4096)
        with contextlib.suppress(Exception):
            exc.close()
        return (int(exc.code), body)
    except Exception:
        return (None, b'')

def api_url(api: Mapping[str, Any]) -> str:
    host = str(api['host'])
    if ':' in host:
        host = f'[{host}]'
    return f"http://{host}:{int(api['port'])}{api['path']}"

def extract_model_ids(body: bytes) -> list[str] | None:
    try:
        value = strict_json_loads(body, max_bytes=MAX_API_BYTES)
    except ProtocolError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get('data'), list):
        return None
    ids: list[str] = []
    for item in value['data']:
        if isinstance(item, dict) and isinstance(item.get('id'), str):
            ids.append(item['id'])
    return ids

def default_meminfo_reader() -> str | None:
    """Read the fixed proc path only; never a caller-supplied path."""
    try:
        return Path(DEFAULT_MEMINFO_PATH).read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return None

def memory_observation(text: str | None) -> dict[str, Any]:
    """Actual MemTotal/MemAvailable in bytes, or explicit unknown — never 0.

    ``null`` values mean "N/A"; they must not be coerced to 0 by any consumer.
    """
    unavailable = {'mem_total_bytes': None, 'mem_available_bytes': None, 'source': 'proc_meminfo', 'reason': 'meminfo_unavailable'}
    if not text:
        return unavailable
    total_kb: int | None = None
    available_kb: int | None = None
    for line in text.splitlines():
        head, sep, tail = line.partition(':')
        if not sep:
            continue
        fields = tail.strip().split()
        if not fields:
            continue
        try:
            number = int(fields[0])
        except ValueError:
            continue
        if head.strip() == 'MemTotal':
            total_kb = number
        elif head.strip() == 'MemAvailable':
            available_kb = number
    if total_kb is None or available_kb is None or total_kb <= 0 or (available_kb < 0) or (available_kb > total_kb):
        return {**unavailable, 'reason': 'meminfo_unparseable'}
    return {'mem_total_bytes': total_kb * 1024, 'mem_available_bytes': available_kb * 1024, 'source': 'proc_meminfo', 'reason': None}

@dataclass
class Runtime:
    manifest: Mapping[str, Any]
    fence: Fence
    runner: CommandRunner
    clock: Callable[[], float] = time.time
    api_get: Callable[[str], tuple[int | None, bytes]] = default_api_get
    meminfo: Callable[[], str | None] = default_meminfo_reader
    process_container_id: Callable[[int], str | None] = default_process_container_id
    guard_status_reader: Callable[[], Mapping[str, Any]] | None = None
    qualification_reader: Callable[[], Any] = qp.optional_node
    qualification_proof_reader: Callable[[], Any] = load_qualification_guard_proof
    cpu_count: Callable[[], int] = lambda: len(os.sched_getaffinity(0))

def load_runtime_guard_status() -> Mapping[str, Any]:
    """Root-only fixed-path heartbeat; no caller-selected files or processes."""
    for directory in GUARD_STATUS_PATH.parents:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 18:
            raise ValueError('guard_directory_untrusted')
    fd = os.open(GUARD_STATUS_PATH, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 384:
            raise ValueError('guard_file_untrusted')
        raw = os.read(fd, 8193)
    finally:
        os.close(fd)
    value = strict_json_loads(raw, max_bytes=8192)
    pid = value.get('guard_pid') if isinstance(value, dict) else None
    if type(pid) is not int or pid <= 1:
        raise ValueError('guard_pid_unknown')
    os.kill(pid, 0)
    proc = Path('/proc') / str(pid)
    status = (proc / 'status').read_text()
    uid_rows = [line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
    if uid_rows != [['0', '0', '0', '0']]:
        raise ValueError('guard_process_not_root')
    argv = (proc / 'cmdline').read_bytes().split(b'\x00')
    if argv != [b'/usr/bin/python3', b'-I', GUARD_ENTRYPOINT.encode(), b'--serve', b'']:
        raise ValueError('guard_process_identity_unknown')
    return value

def runtime_guard_verified(runtime: Runtime, request: Mapping[str, Any], record: Mapping[str, Any] | None, *, ready: bool=False) -> bool:
    if runtime.manifest.get('runtime_guard_required') is not True:
        return not (request.get('profile') in qp.c.PROFILES and runtime.manifest['profiles'].get(request.get('profile'), {}).get('launch_enabled') is False)
    try:
        data = (runtime.guard_status_reader or load_runtime_guard_status)()
        document = qualification_document(runtime, request, starting=not ready)
        if document is not None:
            proof = runtime.qualification_proof_reader()
            qp.c.need(type(proof) is dict and set(proof) == {'schema', 'node', 'guard_pid', 'observed_at', 'permit_sha256'} and (proof['schema'] == 'g7-qualification-guard-proof/v1'), 'qualification_guard_proof_shape')
            qp.c.need(proof['node'] == runtime.manifest['node'] and type(proof['guard_pid']) is int and (proof['guard_pid'] == data.get('guard_pid')) and (proof['permit_sha256'] == document.sha256), 'qualification_guard_not_armed')
            stamp = qp.c.number(proof['observed_at'])
            now = qp.c.number(runtime.clock())
            qp.c.need(data['observed_at'] <= stamp <= now and now - stamp <= GUARD_MAX_AGE_SECONDS, 'qualification_guard_proof_stale')
        fields = {'schema', 'node', 'guard_pid', 'observed_at', 'state', 'profile', 'owner', 'generation', 'container_id', 'image', 'reason_code'}
        if set(data) != fields or data['schema'] != 'dgx-v4-runtime-guard-v1' or data['node'] != runtime.manifest['node']:
            return False
        stamp = data['observed_at']
        now = runtime.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or type(stamp) not in (int, float) or (not math.isfinite(stamp)) or (not 0 <= now - stamp <= GUARD_MAX_AGE_SECONDS):
            return False
        if type(data['guard_pid']) is not int or data['guard_pid'] <= 1:
            return False
        if ready:
            plan = runtime.manifest['profiles'][request['profile']]
            return bool(record and data['state'] == 'ACTIVE' and (data['reason_code'] in ('active', 'active_warning')) and all((data[k] == request[k] for k in ('profile', 'owner', 'generation'))) and (type(data['generation']) is int) and (data['container_id'] == record.get('container_id')) and (data['image'] == plan['image']))
        if data['state'] == 'IDLE_HOLD_RETAINED':
            if data['reason_code'] not in ('idle_no_record', 'idle_db_clear') or any((data[k] is not None for k in ('profile', 'owner', 'generation', 'container_id', 'image'))):
                return False
            if record is None:
                return data['reason_code'] == 'idle_no_record'
            state = record.get('state')
            if state == STATE_CLEAR:
                released_at, updated_at = (record.get('released_at'), record.get('updated_at'))
                return bool(data['reason_code'] == 'idle_db_clear' and type(released_at) in (int, float) and math.isfinite(released_at) and (type(updated_at) in (int, float)) and math.isfinite(updated_at) and (updated_at >= released_at > 0) and (stamp >= updated_at))
            if state != STATE_CLAIMED or data['reason_code'] not in ('idle_no_record', 'idle_db_clear'):
                return False
            if record.get('container_id') is not None or any((record.get(key) != request.get(key) for key in ('profile', 'owner', 'generation'))) or type(record.get('generation')) is not int:
                return False
            claimed_at, updated_at = (record.get('claimed_at'), record.get('updated_at'))
            return bool(type(claimed_at) in (int, float) and math.isfinite(claimed_at) and (type(updated_at) in (int, float)) and math.isfinite(updated_at) and (claimed_at == updated_at) and (stamp <= claimed_at <= now))
        return bool(data['state'] == 'ARMING_HOLD_RETAINED' and record and (record['state'] == STATE_CLAIMED) and all((data[k] == request[k] for k in ('profile', 'owner', 'generation'))) and (type(data['generation']) is int) and (data['container_id'] is None) and (data['reason_code'] == 'arming_claimed') and (data['image'] == runtime.manifest['profiles'][request['profile']]['image']))
    except Exception:
        return False

def ok(**fields: Any) -> dict[str, Any]:
    return {'status': 'ok', 'reason_code': None, **fields}

def refused(reason_code: str, **fields: Any) -> dict[str, Any]:
    return {'status': 'refused', 'reason_code': reason_code, **fields}

def _identity(request: Mapping[str, Any]) -> dict[str, Any]:
    return {key: request[key] for key in ('profile', 'owner', 'generation') if key in request}

def qualification_observation(runtime, connection):
    document = runtime.qualification_reader()
    if document is None:
        return None
    v = document.check(now=runtime.clock(), manifest=runtime.manifest, starting=False).value
    record = read_record(connection)
    qp.c.need(record is not None and same_identity(record, v['profile'], v['owner'], v['generation']), 'qualification_record_identity')
    row = qualification_record(connection, document)
    qp.c.need(record.get('state') == STATE_RUNNING and row is not None and (row['start_intent_at'] is not None), 'qualification_durable_running_launch_required')
    data = (runtime.guard_status_reader or load_runtime_guard_status)()
    proof = runtime.qualification_proof_reader()
    fields = {'schema', 'node', 'guard_pid', 'observed_at', 'state', 'profile', 'owner', 'generation', 'container_id', 'image', 'reason_code'}
    qp.c.need(type(data) is dict and set(data) == fields and (data['schema'] == 'dgx-v4-runtime-guard-v1') and (data['node'] == runtime.manifest['node']), 'qualification_guard_shape')
    qp.c.need(type(proof) is dict and set(proof) == {'schema', 'node', 'guard_pid', 'observed_at', 'permit_sha256'} and (proof['schema'] == 'g7-qualification-guard-proof/v1'), 'qualification_guard_proof_shape')
    qp.c.need(proof['node'] == data['node'] and type(proof['guard_pid']) is int and (proof['guard_pid'] == data['guard_pid']) and (data['guard_pid'] > 1) and (proof['permit_sha256'] == document.sha256), 'qualification_guard_binding')
    now = qp.c.number(runtime.clock())
    stamp = qp.c.number(data['observed_at'])
    proofstamp = qp.c.number(proof['observed_at'])
    qp.c.need(stamp <= proofstamp <= now and now - stamp <= GUARD_MAX_AGE_SECONDS, 'qualification_guard_stale')
    qp.c.need(all((data[k] == v[k] and type(data[k]) is type(v[k]) for k in ('profile', 'owner', 'generation'))) and data['container_id'] == record['container_id'] and (data['image'] == v['image']), 'qualification_guard_record_binding')
    return {'schema': 'g7-qualification-observation/v1', 'run_id': v['run_id'], 'permit_sha256': document.sha256, **{k: v[k] for k in ('profile', 'owner', 'generation')}, 'guard_state': data['state'], 'reason_code': data['reason_code'], 'observed_at': stamp}

def action_probe(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    record = read_record(connection)
    fields = {}
    if record and record.get('profile') in qp.c.PROFILES and (runtime.manifest['profiles'].get(record['profile'], {}).get('launch_enabled') is False):
        try:
            fields['qualification'] = qualification_observation(runtime, connection)
        except Exception:
            fields['qualification'] = {'verified': False, 'reason_code': 'qualification_observation_unknown'}
    return ok(healthy=True, checks={'manifest': True, 'fence': True}, record_state=record['state'] if record else None, memory=memory_observation(runtime.meminfo()), **fields)

def action_preflight(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    record = read_record(connection)
    if not runtime_guard_verified(runtime, request, record):
        return refused('runtime_guard_unverified')
    snapshot = enumerate_gpu(runtime.runner, record=record)
    summary = gpu_summary(snapshot)
    memory = memory_observation(runtime.meminfo())
    if not snapshot.complete:
        return ok(clear=False, gpu=summary, memory=memory, reason_code='enumeration_unknown')
    if snapshot.truncated:
        return ok(clear=False, gpu=summary, memory=memory, reason_code='enumeration_truncated')
    if snapshot.processes:
        return ok(clear=False, gpu=summary, memory=memory, reason_code='unowned_compute_processes')
    if snapshot.containers:
        unowned = [item for item in snapshot.containers if not item.get('mapped')]
        return ok(clear=False, gpu=summary, memory=memory, reason_code='unowned_gpu_work' if unowned else 'owned_gpu_work_running')
    if record is not None and record['state'] != STATE_CLEAR and (not (record['state'] == STATE_CLAIMED and same_identity(record, request['profile'], request['owner'], request['generation']))):
        return ok(clear=False, gpu=summary, memory=memory, record_state=record['state'], reason_code='node_fence_not_clear')
    return ok(clear=True, gpu=summary, memory=memory, reason_code='gpu_clear')

def action_claim(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    now = runtime.clock()
    record = read_record(connection)
    if not runtime_guard_verified(runtime, request, record):
        return refused('runtime_guard_unverified')
    try:
        document = qualification_document(runtime, request, starting=True)
        if document is not None and qualification_record(connection, document) is None:
            v = document.value
            connection.execute('INSERT INTO g7_qualification_runs VALUES(?,?,?,?,?,?,NULL)', (v['run_id'], profile, owner, generation, document.sha256, now))
    except Exception:
        return refused('qualification_claim_refused')
    if record is None:
        snapshot = enumerate_gpu(runtime.runner)
        summary = gpu_summary(snapshot)
        if not snapshot.complete or snapshot.truncated:
            return refused('enumeration_unknown', record_state=None, gpu=summary)
        if not snapshot.gpu_empty:
            return refused('gpu_not_clear', record_state=None, gpu=summary)
        save_record(connection, _new_record(STATE_CLAIMED, profile=profile, owner=owner, generation=generation, now=now))
        return ok(claimed=True, bootstrap=True, record_state=STATE_CLAIMED)
    if record['state'] == STATE_CLEAR:
        save_record(connection, _new_record(STATE_CLAIMED, profile=profile, owner=owner, generation=generation, now=now))
        return ok(claimed=True, replaced_released=True, record_state=STATE_CLAIMED)
    if record['state'] == STATE_CLAIMED and same_identity(record, profile, owner, generation):
        record['updated_at'] = now
        record['note'] = 'idempotent claim'
        save_record(connection, record)
        return ok(claimed=True, idempotent=True, record_state=STATE_CLAIMED)
    return refused('claim_refused', record_state=record['state'], record_profile=record.get('profile'), record_owner=record.get('owner'), record_generation=record.get('generation'))

def action_start(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    node = runtime.manifest['node']
    now = runtime.clock()
    record = read_record(connection)
    if record is None:
        return refused('no_record')
    if not same_identity(record, profile, owner, generation):
        return refused('record_identity_mismatch', record_state=record['state'], record_profile=record.get('profile'), record_owner=record.get('owner'), record_generation=record.get('generation'))
    if record['state'] != STATE_CLAIMED:
        return refused('start_refused_state', record_state=record['state'])
    if runtime.manifest.get('launch_enabled') is not True:
        return refused('launch_disabled', record_state=record['state'])
    plan = runtime.manifest.get('profiles', {}).get(profile)
    if plan is None:
        return refused('plan_missing', record_state=record['state'])
    document = None
    if plan.get('launch_enabled', True) is not True:
        try:
            document = qualification_document(runtime, request, starting=True)
            if document is None:
                raise ValueError('no_qualification_permission')
            row = qualification_record(connection, document)
            qp.c.need(row is not None and row['start_intent_at'] is None, 'qualification_launch_already_attempted')
        except Exception:
            return refused('qualification_launch_refused', record_state=record['state'])
    if node not in plan.get('nodes', []):
        return refused('plan_node_mismatch', record_state=record['state'])
    if not runtime_guard_verified(runtime, request, record):
        return refused('runtime_guard_unverified', record_state=record['state'])
    snapshot = enumerate_gpu(runtime.runner, record=record)
    summary = gpu_summary(snapshot)
    if not snapshot.complete or snapshot.truncated:
        return refused('enumeration_unknown', record_state=record['state'], gpu=summary)
    if not snapshot.gpu_empty:
        return refused('gpu_not_clear', record_state=record['state'], gpu=summary)
    if not runtime_guard_verified(runtime, request, read_record(connection)):
        return refused('runtime_guard_unverified', record_state=record['state'])
    if document is not None:
        try:
            current = qualification_document(runtime, request, starting=True)
            qp.c.need(current.sha256 == document.sha256, 'qualification_permit_changed_before_dispatch')
            count = connection.execute('UPDATE g7_qualification_runs SET start_intent_at=? WHERE run_id=? AND start_intent_at IS NULL', (runtime.clock(), document.value['run_id'])).rowcount
            qp.c.need(count == 1, 'qualification_launch_already_attempted')
        except Exception:
            return refused('qualification_launch_refused', record_state=record['state'])
    argv = docker_run_argv(plan, node=node, profile=profile, owner=owner, generation=generation)
    result = runtime.runner.run(argv)
    if not result.ok:
        found = find_container_by_name(runtime.runner, container_name(profile, generation, node))
        if found:
            record['state'] = STATE_QUARANTINED
            record['container_id'] = found
            record['updated_at'] = now
            record['quarantine_reason'] = 'docker_run_failed_but_container_found'
            save_record(connection, record)
            return refused('start_unconfirmed', container_id=found, record_state=STATE_QUARANTINED)
        return refused('docker_run_failed', record_state=record['state'])
    container_id = result.stdout.strip()
    if not CONTAINER_ID_RE.fullmatch(container_id):
        found = find_container_by_name(runtime.runner, container_name(profile, generation, node))
        if found:
            record['state'] = STATE_QUARANTINED
            record['container_id'] = found
            record['updated_at'] = now
            record['quarantine_reason'] = 'docker_run_output_unparsed_but_container_found'
            save_record(connection, record)
            return refused('start_unconfirmed', container_id=found, record_state=STATE_QUARANTINED)
        return refused('docker_run_unparsed', record_state=record['state'])
    inspected = inspect_own_container(runtime.runner, container_id)
    if inspected.exists is None:
        record['state'] = STATE_QUARANTINED
        record['container_id'] = container_id
        record['updated_at'] = now
        record['quarantine_reason'] = 'start_verification_unknown'
        save_record(connection, record)
        return refused('start_uncertain', container_id=container_id, record_state=STATE_QUARANTINED)
    if inspected.exists is False:
        record['state'] = STATE_QUARANTINED
        record['container_id'] = container_id
        record['updated_at'] = now
        record['quarantine_reason'] = 'container_vanished_after_start'
        save_record(connection, record)
        return refused('start_vanished', container_id=container_id, record_state=STATE_QUARANTINED)
    data = inspected.data or {}
    if not labels_match_identity(data, node=node, profile=profile, owner=owner, generation=generation):
        record['state'] = STATE_QUARANTINED
        record['container_id'] = container_id
        record['updated_at'] = now
        record['quarantine_reason'] = 'label_verification_failed'
        save_record(connection, record)
        return refused('label_verification_failed', container_id=container_id, record_state=STATE_QUARANTINED)
    if data.get('restart_policy') != 'no':
        record['state'] = STATE_QUARANTINED
        record['container_id'] = container_id
        record['updated_at'] = now
        record['quarantine_reason'] = 'restart_policy_invalid'
        save_record(connection, record)
        return refused('restart_policy_invalid', container_id=container_id, record_state=STATE_QUARANTINED)
    if data.get('status') != 'running' or data.get('running') is not True:
        record['state'] = STATE_QUARANTINED
        record['container_id'] = container_id
        record['updated_at'] = now
        record['quarantine_reason'] = 'container_not_running_after_start'
        save_record(connection, record)
        return refused('start_not_running', container_id=container_id, record_state=STATE_QUARANTINED)
    record['state'] = STATE_RUNNING
    record['container_id'] = container_id
    record['updated_at'] = now
    record['quarantine_reason'] = None
    record['note'] = None
    save_record(connection, record)
    return ok(started=True, container_id=container_id, record_state=STATE_RUNNING, launch='launched')

def action_probe_ready(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    node = runtime.manifest['node']
    plan = runtime.manifest.get('profiles', {}).get(profile)
    roles = plan.get('roles') if isinstance(plan, Mapping) else None
    role = roles.get(node) if isinstance(roles, Mapping) else None
    record = read_record(connection)

    def ready_reply(*, healthy: bool, reason: str, record_state: str | None=record['state'] if record else None, api_checked: bool=False, process_verified: bool=False, worker_proof: dict[str, Any] | None=None, **extra: Any) -> dict:
        if healthy and (not runtime_guard_verified(runtime, request, read_record(connection), ready=True)):
            healthy, reason = (False, 'runtime_guard_unverified')
            process_verified, worker_proof = (False, None)
        fields: dict[str, Any] = {'healthy': healthy, 'reason_code': reason, 'record_state': record_state}
        if role is not None:
            fields.update(role=role, api_checked=api_checked)
            if role == ROLE_WORKER:
                fields['process_verified'] = process_verified
                if worker_proof is not None:
                    fields['worker_proof'] = worker_proof
        fields.update(extra)
        return ok(**fields)
    if plan is None:
        return ready_reply(healthy=False, reason='plan_missing')
    if record is None or not same_identity(record, profile, owner, generation):
        return ready_reply(healthy=False, reason='record_mismatch')
    if record['state'] != STATE_RUNNING or not record.get('container_id'):
        return ready_reply(healthy=False, reason='record_state')
    if not runtime_guard_verified(runtime, request, record, ready=True):
        return ready_reply(healthy=False, reason='runtime_guard_unverified')
    inspected = inspect_own_container(runtime.runner, record['container_id'])
    if inspected.exists is None:
        return ready_reply(healthy=False, reason='inspect_uncertain')
    if inspected.exists is False or (inspected.data or {}).get('running') is not True:
        return ready_reply(healthy=False, reason='container_not_running')
    data = inspected.data or {}
    if not labels_match_identity(data, node=node, profile=profile, owner=owner, generation=generation):
        record['state'] = STATE_QUARANTINED
        record['updated_at'] = runtime.clock()
        record['quarantine_reason'] = 'readiness_label_mismatch'
        save_record(connection, record)
        return ready_reply(healthy=False, reason='label_mismatch', record_state=STATE_QUARANTINED)
    if role == ROLE_API_LEADER and (data.get('id') != record['container_id'] or data.get('status') != 'running'):
        return ready_reply(healthy=False, reason='leader_container_unverified')
    if role == ROLE_WORKER:
        container_id = record['container_id']
        if len(container_id) != 64 or data.get('id') != container_id or data.get('status') != 'running':
            return ready_reply(healthy=False, reason='worker_container_unverified')
        actual_image = inspect_container_image(runtime.runner, container_id)
        if actual_image is None:
            return ready_reply(healthy=False, reason='worker_image_unknown')
        if actual_image != plan['image']:
            return ready_reply(healthy=False, reason='worker_image_mismatch')
        snapshot = enumerate_gpu(runtime.runner, record={**record, 'node': node})
        if not snapshot.complete or snapshot.truncated:
            return ready_reply(healthy=False, reason='worker_enumeration_unknown')
        if len(snapshot.containers) != 1 or snapshot.containers[0].get('id') != container_id or snapshot.containers[0].get('mapped') is not True or (snapshot.containers[0].get('status') != 'running'):
            return ready_reply(healthy=False, reason='worker_container_unverified')
        pids = [item.get('pid') for item in snapshot.processes]
        if not pids or len(set(pids)) != len(pids):
            return ready_reply(healthy=False, reason='worker_process_unverified')
        owned_ids = [runtime.process_container_id(pid) for pid in pids]
        if any((container != container_id for container in owned_ids)):
            return ready_reply(healthy=False, reason='worker_process_unverified')
        proof = {'container_id': container_id, 'image': actual_image, 'gpu_process_pids': pids}
        record_reply = {'state': record['state'], 'profile': record['profile'], 'owner': record['owner'], 'generation': record['generation'], 'container_id': container_id}
        return ready_reply(healthy=True, reason='worker_process_verified', process_verified=True, worker_proof=proof, record=record_reply, container={'id': container_id, 'labels_ok': True, 'running': True})
    status_code, body = runtime.api_get(api_url(plan['api']))
    if status_code is None:
        return ready_reply(healthy=False, reason='api_unreachable', api_checked=True)
    if status_code != 200:
        return ready_reply(healthy=False, reason=f'api_http_{int(status_code)}', api_checked=True)
    model_ids = extract_model_ids(body)
    if model_ids is None:
        return ready_reply(healthy=False, reason='api_invalid_response', api_checked=True)
    expected = plan['model_id']
    matched = expected in model_ids
    return ready_reply(healthy=matched, reason='model_serving' if matched else 'api_model_mismatch', api_checked=True, model_id=expected if matched else None, observed_model_ids=[item[:200] for item in model_ids[:8]], record={'state': record['state'], 'profile': record['profile'], 'owner': record['owner'], 'generation': record['generation'], 'container_id': record['container_id']}, container={'id': record['container_id'], 'labels_ok': True, 'running': True}, api_target={'host': plan['api']['host'], 'port': plan['api']['port'], 'path': plan['api']['path']})

def action_stop(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    node = runtime.manifest['node']
    record = read_record(connection)
    if record is None:
        return ok(stop_requested=False, container_id=None, stop_action='none', reason_code='no_record')
    if not same_identity(record, profile, owner, generation):
        return refused('generation_fence_mismatch', record_state=record['state'], record_generation=record.get('generation'))
    connection.execute('UPDATE g7_qualification_runs SET start_intent_at=? WHERE profile=? AND owner=? AND generation=? AND start_intent_at IS NULL', (runtime.clock(), profile, owner, generation))
    if record['state'] in (STATE_CLEAR, STATE_CLAIMED) or not record.get('container_id'):
        return ok(stop_requested=False, container_id=record.get('container_id'), stop_action='none', reason_code='no_container_recorded', record_state=record['state'])
    container_id = record['container_id']
    inspected = inspect_own_container(runtime.runner, container_id)
    if inspected.exists is None:
        return refused('inspect_uncertain', container_id=container_id, record_state=record['state'])
    if inspected.exists is False:
        return ok(stop_requested=False, container_id=container_id, stop_action='none', reason_code='container_absent', record_state=record['state'])
    data = inspected.data or {}
    if not labels_match_identity(data, node=node, profile=profile, owner=owner, generation=generation):
        record['state'] = STATE_QUARANTINED
        record['updated_at'] = runtime.clock()
        record['quarantine_reason'] = 'stop_label_mismatch'
        save_record(connection, record)
        return refused('label_mismatch_refused', container_id=container_id, record_state=STATE_QUARANTINED)
    if not container_is_active(data):
        return ok(stop_requested=False, container_id=container_id, stop_action='none', reason_code='container_already_stopped', record_state=record['state'])
    result = runtime.runner.run(('docker', 'stop', '--time', '10', container_id))
    if not result.ok:
        return refused('docker_stop_failed', container_id=container_id, record_state=record['state'])
    return ok(stop_requested=True, container_id=container_id, stop_action='docker_stop', reason_code='stop_requested', record_state=record['state'])

def action_confirm_stop(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    node = runtime.manifest['node']
    record = read_record(connection)
    identity_matches = same_identity(record, profile, owner, generation)
    if record is not None and (not identity_matches):
        return ok(stopped=False, container_absent=None, record_state=record['state'], reason_code='record_identity_mismatch')
    snapshot = enumerate_gpu(runtime.runner, record=record)
    summary = gpu_summary(snapshot)
    if not snapshot.complete or snapshot.truncated:
        return ok(stopped=False, container_absent=None, record_state=record['state'] if record else None, gpu=summary, reason_code='enumeration_unknown')
    container_absent = True
    if record is not None and record.get('container_id'):
        inspected = inspect_own_container(runtime.runner, record['container_id'])
        if inspected.exists is None:
            return ok(stopped=False, container_absent=None, record_state=record['state'], gpu=summary, reason_code='inspect_uncertain')
        if inspected.exists and container_is_active(inspected.data or {}):
            return ok(stopped=False, container_absent=False, record_state=record['state'], gpu=summary, reason_code='container_still_running')
        if inspected.exists is False:
            container_absent = True
    if snapshot.processes:
        return ok(stopped=False, container_absent=container_absent, record_state=record['state'] if record else None, gpu=summary, reason_code='unowned_compute_processes')
    if snapshot.containers:
        unowned = [item for item in snapshot.containers if not item.get('mapped')]
        return ok(stopped=False, container_absent=container_absent, record_state=record['state'] if record else None, gpu=summary, reason_code='unowned_gpu_work' if unowned else 'owned_gpu_work_running')
    now = runtime.clock()
    if record is None:
        record = _new_record(STATE_CLEAR, profile=profile, owner=owner, generation=generation, now=now)
        record['released_at'] = now
        record['note'] = 'confirmed empty with no prior record'
    else:
        record['state'] = STATE_CLEAR
        record['updated_at'] = now
        record['released_at'] = now
        record['quarantine_reason'] = None
    save_record(connection, record)
    return ok(stopped=True, container_absent=True, record_state=STATE_CLEAR, gpu=summary, reason_code='no_owned_work_observed')

def action_reconcile(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    node = runtime.manifest['node']
    record = read_record(connection)
    snapshot = enumerate_gpu(runtime.runner, record=record)
    summary = gpu_summary(snapshot)
    if record is None:
        return ok(record_state=None, observed='no_record', consistent=None, quarantined=False, gpu=summary)
    observed = 'NO_CONTAINER_RECORDED'
    quarantined = False
    if record.get('container_id'):
        inspected = inspect_own_container(runtime.runner, record['container_id'])
        if inspected.exists is None:
            observed = 'unknown'
        elif inspected.exists is False:
            observed = 'CONTAINER_ABSENT'
            if record['state'] == STATE_RUNNING:
                record['state'] = STATE_QUARANTINED
                record['updated_at'] = runtime.clock()
                record['quarantine_reason'] = 'record_running_but_container_absent'
                save_record(connection, record)
                quarantined = True
        else:
            data = inspected.data or {}
            if not labels_match_identity(data, node=node, profile=profile, owner=owner, generation=generation):
                observed = 'LABEL_MISMATCH'
                record['state'] = STATE_QUARANTINED
                record['updated_at'] = runtime.clock()
                record['quarantine_reason'] = 'reconcile_label_mismatch'
                save_record(connection, record)
                quarantined = True
            elif container_is_active(data):
                observed = 'RUNNING'
            else:
                observed = 'STOPPED_CONTAINER'
    consistent = (record['state'] == STATE_RUNNING) == (observed == 'RUNNING')
    return ok(record_state=record['state'], observed=observed, consistent=bool(consistent), quarantined=bool(quarantined), gpu=summary)

def action_release(request: Mapping[str, Any], runtime: Runtime, connection: sqlite3.Connection) -> dict:
    profile = request['profile']
    owner = request['owner']
    generation = request['generation']
    record = read_record(connection)
    if record is None:
        return refused('no_record')
    if not same_identity(record, profile, owner, generation):
        return refused('generation_fence_mismatch', record_state=record['state'], record_generation=record.get('generation'))
    snapshot = enumerate_gpu(runtime.runner, record=record)
    summary = gpu_summary(snapshot)
    if not snapshot.complete or snapshot.truncated:
        return refused('enumeration_unknown', record_state=record['state'], gpu=summary)
    if record.get('container_id'):
        inspected = inspect_own_container(runtime.runner, record['container_id'])
        if inspected.exists is None:
            return refused('inspect_uncertain', record_state=record['state'], gpu=summary)
        if inspected.exists and container_is_active(inspected.data or {}):
            return refused('container_still_running', record_state=record['state'], gpu=summary)
    if not snapshot.gpu_empty:
        return refused('gpu_not_empty', record_state=record['state'], gpu=summary)
    now = runtime.clock()
    record['state'] = STATE_CLEAR
    record['updated_at'] = now
    record['released_at'] = now
    record['quarantine_reason'] = None
    save_record(connection, record)
    return ok(released=True, record_state=STATE_CLEAR, reason_code='released')
ACTION_TABLE: dict[str, Callable[[Mapping[str, Any], Runtime, sqlite3.Connection], dict]] = {'probe': action_probe, 'preflight': action_preflight, 'claim': action_claim, 'start': action_start, 'probe_ready': action_probe_ready, 'stop': action_stop, 'confirm_stop': action_confirm_stop, 'reconcile': action_reconcile, 'release': action_release}
ACTION_EXTRAS: dict[str, tuple[str, ...]] = {'probe': (), 'preflight': ('profile', 'owner', 'generation'), 'claim': ('profile', 'owner', 'generation'), 'start': ('profile', 'owner', 'generation'), 'probe_ready': ('profile', 'owner', 'generation'), 'stop': ('profile', 'owner', 'generation'), 'confirm_stop': ('profile', 'owner', 'generation'), 'reconcile': ('profile', 'owner', 'generation'), 'release': ('profile', 'owner', 'generation')}

class RequestRefusal(Exception):

    def __init__(self, reason_code: str, detail: str=''):
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail

def validate_request(value: Any, *, expected_node: str) -> dict:
    """Strict per-action request schema. Unknown fields are refused by name."""
    if not isinstance(value, dict):
        raise RequestRefusal('invalid_request', 'request must be an object')
    action = value.get('action')
    if not isinstance(action, str) or action not in WIRE_ACTIONS:
        raise RequestRefusal('unknown_action', 'action must be one of the explicit wire actions')
    allowed = {'schema', 'request_id', 'action', 'node', *ACTION_EXTRAS[action]}
    unknown = sorted((str(key) for key in value if key not in allowed))
    if unknown:
        raise RequestRefusal('unknown_field', f"unknown fields for {action}: {', '.join(unknown)}")
    if value.get('schema') != SCHEMA:
        raise RequestRefusal('bad_schema', 'schema must be dgx-v4-node-v1')
    request_id = value.get('request_id')
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise RequestRefusal('bad_request_id', 'request_id must be lowercase hex')
    node = value.get('node')
    if not isinstance(node, str) or not TOKEN_RE.fullmatch(node):
        raise RequestRefusal('bad_node', 'node must be a plain token')
    if node != expected_node:
        raise RequestRefusal('node_mismatch', 'request node does not match this manifest')
    try:
        if 'profile' in ACTION_EXTRAS[action]:
            require_token(value.get('profile'), 'profile')
            require_token(value.get('owner'), 'owner')
            require_generation(value.get('generation'))
    except ProtocolError as exc:
        raise RequestRefusal(exc.reason_code, str(exc)) from exc
    return value
RESERVED_ENVELOPE_KEYS = frozenset({'schema', 'request_id', 'action', 'node', 'observed_at', 'profile', 'owner', 'generation'})

def dispatch(request: Mapping[str, Any], runtime: Runtime) -> dict:
    """Execute one validated request under the node fence; always returns a reply."""
    action = request['action']
    try:
        with runtime.fence.locked() as connection:
            fields = ACTION_TABLE[action](request, runtime, connection)
    except FenceBusy:
        fields = refused('fence_busy')
    except FenceUnavailable as exc:
        fields = refused('fence_unavailable', detail=str(exc)[:120])
    except Exception:
        fields = refused('internal_error')
    if not isinstance(fields, dict) or RESERVED_ENVELOPE_KEYS & set(fields):
        fields = refused('internal_error')
    reply: dict[str, Any] = {'schema': SCHEMA, 'request_id': request.get('request_id'), 'action': action, 'node': request.get('node'), 'observed_at': runtime.clock()}
    reply.update(_identity(request))
    reply.update(fields)
    return reply

def _emit(out: Any, reply: Mapping[str, Any]) -> None:
    try:
        payload = json.dumps(reply, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        payload = json.dumps({'schema': SCHEMA, 'status': 'refused', 'reason_code': 'internal_error', 'observed_at': 0.0}, sort_keys=True, separators=(',', ':'))
    if len(payload.encode('utf-8')) > MAX_REPLY_BYTES:
        payload = json.dumps({'schema': SCHEMA, 'status': 'refused', 'reason_code': 'reply_too_large', 'observed_at': 0.0}, sort_keys=True, separators=(',', ':'))
    out.write(payload + '\n')
    with contextlib.suppress(Exception):
        out.flush()

def _diagnostic_reply(request: Any, reason_code: str, *, detail: str='') -> dict:
    reply: dict[str, Any] = {'schema': SCHEMA, 'request_id': None, 'action': None, 'node': None, 'status': 'refused', 'reason_code': reason_code, 'observed_at': time.time()}
    if isinstance(request, dict):
        for key in ('request_id', 'action', 'node', 'profile', 'owner', 'generation'):
            value = request.get(key)
            if isinstance(value, (str, int)) and (not isinstance(value, bool)):
                reply[key] = value
    if detail:
        reply['detail'] = detail[:120]
    return reply

def main(argv: Sequence[str] | None=None, *, stdin: Any=None, stdout: Any=None, stderr: Any=None, environ: Mapping[str, str] | None=None, manifest_path: str | Path=DEFAULT_MANIFEST_PATH, binaries: Mapping[str, str] | None=None, require_root_owner: bool=True, runner: CommandRunner | None=None, api_get: Callable[[str], tuple[int | None, bytes]] | None=None, clock: Callable[[], float]=time.time) -> int:
    """Forced-command entrypoint. Returns the process exit code.

    A JSON reply is emitted for every protocol-level outcome (exit 0). Only a
    wrong ``SSH_ORIGINAL_COMMAND`` (exit 4) and an unreadable stdin (exit 3)
    produce no reply.
    """
    del argv
    env = os.environ if environ is None else environ
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    if env.get('SSH_ORIGINAL_COMMAND') != SSH_COMMAND:
        err.write(f'{SSH_COMMAND}: refusing: SSH_ORIGINAL_COMMAND mismatch\n')
        return 4
    source = getattr(stdin, 'buffer', stdin)
    if source is None:
        source = sys.stdin.buffer
    try:
        raw = source.read(MAX_REQUEST_BYTES + 1)
    except Exception:
        err.write(f'{SSH_COMMAND}: refusing: stdin unreadable\n')
        return 3
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='replace')
    if len(raw) > MAX_REQUEST_BYTES:
        _emit(out, _diagnostic_reply(None, 'request_too_large'))
        err.write(f'{SSH_COMMAND}: refused: request_too_large\n')
        return 0
    try:
        request = strict_json_loads(raw, max_bytes=MAX_REQUEST_BYTES)
    except ProtocolError as exc:
        _emit(out, _diagnostic_reply(None, f'invalid_request:{exc.reason_code}'))
        err.write(f'{SSH_COMMAND}: refused: invalid_request:{exc.reason_code}\n')
        return 0
    try:
        manifest = load_manifest(manifest_path, require_root_owner=require_root_owner)
    except ManifestError as exc:
        _emit(out, _diagnostic_reply(request, str(exc.reason_code)))
        err.write(f'{SSH_COMMAND}: refused: {exc.reason_code}\n')
        return 0
    try:
        validated = validate_request(request, expected_node=manifest['node'])
    except RequestRefusal as exc:
        _emit(out, _diagnostic_reply(request, exc.reason_code, detail=exc.detail))
        err.write(f'{SSH_COMMAND}: refused: {exc.reason_code}\n')
        return 0
    runtime = Runtime(manifest=manifest, fence=Fence(manifest['state_db'], manifest['lock_file'], clock=clock), runner=runner if runner is not None else CommandRunner(binaries or DEFAULT_BINARIES), clock=clock, api_get=api_get if api_get is not None else default_api_get)
    reply = dispatch(validated, runtime)
    _emit(out, reply)
    return 0
if __name__ == '__main__':
    sys.exit(main())
