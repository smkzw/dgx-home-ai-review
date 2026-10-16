# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Node-local, fenced Runtime Observer integration. This module never owns starts or leases."""
from __future__ import annotations
import argparse
import contextlib
import fcntl
import importlib.util
import json
import math
import os
import re
import secrets
import signal
import stat
import sys
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path('/etc/dgx-v4/node-runtime-guard-policy.json')
STATE_DIR = Path('/var/lib/dgx-v4/node-runtime-guard')
MAX_POLICY_BYTES = 65536
MAX_STATE_BYTES = 32768
MAX_TOP_PIDS = 4096
MAX_CGROUP_BYTES = 65536
MAX_STARTUP_GRACE_S = 600.0
MAX_SAMPLE_INTERVAL_S = 10.0
REQUIRED_SAMPLE_INTERVAL_S = 2.0
MAX_ACTIVE_STEP_SECONDS = 3.0
MAX_RUNTIME_AGE_S = 86400.0
MAX_MEMORY_GIB = 1048576.0
POLICY_SCHEMA = 'dgx-v4-runtime-guard-policy-v1'
STATE_SCHEMA = 'dgx-v4-runtime-guard-state-v1'
STATUS_SCHEMA = 'dgx-v4-runtime-guard-v1'
STATUS_STATES = frozenset({'IDLE_HOLD_RETAINED', 'ARMING_HOLD_RETAINED', 'ACTIVE', 'QUARANTINED_HOLD_RETAINED', 'STOPPED_HOLD_RETAINED'})
_REASON_CODES = frozenset({'active', 'active_warning', 'idle_no_record', 'idle_db_clear', 'arming_claimed', 'arming_startup', 'arming_startup_grace', 'observe_failed', 'invalid_observation', 'identity_mismatch', 'ownership_unproven', 'runtime_state_unknown', 'runtime_state_changed', 'memory_unknown', 'clock_failed', 'sample_not_fresh', 'sample_not_monotonic', 'container_exited_without_clearance', 'warning_threshold_entered', 'warning_threshold_cleared', 'emergency_memory', 'sustained_low_memory', 'fenced_stop_failed', 'stop_refused', 'stop_ack_identity_mismatch', 'fenced_stop_acknowledged_hold_retained', 'cancelled', 'cancellation_check_failed', 'cancellation_check_unknown', 'wait_failed', 'guard_disabled', 'guard_stopped', 'guard_restarted_unresolved', 'startup_grace_expired', 'db_quarantined', 'record_unknown', 'record_malformed', 'record_not_running', 'container_absent', 'container_inspect_unknown', 'container_identity_mismatch', 'container_labels_mismatch', 'container_image_mismatch', 'container_restart_policy', 'container_restarted', 'container_paused', 'container_pid_unknown', 'docker_top_unknown', 'gpu_enumeration_unknown', 'gpu_process_foreign', 'gpu_container_foreign', 'gpu_ownership_unknown', 'meminfo_unknown', 'identity_changed_without_clear', 'terminal_identity_retained', 'clear_not_proven', 'state_corrupt', 'status_write_failed', 'guard_error', 'stop_revalidation_failed', 'stop_memory_recovered', 'stop_action_refused', 'guard_stop_initiated', 'fence_contention_expired', 'fence_unavailable', 'active_step_overrun'})
_TOKEN = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\Z')
_CID = re.compile('[0-9a-f]{64}\\Z')
_IMAGE = re.compile('sha256:[0-9a-f]{64}\\Z')
_SHA256_REF = re.compile('[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}\\Z')

def _load_frozen_module(alias: str, path: Path):
    """Load only the two explicitly frozen source modules without package side effects."""
    existing = sys.modules.get(alias)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(alias, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load frozen module {path.name}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(alias, None)
        raise
    return module
node = _load_frozen_module('dgx_v4_frozen_node_wrapper', ROOT / 'runtime/node_adapter/node_wrapper.py')
observer = _load_frozen_module('dgx_v4_frozen_runtime_observer', ROOT / 'runtime/runtime_observer/observer.py')
LOCK_CONTENTION_GRACE_SECONDS = 5 * node.CMD_TIMEOUT_SECONDS + 5.0
LOCK_RETRY_SECONDS = 0.1
LOCK_BUSY_ATTEMPTS = math.ceil(LOCK_CONTENTION_GRACE_SECONDS / node.FENCE_LOCK_WAIT_SECONDS)

class GuardConfigError(ValueError):
    pass

class GuardStoreError(RuntimeError):
    pass

class EvidenceFailure(RuntimeError):

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code if reason_code in _REASON_CODES else 'guard_error'

@dataclass(frozen=True, slots=True)
class ProfileConfig:
    enabled: bool
    image_config_id: str
    runtime_policy: Any

@dataclass(frozen=True, slots=True)
class GuardPolicy:
    enabled: bool
    sample_interval_s: float
    startup_grace_seconds: float
    profiles: Mapping[str, ProfileConfig]

@dataclass(frozen=True, slots=True)
class Evidence:
    observation: Any | None
    available_gib: float
    observed_at: float
    sequence: int
    empty_gpu_processes: bool

class GuardProcessLock:
    """Single-process lock; independent of the NodeWrapper resource Fence."""

    def __init__(self, path: Path, *, owner_uid: int=0):
        self.path = Path(path)
        self.owner_uid = owner_uid
        self.fd: int | None = None

    def acquire(self) -> None:
        _check_directory(self.path.parent, self.owner_uid)
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 384)
        except OSError as exc:
            raise GuardStoreError('guard_lock_unavailable') from exc
        try:
            _check_open_file(fd, self.path, self.owner_uid, exact_mode=384)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise GuardStoreError('guard_already_running') from exc
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        if self.fd is None:
            return
        with contextlib.suppress(OSError):
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)
        self.fd = None

def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise GuardStoreError('file_write_failed')
        view = view[written:]

class StateStore:
    """Fixed-path atomic state/status writer and allowlisted append-only event sink."""

    def __init__(self, directory: Path, *, owner_uid: int=0):
        self.directory = Path(directory)
        self.owner_uid = owner_uid
        self.state_path = self.directory / 'guard-state.json'
        self.status_path = self.directory / 'status.json'
        self.events_path = self.directory / 'events.jsonl'
        self.lock_path = self.directory / 'guard.lock'

    def validate_directory(self) -> None:
        _check_directory(self.directory, self.owner_uid)
        for path in (self.state_path, self.status_path, self.events_path, self.lock_path):
            _check_existing_file(path, self.owner_uid, exact_mode=384, missing_ok=True)

    def load_state(self) -> dict[str, Any]:
        self.validate_directory()
        if not self.state_path.exists() and (not self.state_path.is_symlink()):
            return _initial_state()
        value = _read_json_file(self.state_path, owner_uid=self.owner_uid, max_bytes=MAX_STATE_BYTES, exact_mode=384)
        return _validate_state(value)

    def save_state(self, state: Mapping[str, Any]) -> None:
        clean = _validate_state(dict(state))
        self._write_atomic(self.state_path, clean, MAX_STATE_BYTES)

    def write_status(self, payload: Mapping[str, Any]) -> None:
        clean = _validate_status(dict(payload))
        self._write_atomic(self.status_path, clean, 8192)

    def append_event(self, event: Mapping[str, Any]) -> None:
        clean = _validate_event(dict(event))
        raw = (json.dumps(clean, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
        if len(raw) > 4096:
            raise GuardStoreError('event_oversize')
        _check_existing_file(self.events_path, self.owner_uid, exact_mode=384, missing_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(self.events_path, flags, 384)
        except OSError as exc:
            raise GuardStoreError('event_write_failed') from exc
        try:
            _check_open_file(fd, self.events_path, self.owner_uid, exact_mode=384)
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write_atomic(self, path: Path, value: Mapping[str, Any], max_bytes: int) -> None:
        _check_directory(self.directory, self.owner_uid)
        _check_existing_file(path, self.owner_uid, exact_mode=384, missing_ok=True)
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
        if len(raw) > max_bytes:
            raise GuardStoreError('state_oversize')
        tmp = self.directory / f'.{path.name}.tmp'
        _check_existing_file(tmp, self.owner_uid, exact_mode=384, missing_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(tmp, flags, 384)
        except OSError as exc:
            raise GuardStoreError('atomic_temp_unavailable') from exc
        try:
            os.fchmod(fd, 384)
            _check_open_file(fd, tmp, self.owner_uid, exact_mode=384)
            _write_all(fd, raw)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        else:
            os.close(fd)
        try:
            os.replace(tmp, path)
            dir_fd = os.open(self.directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise GuardStoreError('atomic_rename_failed') from exc

def _check_directory(path: Path, owner_uid: int) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise GuardStoreError('state_directory_unavailable') from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise GuardStoreError('state_directory_not_regular')
    if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) & 63:
        raise GuardStoreError('state_directory_permissions')

def _check_existing_file(path: Path, owner_uid: int, *, exact_mode: int, missing_ok: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return
        raise GuardStoreError('required_file_missing')
    except OSError as exc:
        raise GuardStoreError('state_file_unavailable') from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GuardStoreError('state_file_not_regular')
    if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != exact_mode:
        raise GuardStoreError('state_file_permissions')

def _check_open_file(fd: int, path: Path, owner_uid: int, *, exact_mode: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) != exact_mode:
        raise GuardStoreError('state_file_permissions')
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise GuardStoreError('state_file_unavailable') from exc
    if stat.S_ISLNK(named.st_mode) or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
        raise GuardStoreError('state_file_replaced')

def _read_json_file(path: Path, *, owner_uid: int, max_bytes: int, exact_mode: int | None=None) -> Any:
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise GuardStoreError('state_file_unavailable') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid:
            raise GuardStoreError('state_file_permissions')
        if exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode:
            raise GuardStoreError('state_file_permissions')
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            piece = os.read(fd, min(remaining, 8192))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        raw = b''.join(chunks)
        if len(raw) > max_bytes:
            raise GuardStoreError('state_file_oversize')
    finally:
        os.close(fd)
    try:
        return node.strict_json_loads(raw, max_bytes=max_bytes)
    except Exception as exc:
        raise GuardStoreError('state_json_invalid') from exc

def _read_policy(path: Path, *, owner_uid: int, manifest: Mapping[str, Any]) -> GuardPolicy:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise GuardConfigError('policy_missing') from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise GuardConfigError('policy_not_regular')
    if info.st_uid != owner_uid or info.st_mode & 18:
        raise GuardConfigError('policy_permissions')
    try:
        raw = _read_json_file(path, owner_uid=owner_uid, max_bytes=MAX_POLICY_BYTES)
    except GuardStoreError as exc:
        raise GuardConfigError('policy_invalid') from exc
    return parse_policy(raw, manifest)

def _finite_bounded(value: Any, name: str, *, minimum: float, maximum: float) -> float:
    if type(value) not in (int, float):
        raise GuardConfigError(f'{name}_invalid')
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise GuardConfigError(f'{name}_invalid') from None
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise GuardConfigError(f'{name}_invalid')
    return number

def parse_policy(value: Any, manifest: Mapping[str, Any]) -> GuardPolicy:
    """Strictly parse the bounded policy object against every trusted manifest profile."""
    if not isinstance(value, dict) or set(value) != {'schema', 'enabled', 'sample_interval_s', 'startup_grace_seconds', 'profiles'}:
        raise GuardConfigError('policy_shape')
    if value.get('schema') != POLICY_SCHEMA or type(value.get('enabled')) is not bool:
        raise GuardConfigError('policy_schema_or_enabled')
    interval = _finite_bounded(value.get('sample_interval_s'), 'sample_interval_s', minimum=0.1, maximum=MAX_SAMPLE_INTERVAL_S)
    required_guard = manifest.get('runtime_guard_required', False)
    if type(required_guard) is not bool:
        raise GuardConfigError('manifest_guard_flag_invalid')
    if required_guard and (not value['enabled']):
        raise GuardConfigError('required_guard_disabled')
    if required_guard and interval != REQUIRED_SAMPLE_INTERVAL_S:
        raise GuardConfigError('required_guard_sample_interval')
    grace = _finite_bounded(value.get('startup_grace_seconds'), 'startup_grace_seconds', minimum=0.1, maximum=MAX_STARTUP_GRACE_S)
    raw_profiles = value.get('profiles')
    trusted = manifest.get('profiles')
    if not isinstance(raw_profiles, dict) or not isinstance(trusted, dict) or set(raw_profiles) != set(trusted):
        raise GuardConfigError('policy_profiles_mismatch')
    profiles: dict[str, ProfileConfig] = {}
    for name, raw in raw_profiles.items():
        if not isinstance(name, str) or not _TOKEN.fullmatch(name) or (not isinstance(raw, dict)):
            raise GuardConfigError('policy_profile_shape')
        required = {'enabled', 'image_config_id', 'warning_gib', 'sustained_floor_gib', 'emergency_gib', 'sustained_count', 'max_age_s'}
        if set(raw) != required or type(raw.get('enabled')) is not bool:
            raise GuardConfigError('policy_profile_fields')
        image = raw.get('image_config_id')
        if not isinstance(image, str) or not _IMAGE.fullmatch(image):
            raise GuardConfigError('policy_image_config_id')
        plan_image = trusted[name].get('image') if isinstance(trusted[name], dict) else None
        if not isinstance(plan_image, str) or not (_IMAGE.fullmatch(plan_image) or _SHA256_REF.fullmatch(plan_image)):
            raise GuardConfigError('manifest_image_not_immutable')
        local_image = _IMAGE.fullmatch(plan_image) is not None
        if local_image and image != plan_image:
            raise GuardConfigError('policy_image_config_mismatch')
        if required_guard and (not local_image):
            raise GuardConfigError('required_guard_image_not_local')
        warning = _finite_bounded(raw.get('warning_gib'), 'warning_gib', minimum=1e-06, maximum=MAX_MEMORY_GIB)
        floor = _finite_bounded(raw.get('sustained_floor_gib'), 'sustained_floor_gib', minimum=1e-06, maximum=MAX_MEMORY_GIB)
        emergency = _finite_bounded(raw.get('emergency_gib'), 'emergency_gib', minimum=1e-06, maximum=MAX_MEMORY_GIB)
        max_age = _finite_bounded(raw.get('max_age_s'), 'max_age_s', minimum=0.1, maximum=MAX_RUNTIME_AGE_S)
        count = raw.get('sustained_count')
        if type(count) is not int or count < 1 or count > 1000:
            raise GuardConfigError('sustained_count_invalid')
        try:
            runtime_policy = observer.RuntimePolicy(warning_gib=warning, sustained_floor_gib=floor, emergency_gib=emergency, sustained_count=count, max_age_s=max_age)
        except (TypeError, ValueError, OverflowError) as exc:
            raise GuardConfigError('runtime_policy_invalid') from exc
        profiles[name] = ProfileConfig(raw['enabled'], image, runtime_policy)
    if value['enabled'] and any((not profile.enabled for profile in profiles.values())):
        raise GuardConfigError('enabled_policy_has_disabled_profile')
    return GuardPolicy(value['enabled'], interval, grace, profiles)

def _initial_state() -> dict[str, Any]:
    return {'schema': STATE_SCHEMA, 'phase': 'IDLE_HOLD_RETAINED', 'tracked': None, 'last_record': None, 'clear_authorized': False, 'retained_unknown': False, 'ever_tracked': False, 'terminal': None, 'session_id': None, 'arming_started_at': None, 'sequence': 0, 'last_sample_at': None}

def _validate_state(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(_initial_state()):
        raise GuardStoreError('state_corrupt')
    if value.get('schema') != STATE_SCHEMA or value.get('phase') not in STATUS_STATES:
        raise GuardStoreError('state_corrupt')
    if any((type(value.get(key)) is not bool for key in ('clear_authorized', 'ever_tracked', 'retained_unknown'))):
        raise GuardStoreError('state_corrupt')
    if type(value.get('sequence')) is not int or value['sequence'] < 0:
        raise GuardStoreError('state_corrupt')
    for key in ('arming_started_at', 'last_sample_at'):
        item = value.get(key)
        if item is not None:
            try:
                minimum = 0.0 if key == 'arming_started_at' else 0.0
                valid = type(item) in (int, float) and math.isfinite(float(item)) and (float(item) >= minimum)
            except OverflowError:
                valid = False
            if not valid:
                raise GuardStoreError('state_corrupt')
    session = value.get('session_id')
    if session is not None and (not isinstance(session, str) or not re.fullmatch('[0-9a-f]{32}', session)):
        raise GuardStoreError('state_corrupt')
    tracked = value.get('tracked')
    if tracked is not None:
        if not isinstance(tracked, dict) or set(tracked) != {'node', 'profile', 'owner', 'generation', 'container_id', 'image'}:
            raise GuardStoreError('state_corrupt')
        if not all((_safe_token(tracked.get(key)) for key in ('node', 'profile', 'owner'))):
            raise GuardStoreError('state_corrupt')
        if type(tracked.get('generation')) is not int or tracked['generation'] <= 0:
            raise GuardStoreError('state_corrupt')
        if tracked.get('container_id') is not None and (not isinstance(tracked['container_id'], str) or not _CID.fullmatch(tracked['container_id'])):
            raise GuardStoreError('state_corrupt')
        if tracked.get('image') is not None and (not isinstance(tracked['image'], str) or not _IMAGE.fullmatch(tracked['image'])):
            raise GuardStoreError('state_corrupt')
    last_record = value.get('last_record')
    if last_record is not None:
        if not isinstance(last_record, dict) or set(last_record) != {'state', 'profile', 'owner', 'generation', 'container_id', 'updated_at', 'released_at'} or last_record.get('state') not in {node.STATE_CLEAR, node.STATE_CLAIMED, node.STATE_RUNNING, node.STATE_QUARANTINED}:
            raise GuardStoreError('state_corrupt')
        if last_record.get('profile') is not None and (not _safe_token(last_record['profile'])):
            raise GuardStoreError('state_corrupt')
        if last_record.get('owner') is not None and (not _safe_token(last_record['owner'])):
            raise GuardStoreError('state_corrupt')
        generation = last_record.get('generation')
        if generation is not None and (type(generation) is not int or generation <= 0):
            raise GuardStoreError('state_corrupt')
        cid = last_record.get('container_id')
        if cid is not None and (not isinstance(cid, str) or not _CID.fullmatch(cid)):
            raise GuardStoreError('state_corrupt')
        for key in ('updated_at', 'released_at'):
            item = last_record.get(key)
            if item is not None and (not _finite_timestamp(item)):
                raise GuardStoreError('state_corrupt')
    terminal = value.get('terminal')
    if terminal is not None:
        if not isinstance(terminal, dict) or set(terminal) != {'node', 'profile', 'owner', 'generation', 'container_id', 'image', 'reason_code'}:
            raise GuardStoreError('state_corrupt')
        if not all((_safe_token(terminal.get(key)) for key in ('node', 'profile', 'owner'))):
            raise GuardStoreError('state_corrupt')
        if type(terminal.get('generation')) is not int or terminal['generation'] <= 0:
            raise GuardStoreError('state_corrupt')
        cid, image = (terminal.get('container_id'), terminal.get('image'))
        if cid is not None and (not isinstance(cid, str) or not _CID.fullmatch(cid)):
            raise GuardStoreError('state_corrupt')
        if image is not None and (not isinstance(image, str) or not _IMAGE.fullmatch(image)):
            raise GuardStoreError('state_corrupt')
        if terminal.get('reason_code') not in _REASON_CODES:
            raise GuardStoreError('state_corrupt')
    return dict(value)

def _status_payload(*, node_name: str, guard_pid: int, observed_at: float, state: str, profile: str | None, owner: str | None, generation: int | None, container_id: str | None, image: str | None, reason_code: str) -> dict[str, Any]:
    return {'schema': STATUS_SCHEMA, 'node': node_name, 'guard_pid': guard_pid, 'observed_at': observed_at, 'state': state, 'profile': profile, 'owner': owner, 'generation': generation, 'container_id': container_id, 'image': image, 'reason_code': reason_code}

def _validate_status(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {'schema', 'node', 'guard_pid', 'observed_at', 'state', 'profile', 'owner', 'generation', 'container_id', 'image', 'reason_code'}
    if set(value) != allowed or value.get('schema') != STATUS_SCHEMA:
        raise GuardStoreError('status_shape')
    if not isinstance(value.get('node'), str) or not _TOKEN.fullmatch(value['node']):
        raise GuardStoreError('status_invalid')
    if type(value.get('guard_pid')) is not int or value['guard_pid'] <= 0:
        raise GuardStoreError('status_invalid')
    if type(value.get('observed_at')) not in (int, float) or not math.isfinite(float(value['observed_at'])):
        raise GuardStoreError('status_invalid')
    if value.get('state') not in STATUS_STATES or value.get('reason_code') not in _REASON_CODES:
        raise GuardStoreError('status_invalid')
    for key in ('profile', 'owner'):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or not _TOKEN.fullmatch(item)):
            raise GuardStoreError('status_invalid')
    gen = value.get('generation')
    if gen is not None and (type(gen) is not int or gen <= 0):
        raise GuardStoreError('status_invalid')
    cid, image = (value.get('container_id'), value.get('image'))
    if cid is not None and (not isinstance(cid, str) or not _CID.fullmatch(cid)):
        raise GuardStoreError('status_invalid')
    if image is not None and (not isinstance(image, str) or not _IMAGE.fullmatch(image)):
        raise GuardStoreError('status_invalid')
    return value

def _validate_event(value: dict[str, Any]) -> dict[str, Any]:
    allowed = {'event', 'state', 'reason', 'node', 'profile', 'owner', 'generation', 'container_id', 'image', 'sequence', 'available_gib', 'observed_at'}
    if set(value) != allowed:
        raise GuardStoreError('event_shape')
    if value.get('event') not in {'warning', 'terminal', 'guard_state'}:
        raise GuardStoreError('event_invalid')
    if value.get('state') not in STATUS_STATES and value.get('state') not in {'ACTIVE', 'EXITED_HOLD_RETAINED', 'STOPPED_ACKNOWLEDGED_HOLD_RETAINED', 'QUARANTINED_HOLD_RETAINED', 'CANCELLED_OBSERVER_ONLY'}:
        raise GuardStoreError('event_invalid')
    if value.get('reason') not in _REASON_CODES:
        raise GuardStoreError('event_invalid')
    if not isinstance(value.get('node'), str) or not _TOKEN.fullmatch(value['node']):
        raise GuardStoreError('event_invalid')
    for key in ('profile', 'owner'):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or not _TOKEN.fullmatch(item)):
            raise GuardStoreError('event_invalid')
    gen = value.get('generation')
    if gen is not None and (type(gen) is not int or gen <= 0):
        raise GuardStoreError('event_invalid')
    for key, validator in (('container_id', _CID), ('image', _IMAGE)):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or not validator.fullmatch(item)):
            raise GuardStoreError('event_invalid')
    seq = value.get('sequence')
    if seq is not None and (type(seq) is not int or seq <= 0):
        raise GuardStoreError('event_invalid')
    for key in ('available_gib', 'observed_at'):
        item = value.get(key)
        if item is not None and (type(item) not in (int, float) or not math.isfinite(float(item))):
            raise GuardStoreError('event_invalid')
    return value

def _safe_token(value: Any) -> bool:
    return isinstance(value, str) and bool(_TOKEN.fullmatch(value))

def _record_snapshot(record: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return {key: record.get(key) for key in ('state', 'profile', 'owner', 'generation', 'container_id', 'updated_at', 'released_at')}

def _record_key(record: Mapping[str, Any] | None, node_name: str, image: str | None=None) -> dict[str, Any] | None:
    if record is None:
        return None
    profile, owner, generation, cid = (record.get('profile'), record.get('owner'), record.get('generation'), record.get('container_id'))
    if not _safe_token(profile) or not _safe_token(owner) or type(generation) is not int or (generation <= 0):
        return None
    if cid is not None and (not isinstance(cid, str) or not _CID.fullmatch(cid)):
        return None
    return {'node': node_name, 'profile': profile, 'owner': owner, 'generation': generation, 'container_id': cid, 'image': image}

def _same_key(left: Mapping[str, Any] | None, right: Mapping[str, Any] | None, *, allow_missing_cid: bool=False) -> bool:
    if left is None or right is None:
        return False
    base = all((left.get(key) == right.get(key) for key in ('node', 'profile', 'owner', 'generation')))
    if not base:
        return False
    if allow_missing_cid and left.get('container_id') is None:
        return True
    return left.get('container_id') == right.get('container_id')

def _record_exact(record: Mapping[str, Any] | None, identity: Any) -> bool:
    return bool(record is not None and record.get('profile') == identity.profile and (record.get('owner') == identity.owner) and (record.get('generation') == identity.generation) and (record.get('container_id') == identity.container_id))

def _pid_tuple(text: str) -> tuple[int, ...]:
    rows = [line.strip() for line in text.splitlines() if line.strip()]
    if not rows or rows[0].upper() != 'PID' or len(rows) - 1 > MAX_TOP_PIDS:
        raise EvidenceFailure('docker_top_unknown')
    pids: list[int] = []
    seen: set[int] = set()
    for row in rows[1:]:
        if not re.fullmatch('[0-9]+', row):
            raise EvidenceFailure('docker_top_unknown')
        pid = int(row)
        if pid <= 0 or pid in seen:
            raise EvidenceFailure('docker_top_unknown')
        seen.add(pid)
        pids.append(pid)
    if not pids:
        raise EvidenceFailure('docker_top_unknown')
    return tuple(sorted(pids))

def _read_proc_meminfo(runner: Any) -> float:
    result = runner.run(('cat', '/proc/meminfo'))
    if not result.ok:
        raise EvidenceFailure('meminfo_unknown')
    total: list[int] = []
    available: list[int] = []
    for line in result.stdout.splitlines():
        key, sep, tail = line.partition(':')
        if not sep or key not in {'MemTotal', 'MemAvailable'}:
            continue
        fields = tail.split()
        if len(fields) != 2 or fields[1] != 'kB' or (not fields[0].isdigit()):
            raise EvidenceFailure('meminfo_unknown')
        number = int(fields[0])
        (total if key == 'MemTotal' else available).append(number)
    if len(total) != 1 or len(available) != 1 or total[0] <= 0 or (available[0] <= 0) or (available[0] > total[0]):
        raise EvidenceFailure('meminfo_unknown')
    gib = available[0] * 1024 / 1024 ** 3
    if not math.isfinite(gib) or gib <= 0:
        raise EvidenceFailure('meminfo_unknown')
    return gib

def _read_cgroup_container(runner: Any, pid: int) -> str:
    if type(pid) is not int or pid <= 0:
        raise EvidenceFailure('gpu_ownership_unknown')
    result = runner.run(('cat', f'/proc/{pid}/cgroup'))
    if not result.ok or len(result.stdout.encode('utf-8')) > MAX_CGROUP_BYTES:
        raise EvidenceFailure('gpu_ownership_unknown')
    matches = set(node.CONTAINER_CGROUP_ID_RE.findall(result.stdout))
    if len(matches) != 1:
        raise EvidenceFailure('gpu_ownership_unknown')
    return next(iter(matches))

class EvidenceRunner:
    """One collection deadline shared by every command, including per-PID reads."""

    def __init__(self, runner: Any, clock: Callable[[], float], deadline: float):
        self.runner, self.clock, self.deadline = (runner, clock, deadline)

    def remaining(self) -> float:
        remaining = self.deadline - self.clock()
        if not math.isfinite(remaining) or remaining <= 0:
            raise EvidenceFailure('active_step_overrun')
        return remaining

    def run(self, argv: Any) -> Any:
        remaining = self.remaining()
        runner = self.runner
        if type(runner) is node.CommandRunner:
            runner = node.CommandRunner(runner.binaries, timeout=min(runner.timeout, remaining), cap=runner.cap)
        result = runner.run(argv)
        self.remaining()
        if getattr(result, 'timed_out', False):
            raise EvidenceFailure('active_step_overrun')
        return result

class Guard:
    """Real observer adapter with injected runtime seams; the CLI never exposes those seams."""

    def __init__(self, manifest: Mapping[str, Any], policy: GuardPolicy, runner: Any, fence: Any, store: StateStore, *, wall_clock: Callable[[], float]=time.time, monotonic_clock: Callable[[], float]=time.monotonic, wait: Callable[[float], Any]=time.sleep, guard_pid: int | None=None, session_id: str | None=None):
        self.manifest = manifest
        self.policy = policy
        self.runner = runner
        self.fence = fence
        self.store = store
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.wait = wait
        self.guard_pid = os.getpid() if guard_pid is None else guard_pid
        if type(self.guard_pid) is not int or self.guard_pid <= 0:
            raise ValueError('guard_pid must be positive')
        self.session_id = session_id or secrets.token_hex(16)
        if not re.fullmatch('[0-9a-f]{32}', self.session_id):
            raise ValueError('session_id must be 32 lowercase hex characters')
        self.node_name = manifest['node']
        self.state = store.load_state()
        self._previous_session = self.state.get('session_id')
        self._sequence_local = self.state.get('sequence', 0)
        self._notify_reason_override: str | None = None
        self._observer: Any | None = None
        self._identity: Any | None = None
        self._active_evidence: Evidence | None = None
        self._last_error = 'guard_error'
        self._startup_started: float | None = None
        self._stopped = False
        self._fence_local = threading.local()
        self._runtime = node.Runtime(manifest=manifest, fence=fence, runner=runner, clock=wall_clock)

    @contextlib.contextmanager
    def _locked(self):
        existing = getattr(self._fence_local, 'connection', None)
        if existing is not None:
            yield existing
            return
        for attempt in range(LOCK_BUSY_ATTEMPTS):
            context = self.fence.locked()
            try:
                connection = context.__enter__()
            except node.FenceBusy:
                if attempt + 1 == LOCK_BUSY_ATTEMPTS:
                    raise
                self.wait(LOCK_RETRY_SECONDS)
                continue
            self._fence_local.connection = connection
            try:
                try:
                    yield connection
                except BaseException as exc:
                    context.__exit__(type(exc), exc, exc.__traceback__)
                    raise
                else:
                    context.__exit__(None, None, None)
            finally:
                del self._fence_local.connection
            return

    def _fence_failure(self, reason: str) -> Mapping[str, Any]:
        key = self.state.get('tracked')
        self._observer = None
        self._active_evidence = None
        self._persist_terminal_local(key, reason)
        return self._publish_status('QUARANTINED_HOLD_RETAINED', reason, key)

    def step(self) -> Mapping[str, Any]:
        """Run one idle/arming/observer/watch iteration and return the published status."""
        if self._stopped:
            return self._publish_status('STOPPED_HOLD_RETAINED', 'guard_stopped', self._identity or self.state.get('tracked'))
        if self._observer is not None and self._observer.state is observer.ObserverState.ACTIVE:
            self._active_evidence = None
            try:
                with self._locked() as connection:
                    started = self._monotonic()
                    result = self._observer.tick()
                    elapsed = self._monotonic() - started
                    if not math.isfinite(elapsed) or elapsed < 0:
                        raise EvidenceFailure('clock_failed')
                    if result.state is observer.ObserverState.ACTIVE:
                        evidence = self._active_evidence
                        if evidence is None or elapsed > MAX_ACTIVE_STEP_SECONDS:
                            current = node.read_record(connection)
                            reason = 'active_step_overrun' if elapsed > MAX_ACTIVE_STEP_SECONDS else 'ownership_unproven'
                            self._persist_terminal_locked(connection, self._identity, reason, 'QUARANTINED_HOLD_RETAINED', current)
                            self._observer = None
                            return self._publish_status('QUARANTINED_HOLD_RETAINED', reason, self._identity)
                        self.state['phase'] = 'ACTIVE'
                        self.state['sequence'] = max(self.state['sequence'], evidence.sequence)
                        self.state['last_sample_at'] = evidence.observed_at
                        self.state['session_id'] = self.session_id
                        self.store.save_state(self.state)
                        return self._publish_status('ACTIVE', 'active_warning' if result.warning else 'active', self._identity, observed_at=evidence.observed_at)
                    return self._after_terminal(result)
            except node.FenceBusy:
                return self._fence_failure('fence_contention_expired')
            except node.FenceUnavailable:
                return self._fence_failure('fence_unavailable')
            except EvidenceFailure as exc:
                return self._fence_failure(exc.reason_code)
            except Exception:
                return self._fence_failure('guard_error')
        try:
            with self._locked() as connection:
                record = node.read_record(connection)
                return self._step_record_locked(connection, record)
        except node.FenceBusy:
            return self._fence_failure('fence_contention_expired')
        except node.FenceUnavailable:
            return self._fence_failure('fence_unavailable')
        except Exception as exc:
            reason = exc.reason_code if isinstance(exc, EvidenceFailure) else 'guard_error'
            return self._fence_failure(reason)

    def _step_record_locked(self, connection: Any, record: Mapping[str, Any] | None) -> Mapping[str, Any]:
        if record is None:
            if self.state.get('retained_unknown') or self.state.get('terminal') is not None or (self.state.get('ever_tracked') and (not self.state.get('clear_authorized'))):
                return self._publish_status('QUARANTINED_HOLD_RETAINED', 'clear_not_proven', self.state.get('tracked'))
            self.state['phase'] = 'IDLE_HOLD_RETAINED'
            self.state['session_id'] = self.session_id
            self.store.save_state(self.state)
            return self._publish_status('IDLE_HOLD_RETAINED', 'idle_no_record', None)
        state_name = record.get('state')
        if state_name == node.STATE_CLEAR:
            return self._handle_clear_locked(connection, record)
        if self.state.get('retained_unknown'):
            key = self._trusted_record_key(record)
            self.state['last_record'] = _record_snapshot(record)
            self.state['phase'] = 'QUARANTINED_HOLD_RETAINED'
            self.state['session_id'] = self.session_id
            self.store.save_state(self.state)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'terminal_identity_retained', key)
        if state_name == node.STATE_QUARANTINED:
            key = self._trusted_record_key(record)
            if key is not None and key.get('container_id') is not None:
                identity = self._identity_from_key(key)
                self._persist_terminal_locked(connection, identity, 'db_quarantined', 'QUARANTINED_HOLD_RETAINED', record)
            else:
                self._persist_terminal_local(key, 'db_quarantined', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'db_quarantined', key)
        if state_name == node.STATE_CLAIMED:
            return self._handle_claimed_locked(connection, record)
        if state_name == node.STATE_RUNNING:
            return self._handle_running_locked(connection, record)
        key = self._trusted_record_key(record)
        self._persist_terminal_local(key, 'record_unknown', record)
        return self._publish_status('QUARANTINED_HOLD_RETAINED', 'record_unknown', key)

    def _handle_clear_locked(self, connection: Any, record: Mapping[str, Any]) -> Mapping[str, Any]:
        prior = self.state.get('last_record')
        already_authorized = bool(self.state.get('clear_authorized'))
        release_at = record.get('released_at')
        updated_at = record.get('updated_at')
        positive = False
        if already_authorized and _same_key(self.state.get('tracked'), _record_key(record, self.node_name, self._image_for(record.get('profile'))), allow_missing_cid=True):
            positive = True
        elif prior is None and self.state.get('tracked') is None and (self.state.get('terminal') is None):
            positive = _finite_timestamp(release_at) and _finite_timestamp(updated_at) and (float(updated_at) >= float(release_at) > 0)
        elif isinstance(prior, dict):
            same = all((prior.get(key) == record.get(key) for key in ('profile', 'owner', 'generation', 'container_id')))
            prev_updated = prior.get('updated_at')
            positive = same and prior.get('state') in {node.STATE_CLAIMED, node.STATE_RUNNING, node.STATE_QUARANTINED, node.STATE_CLEAR} and _finite_timestamp(prev_updated) and _finite_timestamp(release_at) and _finite_timestamp(updated_at) and (float(release_at) >= float(prev_updated)) and (float(updated_at) >= float(release_at) > 0)
        self.state['phase'] = 'IDLE_HOLD_RETAINED'
        self.state['session_id'] = self.session_id
        if positive:
            self.state['tracked'] = None
            self.state['terminal'] = None
            self.state['clear_authorized'] = True
            self.state['retained_unknown'] = False
            self.state['ever_tracked'] = True
            self.state['arming_started_at'] = None
            self._startup_started = None
            self._observer = None
            self._identity = None
            self._active_evidence = None
        elif self.state.get('tracked') is not None or self.state.get('terminal') is not None or self.state.get('retained_unknown'):
            self.state['clear_authorized'] = False
        self.state['last_record'] = _record_snapshot(record)
        self.store.save_state(self.state)
        if not positive:
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'clear_not_proven', self.state.get('tracked'))
        self._append_guard_event('guard_state', 'IDLE_HOLD_RETAINED', 'idle_db_clear', self.state.get('tracked'))
        return self._publish_status('IDLE_HOLD_RETAINED', 'idle_db_clear', None)

    def _handle_claimed_locked(self, connection: Any, record: Mapping[str, Any]) -> Mapping[str, Any]:
        key = self._trusted_record_key(record)
        if key is None or record.get('container_id') is not None:
            self._persist_terminal_local(key, 'record_malformed', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'record_malformed', key)
        allowed, reason = self._may_attach_claim(key, record)
        if not allowed:
            self._persist_terminal_local(self.state.get('tracked') or key, reason, record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', reason, self.state.get('tracked') or key)
        self.state['tracked'] = key
        self.state['last_record'] = _record_snapshot(record)
        self.state['phase'] = 'ARMING_HOLD_RETAINED'
        self.state['clear_authorized'] = False
        self.state['ever_tracked'] = True
        self.state['session_id'] = self.session_id
        self.state['arming_started_at'] = None
        self.store.save_state(self.state)
        return self._publish_status('ARMING_HOLD_RETAINED', 'arming_claimed', key)

    def _handle_running_locked(self, connection: Any, record: Mapping[str, Any]) -> Mapping[str, Any]:
        key = self._trusted_record_key(record)
        if key is None or key.get('container_id') is None:
            self._persist_terminal_local(key, 'record_malformed', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'record_malformed', key)
        allowed, reason = self._may_attach_running(key, record)
        if not allowed:
            identity_key = self.state.get('tracked') or key
            identity = self._identity_from_key(identity_key) if identity_key.get('container_id') else None
            if identity is not None:
                self._persist_terminal_locked(connection, identity, reason, 'QUARANTINED_HOLD_RETAINED', record)
            else:
                self._persist_terminal_local(identity_key, reason, record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', reason, identity_key)
        if self._previous_session is not None and self._previous_session != self.session_id and (self.state.get('session_id') == self._previous_session) and (self.state.get('phase') in {'ACTIVE', 'ARMING_HOLD_RETAINED', 'STOPPED_HOLD_RETAINED'}):
            prior = self.state.get('tracked')
            if prior is not None and _same_key(prior, key):
                identity = self._identity_from_key(key)
                self._persist_terminal_locked(connection, identity, 'guard_restarted_unresolved', 'QUARANTINED_HOLD_RETAINED', record)
                return self._publish_status('QUARANTINED_HOLD_RETAINED', 'guard_restarted_unresolved', key)
        try:
            now_mono = self._monotonic()
            if self._startup_started is None:
                if self.state.get('phase') == 'ARMING_HOLD_RETAINED' and self.state.get('session_id') == self.session_id:
                    self._startup_started = self.state.get('arming_started_at')
                if self._startup_started is None:
                    self._startup_started = now_mono
            identity = self._identity_from_key(key)
            evidence = self._collect_locked(connection, identity, allow_empty=True)
        except EvidenceFailure as exc:
            identity = self._identity_from_key(key)
            self._persist_terminal_locked(connection, identity, exc.reason_code, 'QUARANTINED_HOLD_RETAINED', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', exc.reason_code, key)
        self.state['tracked'] = key
        self.state['last_record'] = _record_snapshot(record)
        self.state['ever_tracked'] = True
        self.state['clear_authorized'] = False
        self.state['session_id'] = self.session_id
        self.state['sequence'] = max(self.state['sequence'], evidence.sequence)
        self.state['last_sample_at'] = evidence.observed_at
        elapsed = self._monotonic() - float(self._startup_started)
        if not math.isfinite(elapsed) or elapsed < 0:
            self._persist_terminal_locked(connection, identity, 'clock_failed', 'QUARANTINED_HOLD_RETAINED', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'clock_failed', key)
        if elapsed >= self.policy.startup_grace_seconds:
            self._persist_terminal_locked(connection, identity, 'startup_grace_expired', 'QUARANTINED_HOLD_RETAINED', record)
            return self._publish_status('QUARANTINED_HOLD_RETAINED', 'startup_grace_expired', key)
        if evidence.empty_gpu_processes:
            self.state['phase'] = 'ARMING_HOLD_RETAINED'
            self.state['arming_started_at'] = self._startup_started
            self.store.save_state(self.state)
            return self._publish_status('ARMING_HOLD_RETAINED', 'arming_startup_grace', key, observed_at=evidence.observed_at)
        self.state['phase'] = 'ARMING_HOLD_RETAINED'
        self.state['arming_started_at'] = self._startup_started
        self.store.save_state(self.state)
        self._identity = identity
        self._observer = observer.Observer(identity=identity, policy=self.policy.profiles[identity.profile].runtime_policy, observe=self._observe, fenced_stop=self._fenced_stop, notify=self._notify, clock=self.wall_clock, wait=self.wait, event_writer=self._event_writer)
        return self._publish_status('ARMING_HOLD_RETAINED', 'arming_startup', key, observed_at=evidence.observed_at)

    def _may_attach_claim(self, key: Mapping[str, Any], record: Mapping[str, Any]) -> tuple[bool, str]:
        if self.state.get('retained_unknown'):
            return (False, 'terminal_identity_retained')
        terminal = self.state.get('terminal')
        if terminal is not None and _same_key(terminal, key, allow_missing_cid=True):
            return (False, 'terminal_identity_retained')
        tracked = self.state.get('tracked')
        last = self.state.get('last_record')
        if tracked is not None:
            if _same_key(tracked, key, allow_missing_cid=True) and self.state.get('phase') == 'ARMING_HOLD_RETAINED':
                return (True, '')
            if self.state.get('clear_authorized') and isinstance(last, dict) and (type(last.get('generation')) is int):
                last_identity = (last.get('profile'), last.get('owner'), last.get('generation'))
                new_identity = (key['profile'], key['owner'], key['generation'])
                if new_identity != last_identity:
                    return (True, '')
            return (False, 'identity_changed_without_clear')
        if self.state.get('ever_tracked'):
            if self.state.get('clear_authorized') and isinstance(last, dict) and (type(last.get('generation')) is int):
                last_identity = (last.get('profile'), last.get('owner'), last.get('generation'))
                new_identity = (key['profile'], key['owner'], key['generation'])
                if new_identity != last_identity:
                    return (True, '')
                return (False, 'identity_changed_without_clear')
            return (False, 'identity_changed_without_clear')
        if isinstance(last, dict) and last.get('state') == node.STATE_CLEAR and (not self.state.get('clear_authorized')):
            return (False, 'clear_not_proven')
        return (True, '')

    def _may_attach_running(self, key: Mapping[str, Any], record: Mapping[str, Any]) -> tuple[bool, str]:
        if self.state.get('retained_unknown'):
            return (False, 'terminal_identity_retained')
        terminal = self.state.get('terminal')
        if terminal is not None and _same_key(terminal, key, allow_missing_cid=True):
            return (False, 'terminal_identity_retained')
        tracked = self.state.get('tracked')
        last = self.state.get('last_record')
        if tracked is None:
            if not self.state.get('ever_tracked'):
                return (True, '')
            return (False, 'identity_changed_without_clear')
        if _same_key(tracked, key, allow_missing_cid=True):
            if self.state.get('phase') == 'ARMING_HOLD_RETAINED' and isinstance(last, dict):
                if last.get('state') in {node.STATE_CLAIMED, node.STATE_RUNNING}:
                    return (True, '')
            if self.state.get('phase') == 'ACTIVE' and self.state.get('session_id') == self.session_id:
                return (True, '')
            return (False, 'guard_restarted_unresolved')
        return (False, 'identity_changed_without_clear')

    def _trusted_record_key(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        profile = record.get('profile')
        if not _safe_token(profile) or profile not in self.policy.profiles:
            return None
        return _record_key(record, self.node_name, self.policy.profiles[profile].image_config_id)

    def _identity_from_key(self, key: Mapping[str, Any]) -> Any:
        try:
            if key.get('container_id') is None:
                raise ValueError('container id missing')
            return observer.Identity(node=key['node'], profile=key['profile'], owner=key['owner'], generation=key['generation'], container_id=key['container_id'], image=key['image'])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceFailure('record_malformed') from exc

    def _image_for(self, profile: Any) -> str | None:
        if isinstance(profile, str) and profile in self.policy.profiles:
            return self.policy.profiles[profile].image_config_id
        return None

    def _collect_locked(self, connection: Any, identity: Any, *, allow_empty: bool) -> Evidence:
        started = self._monotonic()
        runner = EvidenceRunner(self.runner, self._monotonic, started + MAX_ACTIVE_STEP_SECONDS)
        record = node.read_record(connection)
        if not _record_exact(record, identity) or record.get('state') != node.STATE_RUNNING:
            raise EvidenceFailure('identity_mismatch')
        plan = self.manifest['profiles'].get(identity.profile)
        config = self.policy.profiles.get(identity.profile)
        if not isinstance(plan, dict) or config is None or (not config.enabled):
            raise EvidenceFailure('record_malformed')
        if plan.get('image') is None or not (_IMAGE.fullmatch(plan['image']) or _SHA256_REF.fullmatch(plan['image'])):
            raise EvidenceFailure('container_image_mismatch')
        inspected = node.inspect_own_container(runner, identity.container_id)
        if inspected.exists is None:
            raise EvidenceFailure('container_inspect_unknown')
        if inspected.exists is False:
            raise EvidenceFailure('container_absent')
        data = inspected.data or {}
        if data.get('id') != identity.container_id:
            raise EvidenceFailure('container_identity_mismatch')
        if not node.labels_match_identity(data, node=self.node_name, profile=identity.profile, owner=identity.owner, generation=identity.generation):
            raise EvidenceFailure('container_labels_mismatch')
        if data.get('restart_policy') != 'no':
            raise EvidenceFailure('container_restart_policy')
        extended = runner.run(('docker', 'inspect', '--format', '{{.Id}}' + '\t' + '{{.Image}}' + '\t' + '{{.Config.Image}}' + '\t' + '{{.State.Pid}}' + '\t' + '{{.RestartCount}}' + '\t' + '{{.State.Paused}}' + '\t' + '{{.State.Restarting}}', identity.container_id))
        if not extended.ok:
            raise EvidenceFailure('container_inspect_unknown')
        lines = [line for line in extended.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise EvidenceFailure('container_inspect_unknown')
        fields = lines[0].split('\t')
        if len(fields) != 7 or fields[0] != identity.container_id:
            raise EvidenceFailure('container_identity_mismatch')
        actual_image, configured_image = (fields[1], fields[2])
        if actual_image != identity.image or configured_image != plan['image']:
            raise EvidenceFailure('container_image_mismatch')
        try:
            container_pid = int(fields[3])
            restart_count = int(fields[4])
        except ValueError:
            raise EvidenceFailure('container_pid_unknown') from None
        paused_text, restarting_text = (fields[5].lower(), fields[6].lower())
        status = data.get('status')
        is_running = data.get('running') is True and status == 'running'
        is_inactive = data.get('running') is False and status in node.INACTIVE_CONTAINER_STATES
        if not is_running and (not is_inactive):
            if status == 'paused':
                raise EvidenceFailure('container_paused')
            raise EvidenceFailure('runtime_state_changed')
        if restart_count != 0:
            raise EvidenceFailure('container_restarted')
        if paused_text != 'false' or restarting_text != 'false':
            raise EvidenceFailure('container_paused' if paused_text == 'true' else 'container_restarted')
        gpu = node.enumerate_gpu(runner, record=record)
        if not gpu.complete or gpu.truncated:
            raise EvidenceFailure('gpu_enumeration_unknown')
        process_pids: list[int] = []
        seen_gpu_pids: set[int] = set()
        for item in gpu.processes:
            pid = item.get('pid')
            if type(pid) is not int or pid <= 0 or pid in seen_gpu_pids:
                raise EvidenceFailure('gpu_ownership_unknown')
            seen_gpu_pids.add(pid)
            process_pids.append(pid)
        if is_running:
            if container_pid <= 0:
                raise EvidenceFailure('container_pid_unknown')
            top = runner.run(('docker', 'top', identity.container_id, '-eo', 'pid'))
            if not top.ok:
                raise EvidenceFailure('docker_top_unknown')
            record_pids = _pid_tuple(top.stdout)
            if container_pid not in record_pids:
                raise EvidenceFailure('docker_top_unknown')
            own_gpu_containers = [entry for entry in gpu.containers if entry.get('id') == identity.container_id]
            if any((entry.get('id') != identity.container_id or entry.get('mapped') is not True for entry in gpu.containers)):
                raise EvidenceFailure('gpu_container_foreign')
            if len(gpu.containers) > 1:
                raise EvidenceFailure('gpu_container_foreign')
            if process_pids:
                if len(gpu.containers) != 1 or len(own_gpu_containers) != 1:
                    raise EvidenceFailure('gpu_container_foreign')
                gpu_map: list[tuple[int, str]] = []
                for pid in process_pids:
                    if pid not in record_pids:
                        raise EvidenceFailure('gpu_process_foreign')
                    if _read_cgroup_container(runner, pid) != identity.container_id:
                        raise EvidenceFailure('gpu_process_foreign')
                    gpu_map.append((pid, identity.container_id))
                ownership = observer.OwnershipProof(record_identity=identity, labels_identity=identity, ownership_known=True, probe_known=True, container_pid=container_pid, record_pids=record_pids, gpu_pid_map=tuple(gpu_map))
                running = True
                empty = False
            else:
                if not allow_empty:
                    raise EvidenceFailure('ownership_unproven')
                ownership = None
                running = True
                empty = True
        else:
            if container_pid != 0 or process_pids or gpu.containers:
                raise EvidenceFailure('gpu_process_foreign' if process_pids or gpu.containers else 'container_pid_unknown')
            ownership = observer.OwnershipProof(record_identity=identity, labels_identity=identity, ownership_known=True, probe_known=True, container_pid=None, record_pids=(), gpu_pid_map=())
            running = False
            empty = False
        memory = _read_proc_meminfo(runner)
        observed_at = self._wall_stamp()
        elapsed = self._monotonic() - started
        if not math.isfinite(elapsed) or elapsed < 0:
            raise EvidenceFailure('clock_failed')
        if elapsed > MAX_ACTIVE_STEP_SECONDS:
            raise EvidenceFailure('active_step_overrun')
        sequence = max(self.state.get('sequence', 0), self._sequence_local) + 1
        previous_at = self.state.get('last_sample_at')
        if previous_at is not None and observed_at <= float(previous_at):
            raise EvidenceFailure('sample_not_monotonic')
        if not math.isfinite(memory) or memory <= 0:
            raise EvidenceFailure('memory_unknown')
        self._sequence_local = sequence
        self.state['sequence'] = sequence
        self.state['last_sample_at'] = observed_at
        if empty:
            return Evidence(None, memory, observed_at, sequence, True)
        sample = observer.Observation(identity=identity, observed_at=observed_at, sequence=sequence, available_gib=memory, proof=ownership, running=running, paused=False, restarted=False)
        return Evidence(sample, memory, observed_at, sequence, False)

    def _observe(self, identity: Any) -> Any:
        try:
            with self._locked() as connection:
                evidence = self._collect_locked(connection, identity, allow_empty=False)
                if evidence.observation is None:
                    raise EvidenceFailure('ownership_unproven')
                self._active_evidence = evidence
                record = node.read_record(connection)
                self.state['last_record'] = _record_snapshot(record)
                return evidence.observation
        except EvidenceFailure as exc:
            self._last_error = exc.reason_code
            raise
        except Exception:
            self._last_error = 'observe_failed'
            raise

    def _fenced_stop(self, identity: Any, fresh_proof: Any) -> Any:
        if type(identity) is not observer.Identity or identity != self._identity:
            self._last_error = 'stop_revalidation_failed'
            return observer.StopAck(identity, False)
        if type(fresh_proof) is not observer.FreshProof or fresh_proof.identity != identity:
            self._last_error = 'stop_revalidation_failed'
            return observer.StopAck(identity, False)
        try:
            with self._locked() as connection:
                record = node.read_record(connection)
                if not _record_exact(record, identity) or record.get('state') != node.STATE_RUNNING:
                    self._last_error = 'stop_revalidation_failed'
                    return observer.StopAck(identity, False)
                fresh = self._collect_locked(connection, identity, allow_empty=False)
                if fresh.observation is None or fresh.sequence <= fresh_proof.sequence:
                    self._last_error = 'stop_revalidation_failed'
                    return observer.StopAck(identity, False)
                if fresh.observed_at <= fresh_proof.observed_at:
                    self._last_error = 'stop_revalidation_failed'
                    return observer.StopAck(identity, False)
                if fresh.available_gib >= self.policy.profiles[identity.profile].runtime_policy.sustained_floor_gib:
                    self._last_error = 'stop_memory_recovered'
                    return observer.StopAck(identity, False)
                self._persist_terminal_locked(connection, identity, 'guard_stop_initiated', 'QUARANTINED_HOLD_RETAINED', record)
                request = {'profile': identity.profile, 'owner': identity.owner, 'generation': identity.generation}
                try:
                    result = node.action_stop(request, self._runtime, connection)
                except Exception:
                    current = node.read_record(connection)
                    self._persist_terminal_locked(connection, identity, 'fenced_stop_failed', 'QUARANTINED_HOLD_RETAINED', current)
                    self._last_error = 'fenced_stop_failed'
                    return observer.StopAck(identity, False)
                if result.get('status') == 'ok' and result.get('stop_requested') is True and (result.get('container_id') == identity.container_id) and (result.get('stop_action') == 'docker_stop'):
                    current = node.read_record(connection)
                    self._persist_terminal_locked(connection, identity, 'fenced_stop_acknowledged_hold_retained', 'STOPPED_HOLD_RETAINED', current)
                    self._last_error = 'fenced_stop_acknowledged_hold_retained'
                    return observer.StopAck(identity, True)
                current = node.read_record(connection)
                self._persist_terminal_locked(connection, identity, 'stop_action_refused', 'QUARANTINED_HOLD_RETAINED', current)
                self._last_error = 'stop_action_refused'
                return observer.StopAck(identity, False)
        except EvidenceFailure as exc:
            self._last_error = 'stop_revalidation_failed'
            self._notify_reason_override = exc.reason_code
            return observer.StopAck(identity, False)
        except node.FenceBusy:
            self._last_error = 'fence_contention_expired'
            self._notify_reason_override = 'fence_contention_expired'
            return observer.StopAck(identity, False)
        except node.FenceUnavailable:
            self._last_error = 'fence_unavailable'
            self._notify_reason_override = 'fence_unavailable'
            return observer.StopAck(identity, False)
        except Exception:
            self._last_error = 'fenced_stop_failed'
            return observer.StopAck(identity, False)

    def _notify(self, event: Mapping[str, Any]) -> None:
        raw_identity = self._identity
        if raw_identity is None:
            return
        reason = self._notify_reason_override or event.get('reason')
        terminal = self.state.get('terminal')
        terminal_reason = terminal.get('reason_code') if isinstance(terminal, dict) else None
        stop_reasons = {'guard_stop_initiated', 'fenced_stop_acknowledged_hold_retained', 'stop_action_refused', 'fenced_stop_failed'}
        if self._notify_reason_override is None and terminal_reason in stop_reasons:
            reason = terminal_reason
        elif self._notify_reason_override is None and reason == 'observe_failed' and (self._last_error in _REASON_CODES):
            reason = self._last_error
        elif self._notify_reason_override is None and reason == 'stop_refused':
            reason = self._last_error if self._last_error in {'stop_memory_recovered', 'stop_action_refused', 'stop_revalidation_failed', 'fence_contention_expired', 'fence_unavailable', 'fenced_stop_failed'} else 'stop_action_refused'
        if reason not in _REASON_CODES:
            reason = 'guard_error'
        state_value = event.get('state')
        state = 'STOPPED_HOLD_RETAINED' if state_value == 'STOPPED_ACKNOWLEDGED_HOLD_RETAINED' else 'QUARANTINED_HOLD_RETAINED'
        try:
            with self._locked() as connection:
                current = node.read_record(connection)
                self._persist_terminal_locked(connection, raw_identity, reason, state, current)
        finally:
            self._notify_reason_override = None

    def _event_writer(self, event: Mapping[str, Any]) -> None:
        self.store.append_event(dict(event))

    def _after_terminal(self, result: Any) -> Mapping[str, Any]:
        state_value = result.state.value
        status_state = 'STOPPED_HOLD_RETAINED' if state_value == 'STOPPED_ACKNOWLEDGED_HOLD_RETAINED' else 'QUARANTINED_HOLD_RETAINED'
        reason = result.reason
        if result.reason == 'observe_failed' and self._last_error in _REASON_CODES:
            reason = self._last_error
        elif result.reason == 'stop_refused' and self._last_error in {'stop_memory_recovered', 'stop_action_refused', 'stop_revalidation_failed'}:
            reason = self._last_error
        if reason not in _REASON_CODES:
            reason = 'guard_error'
        if self._identity is not None and self.state.get('terminal') is None:
            with contextlib.suppress(Exception):
                self._notify({'state': state_value, 'reason': reason})
        self.state['phase'] = status_state
        self.state['session_id'] = self.session_id
        with contextlib.suppress(Exception):
            self.store.save_state(self.state)
        return self._publish_status(status_state, reason, self._identity)

    def _persist_terminal_locked(self, connection: Any, identity: Any, reason: str, status_state: str, record: Mapping[str, Any] | None) -> None:
        reason = reason if reason in _REASON_CODES else 'guard_error'
        key = {'node': identity.node, 'profile': identity.profile, 'owner': identity.owner, 'generation': identity.generation, 'container_id': identity.container_id, 'image': identity.image}
        self._persist_terminal_local(key, reason, record, status_state=status_state)
        current = node.read_record(connection)
        if not _record_exact(current, identity):
            return
        if current.get('state') == node.STATE_RUNNING:
            updated = dict(current)
            updated['state'] = node.STATE_QUARANTINED
            updated['updated_at'] = self.wall_clock()
            updated['quarantine_reason'] = reason
            node.save_record(connection, updated)
        elif current.get('state') == node.STATE_QUARANTINED and current.get('quarantine_reason') == 'guard_stop_initiated' and (reason in {'fenced_stop_acknowledged_hold_retained', 'stop_action_refused', 'fenced_stop_failed'}):
            updated = dict(current)
            updated['updated_at'] = self.wall_clock()
            updated['quarantine_reason'] = reason
            node.save_record(connection, updated)

    def _persist_terminal_local(self, key: Mapping[str, Any] | None, reason: str, record: Mapping[str, Any] | None=None, *, status_state: str='QUARANTINED_HOLD_RETAINED') -> None:
        if reason not in _REASON_CODES:
            reason = 'guard_error'
        if key is not None:
            self.state['tracked'] = dict(key)
            self.state['terminal'] = {'node': key.get('node', self.node_name), 'profile': key.get('profile'), 'owner': key.get('owner'), 'generation': key.get('generation'), 'container_id': key.get('container_id'), 'image': key.get('image'), 'reason_code': reason}
        self.state['phase'] = status_state
        self.state['session_id'] = self.session_id
        if key is None:
            self.state['retained_unknown'] = True
        self.state['ever_tracked'] = True if key is not None else self.state.get('ever_tracked', False)
        if record is not None:
            self.state['last_record'] = _record_snapshot(record)
        self.state['clear_authorized'] = False
        self.state['arming_started_at'] = None
        self.store.save_state(self.state)

    def _set_nonterminal_phase(self, phase: str, key: Mapping[str, Any] | None, reason: str) -> None:
        self.state['phase'] = phase
        self.state['session_id'] = self.session_id
        if key is not None:
            self.state['tracked'] = dict(key)
        with contextlib.suppress(Exception):
            self.store.save_state(self.state)

    def _publish_status(self, state: str, reason: str, identity_or_key: Any, *, observed_at: float | None=None) -> Mapping[str, Any]:
        if reason not in _REASON_CODES:
            reason = 'guard_error'
        identity = identity_or_key
        if hasattr(identity_or_key, 'profile') and hasattr(identity_or_key, 'container_id'):
            profile, owner = (identity_or_key.profile, identity_or_key.owner)
            generation, cid, image = (identity_or_key.generation, identity_or_key.container_id, identity_or_key.image)
        elif isinstance(identity_or_key, Mapping):
            profile, owner = (identity_or_key.get('profile'), identity_or_key.get('owner'))
            generation, cid, image = (identity_or_key.get('generation'), identity_or_key.get('container_id'), identity_or_key.get('image'))
        else:
            profile = owner = generation = cid = image = None
        stamp = self._wall_stamp() if observed_at is None else observed_at
        payload = _status_payload(node_name=self.node_name, guard_pid=self.guard_pid, observed_at=stamp, state=state, profile=profile, owner=owner, generation=generation, container_id=cid, image=image, reason_code=reason)
        self.store.write_status(payload)
        return payload

    def _append_guard_event(self, event_name: str, state: str, reason: str, key: Mapping[str, Any] | None) -> None:
        if reason not in _REASON_CODES:
            reason = 'guard_error'
        self.store.append_event({'event': event_name, 'state': state, 'reason': reason, 'node': self.node_name, 'profile': key.get('profile') if key else None, 'owner': key.get('owner') if key else None, 'generation': key.get('generation') if key else None, 'container_id': key.get('container_id') if key else None, 'image': key.get('image') if key else None, 'sequence': None, 'available_gib': None, 'observed_at': self._wall_stamp()})

    def _wall_stamp(self) -> float:
        try:
            value = self.wall_clock()
        except Exception as exc:
            raise EvidenceFailure('clock_failed') from exc
        if not _finite_timestamp(value) or float(value) <= 0:
            raise EvidenceFailure('clock_failed')
        return float(value)

    def _monotonic(self) -> float:
        try:
            value = self.monotonic_clock()
        except Exception as exc:
            raise EvidenceFailure('clock_failed') from exc
        if not _finite_timestamp(value) or float(value) < 0:
            raise EvidenceFailure('clock_failed')
        return float(value)

    def stop(self) -> None:
        """Stop observing only; retain/quarantine any attached generation, never release it."""
        if self._stopped:
            return
        self._stopped = True
        if self._identity is not None and self.state.get('terminal') is None:
            with contextlib.suppress(Exception):
                with self._locked() as connection:
                    current = node.read_record(connection)
                    self._persist_terminal_locked(connection, self._identity, 'guard_stopped', 'STOPPED_HOLD_RETAINED', current)
        self.state['phase'] = 'STOPPED_HOLD_RETAINED'
        self.state['session_id'] = self.session_id
        with contextlib.suppress(Exception):
            self.store.save_state(self.state)
        key = self._identity or self.state.get('tracked')
        with contextlib.suppress(Exception):
            self._publish_status('STOPPED_HOLD_RETAINED', 'guard_stopped', key)

    def run(self, cancelled: Callable[[], bool]) -> None:
        if not self.policy.enabled:
            return
        if not callable(cancelled):
            raise TypeError('cancelled must be callable')
        try:
            while not cancelled():
                self.step()
                if cancelled():
                    break
                try:
                    self.wait(self.policy.sample_interval_s)
                except Exception:
                    key = self._identity or self.state.get('tracked')
                    self._persist_terminal_local(key, 'wait_failed')
                    self._publish_status('QUARANTINED_HOLD_RETAINED', 'wait_failed', key)
                    break
        finally:
            self.stop()

def _finite_timestamp(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False

def load_runtime_config() -> tuple[dict[str, Any], GuardPolicy]:
    """Read the fixed root-owned manifest and fixed policy; no lifecycle or state access."""
    try:
        manifest = node.load_manifest(node.DEFAULT_MANIFEST_PATH, require_root_owner=True)
    except Exception as exc:
        raise GuardConfigError('manifest_invalid') from exc
    policy = _read_policy(POLICY_PATH, owner_uid=0, manifest=manifest)
    return (manifest, policy)

def _build_runner() -> Any:
    binaries = {'docker': node.DEFAULT_BINARIES['docker'], 'nvidia-smi': node.DEFAULT_BINARIES['nvidia-smi'], 'cat': '/usr/bin/cat'}
    return node.CommandRunner(binaries)

def _serve(manifest: Mapping[str, Any], policy: GuardPolicy) -> int:
    if os.geteuid() != 0:
        raise GuardConfigError('serve_requires_root')
    if not policy.enabled:
        print('node guard policy disabled; no lifecycle or device access', file=sys.stderr)
        return 0
    store = StateStore(STATE_DIR, owner_uid=0)
    store.validate_directory()
    process_lock = GuardProcessLock(store.lock_path, owner_uid=0)
    process_lock.acquire()
    fence = node.Fence(manifest['state_db'], manifest['lock_file'])
    runner = _build_runner()
    guard = Guard(manifest, policy, runner, fence, store)
    stopping = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True
    old_term = signal.signal(signal.SIGTERM, request_stop)
    old_int = signal.signal(signal.SIGINT, request_stop)
    try:
        guard.run(lambda: stopping)
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)
        process_lock.close()
    return 0

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(description='bounded node-local runtime memory guard')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='validate fixed root-owned manifest and policy only')
    mode.add_argument('--serve', action='store_true', help='run the observer; never starts or releases containers')
    args = parser.parse_args(argv)
    try:
        manifest, policy = load_runtime_config()
        if args.check:
            print(f"policy valid node={manifest['node']} profiles={len(policy.profiles)} enabled={str(policy.enabled).lower()}")
            return 0
        return _serve(manifest, policy)
    except (GuardConfigError, GuardStoreError) as exc:
        print(f'node guard refused: {type(exc).__name__}:{exc}', file=sys.stderr)
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
