# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import contextlib
import ipaddress
import json
import os
import pwd
import secrets
import math
import selectors
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from control_plane.errors import AdapterUnavailableError
from . import protocol
from .protocol import ProtocolError
CONFIG_SCHEMA = 'dgx-v4-node-adapter-config'
JOURNAL_SCHEMA = 'dgx-v4-node-adapter-journal-v1'
ADAPTER_NAME = 'hx-node-adapter'
_RFC1918_NETWORKS = tuple((ipaddress.ip_network(network) for network in ('192.0.2.10/8', '192.0.2.10/12', '192.0.2.10/16')))
_CONFIG_KEYS = frozenset({'schema', 'enabled', 'user', 'port', 'ssh_binary', 'ssh_config', 'identity_file', 'journal_path', 'hosts', 'profiles', 'timeout_seconds', 'connect_timeout_seconds', 'max_request_bytes', 'max_output_bytes', 'max_stderr_bytes', 'max_clock_skew_seconds'})
_PLAN_KEYS = frozenset({'nodes', 'model_id', 'api_host', 'api_port', 'api_path', 'roles'})
ROLE_API_LEADER = 'api_leader'
ROLE_WORKER = 'worker'
_PROFILE_ROLES = frozenset({ROLE_API_LEADER, ROLE_WORKER})

class ConfigError(ValueError):
    """The adapter configuration is malformed (structural, not availability)."""

def _unknown_keys(payload: Mapping[str, Any], allowed: frozenset[str] | set[str], name: str) -> list[str]:
    return sorted((str(k) for k in payload if k not in allowed))

@dataclass(frozen=True)
class ProfilePlan:
    """Trusted per-profile launch identity, model/API target, and optional node roles."""
    nodes: tuple[str, ...]
    model_id: str
    api_host: str
    api_port: int
    api_path: str
    roles: Mapping[str, str] | None = None

@dataclass(frozen=True)
class NodeAdapterConfig:
    """Trusted, pre-validated adapter configuration. Never derived from caller data."""
    enabled: bool
    user: str
    ssh_binary: str
    ssh_config: Path
    identity_file: Path
    journal_path: Path
    hosts: Mapping[str, str]
    profiles: Mapping[str, ProfilePlan]
    port: int = 22
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 10.0
    max_request_bytes: int = 65536
    max_output_bytes: int = 1048576
    max_stderr_bytes: int = 4096
    max_clock_skew_seconds: float = 30.0

def _require_finite(payload: Mapping[str, Any], key: str, *, positive: bool=True) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f'{key} must be a number')
    number = float(value)
    if number != number or number in (float('inf'), float('-inf')):
        raise ConfigError(f'{key} must be finite')
    if positive and number <= 0:
        raise ConfigError(f'{key} must be positive')
    return number

def _require_positive_int(payload: Mapping[str, Any], key: str, *, low: int, high: int) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or (not low <= value <= high):
        raise ConfigError(f'{key} must be an integer in [{low}, {high}]')
    return int(value)

def _require_abs_path(payload: Mapping[str, Any], key: str) -> Path:
    value = payload.get(key)
    if not isinstance(value, str) or not value or (not Path(value).is_absolute()):
        raise ConfigError(f'{key} must be an absolute path')
    for ch in value:
        if ch < ' ' or ch == '\x7f':
            raise ConfigError(f'{key} must not contain control characters')
    return Path(value)

def config_from_mapping(payload: Mapping[str, Any]) -> NodeAdapterConfig:
    """Strictly validate a configuration mapping; raises :class:`ConfigError`."""
    if not isinstance(payload, Mapping):
        raise ConfigError('configuration must be an object')
    unknown = _unknown_keys(payload, _CONFIG_KEYS, 'config')
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(unknown)}")
    if payload.get('schema') != CONFIG_SCHEMA:
        raise ConfigError(f'schema must be {CONFIG_SCHEMA!r}')
    enabled = payload.get('enabled')
    if not isinstance(enabled, bool):
        raise ConfigError('enabled must be a boolean')
    user = payload.get('user')
    if not isinstance(user, str) or not protocol.TOKEN_RE.fullmatch(user):
        raise ConfigError('user must be a plain token (no ssh option injection)')
    hosts_raw = payload.get('hosts')
    if not isinstance(hosts_raw, Mapping) or not hosts_raw:
        raise ConfigError('hosts must be a non-empty object')
    hosts: dict[str, str] = {}
    for node, value in hosts_raw.items():
        if not isinstance(node, str) or not protocol.TOKEN_RE.fullmatch(node):
            raise ConfigError(f'invalid node name in hosts: {node!r}')
        if not isinstance(value, str):
            raise ConfigError(f'hosts[{node}] must be a literal IPv4 string')
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ConfigError(f'hosts[{node}] must be a literal IP address (no hostnames)') from exc
        if address.version != 4:
            raise ConfigError(f'hosts[{node}] must be IPv4')
        if not any((address in network for network in _RFC1918_NETWORKS)) or address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast or address.is_reserved:
            raise ConfigError(f'hosts[{node}] must be a usable RFC1918 LAN IPv4 address')
        hosts[node] = str(address)
    profiles_raw = payload.get('profiles')
    if not isinstance(profiles_raw, Mapping) or not profiles_raw:
        raise ConfigError('profiles must be a non-empty object of trusted launch plans')
    profiles: dict[str, ProfilePlan] = {}
    for name, raw_plan in profiles_raw.items():
        if not isinstance(name, str) or not protocol.TOKEN_RE.fullmatch(name):
            raise ConfigError(f'invalid profile name: {name!r}')
        if not isinstance(raw_plan, Mapping):
            raise ConfigError(f'profiles[{name}] must be an object')
        unknown_plan = _unknown_keys(raw_plan, _PLAN_KEYS, f'profiles[{name}]')
        if unknown_plan:
            raise ConfigError(f"profiles[{name}] has unknown keys: {', '.join(unknown_plan)}")
        nodes_raw = raw_plan.get('nodes')
        if not isinstance(nodes_raw, list) or not nodes_raw or any((not isinstance(n, str) or not protocol.TOKEN_RE.fullmatch(n) for n in nodes_raw)) or (len(set(nodes_raw)) != len(nodes_raw)):
            raise ConfigError(f'profiles[{name}].nodes must be a unique non-empty token list')
        roles_raw = raw_plan.get('roles')
        roles: dict[str, str] | None = None
        if 'roles' in raw_plan:
            if not isinstance(roles_raw, Mapping) or set(roles_raw) != set(nodes_raw) or any((not isinstance(role, str) or role not in _PROFILE_ROLES for role in roles_raw.values())) or (sum((role == ROLE_API_LEADER for role in roles_raw.values())) != 1) or (sum((role == ROLE_WORKER for role in roles_raw.values())) < 1):
                raise ConfigError(f'profiles[{name}].roles must map every node to exactly one api_leader and at least one worker')
            roles = dict(roles_raw)
        for node in nodes_raw:
            if node not in hosts:
                raise ConfigError(f'profiles[{name}] references node {node!r} without a pinned host')
        model_id = raw_plan.get('model_id')
        if not isinstance(model_id, str) or not model_id or len(model_id) > protocol.MODEL_ID_MAX:
            raise ConfigError(f'profiles[{name}].model_id must be a pinned non-empty string')
        api_host = raw_plan.get('api_host')
        try:
            api_addr = ipaddress.ip_address(api_host) if isinstance(api_host, str) else None
        except ValueError as exc:
            raise ConfigError(f'profiles[{name}].api_host must be a literal loopback IP') from exc
        if api_addr is None or not api_addr.is_loopback:
            raise ConfigError(f'profiles[{name}].api_host must be a literal loopback address')
        api_port = _require_positive_int(raw_plan, 'api_port', low=1, high=65535)
        api_path = raw_plan.get('api_path')
        if not isinstance(api_path, str) or not api_path.startswith('/') or '..' in api_path or (len(api_path) > 128) or any((ch < ' ' or ch == '\x7f' or ch.isspace() for ch in api_path)):
            raise ConfigError(f'profiles[{name}].api_path must be an absolute clean path')
        profiles[name] = ProfilePlan(nodes=tuple(nodes_raw), model_id=model_id, api_host=str(api_addr), api_port=api_port, api_path=api_path, roles=roles)
    return NodeAdapterConfig(enabled=enabled, user=user, ssh_binary=str(_require_abs_path(payload, 'ssh_binary')), ssh_config=_require_abs_path(payload, 'ssh_config'), identity_file=_require_abs_path(payload, 'identity_file'), journal_path=_require_abs_path(payload, 'journal_path'), hosts=hosts, profiles=profiles, port=_require_positive_int(payload, 'port', low=1, high=65535) if 'port' in payload else 22, timeout_seconds=_require_finite(payload, 'timeout_seconds') if 'timeout_seconds' in payload else 30.0, connect_timeout_seconds=_require_finite(payload, 'connect_timeout_seconds') if 'connect_timeout_seconds' in payload else 10.0, max_request_bytes=_require_positive_int(payload, 'max_request_bytes', low=1024, high=4194304) if 'max_request_bytes' in payload else 65536, max_output_bytes=_require_positive_int(payload, 'max_output_bytes', low=1024, high=8388608) if 'max_output_bytes' in payload else 1048576, max_stderr_bytes=_require_positive_int(payload, 'max_stderr_bytes', low=256, high=65536) if 'max_stderr_bytes' in payload else 4096, max_clock_skew_seconds=_require_finite(payload, 'max_clock_skew_seconds', positive=False) if 'max_clock_skew_seconds' in payload else 30.0)

def load_config(path: str | Path) -> NodeAdapterConfig:
    """Load and strictly validate a JSON configuration file. No defaults invented."""
    text = Path(path).read_bytes()
    value = protocol.strict_json_loads(text, max_bytes=262144)
    return config_from_mapping(value)

def _mode_ok(path: Path, *, allow_group: bool=False) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    forbidden = 2 if allow_group else 18
    return mode & forbidden == 0

def static_checks(config: NodeAdapterConfig) -> list[tuple[str, bool, str]]:
    """Operational trust checks. Every check must pass for ``available``."""
    checks: list[tuple[str, bool, str]] = []

    def one(name: str, fn: Callable[[], str]) -> None:
        try:
            detail = fn()
        except Exception as exc:
            checks.append((name, False, f'{type(exc).__name__}: {exc}'))
        else:
            checks.append((name, True, detail))

    def ssh_config_check() -> str:
        path = config.ssh_config
        if path.is_symlink():
            raise ConfigError('dedicated ssh config must not be a symlink')
        if not path.is_file():
            raise ConfigError('dedicated ssh config is missing')
        if not _mode_ok(path):
            raise ConfigError('dedicated ssh config must not be group/world writable')
        return 'dedicated -F config present'

    def identity_check() -> str:
        path = config.identity_file
        if path.is_symlink():
            raise ConfigError('identity file must not be a symlink')
        if not path.is_file():
            raise ConfigError('identity file is missing')
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 63:
            raise ConfigError('identity file must be 0600/0400 (no group/other bits)')
        if path.stat().st_size == 0:
            raise ConfigError('identity file is empty')
        return 'private key present with private mode'

    def journal_check() -> str:
        parent = config.journal_path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise ConfigError('journal directory must exist and not be a symlink')
        if not _mode_ok(parent, allow_group=True):
            raise ConfigError('journal directory must not be world writable')
        if not os.access(parent, os.W_OK):
            raise ConfigError('journal directory is not writable')
        return 'journal directory writable'

    def binary_check() -> str:
        path = Path(config.ssh_binary)
        if not path.is_absolute():
            raise ConfigError('ssh_binary must be absolute')
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ConfigError('ssh_binary must be an executable file')
        return 'ssh binary executable'

    def plans_check() -> str:
        if not config.profiles:
            raise ConfigError('no trusted profile plans configured')
        return f'{len(config.profiles)} trusted profile plan(s)'
    one('ssh_config', ssh_config_check)
    one('identity_file', identity_check)
    one('journal_dir', journal_check)
    one('ssh_binary', binary_check)
    one('profile_plans', plans_check)
    return checks

@dataclass
class TransportResult:
    returncode: int | None = None
    stdout: bytes = b''
    stderr: bytes = b''
    timed_out: bool = False
    output_exceeded: bool = False
    spawn_error: str | None = None

class SshTransport:
    """One bounded ``ssh`` exchange per call. No retries, no shell, no agent.

    The argv below is the complete hardening surface required by the parent
    contract; ``HostName`` is pinned on the command line so no config file rule
    can redirect the destination.
    """

    def __init__(self, config: NodeAdapterConfig, *, spawn: Callable[[Sequence[str]], Any] | None=None):
        self.config = config
        self._spawn_override = spawn

    def build_argv(self, ip: str) -> list[str]:
        return [str(self.config.ssh_binary), '-F', str(self.config.ssh_config), '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'HostName=' + ip, '-o', f'ConnectTimeout={int(self.config.connect_timeout_seconds)}', '-p', str(self.config.port), '-i', str(self.config.identity_file), f'{self.config.user}@{ip}', protocol.SSH_COMMAND]

    def _child_env(self) -> dict[str, str]:
        """Minimal explicit environment: no SSH_AUTH_SOCK, no caller variables."""
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError):
            home = '/'
        return {'PATH': '/usr/bin:/bin', 'HOME': home, 'LC_ALL': 'C'}

    def _spawn(self, argv: Sequence[str]) -> Any:
        if self._spawn_override is not None:
            return self._spawn_override(argv)
        return subprocess.Popen(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._child_env(), close_fds=True)

    def _collect(self, proc: Any, payload: bytes, *, snapshot_deadline: float | None=None) -> TransportResult:
        out = bytearray()
        err = bytearray()
        timed_out = False
        exceeded = False
        child_error = None
        selector = None
        stdin = getattr(proc, 'stdin', None)
        deadline = time.monotonic() + self.config.timeout_seconds if snapshot_deadline is None else snapshot_deadline - 1.0
        written = 0
        try:
            selector = selectors.DefaultSelector()
            payload_view = memoryview(payload)
            if stdin is not None:
                os.set_blocking(stdin.fileno(), False)
                if payload_view:
                    selector.register(stdin, selectors.EVENT_WRITE, 'in')
                else:
                    stdin.close()
            streams = []
            if getattr(proc, 'stdout', None) is not None:
                streams.append((proc.stdout, 'out'))
            if getattr(proc, 'stderr', None) is not None:
                streams.append((proc.stderr, 'err'))
            for stream, kind in streams:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, kind)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    if key.data == 'in':
                        try:
                            written += os.write(key.fd, payload_view[written:])
                        except (BlockingIOError, InterruptedError):
                            continue
                        except (BrokenPipeError, OSError):
                            with contextlib.suppress(Exception):
                                selector.unregister(key.fileobj)
                            with contextlib.suppress(Exception):
                                key.fileobj.close()
                            continue
                        if written == len(payload_view):
                            with contextlib.suppress(Exception):
                                selector.unregister(key.fileobj)
                            with contextlib.suppress(Exception):
                                key.fileobj.close()
                        continue
                    try:
                        chunk = os.read(key.fd, 65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except (OSError, ValueError):
                        selector.unregister(key.fileobj)
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'out':
                        out.extend(chunk)
                        if len(out) > self.config.max_output_bytes:
                            exceeded = True
                    else:
                        room = self.config.max_stderr_bytes - len(err)
                        if room > 0:
                            err.extend(chunk[:room])
                if exceeded:
                    break
            if not timed_out and (not exceeded):
                try:
                    proc.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
            if timed_out or exceeded:
                with contextlib.suppress(Exception):
                    proc.kill()
                if snapshot_deadline is None:
                    with contextlib.suppress(Exception):
                        proc.poll()
                else:
                    try:
                        proc.wait(timeout=max(0.0, snapshot_deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        child_error = 'owned_snapshot_child_not_terminal'
                    except Exception:
                        child_error = 'owned_snapshot_child_terminal_unknown'
        except BaseException:
            if snapshot_deadline is not None:
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=max(0.0, snapshot_deadline - time.monotonic()))
            raise
        finally:
            with contextlib.suppress(Exception):
                selector.close()
            for stream in (stdin, getattr(proc, 'stdout', None), getattr(proc, 'stderr', None)):
                with contextlib.suppress(Exception):
                    if stream is not None:
                        stream.close()
        returncode = None
        with contextlib.suppress(Exception):
            returncode = proc.poll()
        return TransportResult(returncode=returncode, stdout=bytes(out), stderr=bytes(err), timed_out=timed_out, output_exceeded=exceeded, spawn_error=child_error)

    def exchange(self, ip: str, payload: bytes, *, scoped_owner_snapshot_timeout: float | None=None) -> TransportResult:
        snapshot_deadline = None
        if scoped_owner_snapshot_timeout is not None:
            if type(scoped_owner_snapshot_timeout) not in (int, float) or scoped_owner_snapshot_timeout != 20:
                raise ValueError('exact_owner_snapshot20_only')
            doc = json.loads(payload)
            if doc.get('action') != 'owner_recovery_snapshot' or doc.get('node') not in ('spark-a', 'spark-b') or (doc.get('profile'), doc.get('owner'), doc.get('generation')) != ('glm-ab', 'dgx-hx-service', 10) or (type(doc.get('generation')) is not int):
                raise ValueError('fixed_original_owner_snapshot_only')
            snapshot_deadline = time.monotonic() + 20.0
        argv = self.build_argv(ip)
        try:
            proc = self._spawn(argv)
        except OSError as exc:
            return TransportResult(spawn_error=f'{type(exc).__name__}: {exc}')
        return self._collect(proc, payload, snapshot_deadline=snapshot_deadline) if snapshot_deadline is not None else self._collect(proc, payload)

class IntentJournal:
    """Durable, flock-serialized ownership intent for each trusted profile.

    Stop/confirm_stop have no owner argument. A successful complete preflight
    may advance the binding to a newer generation; failed observations never
    replace the previous owner. A profile transition lock serializes preflight
    and start ownership decisions without blocking stop/confirm journal reads.
    """
    _RECORD_KEYS = frozenset({'generation', 'owner', 'nodes', 'status', 'updated_at'})
    _DOCUMENT_KEYS = frozenset({'schema', 'profiles'})

    def __init__(self, path: Path, *, clock: Callable[[], float]=time.time):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + '.lock')
        self._clock = clock
        self._mutex = threading.RLock()

    @staticmethod
    def _corrupt(reason: str) -> AdapterUnavailableError:
        return AdapterUnavailableError('journal_corrupt: lifecycle intent journal is invalid; refusing (fail closed)', details={'reason_code': reason})

    @staticmethod
    def _valid_profile(profile: Any) -> bool:
        return isinstance(profile, str) and bool(protocol.TOKEN_RE.fullmatch(profile))

    @classmethod
    def _validate_record(cls, profile: str, record: Any) -> None:
        if not cls._valid_profile(profile) or not isinstance(record, dict) or set(record) != cls._RECORD_KEYS:
            raise cls._corrupt('journal_bad_record')
        generation = record['generation']
        owner = record['owner']
        nodes = record['nodes']
        status = record['status']
        updated_at = record['updated_at']
        if type(generation) is not int or generation <= 0:
            raise cls._corrupt('journal_bad_generation')
        if not isinstance(owner, str) or not protocol.TOKEN_RE.fullmatch(owner):
            raise cls._corrupt('journal_bad_owner')
        if not isinstance(nodes, list) or not nodes or any((not isinstance(node, str) or not protocol.TOKEN_RE.fullmatch(node) for node in nodes)) or (len(set(nodes)) != len(nodes)):
            raise cls._corrupt('journal_bad_nodes')
        if not isinstance(status, str) or not status or len(status) > 64:
            raise cls._corrupt('journal_bad_status')
        if type(updated_at) not in (int, float) or (type(updated_at) is float and (not math.isfinite(updated_at))):
            raise cls._corrupt('journal_bad_timestamp')

    @staticmethod
    def _validate_intent(profile: str, generation: int, owner: str, nodes: Sequence[str], status: str) -> list[str]:
        if not isinstance(profile, str) or not protocol.TOKEN_RE.fullmatch(profile):
            raise AdapterUnavailableError('invalid_profile: refusing journal update', details={'reason_code': 'invalid_profile'})
        if type(generation) is not int or generation <= 0:
            raise AdapterUnavailableError('invalid_generation: refusing journal update', details={'reason_code': 'invalid_generation'})
        if not isinstance(owner, str) or not protocol.TOKEN_RE.fullmatch(owner):
            raise AdapterUnavailableError('invalid_owner: refusing journal update', details={'reason_code': 'invalid_owner'})
        if not isinstance(nodes, (list, tuple)) or not nodes or any((not isinstance(node, str) or not protocol.TOKEN_RE.fullmatch(node) for node in nodes)) or (len(set(nodes)) != len(nodes)):
            raise AdapterUnavailableError('invalid_nodes: refusing journal update', details={'reason_code': 'invalid_nodes'})
        if not isinstance(status, str) or not status or len(status) > 64:
            raise AdapterUnavailableError('invalid_status: refusing journal update', details={'reason_code': 'invalid_status'})
        return list(nodes)

    def _read_unlocked(self) -> dict:
        if not self.path.exists():
            return {'schema': JOURNAL_SCHEMA, 'profiles': {}}
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise AdapterUnavailableError('journal_corrupt: lifecycle intent journal cannot be read; refusing', details={'reason_code': 'journal_read_failed'}) from exc
        try:
            value = protocol.strict_json_loads(raw, max_bytes=262144)
        except ProtocolError as exc:
            raise AdapterUnavailableError('journal_corrupt: lifecycle intent journal is unreadable; refusing (fail closed)', details={'reason_code': f'journal_{exc.reason_code}'}) from exc
        if not isinstance(value, dict) or set(value) != self._DOCUMENT_KEYS or value.get('schema') != JOURNAL_SCHEMA or (not isinstance(value.get('profiles'), dict)):
            raise self._corrupt('journal_bad_shape')
        for profile, record in value['profiles'].items():
            self._validate_record(profile, record)
        return value

    @contextlib.contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 384)
        try:
            import fcntl
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AdapterUnavailableError('journal_busy: another writer holds the intent journal; refusing', details={'reason_code': 'journal_busy'})
                    time.sleep(0.05)
            yield
        finally:
            with contextlib.suppress(Exception):
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextlib.contextmanager
    def transition(self, profile: str):
        """Serialize one profile's ownership preflight/start decision."""
        if not self._valid_profile(profile):
            raise AdapterUnavailableError('invalid_profile: refusing transition', details={'reason_code': 'invalid_profile'})
        lock_path = self.path.with_name(self.path.name + f'.transition-{profile}.lock')
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 384)
        try:
            import fcntl
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AdapterUnavailableError('journal_busy: another profile transition is in progress; refusing', details={'reason_code': 'journal_busy'})
                    time.sleep(0.05)
            yield
        finally:
            with contextlib.suppress(Exception):
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write_unlocked(self, document: dict) -> None:
        data = json.dumps(document, sort_keys=True, separators=(',', ':')).encode('utf-8')
        tmp = self.path.with_name(self.path.name + f'.tmp-{os.getpid()}-{threading.get_ident()}')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()

    def _record_values(self, profile: str, generation: int, owner: str, nodes: Sequence[str], status: str) -> dict[str, Any]:
        checked_nodes = self._validate_intent(profile, generation, owner, nodes, status)
        updated_at = self._clock()
        if type(updated_at) not in (int, float) or (type(updated_at) is float and (not math.isfinite(updated_at))):
            raise AdapterUnavailableError('invalid_clock: refusing journal update', details={'reason_code': 'invalid_clock'})
        return {'generation': generation, 'owner': owner, 'nodes': checked_nodes, 'status': status, 'updated_at': updated_at}

    @staticmethod
    def _check_existing_identity(current: dict, *, owner: str, nodes: list[str]) -> None:
        if current['owner'] != owner:
            raise AdapterUnavailableError('recorded_owner_mismatch: a lifecycle intent for this generation already exists with a different owner; refusing', details={'reason_code': 'recorded_owner_mismatch', 'generation': current['generation']})
        if set(current['nodes']) != set(nodes):
            raise AdapterUnavailableError('recorded_nodes_mismatch: a lifecycle intent for this generation names different nodes; refusing', details={'reason_code': 'recorded_nodes_mismatch', 'generation': current['generation']})

    def _save_record_unlocked(self, document: dict, profile: str, record: dict[str, Any]) -> None:
        document['profiles'][profile] = record
        try:
            self._write_unlocked(document)
        except OSError as exc:
            raise AdapterUnavailableError('journal_write_failed: lifecycle intent could not be made durable; refusing', details={'reason_code': 'journal_write_failed'}) from exc

    def record(self, *, profile: str, generation: int, owner: str, nodes: Sequence[str], status: str) -> None:
        """Persist same-generation lifecycle progress; never supersede a binding."""
        record = self._record_values(profile, generation, owner, nodes, status)
        with self._mutex, self._locked():
            document = self._read_unlocked()
            current = document['profiles'].get(profile)
            if current is not None:
                if current['generation'] > generation:
                    return
                if current['generation'] == generation:
                    self._check_existing_identity(current, owner=owner, nodes=record['nodes'])
                else:
                    raise AdapterUnavailableError('preflight_required: a newer generation can only replace the journal after complete clear preflight; refusing', details={'reason_code': 'preflight_required', 'profile': profile, 'generation': generation})
            self._save_record_unlocked(document, profile, record)

    def bind_preflight_clear(self, *, profile: str, generation: int, owner: str, nodes: Sequence[str]) -> None:
        """Commit a new generation only after every node positively reports clear."""
        record = self._record_values(profile, generation, owner, nodes, 'preflight_clear')
        with self._mutex, self._locked():
            document = self._read_unlocked()
            current = document['profiles'].get(profile)
            if current is not None:
                if current['generation'] > generation:
                    raise AdapterUnavailableError('stale_generation: a newer lifecycle binding already exists; refusing', details={'reason_code': 'stale_generation', 'profile': profile, 'generation': generation})
                if current['generation'] == generation:
                    self._check_existing_identity(current, owner=owner, nodes=record['nodes'])
            self._save_record_unlocked(document, profile, record)

    def latest(self, profile: str) -> dict | None:
        """Return the validated current record, or ``None``."""
        if not self._valid_profile(profile):
            raise AdapterUnavailableError('invalid_profile: refusing journal lookup', details={'reason_code': 'invalid_profile'})
        with self._mutex, self._locked():
            document = self._read_unlocked()
            record = document['profiles'].get(profile)
        return record

    def lookup(self, profile: str, generation: int) -> dict | None:
        """Return the validated intent for this exact generation, or ``None``."""
        if type(generation) is not int or generation <= 0:
            raise AdapterUnavailableError('invalid_generation: refusing journal lookup', details={'reason_code': 'invalid_generation'})
        record = self.latest(profile)
        if record is None or record['generation'] != generation:
            return None
        return record

class NodeAdapter:
    """Fail-closed implementation of the frozen v2 adapter contract."""
    name = ADAPTER_NAME

    def __init__(self, config: NodeAdapterConfig, *, transport: Any | None=None, clock: Callable[[], float] | None=None):
        if not isinstance(config, NodeAdapterConfig):
            raise ConfigError('NodeAdapter requires a NodeAdapterConfig (use config_from_mapping/load_config)')
        self.config = config
        self._clock = clock or time.time
        self._transport = transport if transport is not None else SshTransport(config)
        self._journal = IntentJournal(config.journal_path, clock=self._clock)

    def capabilities(self) -> dict[str, Any]:
        checks = static_checks(self.config)
        available = bool(self.config.enabled) and all((ok for _name, ok, _detail in checks))
        failed = [name for name, ok, _detail in checks if not ok]
        if not self.config.enabled:
            reason = 'adapter disabled by configuration (enabled=false); lifecycle operations refused (fail closed)'
        elif failed:
            reason = f"trusted configuration incomplete: {', '.join(failed)}; refusing (fail closed)"
        else:
            reason = 'trusted configuration complete; note that live integration is still parent-owned'
        return {'adapter': self.name, 'available': available, 'fixture_only': False, 'contract': protocol.SCHEMA, 'reason': reason, 'checks': {name: {'ok': ok, 'detail': detail} for name, ok, detail in checks}, 'limitations': ['v2 stop/confirm_stop carry no owner: owner is bound from the local intent journal', 'generations reserved but never preflighted have no recorded owner; stop/release refuse', "evidence timestamps use the manager's clock domain; node clock is skew-checked only", 'wire reconcile/release actions exist node-side but are not part of v2; exposed as helpers']}

    def _require_usable(self) -> None:
        caps = self.capabilities()
        if not caps['available']:
            raise AdapterUnavailableError('node_adapter_unavailable: ' + str(caps['reason']), details={'adapter': self.name, 'reason_code': 'node_adapter_unavailable'})

    def _plan(self, profile: str) -> ProfilePlan:
        plan = self.config.profiles.get(profile)
        if plan is None:
            raise AdapterUnavailableError(f'profile_plan_unknown: no trusted launch plan for profile {profile!r}; refusing', details={'profile': profile, 'reason_code': 'profile_plan_unknown'})
        return plan

    def _checked_nodes(self, profile: str, nodes: Sequence[str]) -> list[str]:
        plan = self._plan(profile)
        if not isinstance(nodes, (list, tuple)) or not nodes:
            raise AdapterUnavailableError('invalid_nodes: a non-empty node list is required', details={'profile': profile, 'reason_code': 'invalid_nodes'})
        result = [str(n) for n in nodes]
        if set(result) != set(plan.nodes) or len(result) != len(plan.nodes):
            raise AdapterUnavailableError('profile_nodes_mismatch: requested nodes do not match the trusted plan; refusing', details={'profile': profile, 'requested': result, 'trusted': list(plan.nodes), 'reason_code': 'profile_nodes_mismatch'})
        for node in result:
            if node not in self.config.hosts:
                raise AdapterUnavailableError(f'unknown_node: no pinned host for node {node!r}', details={'node': node, 'reason_code': 'unknown_node'})
        return result

    def _checked_generation(self, generation: Any) -> int:
        try:
            return protocol.require_generation(generation)
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc

    def _exchange(self, node: str, action: str, *, profile: str | None=None, owner: str | None=None, generation: int | None=None, scoped_owner_snapshot_timeout: float | None=None) -> tuple[dict | None, dict[str, Any]]:
        """One ssh exchange. Returns ``(reply | None, meta)``; never retries."""
        if scoped_owner_snapshot_timeout is not None:
            if type(scoped_owner_snapshot_timeout) not in (int, float) or scoped_owner_snapshot_timeout != 20 or action != 'owner_recovery_snapshot' or (node not in ('spark-a', 'spark-b')) or ((profile, owner, generation) != ('glm-ab', 'dgx-hx-service', 10)) or (type(generation) is not int) or (not isinstance(self._transport, SshTransport)):
                raise ValueError('exact_original_owner_snapshot_transport20_only')
        request_id = secrets.token_hex(16)
        request: dict[str, Any] = {'schema': protocol.SCHEMA, 'request_id': request_id, 'action': action, 'node': node}
        identity: tuple[str, str, int] | None = None
        if profile is not None and owner is not None and (generation is not None):
            request['profile'] = profile
            request['owner'] = owner
            request['generation'] = int(generation)
            identity = (profile, owner, int(generation))
        try:
            payload = protocol.encode_request(request, max_bytes=self.config.max_request_bytes)
        except ProtocolError as exc:
            return (None, {'node': node, 'action': action, 'request_id': request_id, 'received_at': self._clock(), 'reason': f'request_{exc.reason_code}', 'stderr_tail': ''})
        sent_at = self._clock()
        result = self._transport.exchange(self.config.hosts[node], payload, scoped_owner_snapshot_timeout=scoped_owner_snapshot_timeout) if scoped_owner_snapshot_timeout is not None else self._transport.exchange(self.config.hosts[node], payload)
        received_at = self._clock()
        meta: dict[str, Any] = {'node': node, 'action': action, 'request_id': request_id, 'received_at': received_at, 'remote_observed_at': None, 'reason': None, 'stderr_tail': protocol.sanitize_stderr(result.stderr)}
        if result.spawn_error:
            meta['reason'] = 'ssh_spawn_error'
            return (None, meta)
        if result.timed_out:
            meta['reason'] = 'ssh_timeout'
            return (None, meta)
        if result.output_exceeded:
            meta['reason'] = 'ssh_output_exceeded'
            return (None, meta)
        if result.returncode != 0:
            meta['reason'] = f'ssh_exit_{result.returncode}'
            return (None, meta)
        try:
            reply = protocol.validate_reply(result.stdout, expect_action=action, expect_node=node, expect_request_id=request_id, identity=identity, max_bytes=self.config.max_output_bytes, sent_at=sent_at, received_at=received_at, max_skew_seconds=self.config.max_clock_skew_seconds)
        except ProtocolError as exc:
            meta['reason'] = f'invalid_reply:{exc.reason_code}'
            return (None, meta)
        meta['remote_observed_at'] = reply.get('observed_at')
        return (reply, meta)

    def probe(self, node: str) -> dict[str, Any]:
        self._require_usable()
        observed = self._clock()
        if node not in self.config.hosts:
            return {'node': node, 'reachable': False, 'healthy': False, 'reason': 'unknown_node', 'observed_at': observed}
        reply, meta = self._exchange(node, 'probe')
        if reply is None:
            return {'node': node, 'reachable': False, 'healthy': False, 'reason': meta['reason'], 'observed_at': meta['received_at']}
        healthy = False
        reason = reply.get('reason_code') or 'unhealthy'
        if reply.get('status') == 'ok' and reply.get('healthy') is True:
            healthy = True
            reason = 'node_ok'
        item: dict[str, Any] = {'node': node, 'reachable': True, 'healthy': healthy, 'reason': reason, 'observed_at': meta['received_at']}
        memory = self._memory_view(reply)
        if memory is not None:
            item['memory'] = memory
        return item

    @staticmethod
    def _memory_view(reply: dict) -> dict[str, Any] | None:
        """Surface a node memory observation only when it is finite and sane.

        ``null`` (N/A) or 0/negative/oversized values are dropped, never coerced
        to 0 — a missing calibration stays missing.
        """
        memory = reply.get('memory')
        if not isinstance(memory, dict):
            return None
        total = memory.get('mem_total_bytes')
        available = memory.get('mem_available_bytes')
        if isinstance(total, bool) or not isinstance(total, int) or total <= 0:
            return None
        if isinstance(available, bool) or not isinstance(available, int) or available < 0 or (available > total):
            return None
        source = memory.get('source')
        return {'mem_total_bytes': int(total), 'mem_available_bytes': int(available), 'source': source if isinstance(source, str) and source else 'unknown'}

    def preflight(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        try:
            generation = protocol.require_generation(generation)
            owner = protocol.require_token(owner, 'owner')
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc
        with self._journal.transition(profile):
            self._check_recorded_owner(profile, generation, owner)
            latest = self._journal.latest(profile)
            if latest is not None and latest['generation'] > generation:
                raise AdapterUnavailableError('stale_generation: a newer lifecycle binding already exists; refusing', details={'reason_code': 'stale_generation', 'profile': profile, 'generation': generation})
            per_node: dict[str, Any] = {}
            for node in nodes:
                reply, meta = self._exchange(node, 'preflight', profile=profile, owner=owner, generation=generation)
                per_node[node] = self._preflight_node(node, reply, meta)
            clear = all((item.get('clear') is True for item in per_node.values()))
            if clear:
                self._journal.bind_preflight_clear(profile=profile, generation=generation, owner=owner, nodes=nodes)
        return {'clear': clear, 'profile': profile, 'owner': owner, 'generation': generation, 'nodes': per_node, 'observed_at': self._clock(), 'reason_code': 'clear' if clear else 'preflight_refused'}

    def _preflight_node(self, node: str, reply: dict | None, meta: dict[str, Any]) -> dict[str, Any]:
        item: dict[str, Any] = {'clear': False, 'observed_at': meta['received_at'], 'reason': 'unknown'}
        if reply is None:
            item['reason'] = meta['reason']
            return item
        memory = self._memory_view(reply)
        if memory is not None:
            item['memory'] = memory
        if reply.get('status') != 'ok':
            item['reason'] = reply.get('reason_code') or 'refused'
            return item
        gpu = reply.get('gpu')
        enumeration = gpu.get('enumeration') if isinstance(gpu, dict) else None
        if reply.get('clear') is not True or enumeration != 'complete':
            item['reason'] = reply.get('reason_code') or 'gpu_not_clear'
            if isinstance(gpu, dict):
                item['gpu'] = {'enumeration': enumeration, 'reasons': list(gpu.get('reasons', []))[:8], 'process_count': gpu.get('process_count'), 'gpu_container_count': gpu.get('gpu_container_count')}
            return item
        item['clear'] = True
        item['reason'] = 'gpu_clear'
        return item

    def start(self, profile: str, *, nodes: list[str], generation: int, env: dict[str, Any]) -> dict[str, Any]:
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        try:
            generation = protocol.require_generation(generation)
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc
        owner = self._env_owner(profile, generation, env)
        with self._journal.transition(profile):
            self._check_recorded_owner(profile, generation, owner)
            latest = self._journal.latest(profile)
            if latest is not None and latest['generation'] > generation:
                raise AdapterUnavailableError('stale_generation: a newer lifecycle binding already exists; refusing', details={'reason_code': 'stale_generation', 'profile': profile, 'generation': generation})
            if latest is not None and latest['generation'] < generation:
                raise AdapterUnavailableError('preflight_required: a newer generation needs a successful complete preflight before start', details={'reason_code': 'preflight_required', 'profile': profile, 'generation': generation})
            self._journal.record(profile=profile, generation=generation, owner=owner, nodes=nodes, status='start_requested')
        claims: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'claim', profile=profile, owner=owner, generation=generation)
            claims[node] = self._claim_node(node, reply, meta)
        if not all((item.get('claimed') is True for item in claims.values())):
            self._journal.record(profile=profile, generation=generation, owner=owner, nodes=nodes, status='claim_failed')
            return {'started': False, 'uncertain': True, 'reason_code': 'claim_failed', 'profile': profile, 'generation': generation, 'nodes': claims, 'holds_retained': True, 'note': 'successful node claims are retained; no automatic rollback (a rollback could kill a newer generation). Operator reconciliation required.'}
        starts: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'start', profile=profile, owner=owner, generation=generation)
            starts[node] = self._start_node(node, reply, meta)
        if not all((item.get('started') is True for item in starts.values())):
            self._journal.record(profile=profile, generation=generation, owner=owner, nodes=nodes, status='start_partial')
            return {'started': False, 'uncertain': True, 'reason_code': 'partial_start', 'profile': profile, 'generation': generation, 'owner': owner, 'nodes': starts, 'holds_retained': True, 'note': 'multi-rank start is incomplete; claims and any started ranks are retained; no automatic rollback. Readiness is not claimed.'}
        self._journal.record(profile=profile, generation=generation, owner=owner, nodes=nodes, status='started')
        return {'started': True, 'profile': profile, 'generation': generation, 'owner': owner, 'nodes': starts, 'observed_at': self._clock(), 'note': 'start acknowledgement only; readiness still requires probe_ready'}

    def _env_owner(self, profile: str, generation: int, env: dict[str, Any]) -> str:
        """The manager passes exactly {profile, generation, owner}; nothing else is accepted."""
        if not isinstance(env, dict):
            raise AdapterUnavailableError('invalid_env: start env must be an object', details={'reason_code': 'invalid_env'})
        allowed = {'profile', 'generation', 'owner'}
        unknown = sorted((str(k) for k in env if k not in allowed))
        if unknown or set(env) != allowed:
            raise AdapterUnavailableError('invalid_env: start env must be exactly profile/generation/owner; caller launch parameters are never accepted (the launch plan is pinned in trusted configuration)', details={'reason_code': 'invalid_env', 'unknown_keys': unknown})
        try:
            env_generation = protocol.require_generation(env.get('generation'))
            owner = protocol.require_token(env.get('owner'), 'owner')
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_env: {exc.reason_code}', details={'reason_code': 'invalid_env'}) from exc
        if env.get('profile') != profile or env_generation != generation:
            raise AdapterUnavailableError('invalid_env: env identity does not match the start request', details={'reason_code': 'invalid_env'})
        return owner

    def _claim_node(self, node: str, reply: dict | None, meta: dict[str, Any]) -> dict[str, Any]:
        if reply is None:
            return {'claimed': False, 'reason': meta['reason'], 'observed_at': meta['received_at']}
        if reply.get('status') != 'ok':
            return {'claimed': False, 'reason': reply.get('reason_code') or 'refused', 'record_state': reply.get('record_state'), 'observed_at': meta['received_at']}
        if reply.get('claimed') is not True:
            return {'claimed': False, 'reason': 'claim_not_confirmed', 'observed_at': meta['received_at']}
        return {'claimed': True, 'reason': 'claimed', 'observed_at': meta['received_at']}

    def _start_node(self, node: str, reply: dict | None, meta: dict[str, Any]) -> dict[str, Any]:
        if reply is None:
            return {'started': False, 'container_id': None, 'reason': meta['reason'], 'observed_at': meta['received_at']}
        if reply.get('status') != 'ok':
            return {'started': False, 'container_id': None, 'reason': reply.get('reason_code') or 'refused', 'observed_at': meta['received_at']}
        container_id = reply.get('container_id')
        try:
            container_id = protocol.require_container_id(container_id, 'container_id')
        except ProtocolError:
            return {'started': False, 'container_id': None, 'reason': 'invalid_container_id', 'observed_at': meta['received_at']}
        if reply.get('started') is not True:
            return {'started': False, 'container_id': container_id, 'reason': 'start_not_confirmed', 'observed_at': meta['received_at']}
        return {'started': True, 'container_id': container_id, 'reason': 'started', 'observed_at': meta['received_at']}

    def probe_ready(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        self._require_usable()
        plan = self._plan(profile)
        nodes = self._checked_nodes(profile, nodes)
        try:
            generation = protocol.require_generation(generation)
            owner = protocol.require_token(owner, 'owner')
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc
        self._check_recorded_owner(profile, generation, owner)
        per_node: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'probe_ready', profile=profile, owner=owner, generation=generation)
            per_node[node] = self._ready_node(node, reply, meta, plan, profile=profile, owner=owner, generation=generation)
        healthy = all((item.get('healthy') is True for item in per_node.values()))
        return {'healthy': healthy, 'profile': profile, 'owner': owner, 'generation': generation, 'model_id': plan.model_id if healthy else None, 'nodes': per_node, 'observed_at': self._clock(), 'reason_code': 'healthy' if healthy else 'ready_refused'}

    def _ready_node(self, node: str, reply: dict | None, meta: dict[str, Any], plan: ProfilePlan, *, profile: str, owner: str, generation: int) -> dict[str, Any]:
        item: dict[str, Any] = {'healthy': False, 'observed_at': meta['received_at'], 'reason': 'unknown'}
        if reply is None:
            item['reason'] = meta['reason']
            return item
        if reply.get('status') != 'ok':
            item['reason'] = reply.get('reason_code') or 'refused'
            return item
        role = plan.roles.get(node) if plan.roles is not None else None
        if role is not None and reply.get('role') != role:
            item['reason'] = 'role_mismatch'
            return item
        if reply.get('healthy') is not True:
            item['reason'] = reply.get('reason_code') or 'unhealthy'
            return item
        if role == ROLE_WORKER:
            if reply.get('api_checked') is not False or 'model_id' in reply:
                item['reason'] = 'worker_api_evidence_invalid'
                return item
            if reply.get('process_verified') is not True:
                item['reason'] = 'worker_process_unverified'
                return item
        elif role == ROLE_API_LEADER and reply.get('api_checked') is not True:
            item['reason'] = 'leader_api_unchecked'
            return item
        if role != ROLE_WORKER and reply.get('model_id') != plan.model_id:
            item['reason'] = 'model_id_mismatch'
            item['observed_model_id'] = reply.get('model_id')
            return item
        record = reply.get('record')
        if not isinstance(record, dict) or record.get('state') != 'RUNNING':
            item['reason'] = 'record_mismatch'
            return item
        if role is not None and (record.get('profile') != profile or record.get('owner') != owner or isinstance(record.get('generation'), bool) or (record.get('generation') != generation)):
            item['reason'] = 'record_mismatch'
            return item
        container_id = record.get('container_id')
        try:
            container_id = protocol.require_container_id(container_id, 'record.container_id')
        except ProtocolError:
            item['reason'] = 'record_mismatch'
            return item
        if role == ROLE_WORKER:
            proof = reply.get('worker_proof')
            if not isinstance(proof, dict) or proof.get('container_id') != container_id:
                item['reason'] = 'worker_proof_mismatch'
                return item
            image = proof.get('image')
            if not isinstance(image, str) or not protocol.IMAGE_REFERENCE_RE.fullmatch(image):
                item['reason'] = 'worker_proof_mismatch'
                return item
            item.update(healthy=True, reason='worker_process_verified', role=ROLE_WORKER, api_checked=False, process_verified=True, container_id=container_id, worker_proof=proof)
            return item
        item['healthy'] = True
        item['reason'] = 'model_serving'
        item['model_id'] = plan.model_id
        item['container_id'] = container_id
        if role is not None:
            item.update(role=role, api_checked=True)
        return item

    def _check_recorded_owner(self, profile: str, generation: int, owner: str) -> None:
        record = self._journal.lookup(profile, generation)
        if record is not None and record['owner'] != owner:
            raise AdapterUnavailableError('recorded_owner_mismatch: a lifecycle intent for this generation already exists with a different owner; refusing', details={'reason_code': 'recorded_owner_mismatch', 'profile': profile, 'generation': generation})

    def _expected_owner(self, profile: str, generation: int) -> str:
        record = self._journal.lookup(profile, generation)
        if record is None:
            raise AdapterUnavailableError('no_recorded_lifecycle_intent: refusing to act without the owner recorded when this generation was preflighted/started; caller-supplied owner evidence is never accepted', details={'reason_code': 'no_recorded_lifecycle_intent', 'profile': profile, 'generation': generation})
        return record['owner']

    def stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        try:
            generation = protocol.require_generation(generation)
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc
        owner = self._expected_owner(profile, generation)
        self._journal.record(profile=profile, generation=generation, owner=owner, nodes=nodes, status='stop_requested')
        per_node: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'stop', profile=profile, owner=owner, generation=generation)
            per_node[node] = self._stop_node(node, reply, meta)
        requested = [node for node, item in per_node.items() if item.get('stop_requested') is True]
        return {'stopped': False, 'stop_requested': len(requested) == len(nodes), 'requested_nodes': sorted(requested), 'profile': profile, 'generation': generation, 'nodes': per_node, 'observed_at': self._clock(), 'reason_code': 'stop_requested' if len(requested) == len(nodes) else 'stop_request_incomplete', 'note': 'stop acknowledgement is not stopped confirmation; confirm_stop must positively observe disappearance with a full successful enumeration'}

    def _stop_node(self, node: str, reply: dict | None, meta: dict[str, Any]) -> dict[str, Any]:
        item: dict[str, Any] = {'stop_requested': False, 'observed_at': meta['received_at'], 'reason': 'unknown'}
        if reply is None:
            item['reason'] = meta['reason']
            return item
        if reply.get('status') != 'ok':
            item['reason'] = reply.get('reason_code') or 'refused'
            return item
        item['stop_requested'] = reply.get('stop_requested') is True
        item['reason'] = reply.get('reason_code') or ('stop_requested' if item['stop_requested'] else 'no_container')
        stop_action = reply.get('stop_action')
        if isinstance(stop_action, str) and len(stop_action) <= 32:
            item['stop_action'] = stop_action
        container_id = reply.get('container_id')
        if isinstance(container_id, str) and protocol.CONTAINER_ID_RE.fullmatch(container_id):
            item['container_id'] = container_id
        return item

    def confirm_stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        try:
            generation = protocol.require_generation(generation)
        except ProtocolError as exc:
            raise AdapterUnavailableError(f'invalid_request: {exc.reason_code}', details={'reason_code': exc.reason_code}) from exc
        owner = self._expected_owner(profile, generation)
        per_node: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'confirm_stop', profile=profile, owner=owner, generation=generation)
            per_node[node] = self._confirm_node(node, reply, meta)
        stopped = all((item.get('stopped') is True for item in per_node.values()))
        return {'stopped': stopped, 'profile': profile, 'generation': generation, 'nodes': per_node, 'unknown_nodes': sorted((node for node, item in per_node.items() if item.get('stopped') is not True)), 'observed_at': self._clock(), 'reason_code': 'no_owned_work_observed' if stopped else 'stop_unconfirmed'}

    def _confirm_node(self, node: str, reply: dict | None, meta: dict[str, Any]) -> dict[str, Any]:
        item: dict[str, Any] = {'stopped': False, 'observed_at': meta['received_at'], 'reason': 'unknown'}
        if reply is None:
            item['reason'] = meta['reason']
            return item
        if reply.get('status') != 'ok':
            item['reason'] = reply.get('reason_code') or 'refused'
            return item
        if reply.get('container_absent') is not True:
            item['reason'] = reply.get('reason_code') or 'container_not_absent'
            return item
        gpu = reply.get('gpu')
        enumeration = gpu.get('enumeration') if isinstance(gpu, dict) else None
        if enumeration != 'complete':
            item['reason'] = reply.get('reason_code') or 'enumeration_unknown'
            return item
        if gpu.get('empty') is not True:
            item['reason'] = reply.get('reason_code') or 'gpu_not_empty'
            return item
        if reply.get('stopped') is not True:
            item['reason'] = reply.get('reason_code') or 'stop_not_confirmed'
            return item
        item['stopped'] = True
        item['reason'] = 'no_owned_work_observed'
        item['source_observed_at'] = reply.get('observed_at')
        record_state = reply.get('record_state')
        if isinstance(record_state, str):
            item['record_state'] = record_state
        return item

    def reconcile(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        """Wire ``reconcile`` observation (not part of the frozen v2 contract)."""
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        generation = self._checked_generation(generation)
        owner = self._expected_owner(profile, generation)
        per_node: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'reconcile', profile=profile, owner=owner, generation=generation)
            if reply is None:
                per_node[node] = {'observed': 'unknown', 'reason': meta['reason'], 'observed_at': meta['received_at']}
            else:
                per_node[node] = {'observed': reply.get('observed'), 'record_state': reply.get('record_state'), 'consistent': reply.get('consistent'), 'quarantined': reply.get('quarantined'), 'reason': reply.get('reason_code') or reply.get('status'), 'observed_at': meta['received_at']}
        return {'profile': profile, 'generation': generation, 'nodes': per_node, 'observed_at': self._clock()}

    def release(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        """Wire ``release`` for claim-only cleanup (not part of the frozen v2 contract).

        The manager's release path uses ``confirm_stop`` evidence instead; this
        helper exists for a future operator CLI and for tests.
        """
        self._require_usable()
        nodes = self._checked_nodes(profile, nodes)
        generation = self._checked_generation(generation)
        owner = self._expected_owner(profile, generation)
        per_node: dict[str, Any] = {}
        for node in nodes:
            reply, meta = self._exchange(node, 'release', profile=profile, owner=owner, generation=generation)
            if reply is None:
                per_node[node] = {'released': False, 'reason': meta['reason'], 'observed_at': meta['received_at']}
            else:
                per_node[node] = {'released': reply.get('status') == 'ok' and reply.get('released') is True, 'reason': reply.get('reason_code') or reply.get('status'), 'observed_at': meta['received_at']}
        released = all((item.get('released') is True for item in per_node.values()))
        return {'released': released, 'profile': profile, 'generation': generation, 'nodes': per_node, 'observed_at': self._clock()}
