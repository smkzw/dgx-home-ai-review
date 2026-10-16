# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit trusted-config construction and process-lifetime maintenance lease."""
from __future__ import annotations
import errno
import fcntl
import ipaddress
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from control_plane import config as control_config
from control_plane.manager import Manager
from control_plane.store import open_store
from llm_gateway import upstream
from llm_gateway.config import GatewayConfig, load_gateway_config
from llm_gateway.registry import TokenRegistry, read_private_json
from llm_gateway.server import GatewayServer
from llm_gateway.state import open_gateway_store
from node_adapter.client import NodeAdapter, NodeAdapterConfig, load_config as load_node_config, static_checks
from .facade import LoopbackActiveWorkProbe, ManagerBackendFacade, ProfileBinding
SERVICE_SCHEMA = 'dgx-v4-hx-service-v1'
MAINTENANCE_LOCK_PATH = Path('/srv/dgx-home-ai/runtime/MAINTENANCE.lock')
_OWNER_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\Z')
_PROFILE_RE = re.compile('[a-z0-9][a-z0-9._-]{0,63}\\Z')
_TOP_KEYS = frozenset({'schema', 'enabled', 'service_owner', 'state_root', 'profiles_file', 'node_adapter_config', 'gateway_config', 'profiles'})
_PROFILE_KEYS = frozenset({'enabled', 'active_work_path'})

class ServiceConfigError(ValueError):
    """Explicit HX service configuration is structurally or operationally unsafe."""

class MaintenanceLockBusy(RuntimeError):
    """Another maintenance or manager owner holds the physical process lease."""

class MaintenanceLeaseError(RuntimeError):
    """The maintenance lock could not be safely opened or held."""

@dataclass(frozen=True)
class ProfileActivation:
    enabled: bool
    active_work_path: str

@dataclass(frozen=True)
class ServiceConfig:
    source_path: Path
    enabled: bool
    service_owner: str
    state_root: Path
    profiles_file: Path
    node_adapter_config: Path
    gateway_config: Path
    profiles: Mapping[str, ProfileActivation]

class MaintenanceLease:
    """Non-blocking FLOCK on the keeper's exact path; never expires or takes over."""

    def __init__(self, path: Path | str=MAINTENANCE_LOCK_PATH):
        self.path = Path(path)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> 'MaintenanceLease':
        if self._fd is not None:
            raise MaintenanceLeaseError('maintenance lease already held by this object')
        flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        try:
            fd = os.open(self.path, flags, 384)
        except OSError as exc:
            raise MaintenanceLeaseError('maintenance lock path is unavailable') from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 18:
                raise MaintenanceLeaseError('maintenance lock must be a regular non-writable-by-group/world file')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                    raise MaintenanceLockBusy('maintenance flock is already held') from exc
                raise MaintenanceLeaseError('maintenance flock could not be acquired') from exc
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = (self._fd, None)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> 'MaintenanceLease':
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def _reject_json_constant(value: str) -> Any:
    raise ValueError(f'non-finite JSON constant {value}')

def _finite_json_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('non-finite JSON number')
    return value

def _require_unambiguous_json_file(path: Path, label: str) -> None:
    try:
        raw = path.read_bytes()
        if len(raw) > 1048576:
            raise ValueError('configuration exceeds the size limit')
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_json_constant, parse_float=_finite_json_float)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ServiceConfigError(f'{label} is ambiguous, malformed, or oversized') from exc
    if not isinstance(document, dict):
        raise ServiceConfigError(f'{label} must be a JSON object')

def load_service_config(path: Path | str) -> ServiceConfig:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise ServiceConfigError('service configuration must be a regular non-symlink file')
    if source.stat().st_mode & 18:
        raise ServiceConfigError('service configuration must not be group/world writable')
    if source.stat().st_size > 262144:
        raise ServiceConfigError('service configuration exceeds the size limit')
    try:
        document = json.loads(source.read_text(encoding='utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_json_constant, parse_float=_finite_json_float)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ServiceConfigError('service configuration is unreadable or malformed') from exc
    if not isinstance(document, dict) or set(document) != _TOP_KEYS:
        raise ServiceConfigError('service configuration must contain exactly the declared top-level keys')
    if document.get('schema') != SERVICE_SCHEMA:
        raise ServiceConfigError('unsupported HX service configuration schema')
    enabled = document.get('enabled')
    if not isinstance(enabled, bool):
        raise ServiceConfigError('enabled must be an explicit boolean')
    owner = document.get('service_owner')
    if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner):
        raise ServiceConfigError('service_owner must be a fixed opaque token')
    state_root_raw = document.get('state_root')
    if not isinstance(state_root_raw, str) or not Path(state_root_raw).is_absolute():
        raise ServiceConfigError('state_root must be an explicit absolute path')
    state_root = Path(state_root_raw)
    base = source.absolute().parent

    def config_path(key: str) -> Path:
        value = document.get(key)
        if not isinstance(value, str) or not value.strip() or '$' in value or value.startswith('~'):
            raise ServiceConfigError(f'{key} must be an explicit path without shell/environment expansion')
        candidate = Path(value)
        return candidate if candidate.is_absolute() else base / candidate
    profiles_raw = document.get('profiles')
    if not isinstance(profiles_raw, dict) or not profiles_raw:
        raise ServiceConfigError('profiles must be a non-empty trusted object')
    profiles: dict[str, ProfileActivation] = {}
    for name, raw in profiles_raw.items():
        if not isinstance(name, str) or not _PROFILE_RE.fullmatch(name):
            raise ServiceConfigError('invalid service profile name')
        if not isinstance(raw, dict) or set(raw) != _PROFILE_KEYS:
            raise ServiceConfigError(f'profiles.{name} must contain exactly enabled and active_work_path')
        profile_enabled = raw.get('enabled')
        path = raw.get('active_work_path')
        if not isinstance(profile_enabled, bool) or not isinstance(path, str):
            raise ServiceConfigError(f'profiles.{name} has invalid enabled/path types')
        if path:
            _validate_fixed_path(path, name)
        if profile_enabled and (not path):
            raise ServiceConfigError(f'enabled profile {name} requires an engine-observed active_work_path')
        profiles[name] = ProfileActivation(profile_enabled, path)
    return ServiceConfig(source_path=source.absolute(), enabled=enabled, service_owner=owner, state_root=state_root, profiles_file=config_path('profiles_file'), node_adapter_config=config_path('node_adapter_config'), gateway_config=config_path('gateway_config'), profiles=MappingProxyType(profiles))

def _validate_fixed_path(path: str, profile: str) -> None:
    if not path.startswith('/') or path.startswith('//') or '?' in path or ('#' in path) or ('\\' in path) or any((part in {'.', '..'} for part in path.split('/'))) or any((ord(char) < 33 or ord(char) == 127 for char in path)) or (len(path) > 256):
        raise ServiceConfigError(f'profiles.{profile}.active_work_path must be one fixed absolute HTTP path')

def _trusted_config_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ServiceConfigError(f'{label} is missing or unreadable') from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 18:
        raise ServiceConfigError(f'{label} must be a regular non-symlink file not writable by group/world')

def _require_qualified(spec: Mapping[str, Any], nodes: tuple[str, ...], profile: str) -> None:
    if spec.get('hardware_validated') is not True:
        raise ServiceConfigError(f'enabled profile {profile} is not hardware-qualified')
    calibration = spec.get('min_start_available_gib')
    if not isinstance(calibration, Mapping) or set(calibration) != set(nodes):
        raise ServiceConfigError(f'enabled profile {profile} lacks exact per-node calibration')
    for node in nodes:
        value = calibration.get(node)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ServiceConfigError(f'enabled profile {profile} has invalid calibration for {node}')
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite or value <= 0:
            raise ServiceConfigError(f'enabled profile {profile} has invalid calibration for {node}')

def _check_gateway_profile_set(gateway: GatewayConfig, service: ServiceConfig) -> None:
    backend_profiles = set(gateway.backends)
    if backend_profiles != set(service.profiles):
        raise ServiceConfigError('gateway backends and explicit HX profile activations must match exactly')
    used = {model.profile for model in gateway.models.values()}
    if used != backend_profiles:
        raise ServiceConfigError('every backend must be used by at least one fixed gateway model alias')
    if gateway.host not in {'127.0.0.1', '::1'}:
        raise ServiceConfigError('gateway listener must use a numeric loopback address')

def _validate_loaded_configs(service: ServiceConfig, gateway: GatewayConfig, node_config: NodeAdapterConfig, core_profiles: Mapping[str, Mapping[str, Any]]) -> None:
    _check_gateway_profile_set(gateway, service)
    if gateway.enabled is not True:
        raise ServiceConfigError('enabled HX service requires enabled gateway configuration')
    if Path(gateway.state_root) != service.state_root / 'gateway':
        raise ServiceConfigError('gateway state_root must be the gateway child of the declared service state_root')
    expected_journal_parent = service.state_root / 'node-adapter'
    try:
        journal_mode = expected_journal_parent.stat().st_mode
    except OSError as exc:
        raise ServiceConfigError('NodeAdapter state directory must exist before service start') from exc
    if node_config.journal_path.parent != expected_journal_parent or not stat.S_ISDIR(journal_mode) or journal_mode & 18 or expected_journal_parent.is_symlink():
        raise ServiceConfigError('NodeAdapter journal must use the private declared node-adapter state directory')
    if not node_config.enabled:
        raise ServiceConfigError('explicit NodeAdapter transport is disabled')
    if set(service.profiles) - set(node_config.profiles):
        raise ServiceConfigError('a gateway profile has no explicit NodeAdapter launch plan')
    for spec in core_profiles.values():
        for node in spec.get('nodes', ()):
            if node not in node_config.hosts:
                raise ServiceConfigError(f'control-plane node {node} has no pinned NodeAdapter host')
    for node, host in node_config.hosts.items():
        address = ipaddress.ip_address(host)
        if address.is_global or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ServiceConfigError(f'node host {node} is outside the pinned private management scope')
    for profile, activation in service.profiles.items():
        backend = gateway.backends[profile]
        plan = node_config.profiles[profile]
        core = core_profiles.get(profile)
        if core is None:
            raise ServiceConfigError(f'gateway profile {profile} is absent from the explicit control-plane profile file')
        nodes = tuple(core.get('nodes', ()))
        if not nodes or tuple(backend.nodes) != nodes or tuple(plan.nodes) != nodes:
            raise ServiceConfigError(f'profile {profile} node sets disagree across trusted configurations')
        if not backend.expected_model_id or backend.expected_model_id.startswith('REPLACE-'):
            raise ServiceConfigError(f'profile {profile} has no pinned backend model id')
        if plan.model_id != backend.expected_model_id:
            raise ServiceConfigError(f'profile {profile} model id disagrees across gateway and NodeAdapter plans')
        if not backend.auth_token_file:
            raise ServiceConfigError(f'profile {profile} requires a private backend bearer token')
        if backend.host not in {'127.0.0.1', '::1'}:
            raise ServiceConfigError(f'profile {profile} backend must use a numeric loopback forwarded endpoint')
        if not activation.active_work_path:
            raise ServiceConfigError(f'profile {profile} requires a fixed active-work probe path')
        if activation.enabled:
            _require_qualified(core, nodes, profile)
        _require_strong_backend_token(backend.auth_token_file, profile)
    checks = static_checks(node_config)
    if not checks or not all((ok for _name, ok, _detail in checks)):
        raise ServiceConfigError('NodeAdapter transport is incomplete or unavailable')

def _require_strong_backend_token(path: str, profile: str) -> None:
    try:
        document = read_private_json(path, label=f'backend token for {profile}')
        _require_unambiguous_json_file(Path(path), f'backend token for {profile}')
    except Exception as exc:
        raise ServiceConfigError(f'profile {profile} backend token is unavailable, ambiguous, or not private') from exc
    token = document.get('token')
    if not isinstance(token, str) or token != token.strip() or len(token) < 32 or token.startswith('REPLACE-'):
        raise ServiceConfigError(f'profile {profile} backend bearer token is weak or malformed')

@dataclass
class ServiceRuntime:
    manager: Manager
    adapter: NodeAdapter
    facade: ManagerBackendFacade
    control_store: Any
    gateway_store: Any
    server: GatewayServer
    _control_lock: Any
    _gateway_lock: Any
    _serving: bool = False
    _server_stopped: bool = False
    _closed: bool = False

    def serve_forever(self) -> None:
        self._serving = True
        try:
            self.server.serve_forever()
        finally:
            self._serving = False
            self.server.shutdown()
            self._server_stopped = True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._server_stopped:
            self.server.httpd.server_close()
        try:
            self.gateway_store.close()
        finally:
            if self._gateway_lock is not None:
                self._gateway_lock.release()
        try:
            self.control_store.close()
        finally:
            if self._control_lock is not None:
                self._control_lock.release()

def create_service(config: ServiceConfig, *, maintenance_lease: MaintenanceLease, node_transport: Any | None=None, active_work_probe: Any | None=None, clock: Any=time.time) -> ServiceRuntime:
    """Construct the real stores, Manager, NodeAdapter, facade and loopback gateway.

    The maintenance lease must already be held. Optional transport/probe objects
    are dependency injection for local tests; the CLI supplies neither and no
    config file can name an executable plugin.
    """
    if not isinstance(maintenance_lease, MaintenanceLease) or not maintenance_lease.held:
        raise ServiceConfigError('the exact maintenance flock must be held before constructing services')
    if not isinstance(config, ServiceConfig):
        raise ServiceConfigError('service configuration must be loaded from an explicit trusted file')
    try:
        current_config = load_service_config(config.source_path)
    except Exception as exc:
        raise ServiceConfigError('service configuration source could not be revalidated') from exc
    if current_config != config:
        raise ServiceConfigError('service configuration differs from its explicit trusted source')
    config = current_config
    if config.enabled is not True:
        raise ServiceConfigError('disabled HX service configuration cannot construct a serving runtime')
    for path, label in ((config.profiles_file, 'profiles file'), (config.node_adapter_config, 'NodeAdapter configuration'), (config.gateway_config, 'gateway configuration')):
        _trusted_config_file(path, label)
        _require_unambiguous_json_file(path, label)
    try:
        gateway_config = load_gateway_config(config.gateway_config)
        node_config = load_node_config(config.node_adapter_config)
        core_profiles = control_config.read_profiles_json(config.profiles_file)
    except Exception as exc:
        raise ServiceConfigError('a trusted service configuration could not be loaded') from exc
    _validate_loaded_configs(config, gateway_config, node_config, core_profiles)
    registry_document = read_private_json(gateway_config.token_registry, label='token registry')
    _require_unambiguous_json_file(Path(gateway_config.token_registry), 'token registry')
    client_tokens = registry_document.get('tokens')
    if not isinstance(client_tokens, dict) or not client_tokens or any((not isinstance(token, str) or len(token) < 32 or token.startswith('REPLACE-') for token in client_tokens)):
        raise ServiceConfigError('gateway registry must contain strong client tokens')
    registry = TokenRegistry.load(gateway_config.token_registry)
    for backend in gateway_config.backends.values():
        upstream._load_auth_header(backend)
    adapter = NodeAdapter(node_config, transport=node_transport, clock=clock)
    adapter_caps = adapter.capabilities()
    if adapter_caps.get('available') is not True or adapter_caps.get('fixture_only') is not False:
        raise ServiceConfigError('NodeAdapter transport became unavailable during construction')
    bindings = {profile: ProfileBinding(nodes=tuple(core_profiles[profile]['nodes']), expected_model_id=gateway_config.backends[profile].expected_model_id, enabled=activation.enabled, active_work_path=activation.active_work_path) for profile, activation in config.profiles.items()}
    probe = active_work_probe if active_work_probe is not None else LoopbackActiveWorkProbe(gateway_config.backends, {profile: activation.active_work_path for profile, activation in config.profiles.items()}, timeout=gateway_config.connect_timeout_seconds)
    control_store = None
    gateway_store = None
    control_lock = None
    gateway_lock = None
    server = None
    try:
        control_store, control_lock = open_store(config.state_root / 'control', lock=True, profiles=core_profiles, clock=clock)
        manager = Manager(control_store, adapter=adapter, adapter_explicit=True, allow_fixture_ready=False, allow_test_holds=False)
        facade = ManagerBackendFacade(manager=manager, adapter=adapter, service_owner=config.service_owner, profiles=bindings, active_work_probe=probe, clock=clock)
        gateway_store, gateway_lock = open_gateway_store(gateway_config.state_root, lock=True, clock=clock)
        manager.reconcile()
        server = GatewayServer(config=gateway_config, registry=registry, store=gateway_store, facade=facade, probe_backend=upstream.probe_backend_models, clock=clock)
        return ServiceRuntime(manager=manager, adapter=adapter, facade=facade, control_store=control_store, gateway_store=gateway_store, server=server, _control_lock=control_lock, _gateway_lock=gateway_lock)
    except BaseException:
        if server is not None:
            try:
                server.server_close()
            except Exception:
                pass
        if gateway_store is not None:
            gateway_store.close()
        if gateway_lock is not None:
            gateway_lock.release()
        if control_store is not None:
            control_store.close()
        if control_lock is not None:
            control_lock.release()
        raise
