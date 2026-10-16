# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Offline composition of the HX gateway and fixed authenticated engine fronts."""
from __future__ import annotations
import http.client
import ipaddress
import json
import math
import os
import re
import signal
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping
from control_plane.config import read_profiles_json
from engine_front import ACTIVE_WORK_PATH, CHAT_PATHS, HEALTH_PATH, MODELS_PATH, EngineFrontConfig, create_server
from hx_service.service import MAINTENANCE_LOCK_PATH, MaintenanceLease, MaintenanceLeaseError, MaintenanceLockBusy, ServiceConfig, ServiceConfigError, _check_gateway_profile_set, create_service, load_service_config
from llm_gateway.config import GatewayConfig, load_gateway_config
from node_adapter.client import NodeAdapterConfig, load_config as load_node_config
from .readiness import ManagerReadinessBinding
from .thread_scope import RequestScopedFacade, RequestScopedReadiness
COMPOSITION_SCHEMA = 'dgx-v4-service-composition-v1'
_MIN_FORWARD_TIMEOUT_SECONDS = 3600.0
_CONFIG_LIMIT_BYTES = 1048576
_STARTUP_TIMEOUT_SECONDS = 10.0
_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_RETAINED_SHUTDOWNS: list[tuple[Any, Any, Any]] = []
_RETAINED_SHUTDOWNS_LOCK = threading.Lock()
_PROFILE_RE = re.compile('[a-z0-9][a-z0-9._-]{0,63}\\Z')
_NODE_RE = _PROFILE_RE

class CompositionError(ValueError):
    """Trusted composition input or lifecycle refused before safe serving."""

@dataclass(frozen=True)
class FrontConfig:
    profile: str
    bind_host: str
    bind_port: int
    native_host: str
    native_port: int
    expected_model_id: str
    expected_nodes: tuple[str, ...]
    backend_token_file: str

@dataclass(frozen=True)
class CompositionConfig:
    source_path: Path
    enabled: bool
    service_config: Path
    fronts: Mapping[str, FrontConfig]

@dataclass(frozen=True)
class CompositionPlan:
    composition: CompositionConfig
    service: ServiceConfig
    gateway: GatewayConfig
    node_config: NodeAdapterConfig
    core_profiles: Mapping[str, Mapping[str, Any]]

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def _reject_constant(value: str) -> Any:
    raise ValueError(f'non-finite JSON constant {value}')

def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('non-finite JSON number')
    return value

def _config_file_info(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CompositionError(f'{label} is missing or unreadable') from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise CompositionError(f'{label} must be a regular non-symlink file')
    if stat.S_IMODE(info.st_mode) != 288:
        raise CompositionError(f'{label} must be root-owned mode 0440 and group-readable')
    groups = set(os.getgroups())
    groups.add(os.getegid())
    if info.st_gid not in groups:
        raise CompositionError(f'{label} must be readable by the service group')
    if info.st_size > _CONFIG_LIMIT_BYTES:
        raise CompositionError(f'{label} exceeds the configuration size limit')
    return info

def _require_root_owner(path: Path, label: str) -> None:
    """Require root ownership and non-writable ancestors for trusted config paths."""
    info = _config_file_info(path, label)
    if info.st_uid != 0:
        raise CompositionError(f'{label} must be owned by root')
    for directory in reversed(path.absolute().parents):
        try:
            parent = directory.lstat()
        except OSError as exc:
            raise CompositionError(f'{label} has an unavailable parent directory') from exc
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 18:
            raise CompositionError(f'{label} parent directories must be root-owned and not group/world writable')

def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_uid, left.st_gid, left.st_mode, left.st_size) == (right.st_dev, right.st_ino, right.st_uid, right.st_gid, right.st_mode, right.st_size)

def _read_trusted_json(path: Path, label: str) -> dict[str, Any]:
    _require_root_owner(path, label)
    before = _config_file_info(path, label)
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CompositionError(f'{label} could not be opened without following symlinks') from exc
    try:
        opened = os.fstat(fd)
        if not _same_file(before, opened):
            raise CompositionError(f'{label} changed while being opened')
        raw = bytearray()
        while len(raw) <= _CONFIG_LIMIT_BYTES:
            chunk = os.read(fd, min(65536, _CONFIG_LIMIT_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > _CONFIG_LIMIT_BYTES:
            raise CompositionError(f'{label} exceeds the configuration size limit')
        after = path.lstat()
        if not _same_file(opened, after):
            raise CompositionError(f'{label} changed while being read')
    except OSError as exc:
        raise CompositionError(f'{label} could not be read safely') from exc
    finally:
        os.close(fd)
    try:
        document = json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError, RecursionError) as exc:
        raise CompositionError(f'{label} is ambiguous or malformed JSON') from exc
    if not isinstance(document, dict):
        raise CompositionError(f'{label} must contain a JSON object')
    return document

def _explicit_path(value: Any, where: str) -> Path:
    if not isinstance(value, str) or not value or (not Path(value).is_absolute()) or value.startswith('~') or ('$' in value) or ('\x00' in value) or ('..' in Path(value).parts):
        raise CompositionError(f'{where} must be an explicit absolute path')
    return Path(value)

def _numeric_loopback(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise CompositionError(f'{where} must be a numeric loopback address')
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CompositionError(f'{where} must be a numeric loopback address') from exc
    if not address.is_loopback:
        raise CompositionError(f'{where} must be a numeric loopback address')
    return value

def _port(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (not 1 <= value <= 65535):
        raise CompositionError(f'{where} must be an integer in [1, 65535]')
    return value

def load_composition_config(path: Path | str) -> CompositionConfig:
    """Read a strict root-owned composition document without side effects."""
    source = Path(path)
    if not source.is_absolute() or '..' in source.parts:
        raise CompositionError('composition config path must be an explicit absolute path')
    document = _read_trusted_json(source, 'composition configuration')
    expected = {'schema', 'enabled', 'service_config', 'fronts'}
    if set(document) != expected:
        raise CompositionError('composition configuration must contain exactly the declared top-level keys')
    if document.get('schema') != COMPOSITION_SCHEMA:
        raise CompositionError('unsupported composition configuration schema')
    enabled = document.get('enabled')
    if not isinstance(enabled, bool):
        raise CompositionError('enabled must be an explicit boolean')
    service_path = _explicit_path(document.get('service_config'), 'service_config')
    fronts_raw = document.get('fronts')
    if not isinstance(fronts_raw, dict) or not fronts_raw:
        raise CompositionError('fronts must be a non-empty profile mapping')
    fronts: dict[str, FrontConfig] = {}
    front_keys = {'profile', 'bind_host', 'bind_port', 'native_host', 'native_port', 'expected_model_id', 'expected_nodes', 'backend_token_file'}
    for profile, raw in fronts_raw.items():
        if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
            raise CompositionError('fronts contains an invalid profile name')
        if not isinstance(raw, dict) or set(raw) != front_keys:
            raise CompositionError(f'fronts.{profile} must contain exactly the fixed engine-front fields')
        declared_profile = raw.get('profile')
        if declared_profile != profile:
            raise CompositionError(f'fronts.{profile}.profile must equal its mapping key')
        model = raw.get('expected_model_id')
        if not isinstance(model, str) or not model or model != model.strip() or (len(model) > 512) or any((ord(char) < 32 or ord(char) == 127 for char in model)):
            raise CompositionError(f'fronts.{profile}.expected_model_id must be fixed non-empty text')
        nodes_raw = raw.get('expected_nodes')
        if not isinstance(nodes_raw, list) or not nodes_raw or any((not isinstance(node, str) or not _NODE_RE.fullmatch(node) for node in nodes_raw)) or (len(set(nodes_raw)) != len(nodes_raw)):
            raise CompositionError(f'fronts.{profile}.expected_nodes must contain unique node identifiers')
        token_path = _explicit_path(raw.get('backend_token_file'), f'fronts.{profile}.backend_token_file')
        fronts[profile] = FrontConfig(profile=profile, bind_host=_numeric_loopback(raw.get('bind_host'), f'fronts.{profile}.bind_host'), bind_port=_port(raw.get('bind_port'), f'fronts.{profile}.bind_port'), native_host=_numeric_loopback(raw.get('native_host'), f'fronts.{profile}.native_host'), native_port=_port(raw.get('native_port'), f'fronts.{profile}.native_port'), expected_model_id=model, expected_nodes=tuple(nodes_raw), backend_token_file=str(token_path))
    return CompositionConfig(source_path=source, enabled=enabled, service_config=service_path, fronts=MappingProxyType(fronts))

def _check_static_profile_mapping(composition: CompositionConfig, service: ServiceConfig, gateway: GatewayConfig, node_config: NodeAdapterConfig, core_profiles: Mapping[str, Mapping[str, Any]]) -> None:
    backend_profiles = set(gateway.backends)
    try:
        _check_gateway_profile_set(gateway, service)
    except ServiceConfigError as exc:
        raise CompositionError('gateway backend/profile configuration is unsafe') from exc
    if backend_profiles != set(composition.fronts):
        raise CompositionError('every gateway backend must map to exactly one engine front')
    if Path(gateway.state_root) != service.state_root / 'gateway':
        raise CompositionError('gateway state_root must be the gateway child of the declared service state_root')
    binds: set[tuple[str, int]] = set()
    native_destinations: set[tuple[str, int]] = set()
    for profile in sorted(backend_profiles):
        backend = gateway.backends[profile]
        front = composition.fronts[profile]
        plan = node_config.profiles.get(profile)
        core = core_profiles.get(profile)
        if plan is None or core is None:
            raise CompositionError(f'profile {profile} is missing from NodeAdapter or control-plane configuration')
        core_nodes = tuple(core.get('nodes', ()))
        if not core_nodes or tuple(backend.nodes) != core_nodes or tuple(plan.nodes) != core_nodes:
            raise CompositionError(f'profile {profile} nodes disagree across trusted configurations')
        if front.expected_nodes != core_nodes:
            raise CompositionError(f'fronts.{profile}.expected_nodes differs from trusted profile nodes')
        if not backend.expected_model_id or backend.expected_model_id.startswith('REPLACE-'):
            raise CompositionError(f'profile {profile} has no pinned backend model id')
        if plan.model_id != backend.expected_model_id or front.expected_model_id != backend.expected_model_id:
            raise CompositionError(f'profile {profile} model id disagrees across trusted configurations')
        if front.profile != profile:
            raise CompositionError(f'fronts.{profile}.profile differs from trusted profile identity')
        if service.profiles[profile].active_work_path != ACTIVE_WORK_PATH:
            raise CompositionError(f'profile {profile} must use the fixed engine active-work path')
        if not backend.auth_token_file or front.backend_token_file != backend.auth_token_file:
            raise CompositionError(f'fronts.{profile}.backend_token_file differs from the trusted gateway token file')
        _numeric_loopback(backend.host, f'backends.{profile}.base_url host')
        if (front.bind_host, front.bind_port) != (backend.host, backend.port):
            raise CompositionError(f'fronts.{profile} bind address must exactly equal its gateway backend URL')
        if backend.chat_path not in CHAT_PATHS or backend.models_path != MODELS_PATH or backend.health_path != MODELS_PATH:
            raise CompositionError(f'profile {profile} gateway paths require fixed chat paths and /v1/models model identity probes')
        bind = (front.bind_host, front.bind_port)
        native = (front.native_host, front.native_port)
        if bind == native:
            raise CompositionError(f'fronts.{profile} native destination must differ from its frontend listener')
        if bind in binds:
            raise CompositionError('engine frontend bind addresses must be unique')
        if native in native_destinations:
            raise CompositionError('native tunnel destinations must be unique')
        binds.add(bind)
        native_destinations.add(native)
    endpoints = binds | native_destinations
    if gateway.port and (gateway.host, gateway.port) in endpoints:
        raise CompositionError('gateway listener must not overlap a fixed engine-front endpoint')
    if binds & native_destinations:
        raise CompositionError('native tunnel destinations must not overlap any engine-front listener')
    if gateway.read_timeout_seconds < _MIN_FORWARD_TIMEOUT_SECONDS:
        raise CompositionError('gateway read timeout must be at least 3600 seconds for bounded long-prefill forwarding')

def prepare_composition(config: CompositionConfig) -> CompositionPlan:
    """Parse and cross-check every root-owned static input; never construct runtime state."""
    if not isinstance(config, CompositionConfig):
        raise CompositionError('composition must come from an explicit trusted configuration')
    current = load_composition_config(config.source_path)
    if current != config:
        raise CompositionError('composition values differ from their explicit trusted source')
    config = current
    try:
        _read_trusted_json(config.service_config, 'HX service configuration')
        service = load_service_config(config.service_config)
        root_config_paths = ((service.profiles_file, 'control-plane profiles configuration'), (service.node_adapter_config, 'NodeAdapter configuration'), (service.gateway_config, 'gateway configuration'))
        for path, label in root_config_paths:
            _read_trusted_json(path, label)
        gateway = load_gateway_config(service.gateway_config)
        node_config = load_node_config(service.node_adapter_config)
        core_profiles = read_profiles_json(service.profiles_file)
    except (CompositionError, ServiceConfigError):
        raise
    except Exception as exc:
        raise CompositionError('a root-owned HX, gateway, NodeAdapter, or profile config is invalid') from exc
    _check_static_profile_mapping(config, service, gateway, node_config, core_profiles)
    if config.enabled and (service.enabled is not True or gateway.enabled is not True):
        raise CompositionError('enabled composition requires enabled HX service and gateway configurations')
    return CompositionPlan(composition=config, service=service, gateway=gateway, node_config=node_config, core_profiles=MappingProxyType(dict(core_profiles)))

def _unauthorized_startup_probe(host: str, port: int, *, timeout: float=0.5) -> None:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request('GET', '/', headers={'Connection': 'close'})
        response = connection.getresponse()
        response.read(65536)
        if response.status != 401:
            raise CompositionError('fixed loopback listener did not pass its unauthenticated startup check')
    except (OSError, http.client.HTTPException, TimeoutError) as exc:
        raise CompositionError('fixed loopback listener did not accept its startup check') from exc
    finally:
        connection.close()

def _shutdown_event(server: Any) -> Any:
    return getattr(server, '_BaseServer__is_shut_down', None)

class _ServerRunner:

    def __init__(self, server: Any, target: Callable[[], Any], name: str):
        self.server = server
        self.target = target
        self.name = name
        self.thread: threading.Thread | None = None
        self.finished = threading.Event()
        self.failure: BaseException | None = None
        self.start_returned = False
        self.failure_observed = False

    def start(self) -> None:
        if self.thread is not None:
            raise CompositionError(f'{self.name} thread was already started')
        self.thread = threading.Thread(target=self._run, name=self.name, daemon=False)
        self.thread.start()
        self.start_returned = True

    def _run(self) -> None:
        try:
            self.target()
        except BaseException as exc:
            self.failure = exc
        finally:
            self.finished.set()

    def wait_until_serving(self, *, timeout: float=_STARTUP_TIMEOUT_SECONDS) -> None:
        server_event = _shutdown_event(self.server)
        if server_event is None:
            raise CompositionError(f'{self.name} has no observable standard-library serve loop')
        deadline = time.monotonic() + timeout
        while True:
            self.raise_if_failed()
            if not server_event.is_set():
                return
            if time.monotonic() >= deadline:
                raise CompositionError(f'{self.name} did not enter serve_forever before the startup deadline')
            time.sleep(0.005)

    def raise_if_failed(self) -> None:
        if self.failure is not None:
            self.failure_observed = True
            raise CompositionError(f'{self.name} thread failed: {type(self.failure).__name__}') from self.failure
        if self.finished.is_set():
            self.failure_observed = True
            raise CompositionError(f'{self.name} thread stopped unexpectedly')

    def stop(self, *, deadline: float) -> None:
        thread = self.thread
        if thread is None or not self.start_returned:
            return
        event = _shutdown_event(self.server)
        if event is None:
            raise CompositionError(f'{self.name} has no observable standard-library serve loop')
        failure: BaseException | None = None
        try:
            while thread.is_alive() and event.is_set() and (self.failure is None):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.005, remaining))
            if thread.is_alive():
                if event.is_set():
                    thread.join(max(0.0, deadline - time.monotonic()))
                    if thread.is_alive():
                        raise TimeoutError(f'{self.name} thread did not enter serve_forever before shutdown')
                else:
                    self.server.shutdown()
        except BaseException as exc:
            failure = exc
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            if failure is not None:
                raise failure
            raise TimeoutError(f'{self.name} thread did not stop before the shutdown deadline')
        if self.failure is not None and (not self.failure_observed):
            self.failure_observed = True
            raise CompositionError(f'{self.name} thread failed during shutdown: {type(self.failure).__name__}') from self.failure
        if failure is not None:
            raise failure

def _server_threads(server: Any) -> tuple[threading.Thread, ...]:
    threads = getattr(server, '_handler_threads', None)
    if threads is None:
        threads = getattr(server, '_threads', None)
    if threads is None:
        return ()
    try:
        return tuple(threads)
    except TypeError:
        return ()

def _close_listener(server: Any, *, deadline: float) -> None:
    errors: list[BaseException] = []
    cancel_active = getattr(server, 'cancel_active', None)
    if callable(cancel_active):
        try:
            cancel_active()
        except BaseException as exc:
            errors.append(exc)
    try:
        if hasattr(server, 'block_on_close'):
            server.block_on_close = False
        if hasattr(server, 'shutdown_timeout_seconds'):
            server.shutdown_timeout_seconds = max(0.0, deadline - time.monotonic())
        server.server_close()
    except BaseException as exc:
        errors.append(exc)
    try:
        listener = getattr(server, 'socket', None)
        if listener is not None and listener.fileno() >= 0:
            listener.close()
    except BaseException as exc:
        errors.append(exc)
    wait_for_handlers = getattr(server, 'wait_for_handlers', None)
    if callable(wait_for_handlers):
        try:
            wait_for_handlers(timeout=max(0.0, deadline - time.monotonic()))
        except BaseException as exc:
            errors.append(exc)
    else:
        for thread in _server_threads(server):
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                errors.append(TimeoutError(f'HTTP worker {thread.name} did not stop before the shutdown deadline'))
                break
    has_live_threads = getattr(server, 'has_live_threads', None)
    if callable(has_live_threads) and has_live_threads():
        errors.append(TimeoutError('HTTP server still has active worker threads'))
    if errors:
        raise errors[0]

def _server_has_live_workers(server: Any) -> bool:
    check = getattr(server, 'has_live_threads', None)
    if callable(check):
        return bool(check())
    return any((thread.is_alive() for thread in _server_threads(server)))

class _CompositionController:

    def __init__(self, plan: CompositionPlan, runtime: Any, *, front_factory: Callable[..., Any]=create_server, startup_probe: Callable[..., None]=_unauthorized_startup_probe, stop_event: threading.Event | None=None):
        self.plan = plan
        self.runtime = runtime
        self.front_factory = front_factory
        self.startup_probe = startup_probe
        self.stop_event = stop_event
        self.front_servers: list[Any] = []
        self.front_runners: list[_ServerRunner] = []
        self.gateway_runner: _ServerRunner | None = None
        self._closed = False
        self._safe_to_release_lease = False
        self._shutdown_error: BaseException | None = None

    def _raise_if_stopping(self) -> None:
        if self.stop_event is not None and self.stop_event.is_set():
            raise KeyboardInterrupt

    def start(self) -> None:
        scoped = RequestScopedFacade(self.runtime.facade, self.runtime.control_store)
        self.runtime.facade = scoped
        self.runtime.server.facade = scoped
        self.runtime.server.scheduler.facade = scoped
        readiness = RequestScopedReadiness(ManagerReadinessBinding(self.runtime), self.runtime.control_store)
        self._raise_if_stopping()
        gateway = self.plan.gateway
        for profile in sorted(self.plan.composition.fronts):
            self._raise_if_stopping()
            entry = self.plan.composition.fronts[profile]
            backend = gateway.backends[profile]
            front_config = EngineFrontConfig(backend_host=entry.native_host, backend_port=entry.native_port, profile=profile, expected_model_id=backend.expected_model_id, expected_nodes=tuple(backend.nodes), backend_token_file=backend.auth_token_file, max_body_bytes=gateway.max_body_bytes, max_response_bytes=gateway.max_response_bytes, connect_timeout_seconds=gateway.connect_timeout_seconds, read_timeout_seconds=gateway.read_timeout_seconds)
            server = self.front_factory(front_config, readiness_binding=readiness, bind_host=entry.bind_host, bind_port=entry.bind_port)
            self.front_servers.append(server)
            server.daemon_threads = False
            if hasattr(server, 'block_on_close'):
                server.block_on_close = False
            if hasattr(server, 'shutdown_timeout_seconds'):
                server.shutdown_timeout_seconds = _SHUTDOWN_TIMEOUT_SECONDS
            address = server.server_address
            if address[0] != entry.bind_host or address[1] != entry.bind_port:
                raise CompositionError(f'frontend {profile} did not bind its exact trusted address')
        self._raise_if_stopping()
        for profile, server in zip(sorted(self.plan.composition.fronts), self.front_servers):
            runner = _ServerRunner(server, server.serve_forever, f'engine-front-{profile}')
            self.front_runners.append(runner)
            runner.start()
            runner.wait_until_serving()
            entry = self.plan.composition.fronts[profile]
            self.startup_probe(entry.bind_host, entry.bind_port)
            runner.raise_if_failed()
            self._raise_if_stopping()
        for runner in self.front_runners:
            runner.raise_if_failed()
        self._raise_if_stopping()
        gateway_server = self.runtime.server
        gateway_server.httpd.daemon_threads = False
        gateway_server.httpd.block_on_close = False
        gateway_server.httpd.shutdown_timeout_seconds = _SHUTDOWN_TIMEOUT_SECONDS
        gateway_server.shutdown_timeout_seconds = _SHUTDOWN_TIMEOUT_SECONDS
        self.gateway_runner = _ServerRunner(gateway_server.httpd, self.runtime.serve_forever, 'hx-gateway')
        self.gateway_runner.start()
        self.gateway_runner.wait_until_serving()
        self.startup_probe(gateway_server.host, gateway_server.port)
        self.gateway_runner.raise_if_failed()

    def check_health(self) -> None:
        for runner in self.front_runners:
            runner.raise_if_failed()
        if self.gateway_runner is not None:
            self.gateway_runner.raise_if_failed()

    @property
    def safe_to_release_lease(self) -> bool:
        return self._safe_to_release_lease

    def close(self) -> None:
        if self._closed:
            if self._shutdown_error is not None:
                raise self._shutdown_error
            return
        self._closed = True
        deadline = time.monotonic() + _SHUTDOWN_TIMEOUT_SECONDS
        errors: list[BaseException] = []
        gateway_server = getattr(self.runtime, 'server', None)
        if gateway_server is not None:
            cancel_active = getattr(gateway_server, 'cancel_active', None)
            if not callable(cancel_active):
                cancel_active = getattr(getattr(gateway_server, 'httpd', None), 'cancel_active', None)
            if callable(cancel_active):
                try:
                    cancel_active()
                except BaseException as exc:
                    errors.append(exc)
            try:
                gateway_server.shutdown_timeout_seconds = max(0.0, deadline - time.monotonic())
                gateway_server.httpd.shutdown_timeout_seconds = max(0.0, deadline - time.monotonic())
            except Exception:
                pass
        for server in self.front_servers:
            cancel_active = getattr(server, 'cancel_active', None)
            if callable(cancel_active):
                try:
                    cancel_active()
                except BaseException as exc:
                    errors.append(exc)
        if self.gateway_runner is not None:
            try:
                self.gateway_runner.stop(deadline=deadline)
            except BaseException as exc:
                errors.append(exc)
        for runner in reversed(self.front_runners):
            try:
                runner.stop(deadline=deadline)
            except BaseException as exc:
                errors.append(exc)
        for server in reversed(self.front_servers):
            try:
                _close_listener(server, deadline=deadline)
            except BaseException as exc:
                errors.append(exc)
        workers_active = False
        for runner in [*self.front_runners, *([self.gateway_runner] if self.gateway_runner else [])]:
            if runner.thread is not None and runner.thread.is_alive():
                workers_active = True
        for server in self.front_servers:
            workers_active = workers_active or _server_has_live_workers(server)
        if gateway_server is not None:
            gateway_httpd = getattr(gateway_server, 'httpd', None)
            if gateway_httpd is not None:
                workers_active = workers_active or _server_has_live_workers(gateway_httpd)
            workers_active = workers_active or getattr(gateway_server, 'shutdown_safe', True) is False
            scheduler_thread = getattr(getattr(gateway_server, 'scheduler', None), '_thread', None)
            workers_active = workers_active or (scheduler_thread is not None and scheduler_thread.is_alive())
        if workers_active and (not errors):
            errors.append(TimeoutError('composition workers remain active; stores and lease stay owned'))
        if not errors:
            try:
                self.runtime.close()
                self._safe_to_release_lease = True
            except BaseException as exc:
                errors.append(exc)
        self._shutdown_error = CompositionError(f'composition shutdown failed: {type(errors[0]).__name__}') if errors else None
        if self._shutdown_error is not None:
            raise self._shutdown_error from errors[0]

def _install_sigterm(stop_event: threading.Event) -> Callable[[], None]:
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    previous = signal.getsignal(signal.SIGTERM)

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()
    signal.signal(signal.SIGTERM, request_stop)

    def restore() -> None:
        signal.signal(signal.SIGTERM, previous)
    return restore

def run_service(config_path: Path | str, *, maintenance_lock_path: Path | str=MAINTENANCE_LOCK_PATH, lease_factory: Callable[[Path | str], Any]=MaintenanceLease, service_factory: Callable[..., Any]=create_service, front_factory: Callable[..., Any]=create_server, startup_probe: Callable[..., None]=_unauthorized_startup_probe, stop_event: threading.Event | None=None) -> int:
    """Serve one explicitly configured composition while holding the HX lease."""
    stop = stop_event if stop_event is not None else threading.Event()
    lease = lease_factory(maintenance_lock_path)
    try:
        lease.acquire()
    except MaintenanceLockBusy:
        print(json.dumps({'ok': False, 'reason_code': 'maintenance_flock_busy', 'lifecycle_started': False}))
        return 75
    except MaintenanceLeaseError as exc:
        print(json.dumps({'ok': False, 'reason_code': 'maintenance_lock_unavailable', 'error': type(exc).__name__, 'lifecycle_started': False}))
        return 2
    runtime = None
    controller: _CompositionController | None = None
    restore_signal: Callable[[], None] = lambda: None
    result = 2
    try:
        restore_signal = _install_sigterm(stop)
        if stop.is_set():
            raise KeyboardInterrupt
        composition = load_composition_config(config_path)
        plan = prepare_composition(composition)
        if stop.is_set():
            raise KeyboardInterrupt
        if composition.enabled is not True:
            raise CompositionError('disabled composition configuration cannot serve')
        runtime = service_factory(plan.service, maintenance_lease=lease)
        if stop.is_set():
            raise KeyboardInterrupt
        controller = _CompositionController(plan, runtime, front_factory=front_factory, startup_probe=startup_probe, stop_event=stop)
        controller.start()
        while not stop.wait(0.1):
            controller.check_health()
        result = 0
    except KeyboardInterrupt:
        result = 0
    except Exception as exc:
        code = 'composition_start_refused'
        if isinstance(exc, CompositionError):
            code = 'composition_refused'
        elif isinstance(exc, ServiceConfigError):
            code = 'service_config_refused'
        print(json.dumps({'ok': False, 'reason_code': code, 'error': type(exc).__name__}))
        result = 2
    finally:
        try:
            restore_signal()
        except Exception as exc:
            print(json.dumps({'ok': False, 'reason_code': 'signal_restore_failed', 'error': type(exc).__name__}))
            result = 2
        ownership_safe = True
        try:
            if controller is not None:
                controller.close()
                ownership_safe = controller.safe_to_release_lease
            elif runtime is not None:
                runtime.close()
        except Exception as exc:
            print(json.dumps({'ok': False, 'reason_code': 'composition_shutdown_failed', 'error': type(exc).__name__}))
            ownership_safe = controller.safe_to_release_lease if controller is not None else False
            result = 2
        if ownership_safe:
            try:
                lease.release()
            except Exception as exc:
                with _RETAINED_SHUTDOWNS_LOCK:
                    _RETAINED_SHUTDOWNS.append((lease, runtime, controller))
                print(json.dumps({'ok': False, 'reason_code': 'maintenance_lease_release_failed', 'error': type(exc).__name__, 'ownership_retained': True}))
                result = 2
        else:
            with _RETAINED_SHUTDOWNS_LOCK:
                _RETAINED_SHUTDOWNS.append((lease, runtime, controller))
            print(json.dumps({'ok': False, 'reason_code': 'composition_shutdown_incomplete', 'ownership_retained': True}))
            result = 2
    return result

def check_config(config_path: Path | str) -> int:
    """Parse and validate static inputs only; never acquire a lease or construct services."""
    composition = load_composition_config(config_path)
    plan = prepare_composition(composition)
    print(json.dumps({'ok': True, 'enabled': composition.enabled, 'profiles': sorted(plan.gateway.backends), 'lifecycle_started': False}, sort_keys=True))
    return 0

def main(argv: list[str] | None=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog='deployment_integrations', description=__doc__)
    parser.add_argument('--config', required=True, help='root-owned mode-0440 composition JSON')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='parse-only; no flock, state writes, GPU, or sockets')
    mode.add_argument('--serve', action='store_true', help='hold the HX maintenance lease for process lifetime')
    args = parser.parse_args(argv)
    try:
        if args.check:
            return check_config(args.config)
        return run_service(args.config)
    except Exception as exc:
        print(json.dumps({'ok': False, 'reason_code': 'composition_refused', 'error': type(exc).__name__}))
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
