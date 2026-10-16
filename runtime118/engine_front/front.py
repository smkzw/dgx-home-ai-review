# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Authenticated fixed-loopback relay for the HX native engine tunnel.

The parent owns lifecycle. The injected readiness callback is called twice for
active-work probes and must derive each proof from a fresh Manager Store view
and a positive NodeAdapter.probe_ready observation; this module owns no model
state and never infers readiness from native health or a zero count.
"""
from __future__ import annotations
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import select
import socket
import stat
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
ACTIVE_WORK_PATH = '/_dgx/active_work'
HEALTH_PATH = '/health'
MODELS_PATH = '/v1/models'
CHAT_PATHS = frozenset({'/v1/chat/completions', '/v1/responses'})
_PROFILE_RE = re.compile('[a-z0-9][a-z0-9._-]{0,63}\\Z')
_TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9._~+/-]*={0,}\\Z')
_IDENTITY_KEYS = frozenset({'profile', 'owner', 'generation', 'model_id', 'containers', 'state', 'ready', 'observed_at'})
_MAX_HTTP_LINE_BYTES = 64 * 1024
_READ_CHUNK_BYTES = 8192

class EngineFrontConfigError(ValueError):
    """A fixed engine-front configuration is unsafe or malformed."""

class ReadinessBinding(Protocol):
    """Trusted parent callback contract for one fresh lifecycle identity proof.

    ``capture(profile)`` MUST make fresh reads of the exact Manager Store
    profile view and a positive ``NodeAdapter.probe_ready`` result. It returns
    exactly these keys: profile, owner, generation, model_id, containers,
    state, ready, observed_at. ``containers`` maps every configured node name
    to its current non-empty container identity. ``state`` is exactly READY,
    ``ready`` is literal True, and ``observed_at`` is Unix seconds from that
    fresh proof. Implementations must not cache a successful proof or accept
    generation/model/container identities from an HTTP caller.
    """

    def __call__(self, profile: str, /) -> Mapping[str, Any]:
        ...

@dataclass(frozen=True)
class EngineFrontConfig:
    """Pinned one-profile engine and frontend settings; no request can alter them."""
    backend_host: str
    backend_port: int
    profile: str
    expected_model_id: str
    expected_nodes: tuple[str, ...]
    backend_token_file: Path | str
    max_body_bytes: int = 4 * 1024 * 1024
    max_response_bytes: int = 64 * 1024 * 1024
    max_probe_bytes: int = 1 * 1024 * 1024
    max_sse_line_bytes: int = 1024 * 1024
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 300.0
    identity_max_age_seconds: float = 5.0

    def __post_init__(self) -> None:
        _require_numeric_loopback(self.backend_host, field='backend_host')
        if isinstance(self.backend_port, bool) or not isinstance(self.backend_port, int) or (not 1 <= self.backend_port <= 65535):
            raise EngineFrontConfigError('backend_port must be an integer in [1, 65535]')
        if not isinstance(self.profile, str) or not _PROFILE_RE.fullmatch(self.profile):
            raise EngineFrontConfigError('profile must be a fixed profile identifier')
        if not _valid_identity_text(self.expected_model_id, max_length=512):
            raise EngineFrontConfigError('expected_model_id must be non-empty fixed text')
        if not isinstance(self.expected_nodes, (tuple, list)) or not self.expected_nodes:
            raise EngineFrontConfigError('expected_nodes must be a non-empty fixed node set')
        nodes = tuple(self.expected_nodes)
        if any((not isinstance(node, str) or not _PROFILE_RE.fullmatch(node) for node in nodes)) or len(set(nodes)) != len(nodes):
            raise EngineFrontConfigError('expected_nodes must contain unique node identifiers')
        object.__setattr__(self, 'expected_nodes', nodes)
        if not isinstance(self.backend_token_file, (str, os.PathLike)) or not os.fspath(self.backend_token_file):
            raise EngineFrontConfigError('backend_token_file must be a fixed file path')
        _positive_int(self.max_body_bytes, 'max_body_bytes', maximum=64 * 1024 * 1024)
        _positive_int(self.max_response_bytes, 'max_response_bytes', maximum=1024 * 1024 * 1024)
        _positive_int(self.max_probe_bytes, 'max_probe_bytes', maximum=16 * 1024 * 1024)
        _positive_int(self.max_sse_line_bytes, 'max_sse_line_bytes', maximum=16 * 1024 * 1024)
        for name, maximum in (('connect_timeout_seconds', 300.0), ('read_timeout_seconds', 86400.0), ('identity_max_age_seconds', 60.0)):
            _positive_finite(getattr(self, name), name, maximum=maximum)

@dataclass(frozen=True)
class _IdentitySnapshot:
    profile: str
    owner: str
    generation: int
    model_id: str
    containers: tuple[tuple[str, str], ...]
    observed_at: float

    @property
    def identity(self) -> tuple[Any, ...]:
        return (self.profile, self.owner, self.generation, self.model_id, self.containers)

class _FrontFailure(Exception):

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

class _CancellableHTTPConnection(http.client.HTTPConnection):
    """Track the socket before connect blocks so shutdown can interrupt it."""

    def __init__(self, host: str, port: int, *, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._cancel_lock = threading.Lock()
        self._cancelled = False
        self._owned_socket: socket.socket | None = None
        self._getting_response = False

    def connect(self) -> None:
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        last_error: OSError | None = None
        for family, socktype, protocol, _canonname, address in addresses:
            sock = socket.socket(family, socktype, protocol)
            try:
                sock.settimeout(self.timeout)
                if self.source_address:
                    sock.bind(self.source_address)
                with self._cancel_lock:
                    if self._cancelled:
                        raise OSError('engine-front connection was cancelled')
                    self.sock = sock
                    self._owned_socket = sock
                sock.connect(address)
                if self._http_vsn == 11:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with self._cancel_lock:
                    if self._cancelled or self.sock is not sock:
                        raise OSError('engine-front connection was cancelled')
                return
            except OSError as exc:
                with self._cancel_lock:
                    if self.sock is sock:
                        self.sock = None
                    if self._owned_socket is sock:
                        self._owned_socket = None
                    cancelled = self._cancelled
                sock.close()
                if cancelled:
                    raise OSError('engine-front connection was cancelled') from exc
                last_error = exc
        if last_error is not None:
            raise last_error
        raise OSError('native endpoint resolved to no socket addresses')

    def getresponse(self) -> http.client.HTTPResponse:
        with self._cancel_lock:
            if self._cancelled:
                raise OSError('engine-front connection was cancelled')
            self._getting_response = True
        try:
            return super().getresponse()
        finally:
            with self._cancel_lock:
                self._getting_response = False
                cancelled = self._cancelled
            if cancelled:
                self.close()

    def cancel(self) -> None:
        with self._cancel_lock:
            self._cancelled = True
            sock = self._owned_socket
            constructing_response = self._getting_response
            if not constructing_response:
                self._owned_socket = None
                self.sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if not constructing_response:
                sock.close()

    def close(self) -> None:
        with self._cancel_lock:
            if self._getting_response:
                self.sock = None
                return
            sock = self._owned_socket if self._owned_socket is not None else self.sock
            self._owned_socket = None
            self.sock = None
        if sock is not None:
            sock.close()

class ActiveWorkProbe:
    """Fetch native health/models and bind its count to two fresh parent proofs."""

    def __init__(self, config: EngineFrontConfig, readiness_binding: ReadinessBinding, *, clock: Callable[[], float]=time.time):
        if not callable(readiness_binding):
            raise EngineFrontConfigError('readiness_binding must be a trusted callable')
        self.config = config
        self._readiness_binding = readiness_binding
        self._clock = clock
        self.connection_registry: Any | None = None
        self._backend_token = _read_backend_token(config.backend_token_file)

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)):
            raise _FrontFailure('clock_invalid')
        return float(value)

    def _capture_identity(self) -> _IdentitySnapshot:
        try:
            proof = self._readiness_binding(self.config.profile)
        except Exception as exc:
            raise _FrontFailure('identity_unavailable') from exc
        if not isinstance(proof, Mapping) or set(proof) != _IDENTITY_KEYS:
            raise _FrontFailure('identity_malformed')
        profile = proof.get('profile')
        owner = proof.get('owner')
        generation = proof.get('generation')
        model_id = proof.get('model_id')
        containers = proof.get('containers')
        observed_at = proof.get('observed_at')
        if profile != self.config.profile or not _valid_identity_text(owner, max_length=128) or isinstance(generation, bool) or (not isinstance(generation, int)) or (generation <= 0) or (model_id != self.config.expected_model_id) or (proof.get('state') != 'READY') or (proof.get('ready') is not True) or (not isinstance(containers, Mapping)) or (set(containers) != set(self.config.expected_nodes)) or any((not _valid_identity_text(containers.get(node), max_length=256) for node in self.config.expected_nodes)) or (len(set(containers.values())) != len(self.config.expected_nodes)):
            raise _FrontFailure('identity_mismatch')
        if isinstance(observed_at, bool) or not isinstance(observed_at, (int, float)) or (not math.isfinite(observed_at)):
            raise _FrontFailure('identity_timestamp_invalid')
        now = self._now()
        observed = float(observed_at)
        if observed > now + 1.0 or now - observed > self.config.identity_max_age_seconds:
            raise _FrontFailure('identity_stale')
        return _IdentitySnapshot(profile=profile, owner=owner, generation=generation, model_id=model_id, containers=tuple(sorted(((node, containers[node]) for node in self.config.expected_nodes))), observed_at=observed)

    def _native_get(self, path: str) -> tuple[bytes, str | None]:
        conn: _CancellableHTTPConnection | None = None
        registration: int | None = None
        registry = self.connection_registry
        try:
            conn = _CancellableHTTPConnection(self.config.backend_host, self.config.backend_port, timeout=self.config.connect_timeout_seconds)
            if registry is not None:
                registration = registry.register_cancellation(conn.cancel)
                if registration is None:
                    raise OSError('native probe cancelled during shutdown')
            conn.request('GET', path, headers={'Accept': 'application/json', 'Connection': 'close'})
            if conn.sock is not None:
                conn.sock.settimeout(self.config.read_timeout_seconds)
            response = conn.getresponse()
            if 300 <= response.status < 400 or response.getheader('Location') is not None:
                raise _FrontFailure('backend_redirect_refused')
            if response.status != 200:
                raise _FrontFailure('backend_probe_status')
            content_type = response.getheader('Content-Type')
            return (_read_bounded(response, self.config.max_probe_bytes), content_type)
        except _FrontFailure:
            raise
        except (OSError, http.client.HTTPException, TimeoutError) as exc:
            raise _FrontFailure('backend_probe_unavailable') from exc
        finally:
            if conn is not None:
                conn.close()
            if registry is not None:
                registry.unregister_cancellation(registration)

    def _native_health(self) -> tuple[bytes, dict[str, Any]]:
        body, _content_type = self._native_get(HEALTH_PATH)
        document = _strict_json(body)
        if not isinstance(document, dict):
            raise _FrontFailure('backend_health_malformed')
        running = document.get('requests_running')
        busy = document.get('busy')
        if isinstance(running, bool) or not isinstance(running, int) or running < 0 or (not isinstance(busy, bool)):
            raise _FrontFailure('backend_health_malformed')
        if running > 0 and busy is not True:
            raise _FrontFailure('backend_health_inconsistent')
        return (body, document)

    def _native_models(self) -> tuple[bytes, str | None]:
        body, content_type = self._native_get(MODELS_PATH)
        document = _strict_json(body)
        if not isinstance(document, dict) or not isinstance(document.get('data'), list):
            raise _FrontFailure('backend_models_malformed')
        ids: list[str] = []
        for item in document['data']:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                raise _FrontFailure('backend_models_malformed')
            ids.append(item['id'])
        if content_type is not None and ('\r' in content_type or '\n' in content_type):
            raise _FrontFailure('backend_models_malformed')
        if self.config.expected_model_id not in ids:
            raise _FrontFailure('backend_model_mismatch')
        return (body, content_type)

    def native_health(self) -> tuple[bytes, str | None]:
        body, _document = self._native_health()
        return (body, 'application/json')

    def native_models(self) -> tuple[bytes, str | None]:
        return self._native_models()

    def probe_active(self) -> dict[str, Any]:
        try:
            before = self._capture_identity()
            failure: Exception | None = None
            health_document: dict[str, Any] | None = None
            try:
                _health_body, health_document = self._native_health()
                self._native_models()
            except Exception as exc:
                failure = exc
            after = self._capture_identity()
            if failure is not None:
                raise failure
            if before.identity != after.identity or after.observed_at < before.observed_at:
                raise _FrontFailure('identity_changed')
            assert health_document is not None
            return {'known': True, 'profile': after.profile, 'generation': after.generation, 'model_id': after.model_id, 'active_requests': health_document['requests_running'], 'observed_at': self._now()}
        except Exception as exc:
            code = exc.code if isinstance(exc, _FrontFailure) else 'active_work_unavailable'
            return {'known': False, 'profile': self.config.profile, 'generation': None, 'model_id': None, 'active_requests': None, 'observed_at': None, 'reason_code': code}

def make_active_work_probe(config: EngineFrontConfig, *, readiness_binding: ReadinessBinding, clock: Callable[[], float]=time.time) -> ActiveWorkProbe:
    """Build the reusable active-work seam from fixed config and parent identity."""
    return ActiveWorkProbe(config, readiness_binding, clock=clock)

class _EngineFrontServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], probe: ActiveWorkProbe):
        address_info = ipaddress.ip_address(address[0])
        self.address_family = socket.AF_INET6 if address_info.version == 6 else socket.AF_INET
        self.probe = probe
        self.shutdown_timeout_seconds = 10.0
        self._state_lock = threading.Lock()
        self._closing = False
        self._active_sockets: set[socket.socket] = set()
        self._handler_threads: set[threading.Thread] = set()
        self._cancellations: dict[int, Callable[[], None]] = {}
        self._next_cancellation = 0
        super().__init__(address, _RequestHandler)
        probe.connection_registry = self

    def get_request(self) -> tuple[socket.socket, Any]:
        request, address = super().get_request()
        request.settimeout(self.probe.config.read_timeout_seconds)
        return (request, address)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        thread = threading.Thread(target=self.process_request_thread, args=(request, client_address), name='engine-front-handler', daemon=False)
        with self._state_lock:
            self._prune_threads_locked()
            closing = self._closing
            if not closing:
                self._active_sockets.add(request)
                self._handler_threads.add(thread)
        if closing:
            self.shutdown_request(request)
            return
        try:
            thread.start()
        except BaseException:
            with self._state_lock:
                self._active_sockets.discard(request)
                self._handler_threads.discard(thread)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)
        except BaseException:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            with self._state_lock:
                self._active_sockets.discard(request)

    def start_managed_thread(self, thread: threading.Thread) -> bool:
        with self._state_lock:
            self._prune_threads_locked()
            if self._closing:
                return False
            self._handler_threads.add(thread)
        try:
            thread.start()
        except BaseException:
            with self._state_lock:
                self._handler_threads.discard(thread)
            raise
        return True

    def register_cancellation(self, cancel: Callable[[], None]) -> int | None:
        with self._state_lock:
            if self._closing:
                token = None
            else:
                self._next_cancellation += 1
                token = self._next_cancellation
                self._cancellations[token] = cancel
        if token is None:
            cancel()
        return token

    def unregister_cancellation(self, token: int | None) -> None:
        if token is not None:
            with self._state_lock:
                self._cancellations.pop(token, None)

    def cancel_active(self) -> None:
        with self._state_lock:
            self._closing = True
            clients = tuple(self._active_sockets)
            callbacks = tuple(self._cancellations.values())
        for client in clients:
            _shutdown_socket(client)
        first_error: Exception | None = None
        for cancel in callbacks:
            try:
                cancel()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise RuntimeError('one or more engine-front sockets could not be cancelled') from first_error

    def shutdown(self) -> None:
        error: Exception | None = None
        try:
            self.cancel_active()
        except Exception as exc:
            error = exc
        try:
            super().shutdown()
        except Exception as exc:
            if error is None:
                error = exc
        if error is not None:
            raise error

    def server_close(self) -> None:
        error: Exception | None = None
        try:
            self.cancel_active()
        except Exception as exc:
            error = exc
        try:
            super().server_close()
        except Exception as exc:
            if error is None:
                error = exc
        try:
            self.wait_for_handlers(timeout=self.shutdown_timeout_seconds)
        except Exception as exc:
            if error is None:
                error = exc
        if error is not None:
            raise error

    def wait_for_handlers(self, *, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self._state_lock:
                self._prune_threads_locked()
                threads = tuple(self._handler_threads)
            if not threads:
                return
            for thread in threads:
                thread.join(max(0.0, deadline - time.monotonic()))
            with self._state_lock:
                self._prune_threads_locked()
                alive = tuple((thread for thread in self._handler_threads if thread.is_alive()))
            if not alive:
                return
            if time.monotonic() >= deadline:
                names = sorted((thread.name for thread in alive))
                raise TimeoutError(f"engine-front workers did not stop: {', '.join(names)}")

    def has_live_threads(self) -> bool:
        with self._state_lock:
            return any((thread.is_alive() for thread in self._handler_threads))

    def _prune_threads_locked(self) -> None:
        dead = [thread for thread in self._handler_threads if not thread.is_alive()]
        self._handler_threads.difference_update(dead)

def _shutdown_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass

def create_server(config: EngineFrontConfig, *, readiness_binding: ReadinessBinding, bind_host: str='127.0.0.1', bind_port: int=0, clock: Callable[[], float]=time.time) -> ThreadingHTTPServer:
    """Create a loopback-only threaded frontend; bind_port=0 is for CPU tests."""
    _require_numeric_loopback(bind_host, field='bind_host')
    if isinstance(bind_port, bool) or not isinstance(bind_port, int) or (not 0 <= bind_port <= 65535):
        raise EngineFrontConfigError('bind_port must be an integer in [0, 65535]')
    probe = make_active_work_probe(config, readiness_binding=readiness_binding, clock=clock)
    return _EngineFrontServer((bind_host, bind_port), probe)

class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'dgx-engine-front'
    sys_version = ''

    @property
    def _probe(self) -> ActiveWorkProbe:
        return self.server.probe

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def parse_request(self) -> bool:
        if len(self.raw_requestline) > _MAX_HTTP_LINE_BYTES:
            self.send_error(414)
            return False
        return super().parse_request()

    def handle_expect_100(self) -> bool:
        if not self._authorized():
            self._json_error(401, 'unauthorized')
            return False
        return super().handle_expect_100()

    def do_GET(self) -> None:
        if not self._authorized():
            self._json_error(401, 'unauthorized')
            return
        self.close_connection = True
        if self.path == ACTIVE_WORK_PATH:
            observation = self._probe.probe_active()
            if observation.get('known') is True:
                self._json_response(200, observation)
            else:
                self._json_response(503, observation)
            return
        if self.path == HEALTH_PATH:
            try:
                body, content_type = self._probe.native_health()
            except _FrontFailure as exc:
                self._json_error(502, exc.code)
                return
            self._fixed_body_response(200, body, content_type or 'application/json')
            return
        if self.path == MODELS_PATH:
            try:
                body, content_type = self._probe.native_models()
            except _FrontFailure as exc:
                status = 503 if exc.code == 'backend_model_mismatch' else 502
                self._json_error(status, exc.code)
                return
            self._fixed_body_response(200, body, content_type or 'application/json')
            return
        self._json_error(404, 'not_found')

    def do_POST(self) -> None:
        if not self._authorized():
            self._json_error(401, 'unauthorized')
            return
        self.close_connection = True
        if self.path not in CHAT_PATHS:
            self._json_error(404, 'not_found')
            return
        try:
            length = self._content_length()
            body = self.rfile.read(length)
            if len(body) != length:
                raise _FrontFailure('request_body_truncated')
            content_type = self.headers.get('Content-Type', 'application/json')
            if content_type.split(';', 1)[0].strip().lower() != 'application/json':
                self._json_error(415, 'json_content_type_required')
                return
            document = _strict_json(body)
            if not isinstance(document, dict) or document.get('model') != self._probe.config.expected_model_id:
                self._json_error(400, 'configured_model_required')
                return
        except _FrontFailure as exc:
            status = 413 if exc.code == 'request_body_too_large' else 400
            try:
                self._json_error(status, exc.code)
            except OSError:
                pass
            return
        except OSError:
            try:
                self._json_error(408, 'request_body_unavailable')
            except OSError:
                pass
            return
        self._relay_post(self.path, body, content_type)

    def _authorized(self) -> bool:
        values = self.headers.get_all('Authorization', [])
        if len(values) != 1 or not values[0].startswith('Bearer '):
            return False
        supplied = values[0][7:]
        return bool(supplied) and supplied.isascii() and hmac.compare_digest(supplied, self._probe._backend_token)

    def _content_length(self) -> int:
        if self.headers.get_all('Transfer-Encoding', []):
            raise _FrontFailure('transfer_encoding_unsupported')
        values = self.headers.get_all('Content-Length', [])
        if len(values) != 1 or not values[0].isascii() or (not values[0].isdigit()):
            raise _FrontFailure('content_length_required')
        length = int(values[0])
        if length > self._probe.config.max_body_bytes:
            raise _FrontFailure('request_body_too_large')
        return length

    def _relay_post(self, path: str, body: bytes, content_type: str) -> None:
        config = self._probe.config
        conn = _CancellableHTTPConnection(config.backend_host, config.backend_port, timeout=config.connect_timeout_seconds)
        exchange = _NativeExchange(conn)
        server = self.server
        registration = server.register_cancellation(exchange.close)
        watcher: _ClientDisconnectWatcher | None = None
        try:
            if registration is None:
                return
            headers = {'Content-Type': content_type, 'Accept': self.headers.get('Accept') or '*/*', 'Content-Length': str(len(body)), 'Connection': 'close'}
            conn.request('POST', path, body=body, headers=headers)
            exchange.sock = conn.sock
            if conn.sock is not None:
                conn.sock.settimeout(config.read_timeout_seconds)
            watcher = _ClientDisconnectWatcher(self.connection, exchange.close, server)
            if not watcher.start():
                return
            response = conn.getresponse()
            exchange.set_response(response)
            if watcher.disconnected.is_set():
                return
            if 300 <= response.status < 400 or response.getheader('Location') is not None:
                exchange.close()
                self._json_error(502, 'backend_redirect_refused')
                return
            self._stream_response(response, exchange, watcher)
        except (OSError, http.client.HTTPException, TimeoutError):
            if not self.wfile.closed:
                try:
                    self._json_error(502, 'backend_unavailable')
                except (OSError, BrokenPipeError):
                    pass
        finally:
            try:
                if watcher is not None:
                    watcher.stop()
            finally:
                exchange.close()
                server.unregister_cancellation(registration)

    def _stream_response(self, response: http.client.HTTPResponse, exchange: '_NativeExchange', watcher: '_ClientDisconnectWatcher') -> None:
        config = self._probe.config
        try:
            content_length = _response_content_length(response)
            if content_length is not None and content_length > config.max_response_bytes:
                exchange.close()
                self._json_error(502, 'backend_response_too_large')
                return
            content_type = response.getheader('Content-Type') or 'application/octet-stream'
            if '\r' in content_type or '\n' in content_type:
                exchange.close()
                self._json_error(502, 'backend_response_malformed')
                return
            is_sse = content_type.split(';', 1)[0].strip().lower() == 'text/event-stream'
            self.send_response(response.status)
            self.send_header('Content-Type', content_type)
            if content_length is not None:
                self.send_header('Content-Length', str(content_length))
            self.send_header('Connection', 'close')
            self.end_headers()
            total = 0
            line_length = 0
            reader = getattr(response, 'read1', None) or response.read
            while not watcher.disconnected.is_set():
                chunk = reader(_READ_CHUNK_BYTES)
                if not chunk:
                    if getattr(response, 'length', None):
                        raise _FrontFailure('backend_body_truncated')
                    break
                total += len(chunk)
                if total > config.max_response_bytes:
                    raise _FrontFailure('backend_response_too_large')
                if is_sse:
                    for value in chunk:
                        if value == 10:
                            line_length = 0
                        else:
                            line_length += 1
                            if line_length > config.max_sse_line_bytes:
                                raise _FrontFailure('backend_sse_line_too_large')
                self.wfile.write(chunk)
                self.wfile.flush()
            if watcher.disconnected.is_set():
                exchange.close()
        except (_FrontFailure, OSError, http.client.HTTPException, AttributeError):
            self.close_connection = True
            exchange.close()

    def _json_response(self, status: int, document: Mapping[str, Any]) -> None:
        self._fixed_body_response(status, _encode_json(document), 'application/json')

    def _json_error(self, status: int, code: str) -> None:
        self._json_response(status, {'error': {'code': code}})

    def _fixed_body_response(self, status: int, body: bytes, content_type: str) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, BrokenPipeError):
            pass

class _NativeExchange:

    def __init__(self, conn: http.client.HTTPConnection):
        self.conn = conn
        self.sock: socket.socket | None = None
        self.response: http.client.HTTPResponse | None = None
        self._closed = False
        self._lock = threading.Lock()

    def set_response(self, response: http.client.HTTPResponse) -> None:
        with self._lock:
            self.response = response
            if self._closed:
                response.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sock = self.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
            if self.response is not None:
                try:
                    self.response.close()
                except Exception:
                    pass
            cancel = getattr(self.conn, 'cancel', None)
            (cancel if callable(cancel) else self.conn.close)()

class _ClientDisconnectWatcher:

    def __init__(self, client: socket.socket, close_upstream: Callable[[], None], server: _EngineFrontServer):
        self.client = client
        self.close_upstream = close_upstream
        self.server = server
        self.disconnected = threading.Event()
        self._stopping = threading.Event()
        self._started = False
        self._thread = threading.Thread(target=self._watch, name='engine-front-disconnect', daemon=False)

    def start(self) -> bool:
        self._started = self.server.start_managed_thread(self._thread)
        if not self._started:
            self.disconnected.set()
            self.close_upstream()
        return self._started

    def _watch(self) -> None:
        while not self._stopping.is_set():
            try:
                readable, _writable, _exceptional = select.select([self.client], [], [], 0.1)
                if not readable:
                    continue
                data = self.client.recv(1, socket.MSG_PEEK)
                if not data:
                    self.disconnected.set()
                    self.close_upstream()
                    return
                self.disconnected.set()
                self.close_upstream()
                return
            except (OSError, ValueError):
                self.disconnected.set()
                self.close_upstream()
                return

    def stop(self) -> None:
        self._stopping.set()
        if self._started:
            self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                raise TimeoutError('engine-front disconnect watcher did not stop')

def _read_bounded(response: http.client.HTTPResponse, maximum: int) -> bytes:
    content_length = _response_content_length(response)
    if content_length is not None and content_length > maximum:
        raise _FrontFailure('backend_probe_too_large')
    chunks: list[bytes] = []
    total = 0
    reader = getattr(response, 'read1', None) or response.read
    while True:
        chunk = reader(min(_READ_CHUNK_BYTES, maximum + 1 - total))
        if not chunk:
            if getattr(response, 'length', None):
                raise _FrontFailure('backend_body_truncated')
            break
        total += len(chunk)
        if total > maximum:
            raise _FrontFailure('backend_probe_too_large')
        chunks.append(chunk)
    return b''.join(chunks)

def _response_content_length(response: http.client.HTTPResponse) -> int | None:
    values = [value for name, value in response.getheaders() if name.lower() == 'content-length']
    transfer_values = [value for name, value in response.getheaders() if name.lower() == 'transfer-encoding']
    if len(values) > 1 or len(transfer_values) > 1 or (values and transfer_values):
        raise _FrontFailure('backend_response_malformed')
    if transfer_values and transfer_values[0].strip().lower() != 'chunked':
        raise _FrontFailure('backend_response_malformed')
    if not values:
        return None
    value = values[0]
    if not value.isascii() or not value.isdigit():
        raise _FrontFailure('backend_response_malformed')
    return int(value)

def _strict_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode('utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_json_constant, parse_float=_parse_finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        raise _FrontFailure('json_malformed') from exc

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def _reject_json_constant(value: str) -> Any:
    raise ValueError(f'non-finite JSON constant: {value}')

def _parse_finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('non-finite JSON number')
    return value

def _encode_json(document: Mapping[str, Any]) -> bytes:
    return json.dumps(document, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def _read_backend_token(path: Path | str) -> str:
    source = os.fspath(path)
    if not hasattr(os, 'O_NOFOLLOW'):
        raise EngineFrontConfigError('platform cannot safely open a nonsymlink backend token file')
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        fd = os.open(source, flags)
    except OSError as exc:
        raise EngineFrontConfigError('backend token file is unavailable') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 384 or (info.st_size > 4096):
            raise EngineFrontConfigError('backend token file must be a current-user-owned regular mode-0600 file')
        raw = os.read(fd, 4097)
        if len(raw) > 4096:
            raise EngineFrontConfigError('backend token file is too large')
    finally:
        os.close(fd)
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_json_constant, parse_float=_parse_finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        raise EngineFrontConfigError('backend token file is malformed') from exc
    if not isinstance(document, dict) or set(document) != {'token'}:
        raise EngineFrontConfigError('backend token file must contain exactly one token field')
    token = document.get('token')
    if not isinstance(token, str) or len(token) < 32 or (not _TOKEN_RE.fullmatch(token)) or token.startswith('REPLACE-'):
        raise EngineFrontConfigError('backend bearer token is weak or malformed')
    return token

def _require_numeric_loopback(host: str, *, field: str) -> None:
    if not isinstance(host, str):
        raise EngineFrontConfigError(f'{field} must be a numeric loopback address')
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise EngineFrontConfigError(f'{field} must be a numeric loopback address') from exc
    if not address.is_loopback:
        raise EngineFrontConfigError(f'{field} must be a numeric loopback address')

def _valid_identity_text(value: Any, *, max_length: int) -> bool:
    return isinstance(value, str) and bool(value) and (value == value.strip()) and (len(value) <= max_length) and (not any((ord(char) < 32 or ord(char) == 127 for char in value)))

def _positive_int(value: Any, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (not 1 <= value <= maximum):
        raise EngineFrontConfigError(f'{name} must be an integer in [1, {maximum}]')
    return value

def _positive_finite(value: Any, name: str, *, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EngineFrontConfigError(f'{name} must be finite, positive, and at most {maximum}')
    try:
        finite = math.isfinite(value)
    except (OverflowError, TypeError):
        finite = False
    if not finite or value <= 0 or value > maximum:
        raise EngineFrontConfigError(f'{name} must be finite, positive, and at most {maximum}')
    return float(value)
