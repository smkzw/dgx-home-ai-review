# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import http.client
import json
import math
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit
from . import upstream, validation
from .config import LOOPBACK_HOSTS, GatewayConfig, config_summary
from .errors import BackendProtocolError, BackendRedirectRefusedError, BackendUnavailableError, CapabilityDisabledError, ConflictError, GatewayError
from .facade import NullBackendFacade, require_facade
from .registry import Identity, TokenRegistry
from .scheduler import RequestInfo, Scheduler
from .state import REQUEUEABLE_STATES, GatewayStore, digest_of
GATEWAY_CONTRACT_VERSION = '1'
SERVICE_NAME = 'dgx-v4-llm-gateway'
_SERVICE_REASONS = {'profile_not_ready', 'profile_starting', 'profile_lifecycle_pending', 'profile_reconciling', 'facade_unavailable', 'facade_disabled', 'facade_reply_malformed', 'facade_ready_without_identity', 'facade_model_mismatch'}
_UNAVAILABLE_ROOTS = {'assets', 'jobs', 'comfy', 'images', 'workflows'}

class _ClientGone(Exception):
    """The HTTP client went away while we were writing the relayed response."""

class _Relayed(Exception):
    """Internal: the response was already written by the relay path."""

def _backend_model_wire_body(raw: bytes, *, admitted_alias: str, expected_model_id: str) -> bytes:
    """Replace only the top-level model JSON value, preserving all other bytes.

    The alias and native ID must come from the trusted gateway configuration.
    Revalidate before scanning so malformed input or duplicate (including escaped)
    keys cannot select a different model span. Character offsets are converted to
    UTF-8 byte offsets; Unicode before the model value must not shift the splice.
    """
    body = validation.parse_json_object(raw, max_bytes=len(raw))
    actual_alias = body.get('model')
    if not isinstance(admitted_alias, str) or not admitted_alias.strip() or (not isinstance(expected_model_id, str)) or (not expected_model_id.strip()):
        raise validation.ValidationError('trusted model translation configuration is missing', code='invalid_model_translation', http_status=503)
    if not isinstance(actual_alias, str) or actual_alias.strip() != admitted_alias:
        raise validation.ValidationError('request model does not match the admitted alias', code='invalid_model_translation')
    text = raw.decode('utf-8')
    decoder = json.JSONDecoder()
    whitespace = ' \t\r\n'

    def skip_space(index: int) -> int:
        while index < len(text) and text[index] in whitespace:
            index += 1
        return index
    index = skip_space(0) + 1
    while True:
        index = skip_space(index)
        if text[index] == '}':
            break
        key, index = decoder.raw_decode(text, index)
        index = skip_space(index) + 1
        start = skip_space(index)
        _, end = decoder.raw_decode(text, start)
        if key == 'model':
            byte_start = len(text[:start].encode('utf-8'))
            byte_end = len(text[:end].encode('utf-8'))
            native_value = json.dumps(expected_model_id, ensure_ascii=True).encode('ascii')
            return raw[:byte_start] + native_value + raw[byte_end:]
        index = skip_space(end)
        if text[index] == '}':
            break
        index += 1
    raise validation.ValidationError('request model value was not found', code='invalid_model_translation')

def _shutdown_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass

class _ManagedHTTPServer(ThreadingHTTPServer):
    """Track accepted clients, handler workers, and exact upstream cancellers."""
    daemon_threads = False
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        self.shutdown_timeout_seconds = 10.0
        self._state_lock = threading.Lock()
        self._closing = False
        self._active_sockets: set[socket.socket] = set()
        self._handler_threads: set[threading.Thread] = set()
        self._worker_failures: list[Exception] = []
        self._cancellations: dict[int, Callable[[], None]] = {}
        self._next_cancellation = 0
        super().__init__(address, handler)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        thread = threading.Thread(target=self.process_request_thread, args=(request, client_address), name='llm-gateway-handler', daemon=False)
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
            raise RuntimeError('one or more gateway sockets could not be cancelled') from first_error

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
                with self._state_lock:
                    failure = self._worker_failures[0] if self._worker_failures else None
                if failure is not None:
                    raise RuntimeError('a gateway worker did not shut down cleanly') from failure
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
                raise TimeoutError(f"gateway workers did not stop: {', '.join(names)}")

    def record_worker_failure(self, error: Exception) -> None:
        with self._state_lock:
            self._worker_failures.append(error)

    def has_live_threads(self) -> bool:
        with self._state_lock:
            return any((thread.is_alive() for thread in self._handler_threads))

    def _prune_threads_locked(self) -> None:
        dead = [thread for thread in self._handler_threads if not thread.is_alive()]
        self._handler_threads.difference_update(dead)

class _ClientDisconnectWatcher:

    def __init__(self, client: socket.socket, cancel_upstream: Callable[[], None], server: _ManagedHTTPServer):
        self.client = client
        self.cancel_upstream = cancel_upstream
        self.server = server
        self.disconnected = threading.Event()
        self._stopping = threading.Event()
        self._started = False
        self.failure: Exception | None = None
        self._thread = threading.Thread(target=self._watch, name='llm-gateway-disconnect', daemon=False)

    def start(self) -> bool:
        self._started = self.server.start_managed_thread(self._thread)
        if not self._started:
            self._disconnect()
        return self._started

    def _disconnect(self) -> None:
        self.disconnected.set()
        try:
            self.cancel_upstream()
        except Exception as exc:
            self.failure = exc

    def _watch(self) -> None:
        while not self._stopping.is_set():
            try:
                readable, _writable, _exceptional = select.select([self.client], [], [], 0.1)
                if not readable:
                    continue
                data = self.client.recv(1, socket.MSG_PEEK)
                self._disconnect()
                if data:
                    return
                return
            except (OSError, ValueError):
                self._disconnect()
                return

    def stop(self) -> None:
        self._stopping.set()
        if self._started:
            self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                self.failure = TimeoutError('gateway disconnect watcher did not stop')
        if self.failure is not None:
            self.server.record_worker_failure(self.failure)
            raise RuntimeError('gateway disconnect watcher failed') from self.failure

class GatewayServer:
    """Owns the single gateway instance served on loopback."""

    def __init__(self, *, config: GatewayConfig, registry: TokenRegistry, store: GatewayStore, facade: Any, probe_backend: Any | None=None, clock: Any=time.time):
        if config.enabled is not True:
            raise GatewayError('gateway_disabled: configuration must explicitly enable the gateway; the default is disabled until the parent integrates a verified facade', code='gateway_disabled', http_status=503)
        if config.host not in LOOPBACK_HOSTS:
            raise GatewayError('non_loopback_bind_refused: refusing to bind a non-loopback address in this core', code='non_loopback_bind_refused', http_status=400)
        self.config = config
        self.registry = registry
        self.store = store
        self.facade = require_facade(facade)
        self.clock = clock
        self.shutdown_timeout_seconds = 10.0
        self.shutdown_safe = True
        self._stopping = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._shutdown_started = False
        self._shutdown_complete = threading.Event()
        self._shutdown_error: BaseException | None = None
        self._probe_connections = upstream.ConnectionRegistry()
        self.recovery = store.recover_after_restart()
        if probe_backend is None or probe_backend is upstream.probe_backend_models:
            backend_probe = lambda backend: upstream.probe_backend_models(backend, connection_registry=self._probe_connections)
        else:
            backend_probe = probe_backend
        self.scheduler = Scheduler(store=store, facade=self.facade, config=config, probe_backend=backend_probe, clock=clock)
        self._build_time = int(clock())
        handler = self._handler_class()
        self.httpd = _ManagedHTTPServer((config.host, config.port), handler)
        self.httpd.shutdown_timeout_seconds = self.shutdown_timeout_seconds
        self.httpd.register_cancellation(self._stopping.set)
        self.httpd.register_cancellation(self._probe_connections.cancel_all)
        self.host, self.port = (self.httpd.server_address[0], self.httpd.server_address[1])
        self._thread: threading.Thread | None = None

    def start_background(self) -> 'GatewayServer':
        self.scheduler.start()
        self._thread = threading.Thread(target=self.httpd.serve_forever, name='llm-gateway-http', daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self.scheduler.start()
        self.httpd.serve_forever()

    def cancel_active(self) -> None:
        self._stopping.set()
        first_error: BaseException | None = None
        for cancel in (self._probe_connections.cancel_all, self.httpd.cancel_active):
            try:
                cancel()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise RuntimeError('gateway socket cancellation failed') from first_error

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shutdown_complete.is_set():
                if self._shutdown_error is not None:
                    raise self._shutdown_error
                return
            if self._shutdown_started:
                owner = False
            else:
                self._shutdown_started = True
                owner = True
        if not owner:
            if not self._shutdown_complete.wait(self.shutdown_timeout_seconds):
                raise TimeoutError('gateway shutdown coordinator did not finish')
            if self._shutdown_error is not None:
                raise self._shutdown_error
            return
        deadline = time.monotonic() + self.shutdown_timeout_seconds
        errors: list[BaseException] = []
        scheduler_thread = getattr(self.scheduler, '_thread', None)
        serving_thread = self._thread
        try:
            try:
                self.cancel_active()
            except BaseException as exc:
                errors.append(exc)
            try:
                self.httpd.shutdown()
            except BaseException as exc:
                errors.append(exc)
            try:
                self.scheduler.stop()
            except BaseException as exc:
                errors.append(exc)
            if scheduler_thread is not None and scheduler_thread is not threading.current_thread():
                scheduler_thread.join(max(0.0, deadline - time.monotonic()))
                if scheduler_thread.is_alive():
                    errors.append(TimeoutError('gateway scheduler did not stop'))
            self.httpd.shutdown_timeout_seconds = max(0.0, deadline - time.monotonic())
            try:
                self.httpd.server_close()
            except BaseException as exc:
                errors.append(exc)
            if serving_thread is not None and serving_thread is not threading.current_thread():
                serving_thread.join(max(0.0, deadline - time.monotonic()))
                if serving_thread.is_alive():
                    errors.append(TimeoutError('gateway serving thread did not stop'))
                else:
                    self._thread = None
            scheduler_alive = scheduler_thread is not None and scheduler_thread.is_alive()
            serving_alive = serving_thread is not None and serving_thread.is_alive()
            self.shutdown_safe = not scheduler_alive and (not serving_alive) and (not self.httpd.has_live_threads())
            if not self.shutdown_safe and (not errors):
                errors.append(TimeoutError('gateway workers remain active'))
        finally:
            self._shutdown_error = RuntimeError(f'gateway shutdown failed: {type(errors[0]).__name__}') if errors else None
            self._shutdown_complete.set()
        if self._shutdown_error is not None:
            raise self._shutdown_error from errors[0]

    @property
    def base_url(self) -> str:
        host = '127.0.0.1' if self.host in {'0.0.0.0', '::'} else self.host
        return f'http://{host}:{self.port}'

    def _handler_class(self):
        server_outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            server_version = 'dgx-v4-llm-gateway/0.1'

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _send_json(self, status: int, payload: dict[str, Any], extra: dict[str, str] | None=None) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
                headers = {'Content-Type': 'application/json; charset=utf-8', 'Content-Length': str(len(body)), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Connection': 'close'}
                if extra:
                    headers.update(extra)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def _send_raw(self, status: int, headers: dict[str, str], body: bytes) -> None:
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def _begin_raw_stream(self, status: int, headers: dict[str, str]) -> None:
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.close_connection = True
                self.end_headers()

            def _identity(self) -> Identity:
                return server_outer.registry.identify(self.headers.get('Authorization'))

            def _read_raw_body(self, *, limit: int) -> bytes:
                length_header = self.headers.get('Content-Length')
                if length_header is None:
                    raise validation.ValidationError('Content-Length is required for POST bodies', code='length_required', http_status=411)
                try:
                    length = int(length_header)
                except (TypeError, ValueError) as exc:
                    raise validation.ValidationError('invalid Content-Length', code='invalid_length') from exc
                if length < 0:
                    raise validation.ValidationError('invalid Content-Length', code='invalid_length')
                if length > limit:
                    raise validation.PayloadTooLargeError('request body exceeds the configured limit', details={'max_body_bytes': limit, 'declared_bytes': length})
                return self.rfile.read(length) if length else b''

            def _read_small_json(self, *, limit: int=64 * 1024) -> dict[str, Any]:
                raw = self._read_raw_body(limit=limit)
                return validation.parse_json_object(raw, max_bytes=limit)

            def do_GET(self) -> None:
                self._dispatch('GET')

            def do_POST(self) -> None:
                self._dispatch('POST')

            def _dispatch(self, method: str) -> None:
                try:
                    identity = self._identity()
                    parsed = urlsplit(self.path)
                    segments = [s for s in parsed.path.split('/') if s]
                    query = parse_qs(parsed.query)
                    status, payload, extra = server_outer.route(method, segments, query, identity, self)
                    self._send_json(status, payload, extra)
                except _Relayed:
                    return
                except GatewayError as exc:
                    extra: dict[str, str] = {}
                    if exc.request_id:
                        extra['X-Gateway-Request-Id'] = exc.request_id
                    if exc.retry_after_seconds is not None and exc.http_status in (429, 503):
                        extra['Retry-After'] = str(max(1, int(math.ceil(exc.retry_after_seconds))))
                    self._send_json(exc.http_status, exc.as_dict(), extra)
                except Exception as exc:
                    self._send_json(500, {'error': {'message': 'internal error; see server-side logs', 'type': 'server_error', 'code': 'internal_error', 'details': {'type': type(exc).__name__}}})
                finally:
                    server_outer.store.close_thread_connection()
        return Handler

    def route(self, method: str, segments: list[str], query: dict[str, list[str]], identity: Identity, handler: Any) -> tuple[int, dict[str, Any], dict[str, str]]:
        if segments and segments[0] == 'api':
            raise CapabilityDisabledError('capability_disabled: the job/asset API is served by the control-plane core, not by this LLM gateway', details={'surface': 'api/v1'})
        if not segments or segments[0] != 'v1':
            raise validation.ValidationError('unknown endpoint', code='not_found', http_status=404)
        path = segments[1:]
        if path and path[0] in _UNAVAILABLE_ROOTS:
            raise CapabilityDisabledError(f'capability_disabled: {path[0]} is not implemented by this gateway', details={'surface': path[0], 'note': 'assets/Comfy/workflow execution are out of scope'})
        if method == 'GET' and path == ['models']:
            identity.require('models')
            return (200, self._models_document(), {})
        if method == 'GET' and path == ['gateway', 'status']:
            identity.require('models')
            return (200, self._status_document(), {})
        if method == 'POST' and path == ['chat', 'completions']:
            identity.require('chat')
            return self._chat(handler, identity)
        if method == 'POST' and path == ['sessions']:
            identity.require('sessions')
            return self._create_session(handler, identity)
        if method == 'GET' and len(path) == 2 and (path[0] == 'requests'):
            identity.require('chat')
            return (200, self._request_document(identity, path[1]), {})
        if method == 'POST' and len(path) == 3 and (path[0] == 'requests') and (path[2] == 'cancel'):
            identity.require('chat')
            return self._cancel_request(identity, path[1])
        if method == 'POST' and len(path) == 3 and (path[0] == 'sessions') and (path[2] in {'yield', 'resume'}):
            identity.require('sessions')
            return self._session_action(identity, path[1], path[2])
        raise validation.ValidationError('unknown endpoint', code='not_found', http_status=404)

    def _models_document(self) -> dict[str, Any]:
        return {'object': 'list', 'data': [{'id': alias, 'object': 'model', 'created': self._build_time, 'owned_by': SERVICE_NAME} for alias in sorted(self.config.models)]}

    def _status_document(self) -> dict[str, Any]:
        return {'service': SERVICE_NAME, 'contract_version': GATEWAY_CONTRACT_VERSION, 'production_ready': False, 'note': 'Loopback LLM queue/relay only. Lifecycle is facade-controlled; no hardware validation, no G6 acceptance, prompts are never persisted.', 'config': config_summary(self.config), 'registry': {'tokens': len(self.registry), 'owners': len(self.registry.owners)}, 'facade': {'protocol': ['ensure_ready', 'safe_drain_and_stop', 'get_generation', 'health'], 'null_facade': isinstance(self.facade, NullBackendFacade)}, 'queue': self.scheduler.status(), 'recovery': self.recovery}

    def _request_document(self, identity: Identity, request_id: str) -> dict[str, Any]:
        row = self.store.require_request_owner(request_id, owner=identity.name)
        return {'object': 'llm_gateway.request', 'request_id': row['request_id'], 'model': row['model_alias'], 'state': row['state'], 'reason_code': row['reason_code'], 'dispatched': row['dispatched'], 'uncertain': row['uncertain'], 'attempts': row['attempts'], 'created_at': row['created_at'], 'updated_at': row['updated_at'], 'replayable': row['state'] in REQUEUEABLE_STATES and (not row['dispatched']), 'note': 'prompts and completions are never persisted; a terminal request cannot replay its content. Retry a never-dispatched request with the same Idempotency-Key, or call /v1/chat/completions again with a new key'}

    @staticmethod
    def _relay_headers(uc: upstream.UpstreamChat, request_id: str, *, length: int | None) -> dict[str, str]:
        headers: dict[str, str] = {'X-Gateway-Request-Id': request_id, 'Cache-Control': 'no-store', 'Connection': 'close'}
        for key, value in uc.headers.items():
            if key in {'connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'content-length'}:
                continue
            if key.startswith('proxy-'):
                continue
            headers[key.title()] = value
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        if length is not None:
            headers['Content-Length'] = str(length)
        return headers

    def _chat(self, handler: Any, identity: Identity) -> tuple[int, dict[str, Any], dict[str, str]]:
        cfg = self.config
        raw = handler._read_raw_body(limit=cfg.max_body_bytes)
        body = validation.parse_json_object(raw, max_bytes=cfg.max_body_bytes)
        alias = body.get('model')
        if not isinstance(alias, str) or alias.strip() not in cfg.models:
            raise validation.ModelNotFoundError('model_not_found: unknown model', details={'model': alias if isinstance(alias, str) else None, 'known': sorted(cfg.models)})
        model = cfg.models[alias.strip()]
        validation.validate_chat_body(body, capabilities=model.capabilities)
        backend_raw = _backend_model_wire_body(raw, admitted_alias=model.alias, expected_model_id=cfg.backends[model.profile].expected_model_id)
        session_id = validation.validate_session_id(handler.headers.get('X-Session-Id'), header='X-Session-Id')
        parent_id = validation.validate_session_id(handler.headers.get('X-Parent-Session-Id'), header='X-Parent-Session-Id')
        idempotency_key = validation.validate_idempotency_key(handler.headers.get('Idempotency-Key'))
        stream_requested = body.get('stream') is True
        if session_id:
            session = self.store.require_session_owner(session_id, owner=identity.name)
            if session['profile'] != model.profile:
                raise ConflictError('session_profile_mismatch: the session is bound to a different model', code='session_profile_mismatch', details={'session_id': session_id})
            if session['state'] == 'yielded':
                raise ConflictError('session_yielded: resume the session before sending requests', code='session_yielded', details={'session_id': session_id})
            self.store.touch_session(session_id)
        waiting = False
        if parent_id:
            parent = self.store.require_session_owner(parent_id, owner=identity.name)
            if parent['profile'] != model.profile:
                raise ConflictError('parent_session_profile_mismatch: the parent session is bound to a different model', code='parent_session_profile_mismatch', details={'parent_session_id': parent_id})
            waiting = parent['state'] != 'yielded'
        with self.scheduler.operator_admission():
            admission = self.store.admit_request(owner=identity.name, idempotency_key=idempotency_key, payload_digest=digest_of(body), model_alias=model.alias, profile=model.profile, stream=stream_requested, session_id=session_id, parent_session_id=parent_id, waiting=waiting)
            if admission['idempotent_replay']:
                self._replay_response(admission['request'])
            row = admission['request']
            request_id = row['request_id']
            now = self.clock()
            info = RequestInfo(request_id=request_id, owner=identity.name, alias=model.alias, profile=model.profile, session_id=session_id, parent_session_id=parent_id, stream=stream_requested, submitted_at=now, deadline=now + cfg.policy.sync_queue_wait_seconds)
            self.scheduler.register(info)
        granted: dict[str, Any] | None = None
        try:
            while True:
                if self.store.request_view(request_id)['state'] == 'cancelled':
                    error = ConflictError('request_cancelled: the queued request was cancelled before dispatch', code='request_cancelled', details={'request_id': request_id})
                    error.request_id = request_id
                    raise error
                if self._stopping.is_set():
                    self.store.expire_request(request_id, reason_code='gateway_shutdown')
                    self.scheduler.abandon(request_id)
                    raise GatewayError('gateway is shutting down', code='gateway_shutdown', http_status=503, error_type='server_error')
                decision = self.scheduler.try_grant(request_id)
                if decision['granted']:
                    granted = decision
                    break
                remaining = info.deadline - self.clock()
                if remaining <= 0:
                    self.store.expire_request(request_id, reason_code=decision['reason_code'])
                    self.scheduler.abandon(request_id)
                    raise self._timeout_error(decision, model.alias, request_id)
                self.scheduler.wait_for_change(min(0.15, max(0.01, remaining)))
        except BaseException:
            if granted is None:
                self.scheduler.abandon(request_id)
            raise
        generation_check = self.scheduler.validate_dispatch_generation(model.profile, expected_generation=granted['generation'])
        if not generation_check['ok']:
            reason = str(generation_check['reason_code'] or 'facade_generation_unavailable')
            try:
                self.store.finish_request(request_id, state='reconciling', reason_code=reason, uncertain=True)
            finally:
                self.scheduler.release(request_id, keep_slot=True)
            error = GatewayError('facade_generation_unconfirmed: the current profile generation could not be verified', code=reason, http_status=503, error_type='server_error', retry_after_seconds=30.0, details={'cause': reason})
            error.request_id = request_id
            raise error
        try:
            self.store.mark_dispatched(request_id, generation=generation_check['generation'])
        except ConflictError as exc:
            self.scheduler.release(request_id)
            exc.request_id = request_id
            raise
        self._serve(handler, row, backend_raw, stream=stream_requested)
        raise _Relayed()

    def _serve(self, handler: Any, row: dict[str, Any], raw_body: bytes, *, stream: bool) -> None:
        """Relay one dispatched request without retrying an uncertain exchange."""
        request_id = row['request_id']
        backend = self.config.backends[row['profile']]
        cfg = self.config
        connections = upstream.ConnectionRegistry()
        cancellation = self.httpd.register_cancellation(connections.cancel_all)
        watcher = _ClientDisconnectWatcher(handler.connection, connections.cancel_all, self.httpd)
        try:
            if not watcher.start():
                raise BackendUnavailableError('gateway_shutdown: request relay cancelled before backend dispatch', code='backend_unreachable', details={'profile': backend.profile, 'dispatched': False})
            try:
                uc = upstream.open_chat(backend, raw_body, stream=stream, content_type=handler.headers.get('Content-Type'), connect_timeout=cfg.connect_timeout_seconds, read_timeout=cfg.read_timeout_seconds, connection_registry=connections)
            except BackendUnavailableError as exc:
                if exc.details.get('dispatched'):
                    self._finish(request_id, 'reconciling', 'backend_exchange_unconfirmed', keep_slot=True)
                else:
                    self._finish(request_id, 'failed', 'backend_unreachable')
                exc.request_id = request_id
                raise
            except BackendRedirectRefusedError as exc:
                self._finish(request_id, 'reconciling', 'backend_redirect_unconfirmed', keep_slot=True)
                exc.request_id = request_id
                raise
            self._relay(handler, request_id, uc, stream=stream, client_disconnected=watcher.disconnected)
        finally:
            try:
                watcher.stop()
            finally:
                self.httpd.unregister_cancellation(cancellation)

    def _relay(self, handler: Any, request_id: str, uc: upstream.UpstreamChat, *, stream: bool, client_disconnected: threading.Event) -> None:
        status = uc.status
        content_type = uc.header('Content-Type') or 'application/json'
        streaming = stream and status == 200 and content_type.lower().startswith('text/event-stream')
        max_total = self.config.max_response_bytes
        engine_error: Exception | None = None
        client_gone = False
        body_read = False
        stream_started = False
        settled = False
        try:
            if streaming:
                handler._begin_raw_stream(status, self._relay_headers(uc, request_id, length=None))
                stream_started = True
                try:
                    for chunk in upstream.iter_response_chunks(uc.resp, max_total=max_total):
                        try:
                            handler.wfile.write(chunk)
                            handler.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                            raise _ClientGone() from None
                    if uc.cancelled:
                        raise OSError('upstream exchange was cancelled before completion')
                    body_read = True
                except _ClientGone:
                    client_gone = True
                except (BackendProtocolError, http.client.HTTPException, OSError) as exc:
                    engine_error = exc
            else:
                body = b''
                try:
                    body = upstream.read_response_body(uc.resp, max_total=max_total)
                    if uc.cancelled:
                        raise OSError('upstream exchange was cancelled before completion')
                    body_read = True
                except (BackendProtocolError, http.client.HTTPException, OSError) as exc:
                    engine_error = exc
                if engine_error is None:
                    outcome = 'succeeded' if status == 200 else 'failed'
                    reason = None if status == 200 else f'upstream_status_{status}'
                    self._finish(request_id, outcome, reason)
                    settled = True
                    headers = self._relay_headers(uc, request_id, length=len(body))
                    try:
                        handler._send_raw(status, headers, body)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                        client_gone = True
        finally:
            uc.close()
        if client_disconnected.is_set() and (not body_read):
            client_gone = True
            engine_error = None
        if settled:
            return
        if engine_error is not None:
            self._finish(request_id, 'reconciling', 'engine_exchange_unconfirmed', keep_slot=True)
            if stream_started:
                return
            if isinstance(engine_error, GatewayError):
                raise engine_error
            raise BackendProtocolError('backend_stream_failed: the engine exchange failed before any bytes were relayed', code='backend_stream_failed', details={'transport': type(engine_error).__name__, 'request_id': request_id})
        if client_gone:
            if body_read:
                self._finish(request_id, 'failed', 'response_delivery_failed')
            else:
                self._finish(request_id, 'reconciling', 'client_disconnect_unconfirmed', keep_slot=True)
            return
        if status == 200:
            self._finish(request_id, 'succeeded', None)
        else:
            self._finish(request_id, 'failed', f'upstream_status_{status}')

    def _finish(self, request_id: str, state: str, reason_code: str | None, *, keep_slot: bool=False) -> None:
        try:
            self.store.finish_request(request_id, state=state, reason_code=reason_code, uncertain=state == 'reconciling')
        except Exception:
            pass
        self.scheduler.release(request_id, keep_slot=keep_slot)

    def _timeout_error(self, decision: dict[str, Any], alias: str, request_id: str) -> GatewayError:
        reason = str(decision.get('reason_code') or 'sync_wait_timeout')
        retry = float(decision.get('retry_after_seconds') or 15.0)
        waited = self.config.policy.sync_queue_wait_seconds
        service = reason in _SERVICE_REASONS or reason.startswith('facade_') or reason.startswith('backend_')
        if service:
            error: GatewayError = GatewayError(f'model_not_ready: {alias} could not be made ready within the synchronous wait', code=reason, http_status=503, error_type='server_error', retry_after_seconds=retry, details={'model': alias, 'cause': reason, 'waited_seconds': waited})
        else:
            error = GatewayError(f'queue_timeout: {alias} stayed queued for the whole synchronous wait', code='sync_wait_timeout', http_status=429, error_type='rate_limit_error', retry_after_seconds=retry, details={'model': alias, 'cause': reason, 'waited_seconds': waited})
        error.request_id = request_id
        return error

    def _replay_response(self, row: dict[str, Any]) -> None:
        """Answer a duplicate Idempotency-Key with the request's *known state*.

        No duplicate inference is ever started, and no fabricated completion is
        returned: synchronous content is not persisted, so a terminal request
        can only be reported, not replayed.
        """
        request_id = row['request_id']
        state = row['state']
        if state in {'queued', 'waiting_session', 'dispatched'}:
            error = ConflictError('duplicate_request_in_flight: this Idempotency-Key is already in flight; the gateway will not start a second inference', code='duplicate_request_in_flight', details={'request_id': request_id, 'state': state}, retry_after_seconds=5.0)
        elif state == 'reconciling':
            error = ConflictError('duplicate_request_reconciling: this Idempotency-Key is being reconciled after an unconfirmed engine exchange', code='duplicate_request_reconciling', details={'request_id': request_id, 'state': state}, retry_after_seconds=30.0)
        else:
            error = ConflictError('idempotent_replay_terminal: this Idempotency-Key already reached a terminal state; prompts and completions are not persisted, so the original answer cannot be replayed', code='idempotent_replay_terminal', details={'request_id': request_id, 'state': state, 'reason_code': row['reason_code']})
        error.request_id = request_id
        raise error

    def _create_session(self, handler: Any, identity: Identity) -> tuple[int, dict[str, Any], dict[str, str]]:
        body = handler._read_small_json()
        unknown = sorted(set(body) - {'model'})
        if unknown:
            raise validation.ValidationError('unknown field(s) for session creation', code='unknown_field', details={'unknown_fields': unknown})
        alias = body.get('model')
        if not isinstance(alias, str) or alias.strip() not in self.config.models:
            raise validation.ModelNotFoundError('model_not_found: model must be a configured alias', details={'model': alias if isinstance(alias, str) else None})
        model = self.config.models[alias.strip()]
        session = self.store.create_session(owner=identity.name, model_alias=model.alias, profile=model.profile)
        return (201, {'session_id': session['session_id'], 'object': 'llm_gateway.session', 'state': session['state'], 'model': model.alias}, {})

    def _session_action(self, identity: Identity, session_id: str, action: str) -> tuple[int, dict[str, Any], dict[str, str]]:
        if action == 'yield':
            session = self.store.yield_session(session_id, owner=identity.name)
        else:
            session = self.store.resume_session(session_id, owner=identity.name)
        return (200, {'session_id': session['session_id'], 'object': 'llm_gateway.session', 'state': session['state']}, {})

    def _cancel_request(self, identity: Identity, request_id: str) -> tuple[int, dict[str, Any], dict[str, str]]:
        result = self.store.request_cancel(request_id, owner=identity.name)
        row = result['request']
        return (200, {'request_id': row['request_id'], 'object': 'llm_gateway.request', 'state': row['state'], 'cancel': result['cancel']}, {})
