# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Transparent byte relay to exactly-pinned loopback engine backends.

Transport rules (all deliberate):

- ``http.client`` is used directly. Unlike ``urllib.request`` it never consults
  ``http_proxy``/``https_proxy``/``no_proxy`` environment variables, so no
  environment proxy can intercept a request.
- The endpoint comes from trusted configuration only (loopback SSH tunnel
  addresses pinned by the parent). No request field can redirect it.
- Redirects are never followed. A 3xx or a ``Location`` header from the pinned
  backend is refused with ``backend_redirect_refused`` and the socket is closed.
- Exactly one attempt is made per request. If the engine may have received the
  request, the caller learns ``dispatched=True`` so it can retain the profile
  hold; nothing is ever retried after dispatch or after a stream began.
- The caller's JSON body bytes are forwarded unchanged; the engine's response
  bytes (JSON or SSE) are returned unchanged.
"""
from __future__ import annotations
import http.client
import json
import socket
import threading
from typing import Any, Callable, Iterator
from .config import LOOPBACK_HOSTS, BackendConfig
from .errors import BackendProtocolError, BackendRedirectRefusedError, BackendUnavailableError, ValidationError
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_PROBE_BYTES = 1 * 1024 * 1024

def require_loopback_host(host: str) -> str:
    if host not in LOOPBACK_HOSTS:
        raise ValidationError('refusing a non-loopback backend endpoint; pinned backend endpoints must be loopback', code='non_loopback_endpoint_refused', details={'host': host})
    return host

class ConnectionRegistry:
    """Own cancellable connections until a response exchange closes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connections: dict[int, Callable[[], None]] = {}
        self._next_id = 0
        self._closing = False

    def register(self, cancel: Callable[[], None]) -> int | None:
        with self._lock:
            if self._closing:
                token = None
            else:
                self._next_id += 1
                token = self._next_id
                self._connections[token] = cancel
        if token is None:
            cancel()
        return token

    def unregister(self, token: int | None) -> None:
        if token is not None:
            with self._lock:
                self._connections.pop(token, None)

    def cancel_all(self) -> None:
        with self._lock:
            self._closing = True
            callbacks = tuple(self._connections.values())
        first_error: Exception | None = None
        for cancel in callbacks:
            try:
                cancel()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise RuntimeError('one or more upstream connections could not be cancelled') from first_error

class _CancellableHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection whose in-progress TCP connect is visible to close()."""

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
                        raise OSError('upstream connection was cancelled')
                    self.sock = sock
                    self._owned_socket = sock
                sock.connect(address)
                if self._http_vsn == 11:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with self._cancel_lock:
                    if self._cancelled or self.sock is not sock:
                        raise OSError('upstream connection was cancelled')
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
                    raise OSError('upstream connection was cancelled') from exc
                last_error = exc
        if last_error is not None:
            raise last_error
        raise OSError('upstream endpoint resolved to no socket addresses')

    def getresponse(self) -> http.client.HTTPResponse:
        with self._cancel_lock:
            if self._cancelled:
                raise OSError('upstream connection was cancelled')
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

    @property
    def cancelled(self) -> bool:
        with self._cancel_lock:
            return self._cancelled

def _cancel_connection(conn: http.client.HTTPConnection) -> None:
    cancel = getattr(conn, 'cancel', None)
    (cancel if callable(cancel) else conn.close)()

class UpstreamChat:
    """One open engine exchange: connection, response, and its dispatched flag."""
    __slots__ = ('conn', 'resp', 'status', 'headers', 'backend', 'dispatched', '_registry', '_token')

    def __init__(self, conn: http.client.HTTPConnection, resp: http.client.HTTPResponse, backend: BackendConfig, *, registry: ConnectionRegistry | None=None, token: int | None=None):
        self.conn = conn
        self.resp = resp
        self.status = int(resp.status)
        self.headers = {key.lower(): value for key, value in resp.getheaders()}
        self.backend = backend
        self._registry = registry
        self._token = token
        self.dispatched = True

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @property
    def cancelled(self) -> bool:
        return bool(getattr(self.conn, 'cancelled', False))

    def close(self) -> None:
        try:
            self.resp.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        if self._registry is not None:
            self._registry.unregister(self._token)

def _load_auth_header(backend: BackendConfig) -> str | None:
    if not backend.auth_token_file:
        return None
    from .registry import read_private_json
    document = read_private_json(backend.auth_token_file, label=f'backend token for {backend.profile}')
    token = document.get('token')
    if not isinstance(token, str) or not token.strip():
        raise ValidationError(f'backend token file for {backend.profile} must contain a non-empty token', code='invalid_backend_token')
    token = token.strip()
    if any((ord(char) < 33 or ord(char) > 126 for char in token)):
        raise ValidationError('backend token must contain only visible ASCII characters without whitespace', code='invalid_backend_token')
    return 'Bearer ' + token

def _connect(backend: BackendConfig, *, timeout: float) -> http.client.HTTPConnection:
    require_loopback_host(backend.host)
    return _CancellableHTTPConnection(backend.host, backend.port, timeout=timeout)

def probe_backend_models(backend: BackendConfig, *, timeout: float=5.0, connection_registry: ConnectionRegistry | None=None) -> dict[str, Any]:
    """Check the pinned backend actually serves ``expected_model_id``.

    Returns ``{"ok": bool, "reason_code": str, "model_ids": [...]}``. Never
    raises for network conditions; the caller decides how to fail closed.
    """
    if not isinstance(backend.health_path, str) or not backend.health_path.strip() or (not isinstance(backend.expected_model_id, str)) or (not backend.expected_model_id.strip()):
        return {'ok': False, 'reason_code': 'backend_identity_probe_unconfigured', 'model_ids': []}
    try:
        auth = _load_auth_header(backend)
    except (ValidationError, UnicodeError):
        return {'ok': False, 'reason_code': 'backend_auth_invalid', 'model_ids': []}
    headers = {'Accept': 'application/json', 'Connection': 'close'}
    if auth:
        headers['Authorization'] = auth
    conn: http.client.HTTPConnection | None = None
    registration: int | None = None
    try:
        conn = _connect(backend, timeout=timeout)
        if connection_registry is not None:
            registration = connection_registry.register(lambda: _cancel_connection(conn))
            if registration is None:
                raise OSError('backend probe cancelled during shutdown')
        conn.request('GET', backend.health_path, headers=headers)
        resp = conn.getresponse()
        if resp.status in REDIRECT_STATUSES or resp.getheader('Location'):
            return {'ok': False, 'reason_code': 'backend_redirect_refused', 'model_ids': []}
        raw = resp.read(MAX_PROBE_BYTES)
        if resp.status != 200:
            return {'ok': False, 'reason_code': f'backend_health_status_{resp.status}', 'model_ids': []}
    except (OSError, http.client.HTTPException) as exc:
        return {'ok': False, 'reason_code': 'backend_unreachable', 'model_ids': [], 'detail': type(exc).__name__}
    finally:
        if conn is not None:
            conn.close()
        if connection_registry is not None:
            connection_registry.unregister(registration)
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {'ok': False, 'reason_code': 'backend_health_malformed', 'model_ids': []}
    ids: list[str] = []
    data = document.get('data') if isinstance(document, dict) else None
    if isinstance(data, list):
        ids = [item.get('id') for item in data if isinstance(item, dict) and isinstance(item.get('id'), str)]
    if backend.expected_model_id not in ids:
        return {'ok': False, 'reason_code': 'backend_model_mismatch', 'model_ids': ids}
    return {'ok': True, 'reason_code': 'ok', 'model_ids': ids}

def open_chat(backend: BackendConfig, raw_body: bytes, *, stream: bool, content_type: str | None, connect_timeout: float, read_timeout: float, connection_registry: ConnectionRegistry | None=None) -> UpstreamChat:
    """Send exactly one request, retaining dispatch ambiguity on failure."""
    require_loopback_host(backend.host)
    conn: http.client.HTTPConnection | None = None
    registration: int | None = None
    sent = False
    try:
        conn = _connect(backend, timeout=connect_timeout)
        if connection_registry is not None:
            registration = connection_registry.register(lambda: _cancel_connection(conn))
            if registration is None:
                raise OSError('upstream request cancelled during shutdown')
        headers = {'Content-Type': content_type or 'application/json', 'Accept': 'text/event-stream' if stream else 'application/json', 'Connection': 'close', 'Content-Length': str(len(raw_body))}
        auth = _load_auth_header(backend)
        if auth:
            headers['Authorization'] = auth
        conn.connect()
        sent = True
        conn.request('POST', backend.chat_path, body=raw_body, headers=headers)
        if conn.sock is not None:
            conn.sock.settimeout(read_timeout)
        resp = conn.getresponse()
    except ValidationError:
        if conn is not None:
            conn.close()
        if connection_registry is not None:
            connection_registry.unregister(registration)
        raise
    except socket.timeout as exc:
        if conn is not None:
            conn.close()
        if connection_registry is not None:
            connection_registry.unregister(registration)
        raise BackendUnavailableError('backend_timeout: the pinned engine did not answer in time', code='backend_timeout', details={'profile': backend.profile, 'dispatched': sent}) from exc
    except (OSError, http.client.HTTPException) as exc:
        if conn is not None:
            conn.close()
        if connection_registry is not None:
            connection_registry.unregister(registration)
        raise BackendUnavailableError('backend_unreachable: the pinned engine endpoint could not be reached', code='backend_unreachable', details={'profile': backend.profile, 'dispatched': sent, 'transport': type(exc).__name__}) from exc
    if resp.status in REDIRECT_STATUSES or resp.getheader('Location'):
        resp.close()
        conn.close()
        if connection_registry is not None:
            connection_registry.unregister(registration)
        raise BackendRedirectRefusedError('backend_redirect_refused: the pinned engine answered with a redirect/Location; the gateway never follows it', details={'profile': backend.profile, 'status': int(resp.status), 'dispatched': True})
    return UpstreamChat(conn, resp, backend, registry=connection_registry, token=registration)

def iter_response_chunks(resp: http.client.HTTPResponse, *, chunk_size: int=4096, max_total: int) -> Iterator[bytes]:
    """Yield engine response bytes unchanged, bounded by ``max_total``.

    ``read1`` is used so an SSE chunk is relayed as soon as it arrives instead
    of waiting for a full buffer (``read(n)`` may issue multiple raw reads).
    A body that ends before its declared ``Content-Length`` is reported as a
    truncation instead of masquerading as a clean final chunk.
    """
    reader = getattr(resp, 'read1', None) or resp.read
    total = 0
    while True:
        chunk = reader(chunk_size)
        if not chunk:
            remaining = getattr(resp, 'length', None)
            if remaining:
                raise BackendProtocolError('backend_body_truncated: the engine closed before delivering the declared body', details={'remaining_bytes': int(remaining)})
            return
        total += len(chunk)
        if total > max_total:
            raise BackendProtocolError('backend_response_too_large: the engine exceeded the configured response bound', details={'max_response_bytes': max_total})
        yield chunk

def read_response_body(resp: http.client.HTTPResponse, *, max_total: int) -> bytes:
    return b''.join(iter_response_chunks(resp, max_total=max_total))
