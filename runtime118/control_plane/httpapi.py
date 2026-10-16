# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Minimal authenticated loopback HTTP API (contract "1" subset).

Security posture:
- Binds loopback only by default (``127.0.0.1``); no Tailscale/public bind here.
- Two token classes: the admin/lifecycle token (from a 0600 file) may run
  lifecycle operations; ordinary job tokens cannot. ``owner`` is derived from
  the token, never from client input.
- Client input accepts only opaque IDs and fixed workflow names. No profile
  paths, file paths, shell strings, or arbitrary endpoints are accepted.
- Bodies and tokens are never logged.
- Workflow execution is NOT implemented: ``/api/v1/jobs`` persists and reports
  ``capability_disabled`` instead of pretending to produce output.
"""
from __future__ import annotations
import contextlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from .errors import ControlPlaneError, ForbiddenError, UnauthorizedError, ValidationError
from .manager import Manager
from .store import REQUEST_KEY_RE, TOKEN_RE
MAX_BODY_BYTES = 1 * 1024 * 1024
CONTRACT_VERSION = '1'
ADMIN_BODY_FIELDS: dict[str, set[str]] = {'reserve': {'profile', 'operation', 'reason'}, 'release': {'profile', 'generation', 'lose_quarantine', 'override_reason'}, 'quarantine': {'node', 'reason', 'observed_generation'}}

def generate_token(prefix: str='cp') -> str:
    """A fresh 256-bit token that always satisfies :data:`TOKEN_RE`.

    ``secrets.token_urlsafe`` may start with ``-`` or ``_`` (~3% of draws), which
    ``TOKEN_RE`` rejects because opaque identifiers must start alphanumerically.
    Prefixing a fixed alnum label keeps the random part's full entropy while
    making the shape deterministic, so ``init-tokens`` can never fail randomly.
    """
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,15}', prefix or ''):
        raise ValidationError('token prefix must start alphanumeric and be at most 16 identifier characters', code='invalid_token_prefix')
    token = f'{prefix}_{secrets.token_urlsafe(32)}'
    if not TOKEN_RE.fullmatch(token):
        raise ValidationError('generated token does not satisfy the token shape', code='invalid_token_value')
    return token

def load_token_file(path: Path | str, *, label: str) -> str:
    """Read a token from a 0600-or-stricter regular file owned by this user.

    Opens with ``O_NOFOLLOW`` and validates the *opened descriptor* (not a prior
    ``stat`` path), so a symlink swapped in between checks cannot redirect the
    read. Secrets never appear in argv or logs.
    """
    secret_path = Path(path).expanduser()
    try:
        fd = os.open(secret_path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError as exc:
        raise ValidationError(f'{label} token file not found', code='invalid_token_file') from exc
    except OSError as exc:
        raise ValidationError(f'{label} token file must be a regular file that is not a symlink', code='invalid_token_file') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f'{label} token file must be a regular file', code='invalid_token_file')
        if info.st_uid != os.geteuid():
            raise ValidationError(f'{label} token file must be owned by the current user', code='invalid_token_file')
        if info.st_mode & 63:
            raise ValidationError(f'{label} token file must have permissions 0600 or stricter', code='invalid_token_file')
        with os.fdopen(os.dup(fd), 'r', encoding='utf-8') as handle:
            token = handle.read().strip()
    finally:
        os.close(fd)
    if not TOKEN_RE.fullmatch(token):
        raise ValidationError(f'{label} token file does not contain a valid token', code='invalid_token_file')
    return token

def write_token_file(path: Path | str, token: str, *, overwrite: bool=False) -> Path:
    """Atomically create a 0600 token file, refusing to clobber by default.

    Write-to-temp + ``fsync`` + ``os.replace`` so a crash never leaves a partial
    token; the parent directory is fsynced too. An existing symlink or a
    pre-existing file (without ``overwrite=True``) is refused rather than
    silently replaced. The token value is never printed.
    """
    target = Path(path)
    if not TOKEN_RE.fullmatch(token or ''):
        raise ValidationError('refusing to write an invalid token value', code='invalid_token_value')
    target.parent.mkdir(parents=True, exist_ok=True, mode=448)
    if target.is_symlink():
        raise ValidationError('refusing to write a token through a symlink', code='invalid_token_file')
    if target.exists() and (not overwrite):
        raise ValidationError('token file already exists; refusing to overwrite silently (pass overwrite to rotate)', code='token_file_exists')
    tmp = target.with_name(target.name + f'.tmp-{os.getpid()}')
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(token + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        os.chmod(target, 384)
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()
    return target

class Identity:
    __slots__ = ('name', 'admin')

    def __init__(self, name: str, *, admin: bool):
        self.name = name
        self.admin = admin

class Authenticator:
    """Constant-time token match. ``owner`` comes from the token, not the body."""

    def __init__(self, *, admin_token: str, jobs_token: str | None=None, jobs_owner: str='jobsub'):
        if not TOKEN_RE.fullmatch(admin_token):
            raise ValueError('admin token must be an opaque identifier')
        self._admin = admin_token
        self._tokens: list[tuple[str, Identity]] = [(admin_token, Identity('admin', admin=True))]
        if jobs_token:
            if not TOKEN_RE.fullmatch(jobs_token):
                raise ValueError('jobs token must be an opaque identifier')
            self._tokens.append((jobs_token, Identity(jobs_owner, admin=False)))

    def identify(self, authorization: str | None) -> Identity:
        if not authorization or not authorization.startswith('Bearer '):
            raise UnauthorizedError('missing bearer token')
        presented = authorization[len('Bearer '):].strip()
        for token, identity in self._tokens:
            if hmac.compare_digest(presented, token):
                return identity
        raise UnauthorizedError('unknown token')

class ControlPlaneServer:
    """Owns the single manager instance served on loopback."""

    def __init__(self, manager: Manager, auth: Authenticator, *, host: str='127.0.0.1', port: int=0):
        if host not in {'127.0.0.1', '::1', 'localhost'}:
            raise ValidationError('refusing to bind a non-loopback address in this core; remote exposure belongs to the reviewed deployment', code='non_loopback_bind_refused')
        if getattr(manager, 'allow_fixture_ready', False):
            raise ValidationError('refusing to serve a manager that would let a fixture adapter publish READY; the HTTP surface never fakes hardware readiness', code='fixture_ready_not_allowed_on_server')
        self.manager = manager
        self.auth = auth
        handler = self._handler_class()
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.host, self.port = (self.httpd.server_address[0], self.httpd.server_address[1])
        self._thread: threading.Thread | None = None

    def _handler_class(self):
        server_outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            server_version = 'dgx-v4-control-plane/0.1-core'

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _send(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.close_connection = True
                self.end_headers()
                self.wfile.write(body)

            def _identity(self) -> Identity:
                return server_outer.auth.identify(self.headers.get('Authorization'))

            def _read_json(self) -> dict[str, Any]:
                length_header = self.headers.get('Content-Length')
                if length_header is None:
                    raise ValidationError('Content-Length is required for POST bodies', code='length_required', http_status=411)
                try:
                    length = int(length_header)
                except (TypeError, ValueError) as exc:
                    raise ValidationError('invalid Content-Length', code='invalid_length') from exc
                if length < 0:
                    raise ValidationError('invalid Content-Length', code='invalid_length')
                if length > MAX_BODY_BYTES:
                    raise ValidationError('request body exceeds the metadata limit', code='payload_too_large')
                raw = self.rfile.read(length) if length else b'{}'
                try:
                    value = json.loads(raw.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValidationError('request body must be a JSON object', code='invalid_json') from exc
                if not isinstance(value, dict):
                    raise ValidationError('request body must be a JSON object', code='invalid_json')
                return value

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
                    status, payload = server_outer.route(method, segments, query, identity, self)
                except ControlPlaneError as exc:
                    status, payload = (exc.http_status, exc.as_dict())
                except Exception as exc:
                    status, payload = (500, {'error': 'InternalError', 'code': 'internal_error', 'message': 'internal error; see server-side logs', 'details': {'type': type(exc).__name__}})
                finally:
                    server_outer.manager.store.close_thread_connection()
                self._send(status, payload)
        return Handler

    @staticmethod
    def _require_admin(identity: Identity) -> None:
        """Ordinary job tokens never hold lifecycle privileges."""
        if not identity.admin:
            raise ForbiddenError('lifecycle_privilege_required: ordinary job tokens cannot change resources')

    def route(self, method: str, segments: list[str], query: dict[str, list[str]], identity: Identity, handler: Any) -> tuple[int, dict[str, Any]]:
        if segments[:2] != ['api', 'v1']:
            raise ValidationError('unknown endpoint', code='not_found')
        path = segments[2:]
        if method == 'GET' and path == ['capabilities']:
            return (200, self.manager.capabilities())
        if method == 'POST' and path == ['jobs']:
            return self._submit_job(identity, handler)
        if method == 'GET' and path == ['jobs', 'lookup']:
            return self._lookup_job(identity, query)
        if method == 'GET' and len(path) == 2 and (path[0] == 'jobs'):
            return self._get_job(identity, path[1])
        if method == 'POST' and len(path) == 3 and (path[0] == 'jobs') and (path[2] == 'cancel'):
            return self._cancel_job(identity, path[1])
        if method == 'GET' and path == ['admin', 'profiles']:
            self._require_admin(identity)
            return (200, {'profiles': self.manager.store.profiles(), 'nodes': self.manager.store.nodes_view()})
        if method == 'GET' and path == ['admin', 'audit']:
            self._require_admin(identity)
            limit_raw = (query.get('limit') or ['200'])[0]
            try:
                limit = int(limit_raw)
            except (TypeError, ValueError) as exc:
                raise ValidationError('limit must be an integer', code='invalid_limit') from exc
            return (200, {'audit': self.manager.store.audit_log(limit=limit)})
        if method == 'POST' and path == ['admin', 'reserve']:
            self._require_admin(identity)
            body = self._strict_body(handler, 'reserve')
            return (200, self.manager.reserve_admin(self._profile(body), owner=identity.name, operation=str(body.get('operation', 'maintenance')), reason=body.get('reason')))
        if method == 'POST' and path == ['admin', 'release']:
            self._require_admin(identity)
            body = self._strict_body(handler, 'release')
            generation = body.get('generation')
            if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
                raise ValidationError('generation must be a positive integer', code='invalid_generation')
            lose_quarantine = body.get('lose_quarantine') is True
            override_reason = body.get('override_reason')
            if lose_quarantine and (not isinstance(override_reason, str)):
                raise ValidationError('lose_quarantine requires a non-empty override_reason (recorded in the audit log)', code='override_reason_required')
            return (200, self.manager.release_profile(self._profile(body), owner=identity.name, generation=generation, lose_quarantine=lose_quarantine, override_reason=override_reason))
        if method == 'POST' and path == ['admin', 'quarantine']:
            self._require_admin(identity)
            body = self._strict_body(handler, 'quarantine')
            node = body.get('node')
            if not isinstance(node, str) or not node:
                raise ValidationError('node is required', code='invalid_node')
            reason = body.get('reason')
            if not isinstance(reason, str) or not reason.strip():
                raise ValidationError('quarantine requires a non-empty reason', code='invalid_reason')
            observed = body.get('observed_generation')
            if observed is not None and (isinstance(observed, bool) or not isinstance(observed, int)):
                raise ValidationError('observed_generation must be an integer', code='invalid_generation')
            return (200, {'node': self.manager.store.quarantine_node(node, reason=reason, observed_generation=observed, actor=identity.name)})
        if method == 'POST' and path == ['admin', 'reconcile']:
            self._require_admin(identity)
            return (200, self.manager.reconcile())
        raise ValidationError('unknown endpoint', code='not_found')

    @staticmethod
    def _strict_body(handler: Any, kind: str) -> dict[str, Any]:
        """Parse a body and refuse unknown fields for this admin route.

        In particular ``/admin/release`` accepts no ``evidence`` field: release
        evidence is derived server-side from the adapter, never supplied by a
        client.
        """
        body = handler._read_json()
        allowed = ADMIN_BODY_FIELDS[kind]
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise ValidationError(f"unknown field(s) for admin {kind}: {', '.join(unknown)}; observations such as stop evidence are adapter-derived and cannot be supplied", code='unknown_field', details={'unknown_fields': unknown, 'allowed_fields': sorted(allowed)})
        return body

    @staticmethod
    def _profile(body: dict[str, Any]) -> str:
        profile = body.get('profile')
        if not isinstance(profile, str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', profile):
            raise ValidationError('Unknown profile identifier', code='invalid_profile')
        return profile

    def _submit_job(self, identity: Identity, handler: Any) -> tuple[int, dict[str, Any]]:
        body = handler._read_json()
        key = body.get('request_key')
        if not isinstance(key, str) or not REQUEST_KEY_RE.fullmatch(key):
            raise ValidationError('request_key must be a stable 8-128 character intent ID', code='invalid_request_key')
        header_key = handler.headers.get('Idempotency-Key')
        if header_key is not None and header_key != key:
            raise ValidationError('Idempotency-Key must equal request_key', code='idempotency_key_mismatch')
        workflow_id = body.get('workflow_id')
        if not isinstance(workflow_id, str) or not re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', workflow_id):
            raise ValidationError('workflow_id must be a known workflow identifier', code='unknown_workflow')
        inputs = body.get('inputs', {})
        parameters = body.get('parameters', {})
        if not isinstance(inputs, dict) or not isinstance(parameters, dict):
            raise ValidationError('inputs/parameters must be JSON objects', code='invalid_request')
        parent = body.get('parent_session_id')
        if parent is not None and (not isinstance(parent, str) or not TOKEN_RE.fullmatch(parent)):
            raise ValidationError('invalid parent_session_id', code='invalid_request')
        job_id = 'job_' + uuid.uuid4().hex
        result = self.manager.submit_job(job_id=job_id, owner=identity.name, request_key=key, workflow_id=workflow_id, inputs=inputs, parameters=parameters, parent_session_id=parent, idempotency_key=header_key)
        job = result['job']
        return (202, {'job_id': job['job_id'], 'request_key': job['request_key'], 'state': job['state'], 'reason_code': job['reason_code'], 'detail': job.get('reason_detail', 'workflow execution is not integrated; this is a durable record, not a result'), 'poll_after_seconds': 30, 'idempotent_replay': result['idempotent_replay'], 'simulated': False})

    def _lookup_job(self, identity: Identity, query: dict[str, list[str]]) -> tuple[int, dict[str, Any]]:
        keys = query.get('request_key') or []
        if len(keys) != 1 or not REQUEST_KEY_RE.fullmatch(keys[0]):
            raise ValidationError('request_key query parameter required', code='invalid_request_key')
        row = self.manager.store.job_lookup(owner=identity.name, request_key=keys[0])
        if row is None:
            return (200, {'found': False, 'request_key': keys[0]})
        return (200, {'found': True, 'job_id': row['job_id'], 'request_key': row['request_key'], 'state': row['state']})

    def _get_job(self, identity: Identity, job_id: str) -> tuple[int, dict[str, Any]]:
        row = self.manager.store.require_job_owner(job_id, owner=identity.name)
        return (200, {'job_id': row['job_id'], 'request_key': row['request_key'], 'state': row['state'], 'stage': row['stage'], 'reason_code': row['reason_code'], 'generation': row['generation'], 'profile': row['profile'], 'created_at': row['created_at']})

    def _cancel_job(self, identity: Identity, job_id: str) -> tuple[int, dict[str, Any]]:
        result = self.manager.store.request_cancel(job_id, owner=identity.name)
        return (200, {'job_id': job_id, 'state': result['job']['state'], 'cancel': result['cancel']})

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start_background(self) -> 'ControlPlaneServer':
        self._thread = threading.Thread(target=self.httpd.serve_forever, name='control-plane-http', daemon=True)
        self._thread.start()
        return self

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
