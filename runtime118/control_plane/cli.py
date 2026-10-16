# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""CLI: run the owner process or talk to it over loopback HTTP.

Client mode never handles profiles by path, never runs shell strings, and only
carries opaque IDs. Tokens are read from 0600 files, never from argv.

Address handling is deliberately strict: exactly ``http`` to an explicit
loopback host and port, no credentials, path, query or fragment, no environment
proxies, and no redirect following (a bearer token must never travel to a
second origin). ``--fixture-adapter`` is a test-only flag for ``runjobs``;
``serve`` refuses it.

Examples (run from the repository root)::

    python3 -m control_plane.cli --store runtime/control_plane/state init-tokens
    python3 -m control_plane.cli --store runtime/control_plane/state serve
    python3 -m control_plane.cli --base http://127.0.0.1:8765 --token-file .../jobs.token capabilities
    python3 -m control_plane.cli --store tmp/state --fixture-adapter runjobs --profile qwen-a-c --owner admin
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from .adapter import TestAdapter
from .errors import ControlPlaneError, ValidationError
from .httpapi import Authenticator, ControlPlaneServer, generate_token, load_token_file, write_token_file
from .manager import Manager
from .store import TOKEN_RE, OwnerLock, Store, open_store
LOOPBACK_HOSTS = {'127.0.0.1', '::1', 'localhost'}

def _emit(payload: Any, status: int=0) -> int:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write('\n')
    return status

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse redirects instead of forwarding the bearer token to a new origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ApiClient:
    """Tiny loopback client. Fails with explicit codes; never retries blindly."""

    def __init__(self, base: str, token: str):
        self.base = self._validate_base(base)
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            raise ValidationError('token must be an opaque identifier', code='invalid_token')
        self.token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())

    @staticmethod
    def _validate_base(base: str) -> str:
        """Accept only ``http://<loopback-host>:<port>`` with nothing else.

        Rejects scheme confusion, userinfo tricks (``localhost@evil.example``),
        prefix confusion (``127.0.0.1.evil.example``), missing/invalid ports,
        and any path/query/fragment. No network call is made while validating.
        """
        if not isinstance(base, str):
            raise ValidationError('base URL must be a string', code='non_loopback_client_refused')
        try:
            parsed = urlsplit(base)
        except ValueError as exc:
            raise ValidationError(f'unparseable base URL: {exc}', code='non_loopback_client_refused') from exc
        if parsed.scheme != 'http':
            raise ValidationError('this CLI only talks plain http to a loopback address (use the reviewed tunnel for remote access)', code='non_loopback_client_refused')
        if parsed.username or parsed.password:
            raise ValidationError('base URL must not contain credentials', code='non_loopback_client_refused')
        if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ValidationError('base URL must not contain a path, query or fragment', code='non_loopback_client_refused')
        host = parsed.hostname
        if host not in LOOPBACK_HOSTS:
            raise ValidationError('this CLI only talks to loopback addresses; remote exposure belongs to the reviewed deployment', code='non_loopback_client_refused', details={'host': host})
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValidationError(f'invalid port in base URL: {exc}', code='non_loopback_client_refused') from exc
        if port is None:
            raise ValidationError('an explicit loopback port is required (e.g. http://127.0.0.1:8765)', code='non_loopback_client_refused')
        if not 1 <= port <= 65535:
            raise ValidationError('port out of range', code='non_loopback_client_refused')
        acceptable = {f'{host}:{port}'}
        if ':' in host:
            acceptable.add(f'[{host}]:{port}')
        if parsed.netloc not in acceptable:
            raise ValidationError('base URL authority must be exactly the loopback host and port', code='non_loopback_client_refused', details={'netloc': parsed.netloc})
        return f'http://{parsed.netloc}'

    def request(self, method: str, path: str, *, body: dict | None=None, headers: dict | None=None) -> tuple[int, dict]:
        data = json.dumps(body).encode('utf-8') if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header('Authorization', 'Bearer ' + self.token)
        req.add_header('Content-Type', 'application/json')
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with self._opener.open(req, timeout=30) as response:
                return (response.status, json.loads(response.read().decode('utf-8')))
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                exc.close()
                return (exc.code, {'code': 'redirect_refused', 'message': 'the server attempted a redirect; the client refuses to forward the bearer token', 'location_ignored': True})
            try:
                return (exc.code, json.loads(exc.read().decode('utf-8')))
            except Exception:
                return (exc.code, {'code': 'http_error', 'message': f'HTTP {exc.code}'})
            finally:
                exc.close()
        except urllib.error.URLError as exc:
            raise ControlPlaneError(f'loopback_request_failed: {exc.reason}', code='loopback_request_failed') from exc

def _client(args: argparse.Namespace) -> ApiClient:
    if not args.token_file:
        raise ValidationError('--token-file is required for client commands', code='missing_token_file')
    return ApiClient(args.base, load_token_file(args.token_file, label=args.command))

def _dispatch_client(args: argparse.Namespace) -> int:
    client = _client(args)

    def call(method: str, path: str, *, body: dict | None=None, headers: dict | None=None) -> int:
        status, payload = client.request(method, path, body=body, headers=headers)
        return _emit(payload, status=0 if status < 400 else 2)
    if args.command == 'capabilities':
        return call('GET', '/api/v1/capabilities')
    if args.command == 'profiles':
        return call('GET', '/api/v1/admin/profiles')
    if args.command == 'reserve':
        return call('POST', '/api/v1/admin/reserve', body={'profile': args.profile, 'operation': args.operation})
    if args.command == 'release':
        body: dict[str, Any] = {'profile': args.profile, 'generation': args.generation}
        if args.lose_quarantine:
            body['lose_quarantine'] = True
            body['override_reason'] = args.override_reason
        return call('POST', '/api/v1/admin/release', body=body)
    if args.command == 'quarantine':
        return call('POST', '/api/v1/admin/quarantine', body={'node': args.node, 'reason': args.reason})
    if args.command == 'reconcile':
        return call('POST', '/api/v1/admin/reconcile', body={})
    if args.command == 'audit':
        query = urllib.parse.urlencode({'limit': args.limit})
        return call('GET', f'/api/v1/admin/audit?{query}')
    if args.command == 'submit':
        body = {'workflow_id': args.workflow, 'inputs': {}, 'parameters': json.loads(args.parameters), 'request_key': args.request_key}
        return call('POST', '/api/v1/jobs', body=body, headers={'Idempotency-Key': args.request_key})
    if args.command == 'lookup':
        query = urllib.parse.urlencode({'request_key': args.request_key})
        return call('GET', f'/api/v1/jobs/lookup?{query}')
    if args.command == 'job':
        return call('GET', f'/api/v1/jobs/{args.job_id}')
    if args.command == 'cancel':
        return call('POST', f'/api/v1/jobs/{args.job_id}/cancel', body={})
    raise ValidationError(f'unhandled client command {args.command}', code='invalid_command')

def _state_root(args: argparse.Namespace) -> Path:
    return Path(args.store)

def _serve(args: argparse.Namespace) -> int:
    if args.fixture_adapter:
        raise ValidationError("serve refuses --fixture-adapter: a test fixture must never back the product HTTP surface (fixture runs happen through 'runjobs' with an explicit adapter)", code='fixture_adapter_not_servable')
    if not args.admin_token_file or not args.jobs_token_file:
        raise ValidationError('serve requires --admin-token-file and --jobs-token-file', code='missing_token_file')
    admin_token = load_token_file(args.admin_token_file, label='admin')
    jobs_token = load_token_file(args.jobs_token_file, label='jobs')
    store, lock = open_store(_state_root(args), lock=True, profiles_path=args.profiles_file)
    manager = Manager(store, adapter=None, adapter_explicit=False)
    recovery = manager.reconcile()
    server = ControlPlaneServer(manager, Authenticator(admin_token=admin_token, jobs_token=jobs_token))
    print(json.dumps({'listening': f'http://{server.host}:{server.port}', 'recovery': recovery}, ensure_ascii=False))
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        if lock:
            lock.release()
        store.close()
    return 0

def _local_manager(args: argparse.Namespace) -> tuple[Manager, Store, OwnerLock | None]:
    store, lock = open_store(_state_root(args), lock=True, profiles_path=args.profiles_file)
    adapter = TestAdapter() if args.fixture_adapter else None
    return (Manager(store, adapter=adapter, adapter_explicit=bool(args.fixture_adapter), allow_test_holds=True), store, lock)

def _run_local(args: argparse.Namespace) -> int:
    if args.command == 'init-tokens':
        root = _state_root(args)
        admin_token = generate_token('cp_admin')
        jobs_token = generate_token('cp_jobs')
        admin = write_token_file(root / 'admin.token', admin_token, overwrite=args.rotate)
        jobs = write_token_file(root / 'jobs.token', jobs_token, overwrite=args.rotate)
        return _emit({'admin_token_file': str(admin), 'jobs_token_file': str(jobs), 'mode': '0600', 'rotated': bool(args.rotate), 'note': 'token values are never printed; read them from the files'})
    if args.command == 'runjobs':
        manager, store, lock = _local_manager(args)
        try:
            from .fixture_runner import FixtureRunner
            if args.fixture_adapter and hasattr(manager.adapter, 'add_known_nodes'):
                manager.adapter.add_known_nodes(store.profile_view(args.profile)['nodes'])
            runner = FixtureRunner(artifact_root=store.root / 'artifacts', payload_root=store.payload_root)
            return _emit(manager.run_jobs(profile=args.profile, owner=args.owner, runner=runner, limit=args.limit))
        finally:
            store.close()
            if lock:
                lock.release()
    if args.command == 'reconcile-local':
        manager, store, lock = _local_manager(args)
        try:
            return _emit(manager.reconcile())
        finally:
            store.close()
            if lock:
                lock.release()
    raise ValidationError(f'unhandled local command {args.command}', code='invalid_command')

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='control_plane.cli', description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:8765', help='loopback API base URL')
    parser.add_argument('--token-file', help='0600 file containing the bearer token (client mode)')
    parser.add_argument('--store', default='runtime/control_plane/state', help='state root (owner/local mode)')
    parser.add_argument('--admin-token-file', help='0600 admin token file (serve)')
    parser.add_argument('--jobs-token-file', help='0600 jobs token file (serve)')
    parser.add_argument('--fixture-adapter', action='store_true', help='test-only fixture adapter for local runs (refused by serve)')
    parser.add_argument('--profiles-file', help='explicit profiles document for local/owner mode (test aid; fail-closed checks still apply)')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init-tokens')
    init.add_argument('--rotate', action='store_true', help='allow replacing existing token files (default: refuse)')
    sub.add_parser('capabilities')
    sub.add_parser('serve')
    sub.add_parser('profiles')
    sub.add_parser('reconcile')
    sub.add_parser('reconcile-local')
    reserve = sub.add_parser('reserve')
    reserve.add_argument('--profile', required=True)
    reserve.add_argument('--operation', default='maintenance', choices=['start', 'maintenance'])
    release = sub.add_parser('release')
    release.add_argument('--profile', required=True)
    release.add_argument('--generation', type=int, required=True)
    release.add_argument('--lose-quarantine', action='store_true')
    release.add_argument('--override-reason', help='required with --lose-quarantine; recorded in the audit log')
    quarantine = sub.add_parser('quarantine')
    quarantine.add_argument('--node', required=True)
    quarantine.add_argument('--reason', default='operator quarantine')
    audit = sub.add_parser('audit')
    audit.add_argument('--limit', type=int, default=200)
    submit = sub.add_parser('submit')
    submit.add_argument('--workflow', required=True)
    submit.add_argument('--parameters', default='{}', help='JSON object')
    submit.add_argument('--request-key', required=True)
    lookup = sub.add_parser('lookup')
    lookup.add_argument('--request-key', required=True)
    job = sub.add_parser('job')
    job.add_argument('--job-id', required=True)
    cancel = sub.add_parser('cancel')
    cancel.add_argument('--job-id', required=True)
    runjobs = sub.add_parser('runjobs')
    runjobs.add_argument('--profile', required=True)
    runjobs.add_argument('--owner', default='admin')
    runjobs.add_argument('--limit', type=int, default=10)
    return parser
CLIENT_COMMANDS = {'capabilities', 'profiles', 'reserve', 'release', 'quarantine', 'reconcile', 'audit', 'submit', 'lookup', 'job', 'cancel'}
LOCAL_COMMANDS = {'init-tokens', 'runjobs', 'reconcile-local'}

def main(argv: list[str] | None=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == 'serve':
            return _serve(args)
        if args.command in LOCAL_COMMANDS:
            return _run_local(args)
        if args.command in CLIENT_COMMANDS:
            return _dispatch_client(args)
        raise ValidationError(f'unknown command {args.command}', code='invalid_command')
    except ControlPlaneError as exc:
        return _emit(exc.as_dict(), status=2)
    except FileNotFoundError as exc:
        return _emit({'error': 'FileNotFoundError', 'code': 'missing_file', 'message': str(exc)}, status=2)
if __name__ == '__main__':
    sys.exit(main())
