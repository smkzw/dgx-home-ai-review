# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Durable request/session metadata for the LLM gateway.

What is persisted: request identity, owner, alias/profile mapping, payload
digest, state, reason codes, generations, timestamps, idempotency keys, session
ownership and leases, and an append-only event log. What is *never* persisted:
prompt/completion bodies, tokens, or any secret. Synchronous requests keep their
body only in the request-handling thread's memory; nothing here can reconstruct
a prompt.

Restart honesty: ``recover_after_restart`` marks requests that were queued but
never dispatched as ``needs_resubmit`` and requests whose engine dispatch is
ambiguous as ``reconciling``. It never replays anything, never deletes rows and
never clears a hold. A client may explicitly retry a same-key + same-digest
request that was never dispatched; that is a fresh admission of the same intent,
not a silent replay.

One daemon owner: ``open_gateway_store(lock=True)`` takes a non-blocking OS
``flock`` so a second gateway process refuses to start.
"""
from __future__ import annotations
import contextlib
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator
from .errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from .validation import canonical_digest
TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_-]{0,127}')
SHA256_RE = re.compile('[0-9a-f]{64}')
SCHEMA_VERSION = 1
REQUEST_STATES = {'queued', 'waiting_session', 'dispatched', 'succeeded', 'failed', 'cancelled', 'expired', 'needs_resubmit', 'reconciling'}
TERMINAL_REQUEST_STATES = {'succeeded', 'failed', 'cancelled', 'expired'}
DISPATCHABLE_REQUEST_STATES = {'queued', 'waiting_session'}
ACTIVE_REQUEST_STATES = {'queued', 'waiting_session', 'dispatched', 'reconciling'}
REQUEUEABLE_STATES = {'expired', 'needs_resubmit'}
MAX_ADMISSION_ATTEMPTS = 3
SESSION_STATES = {'active', 'yielded'}
SCHEMA_SQL = None

def valid_id(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ValidationError(f'{name} must be an opaque identifier', code='invalid_identifier')
    return value

def new_request_id() -> str:
    return 'req_' + uuid.uuid4().hex

def new_session_id() -> str:
    return 'sess_' + uuid.uuid4().hex

def _chmod_private(path: Path, mode: int) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.chmod(path, mode)

class OwnerLock:
    """Non-blocking exclusive OS lock: one gateway daemon per state root."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> 'OwnerLock':
        if self._fd is not None:
            raise RuntimeError('OwnerLock already held by this instance')
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=448)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 384)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise
        self._fd = fd
        os.write(fd, f'pid={os.getpid()} acquired_at={int(time.time())}\n'.encode())
        os.fsync(fd)
        return self

    def release(self) -> None:
        if self._fd is None:
            return
        import fcntl
        with contextlib.suppress(OSError):
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None

    def __enter__(self) -> 'OwnerLock':
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()

class GatewayStore:
    """SQLite WAL metadata store; thread-safe within the single owner process."""

    def __init__(self, root: Path | str, *, clock: Callable[[], float]=time.time):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=448)
        _chmod_private(self.root, 448)
        self.db_path = self.root / 'llm_gateway.db'
        self.lock_path = self.root / 'llm_gateway.lock'
        self._clock = clock
        self._mutex = threading.RLock()
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        conn = self._connection()
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        _chmod_private(self.db_path, 384)
        conn.executescript(SCHEMA_SQL)
        conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
            self._connections.append(conn)
        return conn

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._mutex:
            conn = self._connection()
            conn.execute('BEGIN IMMEDIATE')
            try:
                yield conn
            except BaseException:
                conn.execute('ROLLBACK')
                raise
            else:
                conn.execute('COMMIT')

    def close(self) -> None:
        with self._mutex:
            for conn in self._connections:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._connections.clear()

    def close_thread_connection(self) -> None:
        with self._mutex:
            conn = getattr(self._local, 'conn', None)
            if conn is None:
                return
            conn.close()
            self._local.conn = None
            with contextlib.suppress(ValueError):
                self._connections.remove(conn)

    def __enter__(self) -> 'GatewayStore':
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _event_conn(self, conn: sqlite3.Connection, action: str, *, owner: str | None=None, request_id: str | None=None, session_id: str | None=None, profile: str | None=None, generation: int | None=None, reason_code: str | None=None, detail: str | None=None) -> None:
        conn.execute('INSERT INTO events(ts,action,owner,request_id,session_id,profile,generation,reason_code,detail) VALUES(?,?,?,?,?,?,?,?,?)', (self._clock(), action[:64], owner[:128] if owner else None, request_id[:128] if request_id else None, session_id[:128] if session_id else None, profile[:64] if profile else None, int(generation) if generation is not None else None, (reason_code or '')[:128] or None, (detail or '')[:512] or None))

    def record_event(self, action: str, **fields: Any) -> None:
        with self._tx() as conn:
            self._event_conn(conn, action, **fields)

    def events(self, *, limit: int=200) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or (not 1 <= limit <= 2000):
            raise ValidationError('limit must be an integer in [1, 2000]', code='invalid_limit')
        rows = self._connection().execute('SELECT seq,ts,action,owner,request_id,session_id,profile,generation,reason_code,detail FROM events ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
        return [dict(row) for row in rows]

    def admit_request(self, *, owner: str, idempotency_key: str | None, payload_digest: str, model_alias: str, profile: str, stream: bool, session_id: str | None, parent_session_id: str | None, waiting: bool=False) -> dict[str, Any]:
        """Atomic admission: idempotency check and insert in one transaction.

        ``idempotent_replay`` is True only for a genuinely new duplicate: the
        second caller receives the *known state* of the first request and no new
        inference is ever started. A same-key + same-digest request recorded as
        ``expired``/``needs_resubmit`` without dispatch may be re-queued as a
        fresh attempt, up to ``MAX_ADMISSION_ATTEMPTS`` total attempts for key.
        """
        valid_id(owner, name='owner')
        if idempotency_key is not None:
            valid_id(idempotency_key, name='idempotency_key')
        if not isinstance(payload_digest, str) or not SHA256_RE.fullmatch(payload_digest):
            raise ValidationError('payload_digest must be a lowercase sha256', code='invalid_digest')
        for name, value in (('model_alias', model_alias), ('profile', profile)):
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f'{name} must be a non-empty string', code='invalid_request')
        state = 'waiting_session' if waiting else 'queued'
        with self._tx() as conn:
            now = self._clock()
            if idempotency_key is not None:
                row = conn.execute('SELECT * FROM requests WHERE owner=? AND idempotency_key=?', (owner, idempotency_key)).fetchone()
                if row is not None:
                    if row['payload_digest'] != payload_digest:
                        raise ConflictError('idempotency_key_payload_mismatch: the same Idempotency-Key was used with a different payload; keep the payload stable for retries', code='idempotency_key_payload_mismatch', details={'request_id': row['request_id']})
                    if row['state'] in REQUEUEABLE_STATES and (not int(row['dispatched'])):
                        attempts = int(row['attempts'])
                        if attempts >= MAX_ADMISSION_ATTEMPTS:
                            raise ConflictError('readmission_attempt_limit_exceeded: this never-dispatched request has reached its same-key admission limit', code='readmission_attempt_limit_exceeded', details={'request_id': row['request_id'], 'attempts': attempts, 'max_attempts': MAX_ADMISSION_ATTEMPTS})
                        conn.execute('UPDATE requests SET state=?, reason_code=NULL, attempts=attempts+1, updated_at=?, dispatched=0, uncertain=0, generation=NULL, dispatched_at=NULL, finished_at=NULL WHERE request_id=?', (state, now, row['request_id']))
                        self._event_conn(conn, 'readmit_intent', owner=owner, request_id=row['request_id'], profile=profile, reason_code='never_dispatched_retry')
                        view = self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (row['request_id'],)).fetchone())
                        return {'request': view, 'idempotent_replay': False, 'requeued': True}
                    return {'request': self._request_view(row), 'idempotent_replay': True, 'requeued': False}
            request_id = new_request_id()
            conn.execute('INSERT INTO requests(request_id,owner,idempotency_key,payload_digest,model_alias,profile,\n                       stream,session_id,parent_session_id,state,attempts,created_at,updated_at)\n                   VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)', (request_id, owner, idempotency_key, payload_digest, model_alias, profile, 1 if stream else 0, session_id, parent_session_id, state, now, now))
            self._event_conn(conn, 'admit', owner=owner, request_id=request_id, session_id=session_id, profile=profile, reason_code=state)
            return {'request': self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone()), 'idempotent_replay': False, 'requeued': False}

    def mark_dispatched(self, request_id: str, *, generation: int | None) -> dict[str, Any]:
        """Durable dispatch marker. Refuses anything not currently dispatchable.

        A cancelled queued request therefore can never be dispatched later: the
        cancellation is a terminal state and this compare-and-set fails.
        """
        with self._tx() as conn:
            row = self._require_row(conn, request_id)
            if row['state'] not in DISPATCHABLE_REQUEST_STATES:
                raise ConflictError('request_not_dispatchable: the request is no longer in a dispatchable state', code='request_not_dispatchable', details={'request_id': request_id, 'state': row['state']})
            now = self._clock()
            conn.execute("UPDATE requests SET state='dispatched', dispatched=1, generation=?, dispatched_at=?, updated_at=? WHERE request_id=?", (generation, now, now, request_id))
            return self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone())

    def finish_request(self, request_id: str, *, state: str, reason_code: str | None=None, uncertain: bool=False) -> dict[str, Any]:
        """Record a terminal state (or ``reconciling`` for unconfirmed work).

        Terminal states are immutable: a late writer can never resurrect or
        silently succeed an already-finished request.
        """
        if state not in TERMINAL_REQUEST_STATES and state != 'reconciling':
            raise ValidationError(f'finish_request requires a terminal/reconciling state, got {state}', code='invalid_state')
        with self._tx() as conn:
            row = self._require_row(conn, request_id)
            if row['state'] in TERMINAL_REQUEST_STATES:
                raise ConflictError('request_terminal_cannot_be_overwritten', code='request_terminal_cannot_be_overwritten', details={'request_id': request_id, 'state': row['state']})
            now = self._clock()
            conn.execute('UPDATE requests SET state=?, reason_code=?, uncertain=?, updated_at=?, finished_at=? WHERE request_id=?', (state, (reason_code or '')[:128] or None, 1 if uncertain else 0, now, now if state in TERMINAL_REQUEST_STATES else None, request_id))
            self._event_conn(conn, 'finish', owner=row['owner'], request_id=request_id, session_id=row['session_id'], profile=row['profile'], generation=row['generation'], reason_code=reason_code or state)
            return self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone())

    def expire_request(self, request_id: str, *, reason_code: str) -> dict[str, Any]:
        """A queued request whose bounded wait elapsed: never dispatched, so it
        is closed and can never be granted later by a stale queue entry."""
        with self._tx() as conn:
            row = self._require_row(conn, request_id)
            if row['state'] not in {'queued', 'waiting_session'}:
                raise ConflictError('request_not_expirable', code='request_not_expirable', details={'request_id': request_id, 'state': row['state']})
            now = self._clock()
            conn.execute("UPDATE requests SET state='expired', reason_code=?, updated_at=?, finished_at=? WHERE request_id=?", ((reason_code or 'sync_wait_timeout')[:128], now, now, request_id))
            self._event_conn(conn, 'expire', owner=row['owner'], request_id=request_id, session_id=row['session_id'], profile=row['profile'], reason_code=reason_code)
            return self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone())

    def request_cancel(self, request_id: str, *, owner: str) -> dict[str, Any]:
        """Owner-checked cancel. Queued requests become terminally cancelled.

        An in-flight engine call cannot be reliably interrupted by this gateway,
        so cancelling a dispatched request is refused explicitly instead of
        pretending the engine stopped.
        """
        valid_id(owner, name='owner')
        with self._tx() as conn:
            row = self._require_row(conn, request_id)
            self._require_owner(row, owner)
            if row['state'] in TERMINAL_REQUEST_STATES:
                return {'request': self._request_view(row), 'cancel': 'already_terminal'}
            if row['state'] in DISPATCHABLE_REQUEST_STATES:
                now = self._clock()
                conn.execute("UPDATE requests SET state='cancelled', reason_code='cancelled_before_dispatch', updated_at=?, finished_at=? WHERE request_id=?", (now, now, request_id))
                return {'request': self._request_view(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone()), 'cancel': 'cancelled'}
            raise ConflictError('cancel_not_supported_in_flight: the engine call is already running and cannot be reliably interrupted; the request is recorded and its hold retained until the call ends', code='cancel_not_supported_in_flight', details={'request_id': request_id, 'state': row['state']})

    def request_view(self, request_id: str) -> dict[str, Any]:
        return self._request_view(self._require_row(self._connection(), request_id))

    def require_request_owner(self, request_id: str, *, owner: str) -> dict[str, Any]:
        row = self._require_row(self._connection(), request_id)
        self._require_owner(row, owner)
        return self._request_view(row)

    def requests_in_states(self, states: set[str]) -> list[dict[str, Any]]:
        if not states:
            return []
        placeholders = ','.join(('?' for _ in states))
        rows = self._connection().execute(f'SELECT * FROM requests WHERE state IN ({placeholders}) ORDER BY created_at, request_id', tuple(sorted(states))).fetchall()
        return [self._request_view(row) for row in rows]

    def reconciling_profiles(self) -> list[str]:
        rows = self._connection().execute("SELECT DISTINCT profile FROM requests WHERE state='reconciling' ORDER BY profile").fetchall()
        return [row['profile'] for row in rows]

    def recover_after_restart(self) -> dict[str, Any]:
        """Restart reconciliation: honest states, no replay, no hold clearing.

        - queued / waiting_session (never dispatched) -> ``needs_resubmit``
        - dispatched / reconciling (engine outcome ambiguous) -> ``reconciling``
        - terminal states are untouched
        """
        with self._tx() as conn:
            now = self._clock()
            never_dispatched = conn.execute("SELECT request_id FROM requests WHERE state IN ('queued','waiting_session')").fetchall()
            for row in never_dispatched:
                conn.execute("UPDATE requests SET state='needs_resubmit', reason_code='restart_before_dispatch', updated_at=? WHERE request_id=?", (now, row['request_id']))
            ambiguous = conn.execute("SELECT request_id, profile FROM requests WHERE state='dispatched'").fetchall()
            for row in ambiguous:
                conn.execute("UPDATE requests SET state='reconciling', uncertain=1, reason_code='restart_uncertain_dispatch', updated_at=? WHERE request_id=?", (now, row['request_id']))
            for row in conn.execute("SELECT request_id FROM requests WHERE state='reconciling'").fetchall():
                conn.execute('UPDATE requests SET uncertain=1, updated_at=? WHERE request_id=?', (now, row['request_id']))
            self._event_conn(conn, 'recovery', reason_code='gateway_restart', detail=f'needs_resubmit={len(never_dispatched)} reconciling={len(ambiguous)}')
            return {'needs_resubmit': [r['request_id'] for r in never_dispatched], 'reconciling': [r['request_id'] for r in ambiguous]}

    def create_session(self, *, owner: str, model_alias: str, profile: str) -> dict[str, Any]:
        valid_id(owner, name='owner')
        with self._tx() as conn:
            now = self._clock()
            session_id = new_session_id()
            conn.execute("INSERT INTO sessions(session_id,owner,model_alias,profile,state,created_at,updated_at,last_activity) VALUES(?,?,?,?,'active',?,?,?)", (session_id, owner, model_alias, profile, now, now, now))
            self._event_conn(conn, 'session_create', owner=owner, session_id=session_id, profile=profile)
            return self._session_view(conn.execute('SELECT * FROM sessions WHERE session_id=?', (session_id,)).fetchone())

    def session_view(self, session_id: str) -> dict[str, Any]:
        return self._session_view(self._require_session(self._connection(), session_id))

    def require_session_owner(self, session_id: str, *, owner: str) -> dict[str, Any]:
        row = self._require_session(self._connection(), session_id)
        if row['owner'] != owner:
            raise ForbiddenError('cross_owner_access_denied: session belongs to another owner', code='cross_owner_access_denied', details={'session_id': session_id})
        return self._session_view(row)

    def touch_session(self, session_id: str) -> None:
        """Renew the session lease (coordination only — never a GPU hold)."""
        with self._tx() as conn:
            self._require_session(conn, session_id)
            now = self._clock()
            conn.execute('UPDATE sessions SET last_activity=?, updated_at=? WHERE session_id=?', (now, now, session_id))

    def session_active_requests(self, session_id: str) -> list[dict[str, Any]]:
        placeholders = ','.join(('?' for _ in ACTIVE_REQUEST_STATES))
        rows = self._connection().execute(f'SELECT * FROM requests WHERE session_id=? AND state IN ({placeholders}) ORDER BY created_at, request_id', (session_id, *sorted(ACTIVE_REQUEST_STATES))).fetchall()
        return [self._request_view(row) for row in rows]

    def yield_session(self, session_id: str, *, owner: str) -> dict[str, Any]:
        """Explicit, owner-checked yield. Refused while the session has any
        non-terminal request: a parent may only step aside when it is idle."""
        valid_id(owner, name='owner')
        with self._tx() as conn:
            row = self._require_session(conn, session_id)
            if row['owner'] != owner:
                raise ForbiddenError('cross_owner_access_denied: session belongs to another owner', code='cross_owner_access_denied', details={'session_id': session_id})
            active = self.session_active_requests(session_id)
            if active:
                raise ConflictError('session_busy: the session has active or waiting requests and cannot yield', code='session_busy', details={'session_id': session_id, 'active_requests': len(active)})
            now = self._clock()
            conn.execute("UPDATE sessions SET state='yielded', yielded_at=?, updated_at=? WHERE session_id=?", (now, now, session_id))
            self._event_conn(conn, 'session_yield', owner=owner, session_id=session_id)
            return self._session_view(conn.execute('SELECT * FROM sessions WHERE session_id=?', (session_id,)).fetchone())

    def resume_session(self, session_id: str, *, owner: str) -> dict[str, Any]:
        valid_id(owner, name='owner')
        with self._tx() as conn:
            row = self._require_session(conn, session_id)
            if row['owner'] != owner:
                raise ForbiddenError('cross_owner_access_denied: session belongs to another owner', code='cross_owner_access_denied', details={'session_id': session_id})
            if row['state'] != 'yielded':
                raise ConflictError('session_not_yielded: only a yielded session can be resumed', code='session_not_yielded', details={'session_id': session_id, 'state': row['state']})
            now = self._clock()
            conn.execute("UPDATE sessions SET state='active', updated_at=?, last_activity=? WHERE session_id=?", (now, now, session_id))
            self._event_conn(conn, 'session_resume', owner=owner, session_id=session_id)
            return self._session_view(conn.execute('SELECT * FROM sessions WHERE session_id=?', (session_id,)).fetchone())

    def sessions_for_profile(self, profile: str) -> list[dict[str, Any]]:
        rows = self._connection().execute('SELECT * FROM sessions WHERE profile=? ORDER BY created_at, session_id', (profile,)).fetchall()
        return [self._session_view(row) for row in rows]

    def session_row(self, session_id: str) -> dict[str, Any] | None:
        row = self._connection().execute('SELECT * FROM sessions WHERE session_id=?', (session_id,)).fetchone()
        return self._session_view(row) if row is not None else None

    def _require_row(self, conn: sqlite3.Connection, request_id: str) -> sqlite3.Row:
        valid_id(request_id, name='request_id')
        row = conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone()
        if row is None:
            raise NotFoundError('unknown request', details={'request_id': request_id})
        return row

    def _require_session(self, conn: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        valid_id(session_id, name='session_id')
        row = conn.execute('SELECT * FROM sessions WHERE session_id=?', (session_id,)).fetchone()
        if row is None:
            raise NotFoundError('unknown session', details={'session_id': session_id})
        return row

    @staticmethod
    def _require_owner(row: sqlite3.Row, owner: str) -> None:
        if row['owner'] != owner:
            raise ForbiddenError('cross_owner_access_denied: request belongs to another owner', code='cross_owner_access_denied', details={'request_id': row['request_id']})

    @staticmethod
    def _request_view(row: sqlite3.Row) -> dict[str, Any]:
        return {'request_id': row['request_id'], 'owner': row['owner'], 'idempotency_key': row['idempotency_key'], 'payload_digest': row['payload_digest'], 'model_alias': row['model_alias'], 'profile': row['profile'], 'stream': bool(row['stream']), 'session_id': row['session_id'], 'parent_session_id': row['parent_session_id'], 'state': row['state'], 'reason_code': row['reason_code'], 'generation': row['generation'], 'dispatched': bool(row['dispatched']), 'uncertain': bool(row['uncertain']), 'attempts': row['attempts'], 'created_at': row['created_at'], 'updated_at': row['updated_at'], 'dispatched_at': row['dispatched_at'], 'finished_at': row['finished_at']}

    @staticmethod
    def _session_view(row: sqlite3.Row) -> dict[str, Any]:
        return {'session_id': row['session_id'], 'owner': row['owner'], 'model_alias': row['model_alias'], 'profile': row['profile'], 'state': row['state'], 'created_at': row['created_at'], 'updated_at': row['updated_at'], 'last_activity': row['last_activity'], 'yielded_at': row['yielded_at']}

def open_gateway_store(root: Path | str, *, lock: bool=True, clock: Callable[[], float]=time.time) -> tuple[GatewayStore, OwnerLock | None]:
    """Open the state root; ``lock=True`` enforces the single daemon owner."""
    owner_lock: OwnerLock | None = None
    if lock:
        owner_lock = OwnerLock(Path(root) / 'llm_gateway.lock').acquire()
    store = GatewayStore(root, clock=clock)
    return (store, owner_lock)

def digest_of(value: Any) -> str:
    """Canonical payload digest (stable across JSON key order)."""
    return canonical_digest(value)
