# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator
from . import config as cp_config
from .errors import ConflictError, ForbiddenError, GenerationFenceError, HoldOwnershipError, NotFoundError, ProfileStateError, QuarantinedError, StaleCompletionError, ValidationError
TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_-]{0,127}')
REQUEST_KEY_RE = re.compile('[A-Za-z0-9_-]{8,128}')
SHA256_RE = re.compile('[0-9a-f]{64}')
AUDIT_REASON_MAX = 512
PROFILE_STATES = set(cp_config.LIFECYCLE_STATES)
HELD_STATES = {'STARTING', 'READY', 'DRAINING', 'STOPPING', 'QUARANTINED', 'RECONCILING'}
ACTIVE_JOB_STATES = {'queued', 'waiting_resources', 'waiting_session', 'draining', 'loading', 'running', 'cancel_requested', 'reconciling'}
TERMINAL_JOB_STATES = {'succeeded', 'failed', 'cancelled', 'expired'}
QUARANTINE_LOCKED_TARGETS = {'FAILED', 'STOPPED', 'READY', 'STARTING', 'DRAINING', 'STOPPING'}
READY_COMPLETION_STATES = frozenset({'STARTING', 'RECONCILING', 'FAILED'})
COLD_RECOVERY_REASON = 'manager restart: awaiting adapter evidence; origin=STARTING'
READY_RESUME_FAILED_REASONS = frozenset({'post-start readiness probe failed', 'readiness pending deadline exceeded'})
POLICY_BOUNDS: dict[str, tuple[float, float]] = {'sample_max_age_seconds': (1.0, 300.0), 'memory_samples_required': (2.0, 10.0), 'conflict_grace_seconds': (1.0, 3600.0), 'lease_ttl_seconds': (1.0, 86400.0), 'min_residency_seconds': (0.0, 86400.0)}
CONSUMED_POLICY_KEYS = {'sample_max_age_seconds', 'memory_samples_required', 'conflict_grace_seconds', 'lease_ttl_seconds', 'min_residency_seconds'}
SCHEMA_VERSION = 2
DEFAULT_PAYLOAD_RETENTION_SECONDS = 7 * 24 * 3600
SCHEMA_SQL = None

def canonical_digest(payload: Any) -> str:
    """Stable digest of a JSON payload (sorted keys, compact separators)."""
    blob = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()

def finite_number(value: Any, *, name: str, positive: bool=False) -> float:
    """Accept only finite real numbers: bool/NaN/Inf/str/None are refused."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)):
        raise ValidationError(f'{name} must be a finite number', code='invalid_number', details={'field': name})
    if positive and value <= 0:
        raise ValidationError(f'{name} must be positive', code='invalid_number', details={'field': name})
    return float(value)

def positive_generation(value: Any) -> int:
    """Generation must be an explicit positive integer; bool and 0 are refused."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError('generation must be a positive integer', code='invalid_generation', details={'generation': value})
    return int(value)

def clean_reason(value: Any, *, name: str='reason', max_length: int=AUDIT_REASON_MAX) -> str:
    """Operator-supplied reason: printable, bounded, newline-free, never empty."""
    if not isinstance(value, str):
        raise ValidationError(f'{name} must be a string', code='invalid_reason', details={'field': name})
    stripped = ''.join((ch for ch in value if ch >= ' ' and ch != '\x7f')).strip()
    if not stripped or len(stripped) > max_length:
        raise ValidationError(f'{name} must be a non-empty printable string of at most {max_length} characters', code='invalid_reason', details={'field': name})
    return stripped

def valid_token(value: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ValidationError('Invalid opaque identifier', code='invalid_identifier')
    return value

def valid_request_key(value: str) -> str:
    if not isinstance(value, str) or not REQUEST_KEY_RE.fullmatch(value):
        raise ValidationError('request_key must be a stable 8-128 character intent ID; reuse it on retry', code='invalid_request_key')
    return value

def _atomic_write(path: Path, data: bytes, mode: int=384) -> None:
    tmp = path.with_name(path.name + f'.tmp-{os.getpid()}-{threading.get_ident()}')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()

def _chmod_private(path: Path, mode: int) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.chmod(path, mode)

class OwnerLock:
    """Non-blocking exclusive OS lock identifying the single owner process."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> 'OwnerLock':
        if self._fd is not None:
            raise RuntimeError('OwnerLock already held by this instance')
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=448)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 384)
        try:
            self._lock_fd(fd)
        except OSError:
            os.close(fd)
            raise
        self._fd = fd
        os.write(fd, f'pid={os.getpid()} acquired_at={int(time.time())}\n'.encode())
        os.fsync(fd)
        return self

    def _lock_fd(self, fd: int) -> None:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

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

class Store:
    """SQLite-backed durable state. Thread-safe within the owner; single owner across processes."""

    def __init__(self, root: Path | str, *, clock: Callable[[], float]=time.time):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=448)
        _chmod_private(self.root, 448)
        self.payload_root = self.root / 'payloads'
        self.payload_root.mkdir(parents=True, exist_ok=True, mode=448)
        _chmod_private(self.payload_root, 448)
        self.db_path = self.root / 'control.db'
        self.lock_path = self.root / 'owner.lock'
        self._clock = clock
        self._mutex = threading.RLock()
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        conn = self._connection()
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('PRAGMA foreign_keys=ON')
        _chmod_private(self.db_path, 384)
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        """One connection per thread; the manager mutex serializes writers.

        WAL lets readers proceed while one writer holds ``BEGIN IMMEDIATE``, and
        every write path goes through :meth:`_tx`, so a second writer process
        waits instead of corrupting state.
        """
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
            self._connections.append(conn)
        return conn

    def _initialize(self) -> None:
        with self._mutex:
            conn = self._connection()
            conn.executescript(SCHEMA_SQL)
            conn.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))

    @contextlib.contextmanager
    def _tx(self, *, immediate: bool=True) -> Iterator[sqlite3.Connection]:
        """Serialized write transaction on THIS thread's connection.

        ``BEGIN IMMEDIATE`` takes the SQLite write lock up front, so a competing
        writer (thread or process) waits instead of hitting a mid-transaction
        ``SQLITE_BUSY``. The manager mutex serializes threads sharing a store.
        """
        with self._mutex:
            conn = self._connection()
            conn.execute('BEGIN IMMEDIATE' if immediate else 'BEGIN')
            try:
                yield conn
            except BaseException:
                conn.execute('ROLLBACK')
                raise
            else:
                conn.execute('COMMIT')

    def close(self) -> None:
        """Close every per-thread connection this store opened.

        Closed connections stay bound to their creating threads, so a late call
        fails loudly instead of silently opening a second handle to the file.
        """
        with self._mutex:
            for conn in self._connections:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._connections.clear()

    def close_thread_connection(self) -> None:
        """Close (and detach) the calling thread's connection, if any.

        Request-handler threads on the loopback API call this when the request
        finishes so a server that lives for weeks does not accumulate handles.
        """
        with self._mutex:
            conn = getattr(self._local, 'conn', None)
            if conn is None:
                return
            conn.close()
            self._local.conn = None
            with contextlib.suppress(ValueError):
                self._connections.remove(conn)

    def _audit_conn(self, conn: sqlite3.Connection, action: str, *, actor: str, profile: str | None=None, node: str | None=None, generation: int | None=None, reason: str | None=None, detail: str | None=None) -> None:
        """Append one audit row inside an existing transaction.

        Opaque identity only: action/profile/node/generation/reason/time. No
        payload, body, token, or filesystem content is ever recorded here.
        """
        conn.execute('INSERT INTO audit(ts,actor,action,profile,node,generation,reason,detail) VALUES(?,?,?,?,?,?,?,?)', (self._clock(), (actor or 'system')[:128], action[:64], profile[:64] if profile else None, node[:128] if node else None, int(generation) if generation is not None else None, (reason or '')[:AUDIT_REASON_MAX] or None, (detail or '')[:AUDIT_REASON_MAX] or None))

    def audit(self, action: str, *, actor: str, profile: str | None=None, node: str | None=None, generation: int | None=None, reason: str | None=None, detail: str | None=None) -> None:
        with self._tx() as conn:
            self._audit_conn(conn, action, actor=actor, profile=profile, node=node, generation=generation, reason=reason, detail=detail)

    def audit_log(self, *, limit: int=200) -> list[dict[str, Any]]:
        """Append-only audit history, newest first (metadata only)."""
        if isinstance(limit, bool) or not isinstance(limit, int) or (not 1 <= limit <= 1000):
            raise ValidationError('limit must be an integer in [1,1000]', code='invalid_limit')
        rows = self._connection().execute('SELECT seq,ts,actor,action,profile,node,generation,reason,detail FROM audit ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
        return [dict(row) for row in rows]

    def __enter__(self) -> 'Store':
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sync_profiles(self, profiles: dict[str, dict[str, Any]], *, actor: str='system') -> None:
        """Upsert read-only profile definitions. Calibration nulls stay null.

        A profile that currently holds nodes, or is quarantined, must not have its
        node set, calibration, source or validation flag mutated underneath the
        hold: that would orphan holds on nodes the profile no longer lists (and
        silently widen what a quarantined profile may start). Such a change is
        refused; identical definitions are accepted as a no-op.
        """
        with self._tx() as conn:
            for name, spec in profiles.items():
                cal = spec.get('min_start_available_gib')
                floor = spec.get('runtime_floor_gib')
                current = conn.execute('SELECT * FROM profiles WHERE name=?', (name,)).fetchone()
                if current is not None:
                    new_values = {'nodes_json': json.dumps(spec['nodes']), 'source': spec.get('source'), 'role': spec.get('role'), 'hardware_validated': 1 if spec.get('hardware_validated') is True else 0, 'min_start_available_json': json.dumps(cal) if cal is not None else None, 'runtime_floor_json': json.dumps(floor) if floor is not None else None}
                    changed = [key for key, value in new_values.items() if current[key] != value]
                    if changed:
                        hold_rows = conn.execute('SELECT COUNT(*) AS n FROM nodes WHERE hold_profile=?', (name,)).fetchone()['n']
                        if hold_rows or current['state'] != 'STOPPED':
                            raise ProfileStateError(f"profile_config_change_refused_in_held_state: refusing to change {','.join(changed)} while the profile holds nodes or is not STOPPED", code='profile_config_change_refused_in_held_state', details={'profile': name, 'changed': changed, 'state': current['state']})
                conn.execute("INSERT INTO profiles(name,nodes_json,source,role,hardware_validated,\n                           min_start_available_json,runtime_floor_json,state,generation)\n                       VALUES(?,?,?,?,?,?,?, 'STOPPED', 0)\n                       ON CONFLICT(name) DO UPDATE SET\n                           nodes_json=excluded.nodes_json,\n                           source=excluded.source,\n                           role=excluded.role,\n                           hardware_validated=excluded.hardware_validated,\n                           min_start_available_json=excluded.min_start_available_json,\n                           runtime_floor_json=excluded.runtime_floor_json", (name, json.dumps(spec['nodes']), spec.get('source'), spec.get('role'), 1 if spec.get('hardware_validated') is True else 0, json.dumps(cal) if cal is not None else None, json.dumps(floor) if floor is not None else None))
            for row in conn.execute('SELECT nodes_json FROM profiles').fetchall():
                for node in json.loads(row['nodes_json']):
                    conn.execute('INSERT OR IGNORE INTO nodes(name) VALUES(?)', (node,))

    def profile_row(self, name: str) -> sqlite3.Row:
        row = self._connection().execute('SELECT * FROM profiles WHERE name=?', (name,)).fetchone()
        if row is None:
            raise NotFoundError(f'Unknown profile: {name}', details={'profile': name})
        return row

    def profiles(self) -> list[dict[str, Any]]:
        rows = self._connection().execute('SELECT * FROM profiles ORDER BY name').fetchall()
        return [self._profile_view(r) for r in rows]

    @staticmethod
    def _profile_view(row: sqlite3.Row) -> dict[str, Any]:
        calibration = json.loads(row['min_start_available_json']) if row['min_start_available_json'] else None
        floor = json.loads(row['runtime_floor_json']) if row['runtime_floor_json'] else None
        return {'profile': row['name'], 'nodes': json.loads(row['nodes_json']), 'source': row['source'], 'role': row['role'], 'hardware_validated': bool(row['hardware_validated']), 'min_start_available_gib': calibration, 'runtime_floor_gib': floor, 'state': row['state'], 'generation': row['generation'], 'owner': row['owner'], 'last_started_at': row['last_started_at'], 'quarantined_at': row['quarantined_at'], 'reason': row['reason']}

    def profile_view(self, name: str) -> dict[str, Any]:
        return self._profile_view(self.profile_row(name))

    def memory_view(self, name: str) -> dict[str, Any]:
        """Profile view shaped exactly as ``scripts/safety_contract.memory_ready`` expects."""
        view = self.profile_view(name)
        return {'hardware_validated': view['hardware_validated'], 'nodes': view['nodes'], 'min_start_available_gib': view['min_start_available_gib']}

    def nodes_view(self) -> list[dict[str, Any]]:
        rows = self._connection().execute('SELECT n.*, p.state AS hold_state, p.reason AS hold_reason FROM nodes n LEFT JOIN profiles p ON p.name=n.hold_profile AND p.owner=n.hold_owner AND p.generation=n.hold_generation ORDER BY n.name').fetchall()
        return [{'node': r['name'], 'hold_profile': r['hold_profile'], 'hold_owner': r['hold_owner'], 'hold_generation': r['hold_generation'], 'hold_operation': r['hold_operation'], 'held_at': r['held_at'], 'quarantined': bool(r['quarantine']), 'quarantine_reason': r['quarantine_reason'], 'last_seen_at': r['last_seen_at'], 'hold_state': r['hold_state'], 'hold_reason': r['hold_reason'], 'run_uncertain': bool(r['hold_profile']) and (r['hold_state'] is None or r['hold_state'] in {'FAILED', 'QUARANTINED', 'RECONCILING'})} for r in rows]

    def node_view(self, name: str) -> dict[str, Any]:
        for item in self.nodes_view():
            if item['node'] == name:
                return item
        raise NotFoundError(f'Unknown node: {name}', details={'node': name})

    def reserve_profile(self, profile: str, *, owner: str, operation: str='start', resume_generation: int | None=None, reason: str | None=None) -> dict[str, Any]:
        """Atomically hold every node of ``profile`` under one new generation.

        Either all nodes are reserved in the same transaction or none are and the
        caller receives ``queued: True`` with the conflicting nodes.
        """
        valid_token(owner)
        if operation not in {'start', 'maintenance', 'test'}:
            raise ValidationError('operation must be start|maintenance|test', code='invalid_operation')
        if reason is not None:
            reason = clean_reason(reason)
        with self._tx() as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None:
                raise NotFoundError(f'Unknown profile: {profile}', details={'profile': profile})
            if prow['state'] in HELD_STATES:
                return {'reserved': False, 'queued': True, 'reason_code': 'profile_busy', 'profile': profile, 'state': prow['state'], 'owner': prow['owner'], 'generation': prow['generation']}
            nodes = json.loads(prow['nodes_json'])
            busy: list[dict[str, Any]] = []
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None:
                    conn.execute('INSERT INTO nodes(name) VALUES(?)', (node,))
                    nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow['hold_profile'] is not None:
                    busy.append({'node': node, 'held_by': nrow['hold_profile'], 'owner': nrow['hold_owner']})
            if busy:
                return {'reserved': False, 'queued': True, 'reason_code': 'node_conflict', 'profile': profile, 'conflicts': busy}
            base = prow['generation']
            new_generation = base + 1 if resume_generation is None else max(base + 1, int(resume_generation))
            now = self._clock()
            for node in nodes:
                conn.execute('UPDATE nodes SET hold_profile=?, hold_owner=?, hold_generation=?,\n                           hold_operation=?, held_at=? WHERE name=?', (profile, owner, new_generation, operation, now, node))
            conn.execute("UPDATE profiles SET generation=?, owner=?, state='STARTING', reason=NULL WHERE name=?", (new_generation, owner, profile))
            self._audit_conn(conn, 'reserve', actor=owner, profile=profile, generation=new_generation, reason=reason, detail=f"operation={operation} nodes={','.join(nodes)}")
            return {'reserved': True, 'queued': False, 'profile': profile, 'generation': new_generation, 'owner': owner, 'operation': operation, 'nodes': nodes, 'state': 'STARTING'}

    def release_profile(self, profile: str, *, owner: str, generation: int, adapter_evidence: dict[str, Any] | None, lose_quarantine: bool=False, override_reason: str | None=None) -> dict[str, Any]:
        """[REDACTED large text/source constant; see extracted source files]"""
        valid_token(owner)
        generation = positive_generation(generation)
        if lose_quarantine:
            override_reason = clean_reason(override_reason, name='override_reason')
        with self._tx() as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None:
                raise NotFoundError(f'Unknown profile: {profile}', details={'profile': profile})
            if int(prow['generation']) != generation:
                raise GenerationFenceError('stale_generation: release refused; the requested generation is not current', details={'requested_generation': generation, 'current_generation': prow['generation']})
            if prow['owner'] is None:
                raise HoldOwnershipError("nothing_to_release: the profile has no active owned holds; a never-reserved or already released profile cannot release another profile's nodes", details={'profile': profile, 'generation': generation})
            if prow['owner'] != owner:
                raise ForbiddenError('owner_mismatch: only the owning operator may release these nodes', details={'hold_owner': prow['owner'], 'caller': owner})
            nodes = json.loads(prow['nodes_json'])
            if not nodes:
                raise ProfileStateError('profile has no nodes to release', details={'profile': profile})
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None or nrow['hold_profile'] != profile:
                    raise HoldOwnershipError('hold_ownership_mismatch: a node of this profile is not held by this profile', details={'node': node, 'held_by': nrow['hold_profile'] if nrow else None, 'expected_profile': profile})
                if nrow['hold_owner'] != owner or int(nrow['hold_generation'] or -1) != generation:
                    raise HoldOwnershipError('hold_ownership_mismatch: node hold owner/generation does not match the release request', details={'node': node, 'hold_owner': nrow['hold_owner'], 'hold_generation': nrow['hold_generation'], 'expected_owner': owner, 'expected_generation': generation})
            self.validate_stop_evidence(conn, nodes=nodes, profile=profile, generation=generation, evidence=adapter_evidence)
            quarantined = [n for n in nodes if conn.execute('SELECT quarantine FROM nodes WHERE name=?', (n,)).fetchone()['quarantine']]
            if quarantined and (not lose_quarantine):
                raise QuarantinedError('quarantined_hold_retained: matching-generation stop evidence accepted, but quarantine holds are retained until an admin explicitly clears them with a reasoned override', details={'quarantined_nodes': quarantined})
            now = self._clock()
            for node in nodes:
                conn.execute('UPDATE nodes SET hold_profile=NULL, hold_owner=NULL, hold_generation=NULL,\n                           hold_operation=NULL, held_at=NULL, quarantine=0, quarantine_reason=NULL,\n                           quarantine_at=NULL, last_seen_at=? WHERE name=?', (now, node))
            conn.execute("UPDATE profiles SET state='STOPPED', owner=NULL, reason=NULL WHERE name=?", (profile,))
            self._audit_conn(conn, 'quarantine_override_release' if quarantined and lose_quarantine else 'release', actor=owner, profile=profile, generation=generation, reason=override_reason, detail=f"nodes={','.join(nodes)} lose_quarantine={bool(quarantined and lose_quarantine)}")
            return {'released': True, 'profile': profile, 'generation': generation, 'nodes': nodes, 'lose_quarantine': bool(lose_quarantine and quarantined), 'override_reason': override_reason if quarantined else None, 'released_at': now}

    def validate_stop_evidence(self, conn: sqlite3.Connection, *, nodes: list[str], profile: str, generation: int, evidence: dict[str, Any] | None) -> None:
        """Shape *and* numeric validation of a stop observation set.

        Refuses: missing evidence, non-matching generation, non-boolean ``stopped``,
        ``stopped`` not exactly ``True``, an incomplete/extra node set, missing or
        non-finite timestamps (bool/NaN/Inf/str), future timestamps, and stale
        timestamps outside the policy sample window. Timeouts and negative
        observations never release anything.
        """
        if not isinstance(evidence, dict):
            raise GenerationFenceError('adapter_confirmation_required: release needs fresh positive adapter evidence; a timeout releases nothing', code='adapter_confirmation_required')
        stopped_flag = evidence.get('stopped')
        if stopped_flag is not True:
            raise GenerationFenceError('adapter_confirmation_required: evidence must assert stopped=true', code='adapter_confirmation_required', details={'stopped': stopped_flag})
        evidence_generation = evidence.get('generation')
        if isinstance(evidence_generation, bool) or not isinstance(evidence_generation, int) or evidence_generation != generation:
            raise GenerationFenceError('adapter_confirmation_required: evidence must be a positive stop for the matching generation', code='adapter_confirmation_required', details={'expected_generation': generation, 'evidence_generation': evidence_generation})
        per_node = evidence.get('nodes')
        if not isinstance(per_node, dict) or set(per_node) != set(nodes):
            raise GenerationFenceError('adapter_confirmation_required: evidence must cover every node of the profile and no others', code='adapter_confirmation_required', details={'expected_nodes': sorted(nodes), 'evidence_nodes': sorted(map(str, per_node or {}))})
        now = self._clock()
        max_age = self.policy_sample_max_age()
        for node in nodes:
            item = per_node.get(node)
            if not isinstance(item, dict):
                raise GenerationFenceError(f'adapter_confirmation_required: node {node} has no observation object', code='adapter_confirmation_required', details={'node': node})
            if item.get('stopped') is not True:
                raise GenerationFenceError(f'adapter_confirmation_required: node {node} has no positive stop evidence', code='adapter_confirmation_required', details={'node': node, 'stopped': item.get('stopped')})
            try:
                observed = finite_number(item.get('observed_at'), name=f'nodes.{node}.observed_at')
            except ValidationError as exc:
                raise GenerationFenceError(f'adapter_confirmation_required: node {node} observation timestamp is not a finite number (bool/NaN/Inf/text are refused)', code='adapter_confirmation_required', details={'node': node, 'observed_at': item.get('observed_at')}) from exc
            if observed > now + 1.0 or now - observed > max_age:
                raise GenerationFenceError(f'adapter_confirmation_required: node {node} evidence is stale or from the future', code='adapter_confirmation_required', details={'node': node, 'observed_at': observed, 'max_age': max_age})
        top_observed = evidence.get('observed_at')
        if top_observed is not None:
            try:
                top = finite_number(top_observed, name='observed_at')
            except ValidationError as exc:
                raise GenerationFenceError('adapter_confirmation_required: evidence timestamp is not a finite number', code='adapter_confirmation_required', details={'observed_at': top_observed}) from exc
            if top > now + 1.0 or now - top > max_age:
                raise GenerationFenceError('adapter_confirmation_required: evidence timestamp is stale or from the future', code='adapter_confirmation_required', details={'observed_at': top, 'max_age': max_age})

    def policy_value(self, key: str, default: float) -> float:
        """Read a policy number recorded at open time (falls back to ``default``)."""
        row = self._connection().execute('SELECT value FROM meta WHERE key=?', (f'policy.{key}',)).fetchone()
        if row is None:
            return default
        try:
            return float(row['value'])
        except (TypeError, ValueError):
            return default

    def policy_sample_max_age(self) -> float:
        """Max accepted age for a memory/stop-observation sample, in seconds."""
        return self.policy_value('sample_max_age_seconds', 10.0)

    def set_policy(self, policy: dict[str, Any]) -> None:
        """Record the scheduler policy keys this core actually consumes.

        Only :data:`CONSUMED_POLICY_KEYS` are validated and stored; declarations
        this core does not enforce (queue priority, keep-warm, fallback flags,
        documentation strings) are skipped rather than pretending to implement
        them. Consumed values must be finite real numbers (bool/NaN/Inf/str are
        refused) and safety-critical ones are bounded by :data:`POLICY_BOUNDS`
        so no policy file can widen freshness or sample-count gates.
        """
        normalized: dict[str, float] = {}
        skipped: list[str] = []
        for key, value in policy.items():
            if key not in CONSUMED_POLICY_KEYS:
                skipped.append(str(key))
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValidationError(f'consumed policy value for {key!r} must be a finite number', code='invalid_policy', details={'key': key, 'value_type': type(value).__name__})
            number = finite_number(value, name=f'policy.{key}')
            if key in POLICY_BOUNDS:
                low, high = POLICY_BOUNDS[key]
                if not low <= number <= high:
                    raise ValidationError(f'policy value for {key!r} outside safe bounds [{low},{high}]', code='invalid_policy', details={'key': key, 'value': number, 'min': low, 'max': high})
            normalized[key] = number
        for key in ('sample_max_age_seconds', 'memory_samples_required'):
            if key not in normalized:
                normalized[key] = self.policy_value(key, cp_config.POLICY_DEFAULTS[key])
        with self._tx() as conn:
            for key, value in normalized.items():
                conn.execute('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (f'policy.{key}', str(value)))
            conn.execute("INSERT INTO meta(key,value) VALUES('sample_max_age_seconds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(normalized['sample_max_age_seconds']),))
            self._audit_conn(conn, 'policy_set', actor='system', detail=';'.join((f'{k}={v}' for k, v in sorted(normalized.items()))) + (f' | ignored_unenforced={len(skipped)}' if skipped else ''))

    def set_profile_state(self, profile: str, state: str, *, generation: int | None=None, reason: str | None=None, actor: str='system', expected_owner: str | None=None, require_holds: bool=False, expected_states: frozenset[str] | set[str] | None=None) -> dict[str, Any]:
        """Generation-fenced lifecycle transition, audited.

        A quarantined profile is locked: it may only stay quarantined or move to
        ``RECONCILING`` until an evidenced release (with a reasoned override)
        clears it. It must never be silently overwritten to FAILED/STOPPED/READY,
        which would hide retained unsafe holds.

        **Hold-fenced completion (N5):** when ``expected_owner`` is given, the
        transition is refused with :class:`StaleCompletionError` unless this
        exact owner+generation still owns the profile *and* every node still
        carries the matching ``hold_profile``/``hold_owner``/``hold_generation``
        — all checked inside this single write transaction. A slow adapter call
        that finishes after a legitimate release therefore cannot publish
        STOPPED/FAILED over freed, newer-owned state, and no audit row claims a
        completion that no longer owns its resource.
        """
        if state not in PROFILE_STATES:
            raise ValidationError(f'Unknown lifecycle state: {state}', code='invalid_state')
        if expected_states is not None and (not expected_states or not set(expected_states).issubset(PROFILE_STATES)):
            raise ValidationError('invalid expected lifecycle states', code='invalid_state')
        if (expected_owner is not None or require_holds) and (expected_owner is None or generation is None):
            raise ValidationError('expected_owner and generation are both required for a hold-fenced transition', code='invalid_request')
        if reason is not None:
            reason = clean_reason(reason)
        with self._tx() as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None:
                raise NotFoundError(f'Unknown profile: {profile}', details={'profile': profile})
            if expected_states is not None and prow['state'] not in expected_states:
                raise ProfileStateError('state_completion_refused: a later lifecycle transition wins', code='state_completion_refused', details={'profile': profile, 'state': prow['state']})
            if generation is not None and int(prow['generation']) != int(generation):
                raise GenerationFenceError('stale_generation: transition refused for a superseded generation', details={'requested_generation': int(generation), 'current_generation': prow['generation']})
            if expected_owner is not None:
                if prow['owner'] != expected_owner:
                    raise StaleCompletionError('stale_completion: the profile is no longer owned by the expected owner; state left unchanged', details={'profile': profile, 'expected_owner': expected_owner, 'current_owner': prow['owner'], 'generation': int(generation)})
                nodes = json.loads(prow['nodes_json'])
                if not nodes:
                    raise StaleCompletionError('stale_completion: the profile no longer lists nodes to hold', details={'profile': profile, 'generation': int(generation)})
                for node in nodes:
                    nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                    if nrow is None or nrow['hold_profile'] != profile or nrow['hold_owner'] != expected_owner or (int(nrow['hold_generation'] or -1) != int(generation)):
                        raise StaleCompletionError('stale_completion: node hold no longer matches the claimed owner/generation; state left unchanged', details={'profile': profile, 'node': node, 'expected_owner': expected_owner, 'expected_generation': int(generation), 'hold_profile': nrow['hold_profile'] if nrow else None, 'hold_owner': nrow['hold_owner'] if nrow else None, 'hold_generation': nrow['hold_generation'] if nrow else None})
            if prow['state'] == 'QUARANTINED' and state in QUARANTINE_LOCKED_TARGETS:
                raise QuarantinedError(f'quarantined_state_locked: a quarantined profile cannot be overwritten to {state}; it needs an evidenced release with a reasoned override', details={'profile': profile, 'current_state': prow['state'], 'requested_state': state})
            extra = ''
            params: list[Any] = [state, reason]
            if state == 'QUARANTINED':
                extra = ', quarantined_at=?'
                params.append(self._clock())
            if state == 'READY':
                extra += ', last_started_at=?'
                params.append(self._clock())
            conn.execute(f'UPDATE profiles SET state=?, reason=?{extra} WHERE name=?', (*params, profile))
            self._audit_conn(conn, 'state_transition', actor=actor, profile=profile, generation=generation if generation is not None else int(prow['generation']), reason=reason, detail=f"{prow['state']}->{state}" + (' (hold-fenced)' if expected_owner is not None else ''))
            return self.profile_view(profile)

    def still_owned(self, profile: str, *, owner: str, generation: int) -> bool:
        """Read-only check that this exact owner/generation still holds every node.

        Used only for early detection; the authoritative guarantee is the
        hold-fenced ``set_profile_state`` CAS, which re-checks atomically at
        publish time.
        """
        with self._tx(immediate=False) as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None or prow['owner'] != owner or int(prow['generation']) != int(generation):
                return False
            nodes = json.loads(prow['nodes_json'])
            if not nodes:
                return False
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None or nrow['hold_profile'] != profile or nrow['hold_owner'] != owner or (int(nrow['hold_generation'] or -1) != int(generation)):
                    return False
            return True

    def reservation_started_at(self, profile: str, *, owner: str, generation: int) -> float | None:
        """Timestamp of the reservation that created these exact holds, or ``None``.

        Reads ``nodes.held_at`` — written in the same transaction as the
        reservation — and only when this exact profile/owner/generation still
        holds **every** node. Used to bound how long a pending model load may
        stay ``STARTING``; it never releases anything by itself.
        """
        generation = positive_generation(generation)
        with self._tx(immediate=False) as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None or prow['owner'] != owner or int(prow['generation']) != generation:
                return None
            nodes = json.loads(prow['nodes_json'])
            if not nodes:
                return None
            stamps: list[float] = []
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None or nrow['hold_profile'] != profile or nrow['hold_owner'] != owner or (int(nrow['hold_generation'] or -1) != generation) or (nrow['held_at'] is None):
                    return None
                stamps.append(float(nrow['held_at']))
            return min(stamps)

    def complete_readiness(self, profile: str, *, owner: str, generation: int, from_states: frozenset[str] | set[str], actor: str='system') -> dict[str, Any]:
        """[REDACTED large text/source constant; see extracted source files]"""
        valid_token(owner)
        generation = positive_generation(generation)
        if not from_states or not set(from_states).issubset(READY_COMPLETION_STATES):
            raise ValidationError(f'complete_readiness from_states must be a non-empty subset of {sorted(READY_COMPLETION_STATES)}', code='invalid_request', details={'from_states': sorted(map(str, from_states))})
        with self._tx() as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None:
                raise NotFoundError(f'Unknown profile: {profile}', details={'profile': profile})
            prior_state = prow['state']
            if prior_state not in from_states:
                raise ProfileStateError('readiness_completion_state_refused: the profile is not in an eligible pre-ready state, so a late positive probe can never complete it', code='readiness_completion_state_refused', details={'profile': profile, 'state': prior_state, 'eligible': sorted(from_states)})
            if int(prow['generation']) != generation:
                raise GenerationFenceError('stale_generation: readiness completion refused for a superseded generation', details={'requested_generation': generation, 'current_generation': prow['generation']})
            if prow['owner'] is None:
                raise HoldOwnershipError('nothing_to_complete: the profile has no owner; released or never-reserved records are never revived by a late readiness probe', details={'profile': profile, 'generation': generation})
            if prow['owner'] != owner:
                raise ForbiddenError('owner_mismatch: only the owning operator may complete readiness', details={'hold_owner': prow['owner'], 'caller': owner})
            if prior_state == 'FAILED' and prow['reason'] not in READY_RESUME_FAILED_REASONS:
                raise ProfileStateError('readiness_resume_reason_refused: only a FAILED record whose reason marks an accepted start with unproven readiness may be resumed; this failure needs explicit admin action instead', code='readiness_resume_reason_refused', details={'profile': profile, 'reason': prow['reason']})
            nodes = json.loads(prow['nodes_json'])
            if not nodes:
                raise ProfileStateError('profile has no nodes to hold', details={'profile': profile})
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None or nrow['hold_profile'] != profile or nrow['hold_owner'] != owner or (int(nrow['hold_generation'] or -1) != generation):
                    raise StaleCompletionError('stale_completion: node hold no longer matches the claimed owner/generation; readiness left unpublished', details={'profile': profile, 'node': node, 'expected_owner': owner, 'expected_generation': generation, 'hold_profile': nrow['hold_profile'] if nrow else None, 'hold_owner': nrow['hold_owner'] if nrow else None, 'hold_generation': nrow['hold_generation'] if nrow else None})
                if nrow['quarantine']:
                    raise QuarantinedError('quarantined_hold_retained: a quarantined node is never revived by a readiness completion', details={'profile': profile, 'node': node})
            now = self._clock()
            conn.execute("UPDATE profiles SET state='READY', reason=NULL, last_started_at=? WHERE name=?", (now, profile))
            self._audit_conn(conn, 'readiness_completed', actor=actor, profile=profile, generation=generation, detail=f"{prior_state}->READY evidence=fresh probe_ready holds={','.join(nodes)}")
            return self.profile_view(profile)

    def quarantine_node(self, node: str, *, reason: str, observed_generation: int | None=None, actor: str='system') -> dict[str, Any]:
        """Mark a lost node; the existing hold is retained, never released by timeouts.

        ``observed_generation`` fences a stale probe: if the node's current hold
        belongs to a different generation than the observation was made against,
        the quarantine is refused instead of clobbering a newer generation's state.
        """
        reason = clean_reason(reason)
        with self._tx() as conn:
            nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
            if nrow is None:
                raise NotFoundError(f'Unknown node: {node}', details={'node': node})
            if observed_generation is not None:
                current = nrow['hold_generation']
                if current is None or int(current) != int(observed_generation):
                    raise GenerationFenceError("stale_generation: quarantine observation does not match the node's current hold generation", details={'node': node, 'observed_generation': observed_generation, 'current_generation': current})
            conn.execute('UPDATE nodes SET quarantine=1, quarantine_reason=?, quarantine_at=? WHERE name=?', (reason, self._clock(), node))
            if nrow['hold_profile']:
                conn.execute("UPDATE profiles SET state='QUARANTINED', quarantined_at=?, reason=? WHERE name=?", (self._clock(), f'node {node}: {reason}', nrow['hold_profile']))
            self._audit_conn(conn, 'quarantine', actor=actor, profile=nrow['hold_profile'], node=node, generation=nrow['hold_generation'], reason=reason)
            return self.node_view(node)

    def begin_stop(self, profile: str, *, owner: str, expected_generation: int, actor: str | None=None) -> dict[str, Any]:
        """Atomic compare-and-set gate before any stop side effect.

        Verifies, in one transaction: the caller owns the profile, the caller's
        explicit ``expected_generation`` is the current one, and every node still
        carries this profile's hold at that owner/generation. Only then does it
        move the profile to ``DRAINING``. A stale or foreign stop can therefore
        never reach the adapter.
        """
        valid_token(owner)
        expected_generation = positive_generation(expected_generation)
        with self._tx() as conn:
            prow = conn.execute('SELECT * FROM profiles WHERE name=?', (profile,)).fetchone()
            if prow is None:
                raise NotFoundError(f'Unknown profile: {profile}', details={'profile': profile})
            if int(prow['generation']) != expected_generation:
                raise GenerationFenceError("stale_generation: stop refused; the caller's expected generation is not current", details={'expected_generation': expected_generation, 'current_generation': prow['generation']})
            if prow['owner'] != owner:
                raise ForbiddenError('owner_mismatch: only the owning operator may stop this profile', details={'hold_owner': prow['owner'], 'caller': owner})
            nodes = json.loads(prow['nodes_json'])
            for node in nodes:
                nrow = conn.execute('SELECT * FROM nodes WHERE name=?', (node,)).fetchone()
                if nrow is None or nrow['hold_profile'] != profile or nrow['hold_owner'] != owner or (int(nrow['hold_generation'] or -1) != expected_generation):
                    raise HoldOwnershipError('hold_ownership_mismatch: node hold does not match the stop request', details={'node': node, 'held_by': nrow['hold_profile'] if nrow else None, 'hold_owner': nrow['hold_owner'] if nrow else None, 'hold_generation': nrow['hold_generation'] if nrow else None, 'expected_owner': owner, 'expected_generation': expected_generation})
            conn.execute("UPDATE profiles SET state='DRAINING', reason='stop requested; holds retained until confirmed release' WHERE name=?", (profile,))
            self._audit_conn(conn, 'stop_begin', actor=actor or owner, profile=profile, generation=expected_generation, detail=f"nodes={','.join(nodes)}")
            return {'profile': profile, 'generation': expected_generation, 'owner': owner, 'nodes': nodes}

    def touch_node(self, node: str) -> None:
        with self._tx() as conn:
            conn.execute('UPDATE nodes SET last_seen_at=? WHERE name=?', (self._clock(), node))
    DISPATCHABLE_STATES = ('queued', 'waiting_resources', 'waiting_session')

    def mark_dispatched(self, job_id: str, *, profile: str, generation: int) -> dict[str, Any]:
        """Guard for post-cancel race: cancellation wins over a later dispatch."""
        with self._tx() as conn:
            row = conn.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
            if row is None:
                raise NotFoundError(f'Unknown job: {job_id}', details={'job_id': job_id})
            if row['state'] not in self.DISPATCHABLE_STATES or row['cancel_requested_at'] is not None:
                raise ProfileStateError('cancelled_or_reconciling_jobs_are_not_dispatched: refusing to dispatch', details={'job_id': job_id, 'state': row['state']})
            now = self._clock()
            conn.execute("UPDATE jobs SET state='running', stage='dispatch', profile=?, generation=?, dispatched_at=?, updated_at=? WHERE job_id=?", (profile, int(generation), now, now, job_id))
            return {'job_id': job_id, 'state': 'running', 'profile': profile, 'generation': int(generation)}

    def recovery_scan(self) -> dict[str, Any]:
        """Manager-start recovery: distrust SQLite for anything possibly running.

        Profiles in an active-looking resumable state are moved to ``RECONCILING``
        (never straight to READY); DRAINING/STOPPING retain their stop intent until a real adapter probe says otherwise. A
        quarantined profile is *not* moved: its quarantine marker and holds stay
        exactly as they were, and it is reported separately so the manager can
        reconcile it without erasing the quarantine. In-flight jobs move to
        ``reconciling``. Recovery never deletes rows and never releases holds.
        """
        with self._tx() as conn:
            rows = conn.execute(f"SELECT name, state, reason FROM profiles WHERE state IN ({','.join(('?' for _ in HELD_STATES))})", tuple(HELD_STATES)).fetchall()
            profiles: list[str] = []
            quarantined_retained: list[str] = []
            teardown_retained: list[str] = []
            for row in rows:
                if row['state'] == 'QUARANTINED':
                    quarantined_retained.append(row['name'])
                    continue
                if row['state'] in {'DRAINING', 'STOPPING'}:
                    teardown_retained.append(row['name'])
                    continue
                profiles.append(row['name'])
                if row['state'] != 'RECONCILING':
                    reason = COLD_RECOVERY_REASON if row['state'] == 'STARTING' else 'manager restart: awaiting adapter evidence; origin=READY'
                    conn.execute("UPDATE profiles SET state='RECONCILING', reason=? WHERE name=?", (reason, row['name']))
            for name in profiles:
                self._audit_conn(conn, 'recovery_reconciling', actor='system', profile=name, detail='manager restart')
            jobs = [r['job_id'] for r in conn.execute(f"SELECT job_id FROM jobs WHERE state IN ({','.join(('?' for _ in ACTIVE_JOB_STATES))})", tuple(ACTIVE_JOB_STATES)).fetchall()]
            now = self._clock()
            for job_id in jobs:
                conn.execute("UPDATE jobs SET state='reconciling', stage='recovery', reason_code='awaiting_adapter_evidence', updated_at=? WHERE job_id=?", (now, job_id))
            return {'profiles_reconciling': profiles, 'quarantined_retained': quarantined_retained, 'teardown_retained': teardown_retained, 'jobs_reconciling': jobs, 'owner_lock_path': str(self.lock_path)}

    def submit_job(self, *, job_id: str, owner: str, request_key: str, workflow_id: str, payload_digest: str, payload: dict[str, Any] | None=None, parent_session_id: str | None=None, retention_seconds: int=DEFAULT_PAYLOAD_RETENTION_SECONDS, state: str='queued', reason_code: str | None=None) -> dict[str, Any]:
        """Idempotent durable submission keyed on ``(owner, request_key)``.

        Same key + same digest returns the existing job. Same key + different
        digest raises ``idempotency_key_payload_mismatch``.
        """
        valid_token(owner)
        valid_request_key(request_key)
        valid_token(job_id)
        if not SHA256_RE.fullmatch(payload_digest):
            raise ValidationError('payload_digest must be a lowercase sha256', code='invalid_digest')
        if state not in ACTIVE_JOB_STATES:
            raise ValidationError(f'jobs cannot start in state {state}', code='invalid_state')
        existing = self.job_lookup(owner=owner, request_key=request_key)
        if existing is not None:
            if existing['payload_digest'] != payload_digest:
                raise ConflictError('request_key reused with different parameters: keep the same payload for retries', details={'job_id': existing['job_id'], 'request_key': request_key})
            return {'job': self.job_view(existing['job_id']), 'idempotent_replay': True}
        payload_file: str | None = None
        if payload is not None:
            payload_file = self._store_payload(job_id, payload, retention_seconds=retention_seconds)
        now = self._clock()
        with self._tx() as conn:
            duplicate = conn.execute('SELECT job_id, payload_digest FROM jobs WHERE owner=? AND request_key=?', (owner, request_key)).fetchone()
            if duplicate is not None:
                if duplicate['payload_digest'] != payload_digest:
                    raise ConflictError('request_key reused with different parameters: keep the same payload for retries', details={'job_id': duplicate['job_id'], 'request_key': request_key})
                return {'job': self.job_view(duplicate['job_id']), 'idempotent_replay': True}
            conn.execute('INSERT INTO jobs(job_id,owner,request_key,workflow_id,payload_digest,payload_file,\n                       payload_retention_until,state,stage,reason_code,parent_session_id,created_at,updated_at)\n                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', (job_id, owner, request_key, workflow_id, payload_digest, payload_file, now + retention_seconds if payload_file else None, state, 'accepted', reason_code, parent_session_id, now, now))
        return {'job': self.job_view(job_id), 'idempotent_replay': False}

    def _store_payload(self, job_id: str, payload: dict[str, Any], *, retention_seconds: int) -> str:
        """Durable job body as an isolated 0600 artifact; SQLite keeps only the path."""
        target = self.payload_root / f'{job_id}.json'
        _atomic_write(target, json.dumps(payload, sort_keys=True, ensure_ascii=False).encode('utf-8'), mode=384)
        return str(target.relative_to(self.root))

    def payload_path(self, job_id: str) -> Path | None:
        row = self.job_row(job_id)
        if not row['payload_file']:
            return None
        return self.root / row['payload_file']

    def job_row(self, job_id: str) -> sqlite3.Row:
        row = self._connection().execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
        if row is None:
            raise NotFoundError(f'Unknown job: {job_id}', details={'job_id': job_id})
        return row

    def job_lookup(self, *, owner: str, request_key: str) -> sqlite3.Row | None:
        return self._connection().execute('SELECT * FROM jobs WHERE owner=? AND request_key=?', (owner, request_key)).fetchone()

    def list_dispatchable_jobs(self) -> list[sqlite3.Row]:
        """Jobs eligible for dispatch, oldest first (FIFO by creation time)."""
        placeholders = ','.join(('?' for _ in self.DISPATCHABLE_STATES))
        return self._connection().execute(f'SELECT job_id FROM jobs WHERE state IN ({placeholders}) ORDER BY created_at, job_id', tuple(self.DISPATCHABLE_STATES)).fetchall()

    def list_job_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        rows = self._connection().execute('SELECT filename,size,sha256,created_at FROM job_artifacts WHERE job_id=? ORDER BY created_at', (job_id,)).fetchall()
        return [dict(row) for row in rows]

    def job_view(self, job_id: str) -> dict[str, Any]:
        return self._job_view(self.job_row(job_id))

    @staticmethod
    def _job_view(row: sqlite3.Row) -> dict[str, Any]:
        return {'job_id': row['job_id'], 'owner': row['owner'], 'request_key': row['request_key'], 'workflow_id': row['workflow_id'], 'payload_digest': row['payload_digest'], 'state': row['state'], 'stage': row['stage'], 'reason_code': row['reason_code'], 'parent_session_id': row['parent_session_id'], 'profile': row['profile'], 'generation': row['generation'], 'cancel_requested_at': row['cancel_requested_at'], 'dispatched_at': row['dispatched_at'], 'created_at': row['created_at'], 'updated_at': row['updated_at'], 'retention_until': row['payload_retention_until']}

    def require_job_owner(self, job_id: str, *, owner: str) -> sqlite3.Row:
        row = self.job_row(job_id)
        if row['owner'] != owner:
            from .errors import ForbiddenError
            raise ForbiddenError('cross_owner_access_denied: job belongs to another owner', details={'job_id': job_id})
        return row

    def request_cancel(self, job_id: str, *, owner: str) -> dict[str, Any]:
        """Cancellation is a durable intent. Queued jobs are cancelled immediately;
        dispatched jobs enter ``cancel_requested`` and can never be (re)dispatched.
        """
        valid_token(owner)
        with self._tx() as conn:
            row = conn.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
            if row is None:
                raise NotFoundError(f'Unknown job: {job_id}', details={'job_id': job_id})
            if row['owner'] != owner:
                from .errors import ForbiddenError
                raise ForbiddenError('cross_owner_access_denied: job belongs to another owner', details={'job_id': job_id})
            now = self._clock()
            if row['state'] in TERMINAL_JOB_STATES:
                return {'job': self._job_view(row), 'cancel': 'already_terminal'}
            if row['state'] in {'queued', 'waiting_resources', 'waiting_session'}:
                conn.execute("UPDATE jobs SET state='cancelled', stage='cancelled', reason_code='cancelled_before_dispatch', cancel_requested_at=?, updated_at=? WHERE job_id=?", (now, now, job_id))
                return {'job': self.job_view(job_id), 'cancel': 'cancelled'}
            conn.execute("UPDATE jobs SET state='cancel_requested', stage='cancel_requested', cancel_requested_at=?, updated_at=? WHERE job_id=?", (now, now, job_id))
            return {'job': self.job_view(job_id), 'cancel': 'cancel_requested'}

    def finish_job(self, job_id: str, *, state: str, reason_code: str | None=None, stage: str | None=None, artifact: dict[str, Any] | None=None) -> dict[str, Any]:
        """Record a terminal state, honouring cancellation intent.

        Rules:

        - a job already in a terminal state can never be overwritten (no
          resurrection, no silent success);
        - if cancellation was requested, the final state is ``cancelled`` no
          matter what the runner reported. A finished-but-cancelled run is
          recorded as cancelled with the completion reason preserved in
          ``detail``, and its artifact metadata is **not** recorded, because the
          engine result was no longer wanted;
        - ``artifact`` stores filename/size/sha256 metadata only.

        Returns the job view plus ``overridden_by_cancellation``.
        """
        if state not in TERMINAL_JOB_STATES:
            raise ValidationError(f'finish_job requires a terminal state, got {state}', code='invalid_state')
        with self._tx() as conn:
            row = conn.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
            if row is None:
                raise NotFoundError(f'Unknown job: {job_id}', details={'job_id': job_id})
            if row['state'] in TERMINAL_JOB_STATES:
                raise ProfileStateError('job_terminal_cannot_be_overwritten: terminal job state is immutable', code='job_terminal_cannot_be_overwritten', details={'job_id': job_id, 'state': row['state'], 'requested_state': state})
            now = self._clock()
            cancelled = row['cancel_requested_at'] is not None
            if cancelled:
                final_state = 'cancelled'
                final_reason = 'cancelled_during_run'
                detail = f'runner reported {state}'
                if reason_code:
                    detail += f' ({reason_code})'
                conn.execute("UPDATE jobs SET state='cancelled', stage='cancelled', reason_code=?, updated_at=? WHERE job_id=?", (final_reason, now, job_id))
                self._audit_conn(conn, 'job_cancelled', actor='system', reason=detail, detail=f'job={job_id} engine={state}')
                view = self.job_view(job_id)
                view['overridden_by_cancellation'] = True
                view['engine_reported'] = state
                return view
            conn.execute('UPDATE jobs SET state=?, stage=COALESCE(?,stage), reason_code=COALESCE(?,reason_code), updated_at=? WHERE job_id=?', (state, stage, reason_code, now, job_id))
            if artifact:
                conn.execute('INSERT INTO job_artifacts(job_id,filename,size,sha256,created_at) VALUES(?,?,?,?,?)', (job_id, artifact.get('filename'), artifact.get('size'), artifact.get('sha256'), now))
            view = self.job_view(job_id)
            view['overridden_by_cancellation'] = False
            return view

    def queue_job_for_resources(self, job_id: str, *, reason_code: str='waiting_resources') -> dict[str, Any]:
        with self._tx() as conn:
            row = self.job_row(job_id)
            if row['state'] != 'queued':
                raise ProfileStateError('only queued jobs may enter waiting_resources', details={'job_id': job_id, 'state': row['state']})
            conn.execute("UPDATE jobs SET state='waiting_resources', reason_code=?, updated_at=? WHERE job_id=?", (reason_code, self._clock(), job_id))
            return self.job_view(job_id)

def open_store(root: Path | str, *, lock: bool, profiles: dict[str, dict[str, Any]] | None=None, profiles_path: Path | str | None=None, policy: dict[str, Any] | None=None, clock: Callable[[], float]=time.time, take_lock: bool=True) -> tuple[Store, OwnerLock | None]:
    """Open a store; optionally require ownership.

    ``lock=True`` acquires the single-owner OS lock and fails closed if another
    process holds it. The default product entry point uses ``lock=True``; tests
    that only exercise state machine internals may pass ``lock=False`` (never
    the server/CLI default).

    ``profiles_path`` lets an operator point at an explicit profiles document
    (test aid). Explicit profiles still face every fail-closed check.
    """
    owner_lock: OwnerLock | None = None
    if lock and take_lock:
        owner_lock = OwnerLock(Path(root) / 'owner.lock').acquire()
    store = Store(root, clock=clock)
    if profiles is None and profiles_path is not None:
        profiles = cp_config.read_profiles_json(Path(profiles_path))
    if profiles is None:
        root_path = cp_config.repo_root(Path(__file__).resolve().parent)
        if (root_path / 'config' / 'profiles.json').is_file():
            profiles = cp_config.load_profiles(root_path)
            policy = policy or cp_config.load_policy(root_path)
    if profiles:
        store.sync_profiles(profiles)
    if policy:
        store.set_policy(policy)
    return (store, owner_lock)
