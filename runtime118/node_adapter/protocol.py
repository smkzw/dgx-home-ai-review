# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Bounded strict-JSON helpers for the ``dgx-v4-node-v1`` wire protocol.

Client-side (HX) helpers used by :mod:`node_adapter.client`.

The Spark-side forced command (``node_wrapper.py``) is deployed as a single
self-contained file on a node and therefore mirrors the strict parsing rules
locally instead of importing this module. ``tests/test_node_wrapper.py``
asserts that both implementations accept and reject the same corpus, so the
mirror cannot drift silently.

Strict rules (both sides):

- bounded byte length before parsing;
- UTF-8 only, single JSON value, no trailing garbage;
- duplicate object keys rejected;
- ``NaN`` / ``Infinity`` / ``-Infinity`` literals rejected and any number that
  overflows to a non-finite float rejected;
- every field used for control flow has an explicit type check; ``bool`` is
  never accepted where a number is required.
"""
from __future__ import annotations
import json
import math
import re
from typing import Any
SCHEMA = 'dgx-v4-node-v1'
SSH_COMMAND = 'dgx-v4-node-v1'
WIRE_ACTIONS = ('probe', 'preflight', 'claim', 'start', 'probe_ready', 'stop', 'confirm_stop', 'reconcile', 'release', 'owner_recovery_snapshot')
TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
REQUEST_ID_RE = re.compile('[0-9a-f]{16,64}')
CONTAINER_ID_RE = re.compile('[0-9a-f]{12,64}')
IMAGE_REFERENCE_RE = re.compile('(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64})')
ROLE_PROOF_FIELDS = frozenset({'role', 'api_checked', 'process_verified', 'worker_proof'})
REASON_MAX = 200
MODEL_ID_MAX = 256
REPLY_STATUSES = ('ok', 'refused')

class ProtocolError(ValueError):
    """A message violated the bounded strict wire protocol (fail closed)."""

    def __init__(self, reason_code: str, message: str=''):
        super().__init__(message or reason_code)
        self.reason_code = reason_code

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ProtocolError('duplicate_key', f'duplicate JSON key: {key!r}')
        seen.add(key)
    return dict(pairs)

def _reject_constant(name: str) -> Any:
    raise ProtocolError('nonfinite_number', f'JSON constant {name!r} is not accepted')

def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ProtocolError('nonfinite_number', 'non-finite JSON number is not accepted')
    return value

def strict_json_loads(raw: Any, *, max_bytes: int) -> Any:
    """Parse exactly one strict JSON value from bounded ``bytes``/``str``.

    Raises :class:`ProtocolError` with a stable ``reason_code`` for empty,
    oversized, non-UTF-8, duplicate-key, non-finite or truncated input.
    """
    if isinstance(raw, (bytes, bytearray)):
        data = bytes(raw)
        if len(data) > max_bytes:
            raise ProtocolError('oversize_payload', f'payload exceeds {max_bytes} bytes')
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ProtocolError('invalid_utf8', 'payload is not valid UTF-8') from exc
    elif isinstance(raw, str):
        text = raw
        if len(text.encode('utf-8')) > max_bytes:
            raise ProtocolError('oversize_payload', f'payload exceeds {max_bytes} bytes')
    else:
        raise ProtocolError('invalid_type', 'payload must be bytes or str')
    if not text.strip():
        raise ProtocolError('empty_payload', 'empty payload')
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant, parse_float=_finite_float)
    except ProtocolError:
        raise
    except RecursionError as exc:
        raise ProtocolError('too_deep', 'payload nesting exceeds the parser limit') from exc
    except ValueError as exc:
        raise ProtocolError('invalid_json', 'payload is not a single valid JSON value') from exc

def finite_number(value: Any, name: str, *, positive: bool=False) -> float:
    """Accept only finite real numbers; bool/NaN/Inf/str/None are refused."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)):
        raise ProtocolError('nonfinite_number', f'{name} must be a finite number')
    if positive and value <= 0:
        raise ProtocolError('nonfinite_number', f'{name} must be positive')
    return float(value)

def require_object(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError('bad_field', f'{name} must be an object')
    return value

def require_str(value: Any, name: str, *, max_len: int=256, allow_empty: bool=False) -> str:
    if not isinstance(value, str):
        raise ProtocolError('bad_field', f'{name} must be a string')
    if not allow_empty and (not value):
        raise ProtocolError('bad_field', f'{name} must be non-empty')
    if len(value) > max_len:
        raise ProtocolError('bad_field', f'{name} exceeds {max_len} characters')
    for ch in value:
        if ch < ' ' or ch == '\x7f':
            raise ProtocolError('bad_field', f'{name} must be printable')
    return value

def require_token(value: Any, name: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ProtocolError('bad_field', f'{name} must match {TOKEN_RE.pattern}')
    return value

def require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError('bad_field', f'{name} must be a boolean')
    return value

def require_generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProtocolError('bad_field', 'generation must be a positive integer')
    return int(value)

def require_container_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not CONTAINER_ID_RE.fullmatch(value):
        raise ProtocolError('bad_field', f'{name} must be a lowercase hex container id')
    return value

def encode_request(request: dict, *, max_bytes: int) -> bytes:
    """Serialize a request canonically and enforce the byte bound up front."""
    try:
        payload = json.dumps(request, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ProtocolError('request_not_serializable', str(exc)) from exc
    data = payload.encode('utf-8')
    if len(data) > max_bytes:
        raise ProtocolError('request_too_large', f'request exceeds {max_bytes} bytes')
    return data

def sanitize_stderr(raw: bytes, *, max_len: int=200) -> str:
    """Audit-only stderr excerpt: printable, bounded, never request contents."""
    text = raw.decode('utf-8', errors='replace')
    cleaned = ''.join((ch if ch >= ' ' and ch != '\x7f' else ' ' for ch in text))
    return ' '.join(cleaned.split())[:max_len]

def _validate_role_proof(reply: dict, *, expect_action: str) -> None:
    present = ROLE_PROOF_FIELDS.intersection(reply)
    if not present:
        return
    if expect_action != 'probe_ready' or 'role' not in reply or 'api_checked' not in reply:
        raise ProtocolError('bad_role_proof', 'role proof fields are only valid on probe_ready and require role/api_checked')
    role = reply['role']
    if role not in ('api_leader', 'worker'):
        raise ProtocolError('bad_role_proof', 'role must be api_leader|worker')
    api_checked = require_bool(reply['api_checked'], 'api_checked')
    healthy = reply.get('healthy')
    if healthy is not None:
        require_bool(healthy, 'healthy')
    if role == 'api_leader':
        if 'process_verified' in reply or 'worker_proof' in reply:
            raise ProtocolError('bad_role_proof', 'api_leader cannot carry worker proof fields')
        if healthy is True and (not api_checked):
            raise ProtocolError('bad_role_proof', 'healthy api_leader must have api_checked=true')
        return
    if api_checked or 'model_id' in reply:
        raise ProtocolError('bad_role_proof', 'worker cannot claim an API check or model ID')
    verified = require_bool(reply.get('process_verified'), 'process_verified')
    if healthy is True and (not verified):
        raise ProtocolError('bad_role_proof', 'healthy worker requires process_verified=true')
    if verified:
        proof = require_object(reply.get('worker_proof'), 'worker_proof')
        if set(proof) != {'container_id', 'image', 'gpu_process_pids'}:
            raise ProtocolError('bad_role_proof', 'worker_proof has unexpected or missing fields')
        container_id = require_container_id(proof.get('container_id'), 'worker_proof.container_id')
        if len(container_id) != 64:
            raise ProtocolError('bad_role_proof', 'worker_proof.container_id must be a full container ID')
        image = proof.get('image')
        if not isinstance(image, str) or not IMAGE_REFERENCE_RE.fullmatch(image):
            raise ProtocolError('bad_role_proof', 'worker_proof.image must be immutable')
        pids = proof.get('gpu_process_pids')
        if not isinstance(pids, list) or not pids or len(pids) > 128 or any((isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 for pid in pids)) or (len(set(pids)) != len(pids)):
            raise ProtocolError('bad_role_proof', 'worker_proof.gpu_process_pids must be unique positive integers')
        if healthy is not True:
            raise ProtocolError('bad_role_proof', 'process_verified worker proof requires healthy=true')
    elif 'worker_proof' in reply:
        raise ProtocolError('bad_role_proof', 'unverified worker cannot carry worker_proof')

def validate_reply(raw: Any, *, expect_action: str, expect_node: str, expect_request_id: str, identity: tuple[str, str, int] | None, max_bytes: int, sent_at: float, received_at: float, max_skew_seconds: float) -> dict:
    """Validate the reply envelope and return it, or raise :class:`ProtocolError`.

    A reply is only accepted when it names this exact exchange (schema,
    request_id, action, node), echoes the exact identity when the request
    carried one, reports a finite ``observed_at`` within the clock-skew window
    and, for a refusal, carries a non-empty ``reason_code``. Everything else is
    treated as unknown/unreachable by the caller (fail closed).
    """
    value = strict_json_loads(raw, max_bytes=max_bytes)
    reply = require_object(value, 'reply')
    if reply.get('schema') != SCHEMA:
        raise ProtocolError('schema_mismatch', 'reply schema is not dgx-v4-node-v1')
    if reply.get('request_id') != expect_request_id:
        raise ProtocolError('request_id_mismatch', 'reply does not echo the request_id')
    if reply.get('action') != expect_action:
        raise ProtocolError('action_mismatch', 'reply action does not match the request')
    if reply.get('node') != expect_node:
        raise ProtocolError('node_mismatch', 'reply node does not match the request')
    status = reply.get('status')
    if status not in REPLY_STATUSES:
        raise ProtocolError('bad_status', 'reply status must be ok|refused')
    if identity is not None:
        profile, owner, generation = identity
        if reply.get('profile') != profile:
            raise ProtocolError('identity_mismatch:profile', 'reply profile does not match')
        if reply.get('owner') != owner:
            raise ProtocolError('identity_mismatch:owner', 'reply owner does not match')
        if reply.get('generation') != generation or isinstance(reply.get('generation'), bool):
            raise ProtocolError('identity_mismatch:generation', 'reply generation does not match')
    observed = finite_number(reply.get('observed_at'), 'observed_at')
    if observed < sent_at - max_skew_seconds:
        raise ProtocolError('stale_observation', 'reply timestamp is behind the accepted clock window')
    if observed > received_at + max_skew_seconds:
        raise ProtocolError('stale_observation', 'reply timestamp is ahead of the accepted clock window')
    if status == 'refused':
        reason = reply.get('reason_code')
        if not isinstance(reason, str) or not reason or len(reason) > REASON_MAX:
            raise ProtocolError('missing_reason_code', 'a refusal must carry a bounded reason_code')
    _validate_role_proof(reply, expect_action=expect_action)
    return reply
