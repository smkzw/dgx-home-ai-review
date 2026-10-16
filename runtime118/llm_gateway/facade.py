# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import math
from typing import Any, Protocol, runtime_checkable
from .errors import ValidationError
REQUIRED_FACADE_METHODS = ('ensure_ready', 'safe_drain_and_stop', 'get_generation', 'health')

@runtime_checkable
class BackendFacade(Protocol):

    def ensure_ready(self, *, profile: str, request_id: str) -> dict[str, Any]:
        ...

    def safe_drain_and_stop(self, *, profile: str, generation: int | None, reason: str) -> dict[str, Any]:
        ...

    def get_generation(self, *, profile: str) -> dict[str, Any]:
        ...

    def health(self, *, profile: str) -> dict[str, Any]:
        ...

def require_facade(facade: Any) -> Any:
    """Validate an injected facade exposes the full protocol before any use."""
    for method in REQUIRED_FACADE_METHODS:
        if not callable(getattr(facade, method, None)):
            raise ValidationError(f'facade lacks required method: {method}', code='invalid_facade', details={'missing': method, 'facade': type(facade).__name__})
    return facade

class NullBackendFacade:
    """Fail-closed default: no lifecycle integration, so nothing may run."""
    name = 'null'
    _REASON = 'no lifecycle facade configured; refusing (fail closed)'

    def ensure_ready(self, *, profile: str, request_id: str) -> dict[str, Any]:
        return {'available': False, 'ready': False, 'generation': None, 'model_id': None, 'reason_code': 'facade_unavailable', 'retry_after_seconds': None}

    def safe_drain_and_stop(self, *, profile: str, generation: int | None, reason: str) -> dict[str, Any]:
        return {'available': False, 'stopped': False, 'generation': None, 'reason_code': 'facade_unavailable'}

    def get_generation(self, *, profile: str) -> dict[str, Any]:
        return {'available': False, 'generation': None, 'ready': False, 'state': 'UNKNOWN', 'reason_code': 'facade_unavailable'}

    def health(self, *, profile: str) -> dict[str, Any]:
        return {'available': False, 'known': False, 'active_requests': None, 'ready': False, 'generation': None, 'model_id': None, 'reason_code': 'facade_unavailable'}

def _as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None

def _as_generation(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value

def _as_reason(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()[:128]
    return default

def _as_optional_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)) or (value < 0):
        return None
    return float(value)

def _malformed(reason: str='facade_reply_malformed') -> str:
    return reason

def validate_ensure_ready_reply(reply: Any) -> dict[str, Any]:
    if not isinstance(reply, dict):
        return _unavailable_ready(reason=_malformed())
    if _as_bool(reply.get('available')) is not True:
        return _unavailable_ready(reason=_as_reason(reply.get('reason_code'), 'facade_unavailable'))
    ready = _as_bool(reply.get('ready')) is True
    generation = _as_generation(reply.get('generation'))
    model_id = reply.get('model_id')
    if ready and (generation is None or not isinstance(model_id, str) or (not model_id.strip())):
        return _unavailable_ready(reason=_malformed('facade_ready_without_identity'), available=True)
    return {'available': True, 'ready': ready, 'generation': generation, 'model_id': model_id.strip() if isinstance(model_id, str) and model_id.strip() else None, 'reason_code': _as_reason(reply.get('reason_code'), 'ready' if ready else 'not_ready'), 'retry_after_seconds': _as_optional_seconds(reply.get('retry_after_seconds'))}

def _unavailable_ready(*, reason: str, available: bool=False) -> dict[str, Any]:
    return {'available': available, 'ready': False, 'generation': None, 'model_id': None, 'reason_code': reason, 'retry_after_seconds': None}

def validate_drain_reply(reply: Any, *, expected_generation: int | None) -> dict[str, Any]:
    if not isinstance(reply, dict):
        return {'available': False, 'stopped': False, 'generation': None, 'reason_code': _malformed()}
    available = _as_bool(reply.get('available')) is True
    stopped = _as_bool(reply.get('stopped')) is True
    generation = _as_generation(reply.get('generation'))
    reason = _as_reason(reply.get('reason_code'), 'drain_refused' if not stopped else 'drained')
    if not available:
        return {'available': False, 'stopped': False, 'generation': generation, 'reason_code': reason}
    if stopped and isinstance(expected_generation, int) and (generation != expected_generation):
        return {'available': True, 'stopped': False, 'generation': generation, 'reason_code': 'facade_drain_generation_mismatch'}
    return {'available': True, 'stopped': stopped, 'generation': generation, 'reason_code': reason}

def validate_generation_reply(reply: Any) -> dict[str, Any]:
    if not isinstance(reply, dict):
        return {'available': False, 'generation': None, 'ready': False, 'state': 'UNKNOWN', 'reason_code': _malformed()}
    available = _as_bool(reply.get('available'))
    if available is not True:
        return {'available': False, 'generation': None, 'ready': False, 'state': 'UNKNOWN', 'reason_code': _as_reason(reply.get('reason_code'), 'facade_unavailable') if available is False else _malformed()}
    ready = _as_bool(reply.get('ready'))
    generation = _as_generation(reply.get('generation'))
    state = reply.get('state')
    if ready is None or not isinstance(state, str) or (not state.strip()) or (ready and generation is None):
        return {'available': False, 'generation': None, 'ready': False, 'state': 'UNKNOWN', 'reason_code': _malformed()}
    return {'available': True, 'generation': generation, 'ready': ready, 'state': state.strip(), 'reason_code': _as_reason(reply.get('reason_code'), 'ok')}

def validate_health_reply(reply: Any) -> dict[str, Any]:
    if not isinstance(reply, dict) or _as_bool(reply.get('available')) is not True:
        return {'available': False, 'known': False, 'active_requests': None, 'ready': False, 'generation': None, 'model_id': None, 'reason_code': 'facade_unavailable'}
    active = reply.get('active_requests')
    if isinstance(active, bool) or not isinstance(active, int) or active < 0:
        active = None
    model_id = reply.get('model_id')
    return {'available': True, 'known': _as_bool(reply.get('known')) is True, 'active_requests': active, 'ready': _as_bool(reply.get('ready')) is True, 'generation': _as_generation(reply.get('generation')), 'model_id': model_id.strip() if isinstance(model_id, str) and model_id.strip() else None, 'reason_code': _as_reason(reply.get('reason_code'), 'ok')}
