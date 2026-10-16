# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Gateway error taxonomy: every refusal carries a stable machine-readable code.

The gateway never invents a model answer. When a request cannot be served the
caller gets a JSON error document in OpenAI's error shape::

    {"error": {"message": ..., "type": ..., "code": ...}, "request_id": "req_..."}

``code`` is stable for machine handling; ``details`` (when present) carries the
bounded reason fields (profile alias, cause, wait window). 429/503 refusals also
carry an integer ``Retry-After`` header on the wire.
"""
from __future__ import annotations
from typing import Any

class GatewayError(Exception):
    """Base class. ``http_status`` and ``code`` are part of the wire contract."""
    code = 'gateway_error'
    http_status = 400
    error_type = 'invalid_request_error'

    def __init__(self, message: str, *, code: str | None=None, details: dict[str, Any] | None=None, http_status: int | None=None, error_type: str | None=None, retry_after_seconds: float | None=None):
        super().__init__(message)
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = int(http_status)
        if error_type is not None:
            self.error_type = error_type
        self.details = dict(details or {})
        self.retry_after_seconds = retry_after_seconds
        self.request_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {'message': str(self), 'type': self.error_type, 'code': self.code}
        if self.details:
            error['details'] = self.details
        payload: dict[str, Any] = {'error': error}
        if self.request_id:
            payload['request_id'] = self.request_id
        return payload

class UnauthorizedError(GatewayError):
    code = 'unauthorized'
    http_status = 401
    error_type = 'authentication_error'

class ForbiddenError(GatewayError):
    code = 'forbidden'
    http_status = 403
    error_type = 'permission_error'

class NotFoundError(GatewayError):
    code = 'not_found'
    http_status = 404
    error_type = 'invalid_request_error'

class ModelNotFoundError(GatewayError):
    code = 'model_not_found'
    http_status = 404
    error_type = 'invalid_request_error'

class ConflictError(GatewayError):
    code = 'conflict'
    http_status = 409
    error_type = 'conflict_error'

class ValidationError(GatewayError):
    code = 'invalid_request'
    http_status = 400
    error_type = 'invalid_request_error'

class UnsupportedFieldError(GatewayError):
    """A field was declared but is not in this model's declared capabilities.

    Refused, never stripped: silently dropping ``tools``/``response_format``
    would let a caller believe a structured contract was honored when it was
    not.
    """
    code = 'unsupported_field'
    http_status = 400
    error_type = 'invalid_request_error'

class PayloadTooLargeError(GatewayError):
    code = 'payload_too_large'
    http_status = 413
    error_type = 'invalid_request_error'

class QueueTimeoutError(GatewayError):
    """The bounded synchronous wait elapsed before the request could run."""
    code = 'sync_wait_timeout'
    http_status = 429
    error_type = 'rate_limit_error'

class ServiceUnavailableError(GatewayError):
    code = 'service_unavailable'
    http_status = 503
    error_type = 'server_error'

class FacadeDisabledError(GatewayError):
    """No usable lifecycle facade: the gateway refuses instead of faking."""
    code = 'facade_disabled'
    http_status = 503
    error_type = 'server_error'

class BackendUnavailableError(GatewayError):
    code = 'backend_unavailable'
    http_status = 503
    error_type = 'server_error'

class BackendRedirectRefusedError(GatewayError):
    """The pinned backend answered with a redirect; the gateway never follows it.

    The backend is a fixed loopback engine: a redirect (or a hostile Location)
    can only mean the pinned endpoint is wrong or something is injecting a
    response, so the relay refuses and closes instead of leaking elsewhere.
    """
    code = 'backend_redirect_refused'
    http_status = 502
    error_type = 'server_error'

class BackendProtocolError(GatewayError):
    code = 'backend_protocol_error'
    http_status = 502
    error_type = 'server_error'

class CapabilityDisabledError(GatewayError):
    code = 'capability_disabled'
    http_status = 503
    error_type = 'server_error'

class InternalError(GatewayError):
    code = 'internal_error'
    http_status = 500
    error_type = 'server_error'
