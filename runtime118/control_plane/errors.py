# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit error taxonomy for the control-plane core.

Every refusal has a machine-readable code so clients cannot mistake a refusal
for success, and so "fail closed" is observable rather than implied.
"""
from __future__ import annotations

class ControlPlaneError(Exception):
    """Base class: every control-plane refusal carries a stable ``code``."""
    code = 'control_plane_error'
    http_status = 400

    def __init__(self, message: str, *, code: str | None=None, details: dict | None=None, http_status: int | None=None):
        super().__init__(message)
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = int(http_status)
        self.details = details or {}

    def as_dict(self) -> dict:
        return {'error': type(self).__name__, 'code': self.code, 'message': str(self), 'details': self.details}

class ValidationError(ControlPlaneError):
    code = 'invalid_request'

class UnauthorizedError(ControlPlaneError):
    code = 'unauthorized'
    http_status = 401

class ForbiddenError(ControlPlaneError):
    code = 'forbidden'
    http_status = 403

class NotFoundError(ControlPlaneError):
    code = 'not_found'
    http_status = 404

class ConflictError(ControlPlaneError):
    """Request key reused with a different payload digest."""
    code = 'idempotency_key_payload_mismatch'
    http_status = 409

class ProfileStateError(ControlPlaneError):
    code = 'profile_state_invalid'
    http_status = 409

class GenerationFenceError(ControlPlaneError):
    """A stop/release was attempted with a generation that is not the current one."""
    code = 'stale_generation'
    http_status = 409

class NodeConflictError(ControlPlaneError):
    code = 'node_conflict'
    http_status = 409

class HoldOwnershipError(ControlPlaneError):
    """Per-node hold ownership/generation assertion failed during release.

    A profile may only ever release holds that it owns, for the exact profile,
    owner and generation recorded on every one of its nodes.
    """
    code = 'hold_ownership_mismatch'
    http_status = 409

class StaleCompletionError(ControlPlaneError):
    """A completion (stop/failure) no longer owns the resource it would claim.

    Raised by the atomic hold-fenced transition when the profile was legitimately
    released — or handed to a newer owner/generation — while a slow adapter call
    was in flight. The caller must report a stale completion and leave the
    current state untouched instead of publishing a fabricated STOPPED/FAILED.
    """
    code = 'stale_completion'
    http_status = 409

class QuarantinedError(ControlPlaneError):
    code = 'node_quarantined_hold_retained'
    http_status = 409

class AdapterUnavailableError(ControlPlaneError):
    """No adapter is configured, or the configured adapter is not usable.

    Default refusal for model lifecycle operations. Never substituted by a mock.
    """
    code = 'adapter_unavailable'
    http_status = 503

class NotValidatedError(ControlPlaneError):
    """Profile is not hardware-validated or lacks node calibration (null == unknown)."""
    code = 'profile_not_validated'
    http_status = 409

class StaleMemorySampleError(ControlPlaneError):
    code = 'memory_samples_rejected'
    http_status = 409

class OwnerLockError(ControlPlaneError):
    code = 'owner_lock_held'
    http_status = 423

class CapabilityDisabledError(ControlPlaneError):
    code = 'capability_disabled'
    http_status = 503
