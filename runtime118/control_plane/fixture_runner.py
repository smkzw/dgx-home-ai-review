# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixture-only workflow runner for durable job lifecycle testing.

This module does NOT generate images or video. It is the demonstration that the
durable job machinery actually drives *something* end to end, using a fixture
adapter that performs exactly two trivial, deterministic operations:

- ``noop``: returns the payload digest and size (no output artifact produced).
- ``echo``: writes the payload text to an isolated ``0700`` directory as a
  ``0600`` file and returns its sha256/size.

Anything else is refused with ``capability_disabled``. The loopback API never
dispatches: only ``cli.py runjobs`` (operator-driven, explicit adapter) calls
this, which is why no HTTP route pretends to execute workflows.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any
from .errors import CapabilityDisabledError, ProfileStateError, ValidationError
from .store import canonical_digest
FIXTURE_MARKER = 'fixture_runner'

class FixtureRunner:
    name = FIXTURE_MARKER

    def __init__(self, *, artifact_root: Path, payload_root: Path):
        self.artifact_root = Path(artifact_root)
        self.artifact_root.mkdir(parents=True, exist_ok=True, mode=448)
        os.chmod(self.artifact_root, 448)
        self.payload_root = Path(payload_root)

    def run(self, *, workflow_id: str, parameters: dict[str, Any], payload_path: Path | None) -> dict[str, Any]:
        if workflow_id not in {'noop', 'echo'}:
            raise CapabilityDisabledError(f'capability_disabled: fixture runner only implements noop/echo, not {workflow_id!r}', details={'workflow_id': workflow_id})
        text = parameters.get('text', '')
        if not isinstance(text, str) or len(text) > 64 * 1024:
            raise ValidationError("fixture 'text' must be a bounded string", code='invalid_request')
        if workflow_id == 'noop':
            return {'artifact': None, 'runner': self.name}
        stamp = f'{int(time.time() * 1000)}'
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        target = self.artifact_root / f'echo-{digest[:16]}-{stamp}.txt'
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
        return {'artifact': {'filename': target.name, 'sha256': digest, 'size': len(text.encode('utf-8')), 'path': str(target)}, 'runner': self.name, 'payload_digest': canonical_digest(parameters)}

def load_payload(store, job_id: str) -> tuple[dict[str, Any], str]:
    """Read the durable payload and re-verify it against the stored digest."""
    path = store.payload_path(job_id)
    if path is None or not path.is_file():
        raise ProfileStateError('reconcile_required: durable payload is missing; refusing to guess a body (NEEDS_RESUBMIT)', code='needs_resubmit', details={'job_id': job_id})
    payload = json.loads(path.read_text(encoding='utf-8'))
    digest = canonical_digest(payload)
    row = store.job_row(job_id)
    if digest != row['payload_digest']:
        raise ProfileStateError('payload_digest_mismatch: stored payload does not match the recorded digest', code='payload_digest_mismatch', details={'job_id': job_id})
    return (payload, digest)
