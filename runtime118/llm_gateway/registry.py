# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Secure token registry: stable owner/permission identity for gateway callers.

The parent manager writes the registry file (``0600``, regular file, owned by
the serving user); this module only reads it. Token values never leave this
module: they are not stored in gateway state, not returned by the API, not put
in argv and never logged. ``owner`` and ``permissions`` are derived from the
token that authenticated, never from client input.

Registry document shape (strict, unknown keys refused)::

    {
      "tokens": {
        "<token>": {"owner": "<opaque>", "permissions": ["chat", "models", "sessions"]}
      }
    }
"""
from __future__ import annotations
import contextlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from .errors import ForbiddenError, UnauthorizedError, ValidationError
TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_-]{0,127}')
KNOWN_PERMISSIONS = ('chat', 'models', 'sessions')
_ENTRY_KEYS = {'owner', 'permissions'}

def read_private_json(path: Path | str, *, label: str) -> dict[str, Any]:
    """Read a 0600-or-stricter regular JSON file owned by the current user.

    Opens with ``O_NOFOLLOW`` and validates the *opened descriptor*, so a
    symlink swapped in later cannot redirect the read.
    """
    target = Path(path).expanduser()
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError as exc:
        raise ValidationError(f'{label} not found', code='invalid_registry_file') from exc
    except OSError as exc:
        raise ValidationError(f'{label} must be a regular file that is not a symlink', code='invalid_registry_file') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f'{label} must be a regular file', code='invalid_registry_file')
        if info.st_uid != os.geteuid():
            raise ValidationError(f'{label} must be owned by the current user', code='invalid_registry_file')
        if info.st_mode & 63:
            raise ValidationError(f'{label} must have permissions 0600 or stricter', code='invalid_registry_file')
        with os.fdopen(os.dup(fd), 'r', encoding='utf-8') as handle:
            text = handle.read()
    finally:
        os.close(fd)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError(f'{label} is not valid JSON', code='invalid_registry_file') from exc
    if not isinstance(value, dict):
        raise ValidationError(f'{label} must contain a JSON object', code='invalid_registry_file')
    return value

class Identity:
    __slots__ = ('name', 'permissions')

    def __init__(self, name: str, permissions: frozenset[str]):
        self.name = name
        self.permissions = permissions

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise ForbiddenError(f'permission_denied: this token may not use {permission}', code='permission_denied', details={'permission': permission})

    def __repr__(self) -> str:
        return f'Identity(name={self.name!r}, permissions={sorted(self.permissions)!r})'

class TokenRegistry:
    """Immutable token -> (owner, permissions) map loaded from a 0600 file."""

    def __init__(self, entries: list[tuple[str, Identity]]):
        self._entries = tuple(entries)

    @classmethod
    def load(cls, path: Path | str) -> 'TokenRegistry':
        document = read_private_json(path, label='token registry')
        unknown = sorted(set(document) - {'tokens'})
        if unknown:
            raise ValidationError('token registry has unknown top-level fields', code='invalid_registry', details={'unknown_fields': unknown})
        tokens = document.get('tokens')
        if not isinstance(tokens, dict) or not tokens:
            raise ValidationError('token registry must contain a non-empty tokens object', code='invalid_registry')
        entries: list[tuple[str, Identity]] = []
        seen: set[str] = set()
        for token, entry in tokens.items():
            if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
                raise ValidationError('token registry contains an invalid token value', code='invalid_registry')
            if token in seen:
                raise ValidationError('token registry contains a duplicate token', code='invalid_registry')
            seen.add(token)
            if not isinstance(entry, dict):
                raise ValidationError('token registry entries must be objects', code='invalid_registry')
            extra = sorted(set(entry) - _ENTRY_KEYS)
            if extra:
                raise ValidationError('token registry entry has unknown fields', code='invalid_registry', details={'unknown_fields': extra})
            owner = entry.get('owner')
            if not isinstance(owner, str) or not TOKEN_RE.fullmatch(owner):
                raise ValidationError('token registry owner must be an opaque identifier', code='invalid_registry')
            permissions = entry.get('permissions')
            if not isinstance(permissions, list) or not permissions or any((not isinstance(p, str) or p not in KNOWN_PERMISSIONS for p in permissions)) or (len(set(permissions)) != len(permissions)):
                raise ValidationError(f'token registry permissions must be a non-empty unique subset of {list(KNOWN_PERMISSIONS)}', code='invalid_registry')
            entries.append((token, Identity(owner, frozenset(permissions))))
        return cls(entries)

    def identify(self, authorization: str | None) -> Identity:
        """Constant-time token match. Missing/unknown tokens are 401."""
        if not authorization or not authorization.startswith('Bearer '):
            raise UnauthorizedError('missing bearer token')
        presented = authorization[len('Bearer '):].strip()
        for token, identity in self._entries:
            if hmac.compare_digest(presented, token):
                return identity
        raise UnauthorizedError('unknown token')

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def owners(self) -> list[str]:
        return sorted({identity.name for _, identity in self._entries})

    @property
    def permissions_union(self) -> list[str]:
        """Union of granted permissions (no token values involved)."""
        granted: set[str] = set()
        for _, identity in self._entries:
            granted.update(identity.permissions)
        return sorted(granted)

    def __repr__(self) -> str:
        with contextlib.suppress(Exception):
            return f'TokenRegistry(entries={len(self._entries)})'
        return 'TokenRegistry()'
