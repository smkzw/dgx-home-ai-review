# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict, finite, fail-closed configuration for the LLM gateway.

Everything the gateway may do is fixed here by the parent: model alias ->
profile mapping, pinned loopback backend endpoints (loopback SSH tunnels only),
per-model declared capabilities, and the numeric queue policy. Nothing in a
request body can add an endpoint, a path, an owner, a priority or a lifecycle
command — those concepts are refused at validation time.

Rules:

- Unknown keys are refused at every level (no silent feature smuggling).
- Non-loopback backends or bind hosts are refused.
- Fabrication keys (``hardware_validated``, ``min_start_available_gib``,
  ``runtime_floor_gib``) are refused outright: the gateway never marks a profile
  validated and never invents calibration.
- Policy numbers must be finite and inside safe bounds; the shipped
  ``config/scheduler-policy.json`` values are the defaults.
- ``enabled`` defaults to ``False``: until the parent supplies a trusted config
  and a verified facade, nothing is served.
"""
from __future__ import annotations
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from .errors import ValidationError
PROFILE_NAME = re.compile('[a-z0-9][a-z0-9._-]{0,63}')
NODE_NAME = re.compile('[a-z0-9][a-z0-9._-]{0,63}')
ALIAS_RE = re.compile('[A-Za-z0-9][A-Za-z0-9._-]{0,95}')
LOOPBACK_HOSTS = frozenset({'127.0.0.1', '::1', 'localhost'})
CAPABILITY_KEYS = ('stream', 'tools', 'response_format', 'response_format_json_schema', 'response_format_strict', 'parallel_tool_calls')
FABRICATION_KEYS = frozenset({'hardware_validated', 'min_start_available_gib', 'runtime_floor_gib'})
_TOP_KEYS = {'_comment', 'version', 'enabled', 'server', 'state_root', 'token_registry', 'backends', 'models', 'policy', 'limits', 'timeouts'}
_SERVER_KEYS = {'host', 'port'}
_BACKEND_KEYS = {'nodes', 'base_url', 'chat_path', 'models_path', 'health_path', 'expected_model_id', 'auth_token_file'}
_MODEL_KEYS = {'profile', 'capabilities'}
_LIMIT_KEYS = {'max_body_bytes', 'max_response_bytes'}
_TIMEOUT_KEYS = {'connect_seconds', 'read_seconds'}
_POLICY_BOUNDS: dict[str, tuple[float, float, float]] = {'conflict_grace_seconds': (120.0, 0.0, 3600.0), 'lease_ttl_seconds': (300.0, 0.05, 86400.0), 'max_contested_lease_protection_seconds': (600.0, 0.0, 86400.0), 'min_residency_seconds': (300.0, 0.0, 86400.0), 'keep_warm_without_conflict_seconds': (900.0, 0.0, 604800.0), 'sync_queue_wait_seconds': (420.0, 1.0, 420.0), 'max_initial_jobs_running_per_profile': (1.0, 1.0, 8.0), 'ensure_poll_seconds': (2.0, 0.05, 60.0), 'maintenance_interval_seconds': (0.25, 0.05, 5.0), 'backend_health_ttl_seconds': (5.0, 0.0, 600.0), 'reconcile_interval_seconds': (5.0, 0.05, 600.0)}
_INT_POLICY_KEYS = {'max_initial_jobs_running_per_profile'}

def _require_dict(value: Any, *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f'{where} must be a JSON object', code='invalid_config')
    return value

def _reject_unknown(value: dict[str, Any], allowed: set[str], *, where: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValidationError(f'{where} has unknown fields', code='invalid_config', details={'where': where, 'unknown_fields': unknown, 'allowed_fields': sorted(allowed)})

def _require_str(value: Any, *, where: str, allow_empty: bool=False) -> str:
    if not isinstance(value, str) or (not allow_empty and (not value.strip())):
        raise ValidationError(f'{where} must be a non-empty string', code='invalid_config')
    return value.strip() if not allow_empty else value

def _finite(value: Any, *, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)):
        raise ValidationError(f'{where} must be a finite number', code='invalid_config')
    return float(value)

def _scan_for_fabrication(value: Any, *, where: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key in FABRICATION_KEYS:
                raise ValidationError('fabricated_calibration_refused: configuration may not declare hardware validation or memory calibration; those belong to the reviewed manager', code='fabricated_calibration_refused', details={'where': where, 'field': key})
            _scan_for_fabrication(item, where=where)
    elif isinstance(value, list):
        for item in value:
            _scan_for_fabrication(item, where=where)

def _loopback_endpoint(base_url: Any, *, where: str) -> tuple[str, int, str]:
    raw = _require_str(base_url, where=where)
    parts = urlsplit(raw)
    if parts.scheme != 'http':
        raise ValidationError(f'{where} must be a plain http:// loopback endpoint (SSH tunnel); https belongs to the parent edge', code='non_loopback_endpoint_refused')
    if parts.username or parts.password:
        raise ValidationError(f'{where} must not carry credentials', code='non_loopback_endpoint_refused')
    if parts.hostname not in LOOPBACK_HOSTS:
        raise ValidationError(f'{where} must be a loopback endpoint (127.0.0.1, ::1 or localhost), got {parts.hostname!r}', code='non_loopback_endpoint_refused')
    if parts.path not in ('', '/') or parts.query or parts.fragment:
        raise ValidationError(f'{where} must be an origin only (host:port), not a path/query/fragment', code='non_loopback_endpoint_refused')
    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f'{where} has an invalid port', code='invalid_config') from exc
    if port is None or not 1 <= int(port) <= 65535:
        raise ValidationError(f'{where} must include an explicit valid port', code='invalid_config')
    return (parts.hostname or '', int(port), raw)

def _fixed_path(value: Any, *, where: str, allow_empty: bool=False) -> str:
    text = _require_str(value, where=where, allow_empty=allow_empty)
    if text == '' and allow_empty:
        return ''
    if not text.startswith('/') or '://' in text or '?' in text or ('#' in text):
        raise ValidationError(f'{where} must be a fixed absolute path without query/fragment', code='invalid_config')
    return text

@dataclass(frozen=True)
class BackendConfig:
    profile: str
    nodes: tuple[str, ...]
    base_url: str
    host: str
    port: int
    chat_path: str
    models_path: str
    health_path: str
    expected_model_id: str
    auth_token_file: str | None

@dataclass(frozen=True)
class ModelConfig:
    alias: str
    profile: str
    capabilities: dict[str, bool]

@dataclass(frozen=True)
class PolicyConfig:
    conflict_grace_seconds: float
    lease_ttl_seconds: float
    max_contested_lease_protection_seconds: float
    min_residency_seconds: float
    keep_warm_without_conflict_seconds: float
    sync_queue_wait_seconds: float
    max_initial_jobs_running_per_profile: int
    ensure_poll_seconds: float
    maintenance_interval_seconds: float
    backend_health_ttl_seconds: float
    reconcile_interval_seconds: float

@dataclass(frozen=True)
class GatewayConfig:
    source_path: str
    config_dir: str
    enabled: bool
    host: str
    port: int
    state_root: str
    token_registry: str
    max_body_bytes: int
    max_response_bytes: int
    connect_timeout_seconds: float
    read_timeout_seconds: float
    backends: dict[str, BackendConfig] = field(default_factory=dict)
    models: dict[str, ModelConfig] = field(default_factory=dict)
    policy: PolicyConfig = None

    def conflict_map(self) -> dict[str, frozenset[str]]:
        """Profiles conflict when their *actual* node sets intersect.

        This is computed from the node lists the parent pinned, so e.g. a
        two-node AB profile vs. a C profile is conflict-free while two AB
        profiles collide — exactly as the runbook requires.
        """
        names = sorted(self.backends)
        out: dict[str, frozenset[str]] = {}
        for name in names:
            nodes = set(self.backends[name].nodes)
            out[name] = frozenset((other for other in names if other != name and nodes & set(self.backends[other].nodes)))
        return out

    def profiles_for_alias(self, alias: str) -> str | None:
        model = self.models.get(alias)
        return model.profile if model else None

def load_gateway_config(path: Path | str) -> GatewayConfig:
    source = Path(path).expanduser()
    try:
        document = json.loads(source.read_text(encoding='utf-8'))
    except FileNotFoundError as exc:
        raise ValidationError('gateway configuration file not found', code='invalid_config') from exc
    except json.JSONDecodeError as exc:
        raise ValidationError('gateway configuration is not valid JSON', code='invalid_config') from exc
    document = _require_dict(document, where='configuration')
    _reject_unknown(document, _TOP_KEYS, where='configuration')
    _scan_for_fabrication(document, where='configuration')
    comment = document.get('_comment')
    if comment is not None and (not isinstance(comment, str)):
        raise ValidationError('_comment must be a string', code='invalid_config')
    version = document.get('version', 1)
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ValidationError('configuration version must be 1', code='invalid_config')
    enabled = document.get('enabled', False)
    if not isinstance(enabled, bool):
        raise ValidationError('enabled must be a boolean', code='invalid_config')
    server = _require_dict(document.get('server', {}), where='server')
    _reject_unknown(server, _SERVER_KEYS, where='server')
    host = server.get('host', '127.0.0.1')
    if not isinstance(host, str) or host not in LOOPBACK_HOSTS:
        raise ValidationError('server.host must be a loopback address in this core; remote exposure belongs to the reviewed edge', code='non_loopback_bind_refused')
    port = server.get('port', 0)
    if isinstance(port, bool) or not isinstance(port, int) or (not 0 <= port <= 65535):
        raise ValidationError('server.port must be an integer in [0, 65535]', code='invalid_config')
    state_root_raw = _require_str(document.get('state_root'), where='state_root')
    registry_raw = _require_str(document.get('token_registry'), where='token_registry')
    config_dir = source.resolve().parent

    def _resolve(value: str) -> str:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = config_dir / candidate
        return str(candidate)
    limits = _require_dict(document.get('limits', {}), where='limits')
    _reject_unknown(limits, _LIMIT_KEYS, where='limits')
    max_body_bytes = _int_bounded(limits.get('max_body_bytes', 4 * 1024 * 1024), where='limits.max_body_bytes', low=1024, high=64 * 1024 * 1024)
    max_response_bytes = _int_bounded(limits.get('max_response_bytes', 64 * 1024 * 1024), where='limits.max_response_bytes', low=1024, high=1024 * 1024 * 1024)
    timeouts = _require_dict(document.get('timeouts', {}), where='timeouts')
    _reject_unknown(timeouts, _TIMEOUT_KEYS, where='timeouts')
    connect_timeout = _bounded_float(timeouts.get('connect_seconds', 5.0), where='timeouts.connect_seconds', low=0.05, high=300.0)
    read_timeout = _bounded_float(timeouts.get('read_seconds', 300.0), where='timeouts.read_seconds', low=0.05, high=86400.0)
    backends_raw = _require_dict(document.get('backends'), where='backends')
    if not backends_raw:
        raise ValidationError('configuration must pin at least one backend', code='invalid_config')
    backends: dict[str, BackendConfig] = {}
    for profile, raw_backend in backends_raw.items():
        if not isinstance(profile, str) or not PROFILE_NAME.fullmatch(profile):
            raise ValidationError(f'invalid profile name {profile!r}', code='invalid_config')
        backend = _require_dict(raw_backend, where=f'backends.{profile}')
        _reject_unknown(backend, _BACKEND_KEYS, where=f'backends.{profile}')
        nodes_raw = backend.get('nodes')
        if not isinstance(nodes_raw, list) or not nodes_raw or any((not isinstance(node, str) or not NODE_NAME.fullmatch(node) for node in nodes_raw)) or (len(set(nodes_raw)) != len(nodes_raw)):
            raise ValidationError(f'backends.{profile}.nodes must be unique node identifiers', code='invalid_config')
        host_name, port_num, base_url = _loopback_endpoint(backend.get('base_url'), where=f'backends.{profile}.base_url')
        chat_path = _fixed_path(backend.get('chat_path', '/v1/chat/completions'), where=f'backends.{profile}.chat_path')
        models_path = _fixed_path(backend.get('models_path', '/v1/models'), where=f'backends.{profile}.models_path')
        health_path = _fixed_path(backend.get('health_path', '/v1/models'), where=f'backends.{profile}.health_path')
        expected_model_id = _require_str(backend.get('expected_model_id'), where=f'backends.{profile}.expected_model_id')
        auth_token_file = backend.get('auth_token_file')
        if auth_token_file is not None:
            auth_token_file = _require_str(auth_token_file, where=f'backends.{profile}.auth_token_file')
            auth_token_file = _resolve(auth_token_file)
        backends[profile] = BackendConfig(profile=profile, nodes=tuple(nodes_raw), base_url=base_url, host=host_name, port=port_num, chat_path=chat_path, models_path=models_path, health_path=health_path, expected_model_id=expected_model_id, auth_token_file=auth_token_file)
    models_raw = _require_dict(document.get('models'), where='models')
    if not models_raw:
        raise ValidationError('configuration must declare at least one model alias', code='invalid_config')
    models: dict[str, ModelConfig] = {}
    for alias, raw_model in models_raw.items():
        if not isinstance(alias, str) or not ALIAS_RE.fullmatch(alias):
            raise ValidationError(f'invalid model alias {alias!r}', code='invalid_config')
        model = _require_dict(raw_model, where=f'models.{alias}')
        _reject_unknown(model, _MODEL_KEYS, where=f'models.{alias}')
        profile = _require_str(model.get('profile'), where=f'models.{alias}.profile')
        if profile not in backends:
            raise ValidationError(f'models.{alias}.profile must reference a pinned backend', code='invalid_config', details={'profile': profile, 'known': sorted(backends)})
        caps_raw = _require_dict(model.get('capabilities'), where=f'models.{alias}.capabilities')
        _reject_unknown(caps_raw, set(CAPABILITY_KEYS), where=f'models.{alias}.capabilities')
        capabilities: dict[str, bool] = {}
        for key in CAPABILITY_KEYS:
            if key not in caps_raw:
                raise ValidationError('model capabilities must be declared explicitly (stream/tools/response_format/…)', code='invalid_config', details={'alias': alias, 'missing': key})
            if not isinstance(caps_raw[key], bool):
                raise ValidationError(f'models.{alias}.capabilities.{key} must be a boolean', code='invalid_config')
            capabilities[key] = caps_raw[key]
        models[alias] = ModelConfig(alias=alias, profile=profile, capabilities=capabilities)
    policy_raw = _require_dict(document.get('policy', {}), where='policy')
    policy = _build_policy(policy_raw)
    return GatewayConfig(source_path=str(source), config_dir=str(config_dir), enabled=enabled, host=host, port=int(port), state_root=_resolve(state_root_raw), token_registry=_resolve(registry_raw), max_body_bytes=max_body_bytes, max_response_bytes=max_response_bytes, connect_timeout_seconds=connect_timeout, read_timeout_seconds=read_timeout, backends=backends, models=models, policy=policy)

def _int_bounded(value: Any, *, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (not low <= value <= high):
        raise ValidationError(f'{where} must be an integer in [{low}, {high}]', code='invalid_config', details={'where': where})
    return int(value)

def _bounded_float(value: Any, *, where: str, low: float, high: float) -> float:
    number = _finite(value, where=where)
    if not low <= number <= high:
        raise ValidationError(f'{where} must be within [{low}, {high}]', code='invalid_policy', details={'where': where, 'value': number})
    return number

def _build_policy(raw: dict[str, Any]) -> PolicyConfig:
    _reject_unknown(raw, set(_POLICY_BOUNDS), where='policy')
    values: dict[str, float] = {}
    for key, (default, low, high) in _POLICY_BOUNDS.items():
        values[key] = _bounded_float(raw.get(key, default), where=f'policy.{key}', low=low, high=high)
    max_active = values['max_initial_jobs_running_per_profile']
    if max_active != int(max_active):
        raise ValidationError('policy.max_initial_jobs_running_per_profile must be a whole number', code='invalid_policy')
    return PolicyConfig(conflict_grace_seconds=values['conflict_grace_seconds'], lease_ttl_seconds=values['lease_ttl_seconds'], max_contested_lease_protection_seconds=values['max_contested_lease_protection_seconds'], min_residency_seconds=values['min_residency_seconds'], keep_warm_without_conflict_seconds=values['keep_warm_without_conflict_seconds'], sync_queue_wait_seconds=values['sync_queue_wait_seconds'], max_initial_jobs_running_per_profile=int(max_active), ensure_poll_seconds=values['ensure_poll_seconds'], maintenance_interval_seconds=values['maintenance_interval_seconds'], backend_health_ttl_seconds=values['backend_health_ttl_seconds'], reconcile_interval_seconds=values['reconcile_interval_seconds'])

def config_summary(config: GatewayConfig) -> dict[str, Any]:
    """Redacted summary for status output: no tokens, no auth token paths."""
    return {'enabled': config.enabled, 'server': {'host': config.host, 'port': config.port}, 'models': sorted(config.models), 'profiles': sorted(config.backends), 'policy': {'conflict_grace_seconds': config.policy.conflict_grace_seconds, 'lease_ttl_seconds': config.policy.lease_ttl_seconds, 'max_contested_lease_protection_seconds': config.policy.max_contested_lease_protection_seconds, 'min_residency_seconds': config.policy.min_residency_seconds, 'keep_warm_without_conflict_seconds': config.policy.keep_warm_without_conflict_seconds, 'sync_queue_wait_seconds': config.policy.sync_queue_wait_seconds, 'max_initial_jobs_running_per_profile': config.policy.max_initial_jobs_running_per_profile}}
