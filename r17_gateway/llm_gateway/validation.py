# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict request-body validation for the transparent OpenAI relay.

Two rules shape this module:

1. **Never rewrite the payload.** The caller's bytes are validated and then
   forwarded unchanged, so supported OpenAI fields and reasoning/tool content
   survive byte-for-byte. A field that is not in the model's *explicitly
   declared* capabilities is refused with ``unsupported_field`` — never silently
   stripped.
2. **Never let the body steer the machine.** Lifecycle, endpoint, environment,
   ownership and priority keys are refused outside explicit JSON Schema data
   slots. Schema property names are model data, not machine instructions.
"""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
import math
import re
from typing import Any
from .errors import ModelNotFoundError, PayloadTooLargeError, UnsupportedFieldError, ValidationError
FORBIDDEN_BODY_KEYS: frozenset[str] = frozenset({'endpoint', 'endpoint_url', 'base_url', 'url', 'uri', 'path', 'file', 'file_path', 'env', 'environment', 'environ', 'owner', 'owner_id', 'priority', 'profile', 'profile_name', 'generation', 'node', 'nodes', 'host', 'hostname', 'ssh', 'command', 'cmd', 'shell', 'script', 'docker', 'container', 'systemd', 'lifecycle', 'manager', 'unload', 'restart', 'sudo', 'api_key', 'apikey', 'secret', 'password', 'token_file', 'weights', 'model_path', 'hardware_validated', 'min_start_available_gib'})
MAX_JSON_DEPTH = 128
MAX_INLINE_IMAGE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_INLINE_IMAGE_BYTES = 20 * 1024 * 1024
INLINE_IMAGE_PREFIXES = ('data:image/png;base64,', 'data:image/jpeg;base64,', 'data:image/webp;base64,')
INLINE_BASE64_RE = re.compile('[A-Za-z0-9+/]*={0,2}')
ID_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_-]{0,127}')
IDEMPOTENCY_KEY_RE = re.compile('[A-Za-z0-9_-]{8,128}')

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValidationError('duplicate JSON key in request body', code='duplicate_json_key', details={'key': key})
        seen.add(key)
    return dict(pairs)

def _reject_nonfinite(name: str) -> Any:
    """JSON must be finite: NaN/Infinity are not JSON and are refused outright."""
    raise ValidationError('request body contains a non-finite JSON number', code='nonfinite_json', details={'literal': name})

def _parse_finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise ValidationError('request body contains a non-finite JSON number', code='nonfinite_json')
    return value

def _check_depth(value: Any, *, depth: int=0) -> None:
    if isinstance(value, float) and (not math.isfinite(value)):
        raise ValidationError('request body contains a non-finite JSON number', code='nonfinite_json')
    if depth > MAX_JSON_DEPTH:
        raise ValidationError('request body nesting is too deep', code='json_too_deep')
    if isinstance(value, dict):
        for key, item in value.items():
            _check_depth(key, depth=depth + 1)
            _check_depth(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_depth(item, depth=depth + 1)

def parse_json_object(raw: bytes, *, max_bytes: int) -> dict[str, Any]:
    """Parse a bounded, finite, duplicate-free JSON object from request bytes."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ValidationError('request body must be bytes', code='invalid_body')
    if len(raw) > max_bytes:
        raise PayloadTooLargeError('request body exceeds the configured limit', details={'max_body_bytes': max_bytes, 'observed_bytes': len(raw)})
    try:
        text = bytes(raw).decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValidationError('request body must be UTF-8 JSON', code='invalid_json') from exc
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_nonfinite, parse_float=_parse_finite_float)
    except ValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise ValidationError('request body must be a JSON object', code='invalid_json') from exc
    if not isinstance(value, dict):
        raise ValidationError('request body must be a JSON object', code='invalid_json')
    _check_depth(value)
    return value

def find_forbidden_key(value: Any, *, prefix: str='') -> str | None:
    """Return the JSON path of the first forbidden key, or ``None``."""
    return _find_forbidden_key(value, prefix=prefix, image_urls=frozenset())

def _schema_data_paths(body: dict[str, Any]) -> frozenset[tuple[str | int, ...]]:
    """Identify only standard schema data slots by actual tree structure.

    A schema's business field names have no gateway transport/lifecycle meaning.
    Tuple paths cannot be forged by dots or brackets in a JSON key, and cannot
    exempt the same dict if a direct Python caller also places it elsewhere.
    This identifies schema slots; schema semantics remain the backend's job.
    """
    paths: set[tuple[str | int, ...]] = set()
    tools = body.get('tools')
    if isinstance(tools, list):
        for index, definition in enumerate(tools):
            if not isinstance(definition, dict) or definition.get('type') != 'function':
                continue
            function = definition.get('function')
            if isinstance(function, dict) and isinstance(function.get('parameters'), dict):
                paths.add(('tools', index, 'function', 'parameters'))
    functions = body.get('functions')
    if isinstance(functions, list):
        for index, function in enumerate(functions):
            if isinstance(function, dict) and isinstance(function.get('parameters'), dict):
                paths.add(('functions', index, 'parameters'))
    response_format = body.get('response_format')
    if isinstance(response_format, dict) and response_format.get('type') == 'json_schema':
        schema = response_format.get('json_schema')
        if isinstance(schema, dict) and isinstance(schema.get('schema'), dict):
            paths.add(('response_format', 'json_schema', 'schema'))
    return frozenset(paths)

def _find_forbidden_key(value: Any, *, prefix: str, image_urls: frozenset[int], schema_paths: frozenset[tuple[str | int, ...]]=frozenset(), tree_path: tuple[str | int, ...]=()) -> str | None:
    if tree_path in schema_paths:
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            path = f'{prefix}.{key}' if prefix else str(key)
            if isinstance(key, str) and key.lower() in FORBIDDEN_BODY_KEYS:
                if not (key == 'url' and id(value) in image_urls):
                    return path
            found = _find_forbidden_key(item, prefix=path, image_urls=image_urls, schema_paths=schema_paths, tree_path=(*tree_path, key))
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _find_forbidden_key(item, prefix=f'{prefix}[{index}]', image_urls=image_urls, schema_paths=schema_paths, tree_path=(*tree_path, index))
            if found is not None:
                return found
    return None

def _validate_inline_images(body: dict[str, Any]) -> frozenset[int]:
    """Whitelist only validated URL slots in actual standard image parts.

    Object identity is local to the parsed tree; a key spelling that resembles
    a JSON path cannot obtain this exception. No caller bytes are changed.
    """
    slots: set[int] = set()
    total_bytes = 0
    messages = body.get('messages')
    if not isinstance(messages, list):
        return frozenset()
    for message_index, message in enumerate(messages):
        if not isinstance(message, dict) or not isinstance(message.get('content'), list):
            continue
        for part_index, part in enumerate(message['content']):
            if not isinstance(part, dict) or part.get('type') != 'image_url':
                continue
            field = f'messages[{message_index}].content[{part_index}].image_url'

            def refuse() -> None:
                raise ValidationError('image input must be a bounded inline PNG, JPEG or WEBP data URL', code='invalid_inline_image', details={'field': field})
            image = part.get('image_url')
            if message.get('role') != 'user' or set(part) != {'type', 'image_url'} or (not isinstance(image, dict)) or (set(image) not in ({'url'}, {'url', 'detail'})) or ('detail' in image and image['detail'] not in ('auto', 'low', 'high')):
                refuse()
            url = image.get('url')
            if not isinstance(url, str):
                refuse()
            header = next((p for p in INLINE_IMAGE_PREFIXES if url.startswith(p)), None)
            if header is None:
                refuse()
            encoded_length = len(url) - len(header)
            if not 0 < encoded_length <= 4 * ((MAX_INLINE_IMAGE_BYTES + 2) // 3):
                refuse()
            encoded = url[len(header):]
            if len(encoded) % 4 or not INLINE_BASE64_RE.fullmatch(encoded):
                refuse()
            padding = 2 if encoded.endswith('==') else int(encoded.endswith('='))
            decoded_size = len(encoded) // 4 * 3 - padding
            if not 0 < decoded_size <= min(MAX_INLINE_IMAGE_BYTES, MAX_TOTAL_INLINE_IMAGE_BYTES - total_bytes):
                refuse()
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                refuse()
            if not decoded or len(decoded) > MAX_INLINE_IMAGE_BYTES or base64.b64encode(decoded).decode('ascii') != encoded:
                refuse()
            total_bytes += len(decoded)
            if total_bytes > MAX_TOTAL_INLINE_IMAGE_BYTES:
                refuse()
            slots.add(id(image))
    return frozenset(slots)

def canonical_digest(value: Any) -> str:
    """Stable digest of a parsed JSON payload (sorted keys, compact separators).

    Two semantically identical bodies with different key order hash the same, so
    a retry that reformats its JSON still matches its idempotency key. Whitespace
    inside string values is part of the value and therefore part of the digest.
    """
    _check_depth(value)
    blob = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()

def validate_chat_body(body: dict[str, Any], *, capabilities: Any) -> str:
    """Validate a chat body against declared per-model capabilities.

    Returns the requested model alias. Raises before anything can be forwarded:
    the caller never sees a silently-repaired payload.
    """
    from .config import CAPABILITY_KEYS
    alias = body.get('model')
    if not isinstance(alias, str) or not alias.strip():
        raise ValidationError('model is required and must be a non-empty string', code='invalid_model')
    alias = alias.strip()
    if not ID_RE.fullmatch(alias):
        raise ModelNotFoundError(f'unknown model {alias!r}', details={'model': alias})
    image_urls = _validate_inline_images(body)
    forbidden = _find_forbidden_key(body, prefix='', image_urls=image_urls, schema_paths=_schema_data_paths(body))
    if forbidden is not None:
        raise ValidationError('request body may not contain lifecycle/endpoint/ownership fields', code='forbidden_field', details={'field': forbidden})
    caps = capabilities
    missing = [key for key in CAPABILITY_KEYS if key not in caps]
    if missing:
        raise ValidationError('model capability declaration is incomplete in gateway configuration', code='invalid_capabilities', details={'missing': sorted(missing)}, http_status=503)
    if body.get('stream') is True and (not caps['stream']):
        raise UnsupportedFieldError("stream is not in this model's declared capabilities", details={'field': 'stream'})
    if 'parallel_tool_calls' in body:
        parallel_tool_calls = body['parallel_tool_calls']
        if not isinstance(parallel_tool_calls, bool):
            raise ValidationError('parallel_tool_calls must be a boolean', code='invalid_parallel_tool_calls', details={'field': 'parallel_tool_calls'})
        if parallel_tool_calls and (not caps['parallel_tool_calls']):
            raise UnsupportedFieldError("parallel_tool_calls is not in this model's declared capabilities", details={'field': 'parallel_tool_calls'})
    if any((field in body for field in ('tools', 'functions', 'tool_choice', 'function_call'))):
        field = next((f for f in ('tools', 'functions', 'tool_choice', 'function_call') if f in body))
        if not caps['tools']:
            raise UnsupportedFieldError(f"{field} is not in this model's declared capabilities; the field is refused, not stripped", details={'field': field})
        for field in ('tools', 'functions'):
            definitions = body.get(field)
            if not isinstance(definitions, list):
                continue
            for index, definition in enumerate(definitions):
                if not isinstance(definition, dict):
                    continue
                if definition.get('strict') is True:
                    raise UnsupportedFieldError('strict tool schemas are not qualified on the installed engines', details={'field': f'{field}[{index}].strict'})
                function = definition.get('function')
                if isinstance(function, dict) and function.get('strict') is True:
                    raise UnsupportedFieldError('strict tool schemas are not qualified on the installed engines', details={'field': f'{field}[{index}].function.strict'})
    response_format = body.get('response_format')
    if response_format is not None:
        if not caps['response_format']:
            raise UnsupportedFieldError("response_format is not in this model's declared capabilities; refused, not stripped", details={'field': 'response_format'})
        if not isinstance(response_format, dict):
            raise ValidationError('response_format must be a JSON object', code='invalid_response_format')
        rtype = response_format.get('type')
        if rtype not in {'text', 'json_object', 'json_schema'}:
            raise ValidationError('response_format.type must be text|json_object|json_schema', code='invalid_response_format', details={'type': rtype})
        if rtype == 'json_schema' and (not caps['response_format_json_schema']):
            raise UnsupportedFieldError("json_schema response_format is not in this model's declared capabilities", details={'field': 'response_format.type'})
        if response_format.get('strict') is True and (not caps['response_format_strict']):
            raise UnsupportedFieldError("strict structured output is not in this model's declared capabilities", details={'field': 'response_format.strict'})
        schema = response_format.get('json_schema')
        if isinstance(schema, dict) and schema.get('strict') is True and (not caps['response_format_strict']):
            raise UnsupportedFieldError("strict structured output is not in this model's declared capabilities", details={'field': 'response_format.json_schema.strict'})
    return alias

def validate_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    if not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise ValidationError('Idempotency-Key must be 8-128 characters of A-Z a-z 0-9 _ -', code='invalid_idempotency_key')
    return value

def validate_session_id(value: str | None, *, header: str) -> str | None:
    if value is None:
        return None
    if not ID_RE.fullmatch(value):
        raise ValidationError(f'{header} must be an opaque identifier', code='invalid_session_id')
    return value
