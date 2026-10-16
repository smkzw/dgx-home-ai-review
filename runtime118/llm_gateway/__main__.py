# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Operator surface for the gateway module.

Two modes, both deliberately small:

- ``--check``: load and strictly validate the parent configuration and the
  token registry, then print a redacted summary (no token values, no secrets).
- ``--serve``: refuse. The gateway always runs inside the single manager
  process with an injected, verified facade; a standalone CLI process cannot
  construct one and must not fake it.
"""
from __future__ import annotations
import argparse
import json
import sys
from typing import Any
from . import __version__, describe
from .config import config_summary, load_gateway_config
from .registry import TokenRegistry

def _check(config_path: str) -> tuple[int, dict[str, Any]]:
    config = load_gateway_config(config_path)
    registry = TokenRegistry.load(config.token_registry)
    return (0, {'module': describe(), 'config_path': config.source_path, 'config': config_summary(config), 'registry': {'loaded': True, 'tokens': len(registry), 'owners': registry.owners, 'permissions': registry.permissions_union}})

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(prog='llm_gateway', description=__doc__)
    parser.add_argument('--config', required=True, help='path to the gateway configuration JSON')
    parser.add_argument('--check', action='store_true', help='validate configuration and registry, print a summary')
    parser.add_argument('--serve', action='store_true', help='refused: the gateway runs in-process with the manager')
    parser.add_argument('--version', action='store_true')
    args = parser.parse_args(argv)
    if args.version:
        print(__version__)
        return 0
    if args.serve:
        print('refused: the gateway is started in-process by the single manager with an injected, verified BackendFacade; there is no standalone serve mode', file=sys.stderr)
        return 2
    try:
        code, payload = _check(args.config)
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'message': str(exc)}, ensure_ascii=False))
        return 2
    payload['ok'] = True
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return code
if __name__ == '__main__':
    raise SystemExit(main())
