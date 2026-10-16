# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Run the single HX manager/gateway process after acquiring its physical lease."""
from __future__ import annotations
import argparse
import json
from .service import MAINTENANCE_LOCK_PATH, MaintenanceLease, MaintenanceLeaseError, MaintenanceLockBusy, ServiceConfigError, create_service, load_service_config

def _check(config_path: str) -> int:
    config = load_service_config(config_path)
    print(json.dumps({'ok': True, 'enabled': config.enabled, 'profiles': {name: item.enabled for name, item in config.profiles.items()}, 'lifecycle_started': False}, sort_keys=True))
    return 0

def run_service(config_path: str, *, maintenance_lock_path=MAINTENANCE_LOCK_PATH) -> int:
    """Refuse the obsolete standalone serving path before any side effects.

    The fixed native bootstrap uses deployment_integrations.composition, whose
    shutdown path retains ownership while handlers or scheduler workers remain.
    """
    print(json.dumps({'ok': False, 'reason_code': 'legacy_service_entrypoint_disabled', 'lifecycle_started': False, 'required_entrypoint': 'deployment_integrations.composition'}, sort_keys=True))
    return 126

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(prog='hx_service', description=__doc__)
    parser.add_argument('--config', required=True, help='trusted HX service JSON')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='parse only; no lock, service, RPC or lifecycle')
    mode.add_argument('--serve', action='store_true', help='hold the maintenance flock for process lifetime')
    args = parser.parse_args(argv)
    try:
        if args.check:
            return _check(args.config)
        return run_service(args.config)
    except ServiceConfigError as exc:
        print(json.dumps({'ok': False, 'reason_code': 'service_config_refused', 'error': type(exc).__name__}))
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
