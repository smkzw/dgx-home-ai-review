# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Existing composition runner with one explicit sole factory, no new scheduler."""
from pathlib import Path
from deployment_integrations.composition import run_service, load_composition_config, prepare_composition
from .service_factory import create_service, load_g7_command_configs
from G8_INTEGRATION_RUNTIME_CANDIDATE_R2.runtime_config import load_candidate_config, validate_bindings
from G7_PROFILE_CANDIDATE_R1.deepseek_profile.front import make_server
from G7_INTEGRATION_CANDIDATE_R2.config import load as load_maintenance
from G7_INTEGRATION_CANDIDATE_R3.config import load as load_qualification
from G7_QUALIFICATION_VERIFICATION_R1.config import load as load_verification
CREATIVE_CONFIG = Path('/etc/dgx-v4/creative-runtime.json')

def factory_for(maintenance_config):

    def factory(config, *, maintenance_lease):
        return create_service(config, maintenance_lease=maintenance_lease, creative_config_path=CREATIVE_CONFIG, maintenance_config_path=Path(maintenance_config))
    return factory

def serve(config_path, maintenance_config, **kwargs):
    if 'service_factory' in kwargs or 'front_factory' in kwargs:
        raise ValueError('fixed_sole_factory_required')
    return run_service(config_path, service_factory=factory_for(maintenance_config), front_factory=make_server, **kwargs)

def check(config_path, maintenance_config):
    import json
    plan = prepare_composition(load_composition_config(config_path))
    creative = load_candidate_config(CREATIVE_CONFIG, state_root=plan.service.state_root)
    validate_bindings(creative, plan.service, plan.node_config, plan.core_profiles)
    surfaces, _, _, _ = load_g7_command_configs(maintenance_config)
    from .attach import CONFIG, validate_config, load
    trial = validate_config(load(CONFIG).value, plan.service.state_root)
    print(json.dumps({'ok': True, 'lifecycle_started': False, 'creative_enabled': creative['enabled'], 'creative_api_enabled': creative['api_enabled'], 'sole_factory': 'QV1-telemetryR3-G8-C-firsttrial', 'G7_command_surfaces': {k: v for k, v in surfaces.items() if k != 'schema'}, 'firsttrial_enabled': trial['enabled'], 'native_trial_started': False}))
    return 0

def main(argv=None):
    import argparse, json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--maintenance-config', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--serve', action='store_true')
    args = parser.parse_args(argv)
    try:
        return check(args.config, args.maintenance_config) if args.check else serve(args.config, args.maintenance_config)
    except Exception as error:
        print(json.dumps({'ok': False, 'reason_code': 'creative_composition_refused', 'error': type(error).__name__}))
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
