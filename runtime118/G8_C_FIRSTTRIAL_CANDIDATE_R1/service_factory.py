# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Sole factory copy; no construction on import and no second Manager."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import time
from hx_service.service import MaintenanceLease, ServiceConfig, ServiceConfigError, load_service_config, _trusted_config_file, _require_unambiguous_json_file, _validate_loaded_configs, load_gateway_config, load_node_config, control_config, read_private_json, TokenRegistry, upstream, ProfileBinding, LoopbackActiveWorkProbe, ManagerBackendFacade, open_gateway_store
from G7_QUALIFICATION_IMPLEMENTATION_R1.manager import QualificationManager as Manager
from G7_QUALIFICATION_IMPLEMENTATION_R1.store import open_store
from G7_QUALIFICATION_TELEMETRY_R3.runtime import TelemetryRuntime as ServiceRuntime
from G7_QUALIFICATION_TELEMETRY_R3.command import attach_to_runtime
from G7_INTEGRATION_CANDIDATE_R2.config import load as load_maintenance
from G7_INTEGRATION_CANDIDATE_R2.command import MaintenanceCommands
from G7_INTEGRATION_CANDIDATE_R3.config import load as load_qualification
from G7_QUALIFICATION_VERIFICATION_R1.config import load as load_verification
from G7_QUALIFICATION_VERIFICATION_R1.command import VerificationCommands
from G8_INTEGRATION_RUNTIME_CANDIDATE_R2.adapter import CreativeNodeAdapter as NodeAdapter
from .gateway import GatewayServer
from G8_INTEGRATION_RUNTIME_CANDIDATE_R2.runtime_config import load_candidate_config, validate_bindings
G7_SURFACES = Path('/etc/dgx-home-ai/g8-g7-command-surfaces.json')

def load_g7_command_configs(maintenance_config_path):
    """Only an explicit root-controlled all-false gate skips G7-only configs.

    C firsttrial keeps the exact QV1 Manager/Store/Telemetry classes. Missing or
    malformed surface config refuses startup. Enabling any surface validates all
    three original G7 config schemas; enabled commands keep their original guards.
    """
    from deployment_integrations.composition import _read_trusted_json
    surfaces = _read_trusted_json(G7_SURFACES, 'explicit G7 command surfaces')
    names = ('maintenance', 'qualification', 'verification')
    if type(surfaces) is not dict or set(surfaces) != {'schema', *names} or surfaces.get('schema') != 'g8-explicit-G7-command-surfaces/v1' or any((type(surfaces.get(name)) is not bool for name in names)):
        raise ServiceConfigError('explicit root G7 command surface gates required')
    if not any((surfaces[name] for name in names)):
        return (surfaces, None, None, None)
    maintenance = load_maintenance(maintenance_config_path)
    qualification = load_qualification()
    verification = load_verification()
    for name, config in zip(names, (maintenance, qualification, verification)):
        if surfaces[name] and config.get('enabled') is not True:
            raise ServiceConfigError('enabled G7 command surface requires its original enabled configuration')
    return (surfaces, maintenance, qualification, verification)

def create_service(config: ServiceConfig, *, maintenance_lease: MaintenanceLease, node_transport: Any | None=None, active_work_probe: Any | None=None, clock: Any=time.time, creative_config_path: Path | None=None, maintenance_config_path: Path) -> ServiceRuntime:
    """Construct the real stores, Manager, NodeAdapter, facade and loopback gateway.

    The maintenance lease must already be held. Optional transport/probe objects
    are dependency injection for local tests; the CLI supplies neither and no
    config file can name an executable plugin.
    """
    if not isinstance(maintenance_lease, MaintenanceLease) or not maintenance_lease.held:
        raise ServiceConfigError('the exact maintenance flock must be held before constructing services')
    if not isinstance(config, ServiceConfig):
        raise ServiceConfigError('service configuration must be loaded from an explicit trusted file')
    try:
        current_config = load_service_config(config.source_path)
    except Exception as exc:
        raise ServiceConfigError('service configuration source could not be revalidated') from exc
    if current_config != config:
        raise ServiceConfigError('service configuration differs from its explicit trusted source')
    config = current_config
    if config.enabled is not True:
        raise ServiceConfigError('disabled HX service configuration cannot construct a serving runtime')
    for path, label in ((config.profiles_file, 'profiles file'), (config.node_adapter_config, 'NodeAdapter configuration'), (config.gateway_config, 'gateway configuration')):
        _trusted_config_file(path, label)
        _require_unambiguous_json_file(path, label)
    try:
        gateway_config = load_gateway_config(config.gateway_config)
        node_config = load_node_config(config.node_adapter_config)
        core_profiles = control_config.read_profiles_json(config.profiles_file)
    except Exception as exc:
        raise ServiceConfigError('a trusted service configuration could not be loaded') from exc
    _validate_loaded_configs(config, gateway_config, node_config, core_profiles)
    creative_config = None if creative_config_path is None else load_candidate_config(creative_config_path, state_root=config.state_root)
    if creative_config is not None:
        validate_bindings(creative_config, config, node_config, core_profiles)
    surfaces, maintenance, qualification, verification = load_g7_command_configs(maintenance_config_path)
    registry_document = read_private_json(gateway_config.token_registry, label='token registry')
    _require_unambiguous_json_file(Path(gateway_config.token_registry), 'token registry')
    client_tokens = registry_document.get('tokens')
    if not isinstance(client_tokens, dict) or not client_tokens or any((not isinstance(token, str) or len(token) < 32 or token.startswith('REPLACE-') for token in client_tokens)):
        raise ServiceConfigError('gateway registry must contain strong client tokens')
    registry = TokenRegistry.load(gateway_config.token_registry)
    for backend in gateway_config.backends.values():
        upstream._load_auth_header(backend)
    attach_creative = None
    if creative_config is not None and (creative_config['enabled'] or creative_config['api_enabled']):
        from .integration import attach_creative
    if creative_config is not None and (creative_config['enabled'] or creative_config['api_enabled']):
        raise ServiceConfigError('C firsttrial requires ordinary creative serving disabled')
    adapter = NodeAdapter(node_config, transport=node_transport, clock=clock)
    if creative_config is not None:
        adapter.bind_comfy_plan(creative_config['node_plan'])
    adapter_caps = adapter.capabilities()
    if adapter_caps.get('available') is not True or adapter_caps.get('fixture_only') is not False:
        raise ServiceConfigError('NodeAdapter transport became unavailable during construction')
    bindings = {profile: ProfileBinding(nodes=tuple(core_profiles[profile]['nodes']), expected_model_id=gateway_config.backends[profile].expected_model_id, enabled=activation.enabled, active_work_path=activation.active_work_path) for profile, activation in config.profiles.items()}
    probe = active_work_probe if active_work_probe is not None else LoopbackActiveWorkProbe(gateway_config.backends, {profile: activation.active_work_path for profile, activation in config.profiles.items()}, timeout=gateway_config.connect_timeout_seconds)
    control_store = None
    gateway_store = None
    control_lock = None
    gateway_lock = None
    server = None
    try:
        control_store, control_lock = open_store(config.state_root / 'control', lock=True, profiles=core_profiles, clock=clock)
        manager = Manager(control_store, adapter=adapter, adapter_explicit=True, allow_fixture_ready=False, allow_test_holds=False)
        facade = ManagerBackendFacade(manager=manager, adapter=adapter, service_owner=config.service_owner, profiles=bindings, active_work_probe=probe, clock=clock)
        gateway_store, gateway_lock = open_gateway_store(gateway_config.state_root, lock=True, clock=clock)
        manager.reconcile()
        server = GatewayServer(config=gateway_config, registry=registry, store=gateway_store, facade=facade, probe_backend=upstream.probe_backend_models, clock=clock, creative_manager=manager)
        runtime = ServiceRuntime(manager=manager, adapter=adapter, facade=facade, control_store=control_store, gateway_store=gateway_store, server=server, _control_lock=control_lock, _gateway_lock=gateway_lock)
        server.maintenance = server.qualification = server.verification = None
        if surfaces['maintenance']:
            server.maintenance = MaintenanceCommands(runtime, maintenance_lease, maintenance, reload_config=lambda: load_maintenance(maintenance_config_path))
        if surfaces['qualification']:
            server.qualification = attach_to_runtime(runtime, maintenance_lease, qualification, reload_config=load_qualification)
        if surfaces['verification']:
            server.verification = VerificationCommands(runtime, maintenance_lease, verification, reload_config=load_verification)
        from .attach import attach
        runtime = attach(runtime, maintenance_lease)
        from B_OWNER_RECOVERY_R25_WIRING.wiring import attach_owner_recovery
        return attach_owner_recovery(runtime, maintenance_lease)
    except BaseException:
        if server is not None:
            try:
                server.httpd.server_close()
            except Exception:
                pass
        if gateway_store is not None:
            gateway_store.close()
        if gateway_lock is not None:
            gateway_lock.release()
        if control_store is not None:
            control_store.close()
        if control_lock is not None:
            control_lock.release()
        raise
