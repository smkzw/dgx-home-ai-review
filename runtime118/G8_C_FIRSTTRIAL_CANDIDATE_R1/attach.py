# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Instance-only extension: preserves exact frozen TelemetryRuntime identity."""
from pathlib import Path
from G7_QUALIFICATION_TELEMETRY_R3.runtime import TelemetryRuntime
from .controller import Controller
from .permit import cc, load
CONFIG = Path('/etc/dgx-home-ai/g8-c-firsttrial-config.json')

def validate_config(c, state_root):
    cc.need(set(c) == {'schema', 'enabled', 'parent_accepted', 'run_root'} and c['schema'] == 'g8-c-firsttrial-config/v1' and (type(c['enabled']) is bool) and (type(c['parent_accepted']) is bool), 'exact_root_C_route_config')
    if c['enabled']:
        cc.need(c['parent_accepted'] is True and c['run_root'] == str(Path(state_root) / 'g8-c-firsttrial'), 'fixed_private_C_ledger_root')
    return c

def attach(runtime, lease):
    cc.need(type(runtime) is TelemetryRuntime, 'same_frozen_TelemetryRuntime_type')
    c = validate_config(load(CONFIG).value, runtime.control_store.root.parent)
    if c['enabled'] is False:
        return runtime
    cc.need(c['parent_accepted'] is True and c['run_root'] == str(runtime.control_store.root.parent / 'g8-c-firsttrial'), 'fixed_private_C_ledger_root')
    cc.need(not hasattr(runtime, 'c_firsttrial'), 'one_C_controller_only')
    controller = Controller(runtime, lease, c['run_root'])
    runtime.c_firsttrial = controller
    runtime.server.c_firsttrial = controller
    old_close = runtime.close

    def close():
        controller.close()
        return old_close()
    runtime.close = close
    return runtime
