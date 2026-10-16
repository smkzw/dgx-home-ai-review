# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same original sole factory / manager / scheduler / physical lease callbacks."""
import os, sys, types, re
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, protected_read
from history_bootstrap import HistoricalNegative, historical
from current_epoch import consume, consume_installation as installation_consume
from terminal import consume_terminal, consume_entry_ready
from contract import PC_ROOT, OPERATION
import live_idle
from failed_terminal import consume as consume_failure
import safe_error
import segment_terminal
from B_OWNER_RECOVERY_R25_WIRING.common import exclusive, encode
validate_live_idle = live_idle.validate_live_idle
validate_stopped_idle = live_idle.validate_stopped_idle
collect_live_idle = live_idle.collect
APPROVED_SERVICE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_WHOLE_CLEAR_SHA = 'abbf8c1be3b4c1f0d1f6080b0346ba7e5df3e5da1f589287528309478cca9fef'

def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def whole_clear(p, c, now, *, fenced, baseline=None):
    return validate_live_idle(p, c, now, fenced=fenced, baseline=baseline)

def attach_history(runtime, lease, c, bridge):
    need(APPROVED_SERVICE_REVIEW is not None, 'new_registry_whole_factory_source_pending')
    helper = HistoricalNegative(runtime, lease, c, bridge)
    need(not hasattr(runtime, 'negative_cpu_release'), 'one_negative_ancestor_view')
    runtime.negative_cpu_release = helper
    return helper

def attach_grant(runtime, lease, c, operator, Grant):
    need(APPROVED_SERVICE_REVIEW is not None, 'new_registry_source_idleattach_pending')
    operator._asset_terminal = lambda stage, **kw: segment_terminal.consume(protected_read, c, identity(), stage, runtime.manager._now(), **kw)
    return Grant(runtime, lease, c, operator, negative=lambda: historical(runtime.manager._now()), current_epoch=lambda: consume(protected_read, c, identity(), runtime.manager._now()), entry_ready=lambda: consume_entry_ready(protected_read, c, identity(), runtime.manager._now()), whole_clear=whole_clear, terminal=lambda path, historical: consume_terminal(protected_read, path, c, identity(), runtime.manager._now(), historical=historical), failure_terminal=lambda historical=False: consume_failure(protected_read, c, identity(), runtime.manager._now(), historical=historical))

def current_negative(c, i, now):
    old = historical(now)
    consume(protected_read, c, i, now)
    return old
whole_clear.collect = collect_live_idle

def consume_installation(config, now):
    return installation_consume(protected_read, config, now)

def failure_reply(body, error):
    action = body.get('action')
    value = safe_error.original_safe_error(action, error)
    need(action in safe_error.READONLY, 'safe_registry_error_action')
    if not (set(body) <= set(('action', 'operation', 'request_nonce', 'duration_seconds', 'stage_operation')) and body.get('operation') == OPERATION and (type(body.get('request_nonce')) is str) and re.fullmatch('[0-9a-f]{32}', body['request_nonce'])):
        return value
    root = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d') / ('registry-rpc-failures-' + body['operation'])
    if not root.exists():
        root.mkdir(mode=448)
        os.chmod(root, 448)
    exclusive(root / (body['request_nonce'] + '.json'), {'schema': 'registry-R26-fixed-first-refusal/v1', 'request': body, 'response': value, 'automatic_retry': False})
    return value
