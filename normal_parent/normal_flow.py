# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Parent-only sequencing of already emitted R12 normal/C30 once phases.
No source/hardware admission, transport creation, Manager, retry or default run.
Caller must first accept final source bytes, fresh hardware and staged sources.
The supplied EpochOnce retains its original whole900; it is never reconstructed.
"""
import base64
import hashlib
import json

def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def marker(value, phase):
    need(type(value) is dict and value['worker_failed'] is False and (value['barrier'] == phase), 'actual_new_epoch_barrier_required')
    original = value['original']
    raw = base64.b64decode(original['raw_b64'], validate=True)
    need(sha(raw) == original['sha256'] and raw.endswith(b'\n') and (json.loads(raw) == value['value']), 'complete_barrier_original')
    return value['value']

def normal_c30_once(once, emitted, emission_module, observations, c_bundle):
    """Continue the one already staged normal epoch through its exact C30 gate.
    Phase failures propagate with durable EpochOnce originals; no resend/cleanup.
    Future new-stage1800 and cleanup90 never inherit this epoch transport.
    """
    pc = emission_module.checked_graph(emitted.graph)
    need(c_bundle['PC_root'] == emission_module.PC_ROOT and c_bundle['target_config_raw'] == emitted.graph['config'] and all((pc[n] == body for n, body in c_bundle['PC_files'].items())), 'same_frozen_C30_interface_bytes')
    publisher = c_bundle['publisher']
    need(publisher.APPROVED_RELEASE == emitted.graph['packet']['review_sha256'] and publisher.APPROVED_STAGE_PINS == c_bundle['stage_pins'], 'same_bound_C30_publisher')
    launched = once.actual('epoch-launch', emitted.epoch('launch'))
    need(launched['entry_rc'] == 0, 'actual_epoch_launch_returned_zero')
    before = emission_module.run_normal_phase(once, emitted, 'before-stop')
    after = emission_module.run_normal_phase(once, emitted, 'after-stop')
    prestage = marker(once.actual('C30-prestage-barrier', observations.barrier(emitted, 'C30-prestage'), timeout=180), 'C30-prestage')
    nonce = prestage['request_nonce']
    request = once.actual('C30-prestage-request', emitted.C30_PC('prestage-request', nonce))
    raw = request['request_raw_utf8'].encode()
    cplan = publisher.materialize_C(raw, c_bundle['stage_files'])
    prepared = once.actual('C30-Spark-prestage', emission_module.rootwrap(publisher.C_prestage_transport_command(cplan), 30), node='spark-c', timeout=35)
    once.actual('C30-prestage-ack', emitted.C30_PC('prestage-ack', nonce, prepared))
    current = marker(once.actual('C30-current-barrier', observations.barrier(emitted, 'C30-current'), timeout=180), 'C30-current')
    need(current['request_nonce'] == nonce, 'same_new_nonce_not_reprepared')
    verified = once.actual('C30-prepare', emitted.C30_PC('prepare', nonce))
    need(verified['request_raw_utf8'] == request['request_raw_utf8'], 'one_original_request_before_BEGIN')
    c_run = emission_module.rootwrap(publisher.C_run_transport_command(cplan, prepared), 25)
    once.actual('C30-BEGIN', emitted.C30_PC('begin', nonce))
    compact = once.actual('C30-Spark-single-run', c_run, node='spark-c', timeout=30)
    finished = once.actual('C30-finish-publish', emitted.C30_PC('finish-publish', nonce, compact))
    packed = once.actual('epoch-terminal-originals', observations.terminal(emitted), timeout=65)
    codec = emission_module.module(pc['service/receipt_codec.py'], 'same_terminal_codec', '<same-reviewed-codec>')
    terminal_raw = codec.unpack(packed)
    terminal = json.loads(terminal_raw)
    need(terminal['ready_for_single_finalize'] is True and terminal['qualifier_called'] is False and (terminal['owned_stop_calls'] == 0), 'actual_retained_terminal_before_single_finalize')
    finalized = once.actual('epoch-finalize-stop', emitted.epoch('finalize-stop'))
    need(finalized['entry_rc'] == 0, 'actual_finalize_returned_zero')
    return {'launch': launched, 'normal_before': before, 'normal_after': after, 'C30_nonce': nonce, 'C30_request_sha256': sha(raw), 'C30_finish': finished, 'terminal_raw_sha256': sha(terminal_raw), 'terminal': terminal, 'finalize': finalized, 'future_current_capture_or_activation_performed': False}
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_requires_final_source_fresh_hardware_and_once')
