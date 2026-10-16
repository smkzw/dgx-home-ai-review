# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root late receiver and UID999 reader of actual nonce-bound C original."""
import os, time, types, math
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, encode, protected_read
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30')
RECEIVED = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30/current-C-received.json')
APPROVED_SOURCE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_C_TYPED_CONSUMER = '3ffbd640d76972a3920e49108a423fd70dfc025ec189bb1230c77034c3b93cdf'

def module():
    need(APPROVED_SOURCE_REVIEW is not None and APPROVED_C_TYPED_CONSUMER is not None, 'fixed_current_C_receiver_pending')
    raw, _ = protected_read(ROOT / 'C_typed_consumer.py', limit=2097152)
    need(sha(raw) == APPROVED_C_TYPED_CONSUMER, 'strict_complete_C_consumer_SHA')
    m = types.ModuleType('held_R5_C_typed')
    m.__file__ = str(ROOT / 'C_typed_consumer.py')
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m

def augment_config(config):
    raw, _ = protected_read('/etc/dgx-home-ai/node-adapter.json')
    need(sha(raw) == config['PC_source_pins']['/etc/dgx-home-ai/node-adapter.json'], 'actual_configured_clock_source')
    value = strict(raw).get('max_clock_skew_seconds', 30.0)
    need(type(value) in (int, float) and math.isfinite(value) and (0 <= value <= 30), 'actual_clock_skew_bound')
    return dict(config, max_clock_skew_seconds=value)

def consume(read, config, now):
    m = module()
    raw, st = read(RECEIVED, limit=4194304)
    v = strict(raw)
    need(v['schema'] == 'R26-current-C-start-received/v1' and v['source_review_sha256'] == APPROVED_SOURCE_REVIEW and (v['config_sha256'] == config['_config_sha256']), 'current_R5_C_receiver_not_old_proof')
    clockraw, clockstat = read(ROOT / 'current-C-clock/received.json')
    clock = strict(clockraw)
    sendraw, sendstat = read(ROOT / 'current-C-clock/send.json')
    need(v['clock_sha256'] == sha(clockraw) and v['clock_stat'] == clockstat and (sha(sendraw) == clock['original_send_sha256']) and (sendstat == clock['original_send_stat']) and (clock['source_review_sha256'] == APPROVED_SOURCE_REVIEW) and (v['request_nonce'] == clock['nonce']), 'actual_PC_original_clock_and_nonce_not_recreated')
    result = m.consume(read, clock, augment_config(config), now)
    need(v['C_receipt_sha256'] == result['receipt_sha256'] and v['C_receipt_stat'] == result['receipt_stat'], 'same_current_C_scope_original_F9')
    return {'schema': 'R26-current-C-start-consumed/v1', 'request_nonce': clock['nonce'], 'clock_sha256': sha(clockraw), 'clock_stat': clockstat, 'C_receipt_sha256': result['receipt_sha256'], 'C_receipt_stat': result['receipt_stat'], 'current_C': result, 'source_review_sha256': APPROVED_SOURCE_REVIEW, 'config_sha256': config['_config_sha256'], 'ARM_accepted': False}

def publish(config, C_receipt_raw, io):
    need(os.getuid() == os.geteuid() == 0 and (not RECEIVED.exists()) and (not RECEIVED.is_symlink()), 'Root_late_current_C_once')
    m = module()
    clockraw, clockstat = protected_read(ROOT / 'current-C-clock/received.json')
    clock = strict(clockraw)
    need(len(C_receipt_raw) <= 4194304, 'C_receipt_fixed4MiB')
    io.fresh(m.RECEIPT, C_receipt_raw, mode=288, gid=989)
    result = m.consume(protected_read, clock, augment_config(config), time.time())
    value = {'schema': 'R26-current-C-start-received/v1', 'source_review_sha256': APPROVED_SOURCE_REVIEW, 'request_nonce': clock['nonce'], 'config_sha256': config['_config_sha256'], 'clock_sha256': sha(clockraw), 'clock_stat': clockstat, 'C_receipt_sha256': result['receipt_sha256'], 'C_receipt_stat': result['receipt_stat'], 'ARM_accepted': False}
    io.fresh(RECEIVED, encode(value), mode=288, gid=989)
    return consume(protected_read, config, time.time())
