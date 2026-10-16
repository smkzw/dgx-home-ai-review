# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Completed R3 proof stays in its old source domain, never current authority."""
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, protected_read, sha, strict, encode
from history_namespace import Namespace
APPROVED_NEW_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_POLICY = None

def consume_released(config, read=protected_read):
    p = APPROVED_POLICY
    need(APPROVED_NEW_REVIEW is not None and type(p) is dict and (set(p) == {'schema', 'Root', 'source', 'order', 'helpers', 'config_sha256', 'review_sha256', 'source118', 'result_sha256'}) and (p['schema'] == 'fixed-R3-completed-ffc2-history/v1') and (config['review_sha256'] == APPROVED_NEW_REVIEW) and (len(config['PC_source_pins']) == 118), 'ffc2_history_new_source_binding_pending')
    root = Path(p['Root'])
    need(str(root) == '/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3' and len(p['source']) == 116 and (len(p['source118']) == 118) and (len(p['order']) == len(set(p['order']))) and (set(p['order']) == set(p['helpers'])), 'ffc2_history_fixed_old_Root_and_complete_source_order')
    held = {}
    for name, ref in p['source'].items():
        raw, f9 = read(root / name, limit=2097152)
        need(sha(raw) == ref['sha256'] and f9 == ref['F9'], 'ffc2_history_all_old_Root116_raw_F9')
        held[name] = (raw, f9)
    packet = strict(held['epoch-packet.json'][0])
    cfg_raw = packet['new_config_raw_utf8'].encode()
    old = strict(cfg_raw)
    need(sha(cfg_raw) == p['config_sha256'] and old['review_sha256'] == p['review_sha256'] and (old['PC_source_pins'] == p['source118']) and (old['review_sha256'] != APPROVED_NEW_REVIEW), 'ffc2_history_exact_old_config_not_new_authority')
    old['_config_sha256'] = sha(cfg_raw)
    namespace = Namespace(str(root / 'service'), p['helpers'])
    modules = {}
    for name in p['order']:
        raw, f9 = held['service/' + name]
        need(sha(raw) == p['helpers'][name] and f9[3:7] == [0, 989, 33056, 1], 'ffc2_history_exact_old_helper_order')
        modules[name] = namespace.load(name, raw, str(root / 'service' / name))
    result = modules['prestart_history.py'].consume_released(old, read)
    need(type(result) is dict and result['historical_only'] is True and (result['work_may_resume'] is False) and (result['state'] == 'FAILED_STAGE_NOT_LAUNCHED_QUIESCENT') and (sha(encode(result)) == p['result_sha256']), 'ffc2_history_complete_old_event_result_not_refreshed')
    for name, pair in held.items():
        need(read(root / name, limit=2097152) == pair, 'ffc2_history_old_Root116_stable_after_consume')
    return result
