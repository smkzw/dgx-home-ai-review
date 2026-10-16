# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One exact completed R12 family, consumed in its original source domain.

This grants no work, clears no fence, and mutates no legacy file or used list.
The new Runtime supplies only its actual held-lease check. Old qualification,
zero-release and stage-terminal algorithms run in the original private namespace
at their recorded events with the old exact config, never the new config.
"""
import base64, types, sys
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read, metadata
from history_namespace import Namespace
APPROVED_POLICY = None
APPROVED_NEW_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'

def _leaf(read, path, expected):
    raw, f = read(Path(path), limit=2097152)
    need(sha(raw) == expected['sha256'] and f == expected['F9'], 'R13_retired_original_exact_fullraw_F9')
    return (raw, f)

def consume(g, read=protected_read):
    p = APPROVED_POLICY
    need(type(p) is dict and APPROVED_NEW_REVIEW is not None and (p['schema'] == 'R13-exact-retired-R12-family-history/v1') and (g.config['review_sha256'] == APPROVED_NEW_REVIEW) and (p['old_review'] != APPROVED_NEW_REVIEW) and (len(g.config['PC_source_pins']) == 118), 'R13_retired_family_SOURCE_pending')
    root = Path(p['old_root'])
    need(str(root) == '/opt/dgx-v4/hx/mimo-registry-native-r26-asset-protocol-r12' and len(p['source']) == 127 and (set(p['helpers']) == set(p['order'])) and (len(p['order']) == len(set(p['order'])) == 66), 'R13_exact_retired_source_order_not_new_source')
    held = {n: _leaf(read, root / n, v) for n, v in p['source'].items()}
    packet = strict(held['epoch-packet.json'][0])
    raw = packet['new_config_raw_utf8'].encode()
    cfg = strict(raw)
    need(sha(raw) == p['old_config_sha256'] and cfg['review_sha256'] == p['old_review'] and (packet['newmap'] == cfg['PC_source_pins']) and (packet['operation'] == p['old_family']), 'R13_retired_exact_oldcfg_no_rebase')
    cfg['_config_sha256'] = sha(raw)
    namespace = Namespace(str(root / 'service'), p['helpers'])
    modules = {}
    original_import = namespace.importer

    def original_namespace_import(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name == 'sys' and ((globals or {}).get('__file__') in (str(root / 'service/history_namespace.py'), str(root / 'pc/r11-gate/gate_loader.py'))):
            return sys
        return original_import(name, globals, locals, fromlist, level)
    namespace.builtins['__import__'] = original_namespace_import
    for name in p['order']:
        body, f = held['service/' + name]
        need(sha(body) == p['helpers'][name] and f[3:7] == [0, 989, 33056, 1], 'R13_retired_complete_original_helper_source')
        modules[name] = namespace.load(name, body, str(root / 'service' / name))
    zero_root = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d') / ('zero-launch-' + p['old_family']) / 'd8d0f06cc54a807f320d03813daf3b4b'
    activation = zero_root.parent.parent / ('asset-source-activation-' + p['old_family']) / p['old_identity']['invocation_id']

    def service_rows(folder, expected):
        before = {n: metadata((folder / n).lstat()) for n in expected}
        rows = modules['asset_stage.py'].stage_originals(folder.parent, folder.name)
        after = {n: metadata((folder / n).lstat()) for n in expected}
        need(set(rows) == set(expected) and before == after == {n: v['F9'] for n, v in expected.items()} and all((sha(rows[n]) == v['sha256'] for n, v in expected.items())), 'R13_retired_service_held_fullraw_F9')
        return rows
    private = {}
    for folder in (zero_root, activation):
        expected = {Path(k).name: v for k, v in p['service7'].items() if Path(k).parent == folder}
        rows = service_rows(folder, expected)
        private.update({str(folder / n): raw for n, raw in rows.items()})
    actor_rows = service_rows(Path(p['old_state_root']) / p['failed_stage'], p['actor_files'])
    z = {n: strict(private[str(zero_root / n)]) for n in ('intent.json', 'terminal.json', 'completed.json', 'fence-released.json')}
    a = {n: strict(private[str(activation / n)]) for n in ('intent.json', 'completed.json', 'fence-released.json')}
    need(a['intent.json']['schema'] == 'asset-source-zero-launch-activation-intent/v1' and a['completed.json']['schema'] == 'asset-source-zero-launch-activation-completed/v1' and (a['intent.json']['operation'] == a['completed.json']['operation'] == p['old_family']) and (a['intent.json']['current_identity'] == a['completed.json']['current_identity'] == p['old_identity']) and (a['completed.json']['state'] == 'SOURCE_EPOCH_READY') and (a['completed.json']['source118'] == cfg['PC_source_pins']) and (a['completed.json']['zero_completed_sha256'] == sha(private[str(zero_root / 'completed.json')])) and (a['intent.json']['zero_intent_sha256'] == sha(private[str(zero_root / 'intent.json')])) and (a['fence-released.json']['completed_sha256'] == sha(private[str(activation / 'completed.json')])) and (a['fence-released.json']['operator_maintenance_observed'] is False) and (a['intent.json']['observed_at'] <= a['completed.json']['observed_at'] <= a['fence-released.json']['observed_at']), 'R13_complete_original_R12_activation_and_zero_causal_chain')
    event = a['completed.json']['observed_at']

    def old_current():
        result = modules['current_epoch.py'].consume(read, cfg, p['old_identity'], event)
        need(result['historical_only'] is True and result['source_qualified_sha256'] == p['source_qualification_sha256'], 'R13_retired_original_current_qualification_full_consumer')
        return result

    def same():
        g.same()
        need(sha(packet['new_config_raw_utf8'].encode()) == p['old_config_sha256'], 'R13_retired_immutable_private_context')
    old = types.SimpleNamespace(config=cfg, s=g.s, runtime=g.runtime, same=same, current_epoch=old_current)

    def terminal(stage, *, historical=False):
        need(historical is True and stage == p['failed_stage'], 'R13_retired_only_fixed_completed_failed_stage')
        completed = strict(actor_rows['completed.json'])
        return modules['segment_terminal.py'].consume(read, cfg, p['old_identity'], stage, completed['finished_at'], historical=True)
    need(sorted((x.name for x in Path(p['old_state_root']).iterdir())) == [p['failed_stage']], 'R13_no_unknown_retired_actor_siblings')
    stage = modules['asset_stage.py'].Stages(old, terminal, read=read, root=Path(p['old_state_root']))
    need(stage.active is None and stage.closed is False and (stage.legacy_pending is False) and (stage.zero_pending is None) and (stage.used == p['ranges']), 'R13_retired_failed_interval_preserved_in_original_family')
    files = modules['asset_stage.py'].stage_originals(Path(p['old_state_root']), p['failed_stage'])
    need(set(files) == set(p['actor_files']) and all((sha(files[n]) == v['sha256'] for n, v in p['actor_files'].items())), 'R13_retired_all_eight_actor_originals_not_summary')
    need(service_rows(Path(p['old_state_root']) / p['failed_stage'], p['actor_files']) == files, 'R13_retired_actor_fullF9_after_constructor')
    value = strict(files['completed.json'])
    need(value['state'] == 'FAILED_REGISTRY_QUIESCENT' and value['image_imported'] is False, 'R13_retired_failure_not_success_or_accepted_bytes')
    zero = modules['zero_recovery.py'].completed_history(stage)
    need(zero == z['completed.json'] and zero['GET'] == 0 and (zero['protected_ranges'] == []), 'R13_retired_zero_release_complete_not_released_again')
    old_current()
    same()
    for name, pair in held.items():
        need(read(root / name, limit=2097152) == pair, 'R13_retired_Root127_after_complete_consumption')
    for folder in (zero_root, activation):
        expected = {Path(k).name: v for k, v in p['service7'].items() if Path(k).parent == folder}
        need(all((raw == private[str(folder / n)] for n, raw in service_rows(folder, expected).items())), 'R13_retired_service7_after_complete_consume')
    return {'schema': 'R13-retired-R12-family-history-consumed/v1', 'family': p['old_family'], 'state': 'FAILED_REGISTRY_QUIESCENT', 'failed_stage': p['failed_stage'], 'old_used_ranges_preserved': p['ranges'], 'completed_sha256': sha(files['completed.json']), 'zero_completed_sha256': sha(private[str(zero_root / 'completed.json')]), 'activation_completed_sha256': sha(private[str(activation / 'completed.json')]), 'historical_only': True, 'work_may_resume': False, 'accepted_bytes': 0, 'new_current_permission': False, 'old_failure_preserved': True}
