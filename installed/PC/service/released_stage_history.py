# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact accepted R9 release, immutable history rather than a new release permit.
All original source and completion bytes are read by their actual SHA/fullF9.
The old helper graph is loaded temporarily and its installation consumer runs;
module state is restored before any new current-source gate is evaluated.
"""
import base64, sys, types
from pathlib import Path
from history_namespace import Namespace
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, need, sha, strict
APPROVED_POLICY = None

def consume(now):
    p = APPROVED_POLICY
    need(type(p) is dict and p['schema'] == 'R10-immutable-R9-stage-release-history/v1', 'R9_released_history_source_pending')
    root = Path(p['Root'])
    old = {}
    mods = {}
    namespace = Namespace(str(root / 'service'), p['helpers'])
    try:
        for name, ref in p['source'].items():
            raw, f9 = protected_read(root / name, limit=2097152)
            need(sha(raw) == ref['sha256'] and f9 == ref['F9'], 'R9_complete_Root98_original_source_SHA_F9')
        for name in p['order']:
            raw, f9 = protected_read(root / 'service' / name, limit=2097152)
            need(sha(raw) == p['helpers'][name] and f9[3:7] == [0, 989, 33056, 1], 'R9_protected_original_helper_closure')
            m = namespace.load(name, raw, str(root / 'service' / name))
            mods[name] = m
        originals = {}
        for name, ref in p['originals'].items():
            raw, f9 = protected_read(root / name, limit=4194304)
            need(sha(raw) == ref['sha256'] and f9 == ref['F9'], 'R9_original_qualified_release_full_SHA_F9')
            originals[name] = strict(raw)
        installation = mods['current_epoch.py'].consume_installation(protected_read, p['config'], now)
        need(installation['initial_identity'] == p['identity'] and installation['source_qualified_sha256'] == p['originals']['current-source-qualified.json']['sha256'], 'R9_installation_original_identity_not_future_PID')
        legacy = mods['legacy_stage.py']
        prior = legacy.prior_released(p['config'])
        need(prior and prior['historical_only'] is True, 'R9_actual_negative_completion_required')
        folders = {}
        for label, ref in p['folders'].items():
            v = legacy.held_actor(ref['path'], expected=ref)
            folders[label] = {name: strict(base64.b64decode(row['raw_b64'], validate=True)) for name, row in v['files'].items()}
        a = folders['activation']
        n = folders['negative_release']
        ai, ad, am = (a[k] for k in ('intent.json', 'completed.json', 'fence-released.json'))
        ni, nd, nm = (n[k] for k in ('intent.json', 'completed.json', 'fence-released.json'))
        need(ai['operation'] == ad['operation'] == ni['operation'] == nd['operation'] == nm['operation'] == p['operation'] and ad['state'] == 'SOURCE_EPOCH_READY' and (nd['state'] == 'FAILED_STAGE_PREPAYLOAD_QUIESCENT'), 'R9_completed_original_operations_and_states')
        need(all((v['current_identity'] == p['identity'] for v in (ai, ad, ni, nd))) and ad['source118'] == nd['source118'] == p['config']['PC_source_pins'] and (nd['stage_operation'] == p['stage_operation']), 'R9_exact_old_current_source_and_failed_stage')
        need(nd['intent_sha256'] == p['folders']['negative_release']['files']['intent.json']['sha256'] and nm['completed_sha256'] == p['folders']['negative_release']['files']['completed.json']['sha256'] and (am['completed_sha256'] == p['folders']['activation']['files']['completed.json']['sha256']) and (nm['operator_maintenance_observed'] is am['operator_maintenance_observed'] is False), 'R9_original_causal_completion_and_release_hashes')
        need(ai['negative'] == ni['negative'] == ad['negative_prior_stage'] and ai['legacy_original'] == ni['legacy_original'] and (nd['original_deadline_monotonic'] == ai['legacy_original']['original_deadline_monotonic']) and (nd['work_deadline_extended'] is False) and (nd['old_failure_preserved'] is True), 'R9_complete_original_negative_and_actor_chain')
        need(ai['qualification'] == ad['qualification'] and ad['qualification']['current_source']['source_qualified_sha256'] == installation['source_qualified_sha256'] and all((x['CPU_success'] is x['image_imported'] is False and type(x['models_started']) is int and (x['models_started'] == 0) for x in (ad, nd))), 'R9_history_never_image_CPU_or_future_source_authority')
        return {'state': 'FAILED_STAGE_PREPAYLOAD_QUIESCENT', 'historical_only': True, 'requires_caller_fresh_current_idle': True, 'operation': p['operation'], 'stage_operation': p['stage_operation'], 'completed_sha256': p['folders']['negative_release']['files']['completed.json']['sha256'], 'activation_sha256': p['folders']['activation']['files']['completed.json']['sha256'], 'source_qualified_sha256': installation['source_qualified_sha256'], 'CPU_success': False, 'image_imported': False, 'models_started': 0}
    finally:
        for name, value in old.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
