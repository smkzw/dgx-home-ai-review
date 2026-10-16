# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Last literal loader after SOURCE index/context; source default None is inert."""
import os, platform, time
from pathlib import Path
import plan
from root_io import held, sha
APPROVED_LITERAL = {'source_index_sha256': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9', 'context_producer_sha256': 'c5fa8dcb08f08462a40c672eb74cf546f67e4ba2ef48d9d408c3d8f8cef0e7f7'}

def source_index():
    plan.need(APPROVED_LITERAL is not None, 'source_loader_default_None')
    raw, st = held(Path(plan.STAGE) / 'source-index.json', APPROVED_LITERAL['source_index_sha256'], mode=384)
    v = plan.strict(raw)
    plan.need(v['schema'] == 'registry-R26-A-final-source-index/v1' and v['operation'] == plan.OPERATION and (v['review_sha256'] == APPROVED_LITERAL['review_sha256']), 'exact_final_index_scope')
    return v

def load_source_closure(c=None):
    v = source_index()
    for name, pin in v['files'].items():
        plan.need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'fixed_relative_stage_source')
        held(Path(plan.STAGE) / name, pin, mode=384)
    return v

def context(*, admit=True):
    plan.need(APPROVED_LITERAL is not None and os.getuid() == os.geteuid() == 0 and (platform.system() == 'Linux') and (platform.node() == 'spark-a321'), 'literal_Root_fixed_A_context')
    raw, st = held(Path(plan.STAGE) / 'context.json', mode=384)
    c = plan.strict(raw)
    plan.need(c['operation'] == plan.OPERATION and c['source_release_sha256'] == APPROVED_LITERAL['review_sha256'] and (c['manifest_sha256'] == plan.MANIFEST) and (c['config_sha256'] == plan.CONFIG) and (c['owned_aggregate_unit'] == plan.UNIT) and (c['owned_aggregate_cgroup'] == plan.CG), 'fixed_A_source_scope_context')
    plan.need(c['A_boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'actual_A_boot')
    proof, st = held(Path(plan.STAGE) / 'current-parent-proof.json', c['parent_proof_sha256'], mode=384)
    plan.need(c['context_producer_sha256'] == APPROVED_LITERAL['context_producer_sha256'], 'Root_source_qualified_dynamic_data_producer_not_JSON_bool')
    from qualification import parent_preflight
    parent_preflight(plan.strict(proof), c)
    load_source_closure(c)
    age = time.time() - c['initial_pulse_original']['A_received_at']
    plan.need(0 <= age < (30 if admit else 1800), 'late_loader_current_pulse_age')
    c['remaining_seconds'] -= age
    plan.need(c['remaining_seconds'] > (30 if admit else 0), 'original_whole_after_A_loader')
    return c

def context_for_failure():
    plan.need(APPROVED_LITERAL is not None and os.getuid() == os.geteuid() == 0 and (platform.system() == 'Linux') and (platform.node() == 'spark-a321'), 'literal_failed_context_only')
    load_source_closure()
    raw, st = held(Path(plan.STAGE) / 'context.json', mode=384)
    c = plan.strict(raw)
    plan.need(c['operation'] == plan.OPERATION and c['source_release_sha256'] == APPROVED_LITERAL['review_sha256'] and (c['manifest_sha256'] == plan.MANIFEST) and (c['config_sha256'] == plan.CONFIG) and (c['owned_aggregate_unit'] == plan.UNIT) and (c['owned_aggregate_cgroup'] == plan.CG) and (c['context_producer_sha256'] == APPROVED_LITERAL['context_producer_sha256']), 'immutable_failed_context_exact_source')
    plan.need(c['A_boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'actual_failed_context_same_boot')
    proof, ps = held(Path(plan.STAGE) / 'current-parent-proof.json', c['parent_proof_sha256'], mode=384)
    from qualification import parent_preflight
    parent_preflight(plan.strict(proof), c)
    return c
