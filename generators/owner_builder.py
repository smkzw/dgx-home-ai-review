# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Three existing leaves; source review -> worker bytes -> bound private policy."""
import ast, json
from source_io import HERE, sha, bind, need, replace_definition
import policy as P

def owner_source():
    raw = (HERE.parent / 'OWNER/CANDIDATE/history_reader.py').read_bytes()
    s = raw.decode()
    at = s.index('import builtins as owner_builtins,')
    s = s[at:]
    replacement = "def owner_actor_snapshot(stages, stage):\n p=owner_policy();context=owner_Context(p['old_sources'],stages.read)\n try:records=context.module('current_prebind').actor_records(stages,stage)\n finally:context.recheck()\n rows={};stats={}\n for name,r in records.items():\n  raw=owner_base64.b64decode(r['raw_b64'],validate=True);owner_need(owner_sha(raw)==r['sha256']and r['F9'][2]==len(raw),'owner_actual_actor_snapshot_SHA');rows[name]=raw;stats[name]=r['F9']\n return rows,stats\n"
    s = replace_definition(s.encode(), replacement.encode(), 'owner_actor_snapshot')
    text = s.decode()
    old = '    from asset_stage import STATE_ROOT\n'
    need(text.count(old) == 1, 'R16_one_normal_lazy_stage_root')
    text = text.replace(old, "    STATE_ROOT=owner_Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/fixed-image-asset-stages-role-context-r14')\n", 1)
    prior = "permit['PC_deadline_monotonic'] - permit['PC_monotonic_origin'] == permit['duration_seconds']"
    next_value = "permit['PC_deadline_monotonic'] == permit['PC_monotonic_origin'] + permit['duration_seconds']"
    need(text.count(prior) == 1, 'R16_owner_finite_exact_producer_formula_once')
    text = text.replace(prior, next_value, 1)
    marker = '    finally:\n        ctx.recheck()\n    return a'
    need(text.count(marker) == 1, 'R16_owner_checked_A_termination_slot')
    extra = None
    text = text.replace(marker, extra + marker, 1)
    from source_io import base
    scope = base('NORMAL_GATE/scope.py')
    node = next((n for n in ast.parse(scope).body if isinstance(n, ast.FunctionDef) and n.name == 'stopped_unit_branch'))
    body = ast.get_source_segment(scope.decode(), node).replace('def stopped_unit_branch(', 'def owner_stopped_unit_branch(', 1).replace('need(', 'owner_need(')
    text += '\n' + body + '\n'
    return text.encode()

def readonly_modules(nonce):
    from source_io import base
    p = json.loads((HERE.parent / 'OWNER_POLICY.unbound.json').read_bytes())
    return {'plan.py': bind(base('PC/service/plan.py'), {'UNIT': 'dgx-v4-prelaunch-release-' + nonce + '.service', 'ENTRY_UNIT': 'dgx-v4-prelaunch-release-' + nonce + '.service', 'OPERATION': P.EPOCH}), 'root_io.py': base('PC/service/root_io.py'), 'bounded_process.py': base('PC/service/bounded_process.py'), 'old_failed_kernel.py': bind(base('PC/service/old_failed_kernel.py'), {'ALLOWED_UNIT': p['old_worker']['unit']})}

def readonly_body(nonce):
    p = json.loads((HERE.parent / 'OWNER_POLICY.unbound.json').read_bytes())
    p = {k: p[k] for k in ('stage', 'old_terminal', 'old_A_sources', 'old_worker')}
    p['probe_nonce'] = nonce
    return bind((HERE.parent / 'owner_readonly_worker.py').read_bytes(), {'APPROVED_COLLECT_POLICY': p})

def readonly_worker(nonce):
    modules = readonly_modules(nonce)
    return bind((HERE.parent / 'owner_worker_main.py').read_bytes(), {'APPROVED_MODULES': {n[:-3]: sha(b) for n, b in modules.items()}, 'APPROVED_BODY': readonly_body(nonce), 'APPROVED_UNIT': 'dgx-v4-prelaunch-release-' + nonce + '.service', 'APPROVED_OPERATION': P.EPOCH})

def policy(review, nonce):
    p = json.loads((HERE.parent / 'OWNER_POLICY.unbound.json').read_bytes())
    p.update(new_review=review, probe_nonce=nonce, probe_unit='dgx-v4-prelaunch-release-' + nonce + '.service', probe_worker_sha=sha(readonly_worker(nonce)))
    need(p['probe_operation'] == P.EPOCH, 'R16_owner_source_epoch_not_family')
    return p

def extend(h, names, review, nonce, qualifier):
    from history_binding import history_reader_source
    h = dict(h)
    h['history_reader.py'] = history_reader_source() + b'\n' + bind(owner_source(), {'owner_APPROVED_POLICY': policy(review, nonce)})
    h['asset_stage.py'] = bind((HERE.parent / 'OWNER/CANDIDATE/asset_stage.py').read_bytes(), {'APPROVED_REVIEW': review})
    h['prelaunch_recovery.py'] = bind((HERE.parent / 'OWNER/CANDIDATE/prelaunch_recovery.py').read_bytes(), {'APPROVED_QUALIFIER_SHA': sha(qualifier)})
    return (h, names)
