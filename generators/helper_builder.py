# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One-way A producer -> service closure -> wire -> config source binding."""
import ast, json, types, pathlib, sys
from source_io import base, bind, expression, sha, encode, need, HERE, BASE, load_source
import policy as P
import operation_domains

def order():
    old = ast.literal_eval(next((n.value for n in ast.parse(base('TOOLS/normal_wire.py')).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'ORDER' for t in n.targets)))))
    new = []
    for n in old:
        if n == 'prestart_history.py':
            new.append('ffc2_history.py')
        if n == 'prelaunch_recovery.py':
            new.extend(('history_reader.py', 'not_launched_history.py', 'zero_negative.py', 'zero_scope.py', 'zero_qualified.py', 'late_scope_context.py', 'zero_recovery.py'))
        new.append(n)
    return tuple(new)

def base_helpers(review, contract_raw, A, qualifier, worker, gate):
    names = order()
    names = tuple((x for n in names for x in (('retired_family.py', n) if n == 'prelaunch_recovery.py' else (n,))))
    h = {n: base('PC/service/' + n) for n in names if n not in ('retired_family.py', 'ffc2_history.py', 'history_reader.py', 'not_launched_history.py', 'zero_negative.py', 'zero_scope.py', 'zero_qualified.py', 'late_scope_context.py', 'zero_recovery.py')}
    for n in ('asset_stage.py', 'prelaunch_recovery.py', 'history_reader.py', 'not_launched_history.py', 'zero_negative.py', 'zero_scope.py', 'zero_qualified.py', 'zero_recovery.py'):
        h[n] = base('H5/PC/service/' + n)
    h['retired_family.py'] = bind((HERE.parent / 'retired_family.py').read_bytes(), {'APPROVED_NEW_REVIEW': review, 'APPROVED_POLICY': json.loads((HERE.parent / 'R12_RETIRED_POLICY.json').read_bytes())})
    stage = h['asset_stage.py'].decode()
    stage = stage.replace('import zero_recovery\n', 'import zero_recovery\nimport retired_family\n', 1)
    before = '  zero_recovery.initialise(self,zero_actor_records,lambda folder:stage_originals(folder.parent,folder.name))'
    after = "  self.retired_family=retired_family.consume(grant,read);self.zero_spent={'d8d0f06cc54a807f320d03813daf3b4b','0177b4f7d21426f8ab8b6c3142b347c9'};self.zero_pending=None"
    need(stage.count(before) == 1, 'R13_one_oldzero_ctor_boundary')
    stage = stage.replace(before, after, 1)
    before = "  protected=list(self.used)+[{'digest':r['digest'],'start':r['start'],'count':r['count']} for r in APPROVED_LEGACY_REFS]"
    after = "  if not self.root.exists()or not list(self.root.iterdir()):need(b['stage_operation']==" + repr(P.CONTRACT['first_stage_operation']) + " and p['ranges']==" + repr([P.CONTRACT['first_range']]) + ",'R13_first_independent_suffix_only_not_blind_retry')\n" + before
    need(stage.count(before) == 1, 'R13_one_first_family_plan_boundary')
    stage = stage.replace(before, after, 1)
    h['asset_stage.py'] = stage.encode()
    h['live_idle.py'] = (HERE.parent / 'CANDIDATE/PC/live_idle.py').read_bytes()
    h['contract.py'] = contract_raw
    h['plan.py'] = A['files']['plan.py']
    h['stage_naming.py'] = A['files']['stage_naming.py']
    h['entry_clock.py'] = A['files']['entry_clock.py']
    h['stage_entry_clock.py'] = A['files']['stage_entry_clock.py']
    h['ffc2_history.py'] = bind(base('FFC2/ffc2_history.py'), {'APPROVED_NEW_REVIEW': review, 'APPROVED_POLICY': json.loads(base('FFC2/ffc2-old-domain-policy.json'))})
    fn = next((n for n in ast.parse(h['prestart_history.py']).body if isinstance(n, ast.FunctionDef) and n.name == 'consume_released'))
    expected = ast.parse('def consume_released(config,read=protected_read):\n import ffc2_history\n return ffc2_history.consume_released(config,read)\n').body[0]
    need(ast.dump(fn, include_attributes=False) == ast.dump(expected, include_attributes=False), 'R13_exact_existing_FFC2_historical_seam')
    h['history_bootstrap.py'] = bind(h['history_bootstrap.py'], {'APPROVED_NEW_REVIEW': review})
    h['current_epoch.py'] = bind(base('NORMAL/templates/service/current_epoch.py'), {'APPROVED_QUALIFIER_SHA': sha(qualifier), 'APPROVED_EPOCH_WORKER_SHA': sha(worker), 'APPROVED_PHASE_GATE_SHA': gate['PC_pins']['gate_loader.py']})
    policy = {'operation': P.ASSET_OPERATION, 'source_review_sha256': review, 'producer_sha256': A['agent_sha256'], 'worker_sha256': A['entry_worker_sha256'], 'source_index_sha256': A['source_index_sha256'], 'clock_policy_sha256': json.loads(base('INPUTS/actual-old-config.raw'))['PC_source_pins']['/etc/dgx-home-ai/node-adapter.json'], 'max_clock_skew_seconds': 30}
    h['entry_clock.py'] = bind(h['entry_clock.py'], {'APPROVED_POLICY': policy})
    h['stage_entry_clock.py'] = bind(h['stage_entry_clock.py'], {'APPROVED_POLICY': dict(policy, worker_sha256=A['ready_worker_sha256'])})
    h['terminal.py'] = bind(h['terminal.py'], {'APPROVED_ENTRY_PRODUCER_SHA': A['agent_sha256'], 'APPROVED_FETCH_PRODUCER_SHA': sha(A['files']['fetch/entry.py'])})
    h['failed_terminal.py'] = bind(h['failed_terminal.py'], {'APPROVED_FAILURE_PRODUCER_SHA': sha(A['files']['failed_terminal.py']), 'APPROVED_FETCH_WORKER_SHA': sha(A['files']['root_worker.py']), 'APPROVED_FETCH_INDEX_SHA': A['source_index_sha256']})
    h['asset_stage.py'] = bind(h['asset_stage.py'], {'APPROVED_REVIEW': review})
    h['asset_stage.py'] = expression(h['asset_stage.py'], 'STATE_ROOT', 'OPERATOR/' + repr('fixed-image-asset-stages-' + P.FAMILY))
    h['asset_segments.py'] = bind(h['asset_segments.py'], {'STORE_ROOT': P.A_DATA, 'SOURCE_ROOT': P.A_ROOT, 'APPROVED_REVIEW': review})
    h['segment_terminal.py'] = bind(h['segment_terminal.py'], {'APPROVED_SOURCE_INDEX': A['source_index_sha256'], 'APPROVED_WORKER_SHA': A['segment_worker_sha256'], 'APPROVED_PRODUCER_SHA': A['segment_terminal_producer_sha256'], 'APPROVED_A_STAGE': P.A_ROOT, 'APPROVED_DATA': P.A_DATA})
    h['callbacks.py'] = bind(h['callbacks.py'], {'APPROVED_SERVICE_REVIEW': review})
    h['grant.py'] = bind(h['grant.py'], {'APPROVED_RELEASE': review})
    h['prelaunch_recovery.py'] = bind(h['prelaunch_recovery.py'], {'APPROVED_QUALIFIER_SHA': sha(qualifier)})
    rec = h['prelaunch_recovery.py'].decode()
    need(rec.count('import zero_recovery\n') == 1, 'R13_recovery_retired_import')
    rec = rec.replace('import zero_recovery\n', 'import zero_recovery\nimport retired_family\n', 1)
    marker = '  prior=stages.prestart_released\n  need(prior==prestart_history.consume_released(g.config,protected_read)'
    need(rec.count(marker) == 2, 'R13_original_zero_and_normal_prior_seams')
    start = rec.index(' def release(self,body):')
    head, tail = (rec[:start], rec[start:])
    old = '  prior=stages.prestart_released\n'
    need(tail.count(old) == 1, 'R13_normal_activation_retired_once')
    tail = tail.replace(old, "  retired=retired_family.consume(g,protected_read);need(retired==stages.retired_family and retired['historical_only']is True and retired['accepted_bytes']==0,'R13_complete_retired_history_before_new_activation')\n" + old, 1)
    old = "    need(prestart_history.consume_released(g.config,protected_read)==prior,'prestart_immutable_completion_not_raced')"
    need(tail.count(old) == 1, 'R13_activation_actual_scheduler_lock_history_boundary')
    tail = tail.replace(old, old + "\n    need(retired_family.consume(g,protected_read)==retired,'R13_retired_history_not_raced_at_single_activation')", 1)
    old = "'qualification':source,'negative':negative,'legacy_original':legacy"
    need(tail.count(old) == 1, 'R13_retired_activation_intent_SHA_chain')
    tail = tail.replace(old, "'qualification':source,'retired_family':retired,'negative':negative,'legacy_original':legacy", 1)
    old = "'qualification':source,'negative_prior_stage':negative"
    need(tail.count(old) == 1, 'R13_retired_activation_completed_SHA_chain')
    tail = tail.replace(old, "'qualification':source,'retired_family':retired,'negative_prior_stage':negative", 1)
    old = "'prior_stage_state':'FAILED_STAGE_NOT_LAUNCHED_QUIESCENT'"
    need(tail.count(old) == 1, 'R13_prior_failure_type_preserved')
    tail = tail.replace(old, "'prior_stage_state':'FAILED_REGISTRY_QUIESCENT'", 1)
    h['prelaunch_recovery.py'] = (head + tail).encode()
    h['late_scope_context.py'] = (HERE / 'late_scope_context.py').read_bytes()
    oldpolicy = json.loads(base('INPUTS/zero-history-policy.json'))
    pc = json.loads(base('INPUTS/zero-history-pc.raw'))
    data = __import__('history_data').materialize()[1]
    h['not_launched_history.py'] = bind(h['not_launched_history.py'], {'HISTORY_ROOT': P.PC_DATA, 'APPROVED_POLICY': oldpolicy, 'APPROVED_PACKED_PINS': {n: x['packed_sha256'] for n, x in data.items()}, 'APPROVED_PUBLICATION_OPERATION': P.EPOCH})
    h['zero_negative.py'] = bind(h['zero_negative.py'], {'APPROVED_POLICY': oldpolicy, 'APPROVED_REVIEW': review, 'OPERATION': P.EPOCH})
    h['zero_recovery.py'] = bind(h['zero_recovery.py'], {'OLD_ACTOR_ROOT': None, 'OLD_STAGE': P.OLD_STAGE, 'APPROVED_ACTOR_F9': {n: x['F9'] for n, x in pc['files'].items()}, 'RECOVERY_ROOT': '/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/zero-launch-' + P.EPOCH, 'QUALIFIED_ROOT': P.PC_ROOT, 'APPROVED_REVIEW': review})
    zr = h['zero_recovery.py'].decode()
    zr = zr.replace('import zero_qualified\n', 'import zero_qualified\nimport late_scope_context\n', 1)
    old = 't=zero_qualified.consume(raw,st,a,pc,c,now)'
    need(zr.count(old) == 1, 'one_current_zero_consumer')
    zr = zr.replace(old, "t=late_scope_context.consume('historical-fixed',g,raw,st,None,now)", 1)
    old = "check=zero_qualified.consume(raw,st,a,pc,v['current'],i['observed_at'])"
    need(zr.count(old) == 1, 'one_warm_zero_consumer')
    zr = zr.replace(old, "check=late_scope_context.consume_history('historical-fixed',stages.g,raw,st,None,i['observed_at'])", 1)
    h['zero_recovery.py'] = zr.encode()
    h['zero_recovery.py'] = base('PC/service/zero_recovery.py')
    h['grant.py'] = operation_domains.grant(h['grant.py'])
    h['prelaunch_recovery.py'] = operation_domains.recovery(h['prelaunch_recovery.py'])
    return (h, names)

def wire(cold_wire, helpers, names, review):
    raw = base('TOOLS/normal_wire.py')
    raw = bind(raw, {'ORDER': names})
    raw = expression(raw, 'PC_ROOT', 'Path(' + repr(P.PC_ROOT) + ')')
    path = BASE / 'TOOLS/normal_wire.py'
    sentinel = object()
    old = sys.modules.get('source_tools', sentinel)
    source = types.ModuleType('source_tools')
    source.need = need
    source.sha = sha
    source.bind = bind
    source.encode = encode
    sys.modules['source_tools'] = source
    try:
        m = load_source(raw, 'offline_R12_wire', path)
        pins = {n: sha(b) for n, b in helpers.items()}
        out = m.transform(cold_wire, pins, review)
        out = m.startup_diagnostics(out, P.EPOCH, review, list(helpers.values()))
        return out
    finally:
        if old is sentinel:
            sys.modules.pop('source_tools', None)
        else:
            sys.modules['source_tools'] = old
