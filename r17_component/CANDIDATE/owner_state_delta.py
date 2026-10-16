# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite co-located Journal/Recovery context. No RPC or scheduler authority.

The unbound policy is an internal source literal. Root historical reads cannot
confirm durability, write projections, finish maintenance or admit work.
"""
from contextlib import contextmanager as owner_contextmanager
import owner_decision as owner_journal_module
import owner_projection as owner_projection_module
owner_DECISION_POLICY = None

def owner_decision_policy():
    p = owner_DECISION_POLICY
    owner_need(type(p) is dict and set(p) == {'parent', 'operation', 'prepared_closure_sha256'}, 'owner_decision_context_SOURCE_None')
    old = owner_policy()
    parent = owner_Path(p['parent'])
    owner_need(parent.parent == owner_Path(old['activation_root']).parent and parent.name == 'owner-decisions-' + old['probe_operation'] and (p['operation'] == old['probe_nonce']) and owner_re.fullmatch('[0-9a-f]{64}', p['prepared_closure_sha256']), 'owner_decision_context_fixed_source_domain')
    return p

@owner_contextmanager
def owner_private_directory(path, *, base=None, create=False):
    """Original HeldParent up to fixed service base, then private dirFD child."""
    from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, directory_identity
    path = owner_Path(path)
    base = path if base is None else owner_Path(base)
    owner_need(path == base or path.parent == base, 'owner_decision_single_private_child')
    with HeldParent(base, legacy=True) as chain:

        def opened(name, parent):
            try:
                return owner_os.open(name, owner_os.O_RDONLY | owner_os.O_DIRECTORY | owner_os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                owner_need(create and owner_os.getuid() == owner_os.geteuid() == 999, 'owner_decision_directory_existing_or_service_create')
                owner_os.mkdir(name, 448, dir_fd=parent)
                value = owner_os.open(name, owner_os.O_RDONLY | owner_os.O_DIRECTORY | owner_os.O_NOFOLLOW, dir_fd=parent)
                owner_os.fchmod(value, 448)
                owner_os.fsync(parent)
                return value
        fd = opened(base.name, chain.parent_fd)
        sub = None
        try:
            ident = directory_identity(owner_os.fstat(fd))
            owner_need(ident[2:] == (999, 989, 16832) and ident == directory_identity(chain.named_leaf()), 'owner_decision_directory_private_identity')
            if path != base:
                sub = opened(path.name, fd)
                child = directory_identity(owner_os.fstat(sub))
                owner_need(child[2:] == (999, 989, 16832) and child == directory_identity(owner_os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'owner_decision_private_child_identity')
            yield (fd if sub is None else sub)
            if sub is not None:
                owner_need(child == directory_identity(owner_os.fstat(sub)) == directory_identity(owner_os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'owner_decision_private_child_identity_after')
            owner_need(ident == directory_identity(owner_os.fstat(fd)) == directory_identity(chain.named_leaf()), 'owner_decision_directory_identity_after')
            chain.recheck()
        finally:
            if sub is not None:
                owner_os.close(sub)
            owner_os.close(fd)

@owner_contextmanager
def owner_decision_context(*, read_only=False, create_parent=False):
    policy = owner_decision_policy()
    with owner_private_directory(policy['parent'], create=create_parent) as parent:
        journal = owner_journal_module.Journal(parent, policy['operation'], read_only=read_only)
        try:
            yield journal
        finally:
            journal.close()

def owner_validate_decision_history(stages, journal, *, historical_only=False):
    """Full past-event eligibility plus actual old actor; no fresh release."""
    p = owner_policy()
    state = journal.state()
    owner_need(state['state'] == 'COMMITTED' or (historical_only is True and state['state'] == 'FINISH_WITNESS_PRESENT' and ('projections' in state)), 'owner_history_requires_cold_durability_barrier_or_sealed_past_event')
    prepared, _ = journal.read('prepared.json')
    binding = prepared['binding']
    recipe = state['decision']['payload']['recipe']
    policy = owner_decision_policy()
    actual, stats = owner_actor_snapshot(stages, p['stage'])
    names = set(p['old_records'])
    owner_need(names <= set(actual) <= names | owner_projection_module.ACTOR_NAMES, 'owner_v2_history_exact_old_projection_entries')
    base = {n: actual[n] for n in names}
    base_stats = {n: stats[n] for n in names}
    pending = owner_pending(stages.read, base, base_stats, p)
    expected = {'operation': policy['operation'], 'stage': p['stage'], 'prepared_closure_sha256': policy['prepared_closure_sha256'], 'initial_identity': recipe['eligibility']['new_current']['manager_identity'], 'original_deadline_monotonic': pending['original_deadline_monotonic'], 'old_terminal_sha256': pending['terminal_sha256']}
    owner_need(binding == expected and state['decision']['payload']['binding'] == binding and (recipe['operation'] == policy['operation']) and (recipe['stage'] == p['stage']) and (recipe['old_terminal'] == p['old_terminal']), 'owner_v2_decision_exact_prepared_old_event')
    event = recipe['eligibility']
    checked = owner_fresh_v2(stages.read, p, stages.g, pending, None, event['observed_at'], historical=True, event=event)
    owner_need(checked == event and recipe['recorded_at'] >= event['observed_at'], 'owner_v2_original_eligibility_event_equal')
    terminal = owner_held(stages.read, p['old_terminal'], [0, 989, 33056, 1])
    owner_need(recipe['release_clock'] == state['decision']['before_durable_write'], 'owner_v2_recipe_exact_precommit_clock')
    wanted = owner_projection_module.render(recipe, terminal, state['witness']['maintenance_finish_observed'])
    return (state, recipe, pending, terminal, wanted)

def owner_restore_decision_cold(recovery, stages):
    """Called only inside original Grant construction's scheduler RLock.

    The new HistoricalNegative source fence is deliberately left pending. This
    restores only a past complete owner transaction's fixed metadata/history.
    """
    g = recovery.g
    lock = g.s._lock
    owner_need(g.prelaunch_recovery is recovery and stages.g is g and lock._is_owned(), 'owner_decision_cold_original_scheduler_lock')
    with owner_decision_context() as journal:
        state = journal.classify()
        if state['state'] not in ('COMMITTED', 'FINISH_WITNESS_PRESENT'):
            return state
        g.same()
        journal.confirm_metadata_durability(lock)
        state, recipe, pending, terminal, wanted = owner_validate_decision_history(stages, journal)
        p = owner_policy()
        inv = recipe['eligibility']['new_current']['manager_identity']['invocation_id']
        owner_need(owner_re.fullmatch('[0-9a-f]{32}', inv), 'owner_v2_fixed_initial_event_invocation')
        with owner_private_directory(stages.root / p['stage'], base=stages.root) as actor:
            with owner_private_directory(owner_Path(p['activation_root']) / inv, base=p['activation_root'], create=True) as source:
                refs = owner_projection_module.project(journal, actor, source, recipe, terminal, set(p['old_records']))
        rows, stats = owner_actor_snapshot(stages, p['stage'])
        owner_need(all((rows[n] == raw and stats[n] == refs['actor'][n]['F9'] and (owner_sha(raw) == refs['actor'][n]['sha256']) for n, raw in wanted['actor'].items())), 'owner_v2_actual_actor_projection_fullF9')
        source_rows, source_stats = owner_activation_records(owner_Path(p['activation_root']) / inv)
        owner_need(source_rows == wanted['source'] and all((source_stats[n] == ref['F9'] and owner_sha(source_rows[n]) == ref['sha256'] for n, ref in refs['source'].items())), 'owner_v2_actual_source_projection_fullF9')
        g.same()
        again = owner_validate_decision_history(stages, journal)
        owner_need(again[1:] == (recipe, pending, terminal, wanted), 'owner_v2_history_stable_after_live_same')
        return {'state': 'COMMITTED', 'historical_only': True, 'pending': pending, 'decision_ref': journal.state()['decision_ref'], 'projections': refs, 'physical_finish_calls': 0, 'current_source_activation_required': True}

def owner_committed_history_v2(stages, stage, rows):
    """Read-only past event for both service and Root phase consumers.

    A present complete witness + sealed exact projections is historical evidence
    only here. No durability confirmation, write or physical finish is exposed.
    """
    p = owner_policy()
    owner_need(stage == p['stage'], 'owner_v2_history_fixed_stage')
    root_role = owner_os.getuid() == owner_os.geteuid() == 0
    with owner_decision_context(read_only=root_role) as journal:
        state, recipe, pending, terminal, wanted = owner_validate_decision_history(stages, journal, historical_only=True)
        refs = state.get('projections')
        owner_need(type(refs) is dict and set(refs) == {'actor', 'source'}, 'owner_v2_history_complete_projection_seal')
        actual, stats = owner_actor_snapshot(stages, stage)
        owner_need(actual == rows and set(rows) == set(p['old_records']) | owner_projection_module.ACTOR_NAMES and all((rows[n] == raw and stats[n] == refs['actor'][n]['F9'] and (owner_sha(raw) == refs['actor'][n]['sha256']) for n, raw in wanted['actor'].items())), 'owner_v2_historical_actual_actor_fullF9')
        inv = recipe['eligibility']['new_current']['manager_identity']['invocation_id']
        src, srcstats = owner_activation_records(owner_Path(p['activation_root']) / inv)
        owner_need(src == wanted['source'] and all((srcstats[n] == r['F9'] and owner_sha(src[n]) == r['sha256'] for n, r in refs['source'].items())), 'owner_v2_historical_actual_source_fullF9')
        stages.g.same()
        last, laststats = owner_actor_snapshot(stages, stage)
        owner_need(last == actual and laststats == stats, 'owner_v2_historical_actor_after_live_same')
        owner_need(journal.state()['projections'] == refs, 'owner_v2_historical_authority_after')
        stages.used.extend(pending['ranges'])
        return pending['original_terminal']
