# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed owner-decision metadata recipe; no work or physical release callback.

Co-located SOURCE functions for the existing service private FD context. The
caller must first run the original typed historical eligibility consumer. This
module cannot turn a recipe, a directory or COMMITTED alone into resource
permission. Only six fixed metadata leaves are ever created, never overwritten.
"""
import base64
import hashlib
import json
import os
import stat
UID = 999
GID = 989
CAP = 2 * 1024 ** 2
ACTOR_NAMES = frozenset(('terminal.json', 'completed.json', 'fence-released.json'))
SOURCE_NAMES = frozenset(('intent.json', 'completed.json', 'fence-released.json'))
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

class ProjectionRefused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise ProjectionRefused(reason)

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def f9(z):
    return [getattr(z, k) for k in FIELDS]

def directory_identity(z):
    return tuple((f9(z)[i] for i in (0, 1, 3, 4, 5)))

def render(recipe, terminal_raw, finish_clock):
    """Rebuild exact bytes from one authoritative, finite decision payload.

    The old 1.4MB terminal is referenced, not embedded again in the journal.
    Its original Root SHA/fullF9 are independently re-read by the caller.
    """
    keys = {'schema', 'operation', 'stage', 'old_terminal', 'original_deadline_monotonic', 'release_clock', 'request', 'qualification', 'prior', 'legacy_original', 'eligibility', 'current', 'recorded_at'}
    need(type(recipe) is dict and set(recipe) == keys and (recipe['schema'] == 'owner-projection-recipe/v2'), 'owner_projection_closed_recipe')
    eligibility = recipe['eligibility']
    stage = recipe['stage']
    when = finish_clock['PC_wall_observed']
    need(finish_clock['PC_boot_id'] == eligibility['new_current']['manager_identity']['boot_id'] and 0 <= finish_clock['PC_monotonic_elapsed'] <= 30 and (recipe['recorded_at'] <= when), 'owner_projection_original_postfinish_clock')
    need(eligibility['schema'] == 'failed-owner-terminal-release-eligibility/v2' and eligibility['stage_operation'] == stage and (eligibility['old_terminal_sha256'] == sha(terminal_raw) == recipe['old_terminal']['sha256']) and (eligibility['original_deadline_monotonic'] == recipe['original_deadline_monotonic']) and (eligibility['work_may_resume'] is False) and (eligibility['activation_request_nonce'] == recipe['request']['request_nonce']), 'owner_projection_exact_failed_eligibility')
    terminal = json.loads(terminal_raw)
    need(terminal['state'] == 'FAILED_REGISTRY_QUIESCENT', 'owner_projection_failed_not_success')
    shared = {'decision_operation': recipe['operation'], 'recipe_sha256': sha(encode(recipe))}
    intent = dict(shared, schema='asset-source-owner-recovery-intent/v2', release_commit_clock=finish_clock, request=recipe['request'], qualification=recipe['qualification'], prior=recipe['prior'], legacy_original=recipe['legacy_original'], owner_recovery=eligibility, current=recipe['current'], observed_at=recipe['recorded_at'], automatic_retry=False)
    completion = dict(shared, schema='fixed-image-finite-stage-owner-recovered/v2', stage_operation=stage, state='FAILED_REGISTRY_QUIESCENT', terminal_sha256=sha(terminal_raw), current=recipe['current'], original_deadline_monotonic=recipe['original_deadline_monotonic'], work_deadline_extended=False, image_imported=False, CPU_success=False, models_started=0, finished_at=when, owner_recovery=eligibility)
    activation = dict(shared, schema='asset-source-owner-recovery-completed/v2', state='SOURCE_EPOCH_READY', owner_recovery=eligibility, qualification=recipe['qualification'], current=recipe['current'], image_imported=False, CPU_success=False, models_started=0, observed_at=when)
    result = {'actor': {'terminal.json': terminal_raw, 'completed.json': encode(completion), 'fence-released.json': encode(dict(shared, stage_operation=stage, completed_sha256=sha(encode(completion)), operator_maintenance_observed=False, observed_at=when))}, 'source': {'intent.json': encode(intent), 'completed.json': encode(activation), 'fence-released.json': encode(dict(shared, completed_sha256=sha(encode(activation)), operator_maintenance_observed=False, observed_at=when))}}
    need(all((0 < len(raw) <= CAP for rows in result.values() for raw in rows.values())), 'owner_projection_each_original_leaf_cap')
    return result

def project(journal, actor_fd, source_fd, recipe, terminal_raw, actor_original_names):
    """Complete only a valid decision's fixed metadata, no finish/clock/release.

    FD/ancestor acquisition is the existing private HeldParent algorithm. The
    caller supplies those held FDs, never paths from caller JSON. A missing
    projection may be created until the final descriptor is sealed. After that,
    changed/missing inode or timestamp refuses, even when its bytes are equal.
    """
    state = journal.state()
    need(state['state'] == 'COMMITTED', 'owner_projection_requires_durable_finish_witness')
    need(state['decision']['payload']['recipe'] == recipe, 'owner_projection_exact_decision_recipe')
    desired = render(recipe, terminal_raw, state['witness']['maintenance_finish_observed'])
    fds = {'actor': actor_fd, 'source': source_fd}
    allowed = {'actor': set(actor_original_names) | ACTOR_NAMES, 'source': SOURCE_NAMES}
    identities = {}
    for kind, fd in fds.items():
        z = os.fstat(fd)
        need(stat.S_ISDIR(z.st_mode) and z.st_uid == UID and (z.st_gid == GID) and (stat.S_IMODE(z.st_mode) == 448), 'owner_projection_private_fixed_directory')
        identities[kind] = directory_identity(z)
        need(set(os.listdir(fd)) <= allowed[kind], 'owner_projection_no_foreign_leaf')
    sealed = state.get('projections')
    refs = {}
    for kind, rows in desired.items():
        refs[kind] = {}
        fd = fds[kind]
        for name, raw in rows.items():
            try:
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                need(sealed is None, 'owner_projection_sealed_leaf_missing')
                leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=fd)
                try:
                    os.fchmod(leaf, 384)
                    view = memoryview(raw)
                    while view:
                        n = os.write(leaf, view)
                        need(n > 0, 'owner_projection_write_progress')
                        view = view[n:]
                    os.fsync(leaf)
                finally:
                    os.close(leaf)
                os.fsync(fd)
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                before = f9(os.fstat(leaf))
                need(stat.S_ISREG(before[5]) and before[3:7] == [UID, GID, 33152, 1] and (0 < before[2] <= CAP), 'owner_projection_private_bounded_leaf')
                actual = os.pread(leaf, before[2] + 1, 0)
                need(actual == raw and len(actual) == before[2] and (before == f9(os.fstat(leaf)) == f9(os.stat(name, dir_fd=fd, follow_symlinks=False))), 'owner_projection_exact_raw_held_named_fullF9')
                refs[kind][name] = {'sha256': sha(actual), 'F9': before}
            finally:
                os.close(leaf)
        need(directory_identity(os.fstat(fd)) == identities[kind] and set(os.listdir(fd)) <= allowed[kind], 'owner_projection_directory_identity_after')
    if sealed is not None:
        need(refs == sealed, 'owner_projection_sealed_fullF9_changed')
    else:
        journal.record_projections(refs)
    after = journal.state()
    need(after['state'] == 'COMMITTED' and after['projections'] == refs, 'owner_projection_authority_and_metadata_after')
    for kind, rows in refs.items():
        for name, ref in rows.items():
            need(f9(os.stat(name, dir_fd=fds[kind], follow_symlinks=False)) == ref['F9'], 'owner_projection_final_named_fullF9')
    return refs
