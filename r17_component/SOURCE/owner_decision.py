# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One finite owner operation's private durable decision; no scheduler/SQL authority.

A readable complete finish witness is held until its exact SHA/F9 has an
actual durability barrier in this instance. Cold confirmation never repeats
physical finish. This module never clears maintenance by itself.
"""
import hashlib
import json
import os
import re
import stat
import threading
SERVICE_UID = 999
SERVICE_GID = 989
CAP = 2 * 1024 ** 2
NAMES = frozenset(('prepared.json', 'decision.json', 'durability-witness.json', 'expired.json', 'aborted.json', 'projections.json'))
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

class DecisionRefused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise DecisionRefused(reason)

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'owner_decision_duplicate_key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(DecisionRefused('owner_decision_nonfinite')))
    need(encode(value) == raw, 'owner_decision_canonical_fullraw')
    return value

def f9(value):
    return [getattr(value, name) for name in FIELDS]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(meta):
    return [meta[i] for i in (0, 1, 3, 4, 5)]

class Journal:
    """Already protected private parent FD, opened by existing HeldParent.

    The fixed operation name comes from internally bound policy, never a path
    from an RPC body. Parent lifetime/ancestor protection belongs to HeldParent.
    """

    def __init__(self, parent_fd, operation, *, fault=lambda _: None, read_only=False):
        need(type(operation) is str and re.fullmatch('[0-9a-f]{32}', operation), 'owner_decision_fixed_operation')
        need(os.getuid() == os.geteuid() and (os.getuid() == SERVICE_UID or (read_only is True and os.getuid() == 0)), 'owner_decision_service_or_Root_readonly_role')
        self._read_only = read_only
        self.parent = os.dup(parent_fd)
        self.name = operation
        self.fd = None
        self.fault = fault
        self._metadata_confirmed = None
        self._failed_commit = False
        p = os.fstat(self.parent)
        need(stat.S_ISDIR(p.st_mode) and p.st_uid == SERVICE_UID and (p.st_gid == SERVICE_GID) and (stat.S_IMODE(p.st_mode) == 448), 'owner_decision_private_parent')
        self.parent_identity = identity(f9(p))
        try:
            self.fd = os.open(operation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
            self.check_directory()
        except FileNotFoundError:
            pass
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None

    def check_directory(self):
        need(identity(f9(os.fstat(self.parent))) == self.parent_identity, 'owner_decision_parent_identity')
        current = f9(os.fstat(self.fd))
        named = f9(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False))
        need(current == named and stat.S_ISDIR(current[5]) and (current[3:6] == [SERVICE_UID, SERVICE_GID, 16832]), 'owner_decision_named_private_directory')
        need(set(os.listdir(self.fd)) <= NAMES, 'owner_decision_closed_entries')

    def create(self):
        need(self._read_only is False, 'owner_decision_readonly_never_creates')
        need(self.fd is None, 'owner_decision_operation_once')
        self.fault('before_mkdir')
        os.mkdir(self.name, 448, dir_fd=self.parent)
        self.fault('after_mkdir')
        self.fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
        os.fchmod(self.fd, 448)
        os.fsync(self.parent)
        self.fault('after_mkdir_fsync')
        self.check_directory()

    def read(self, name):
        need(name in NAMES and self.fd is not None, 'owner_decision_fixed_leaf')
        self.check_directory()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            before = f9(os.fstat(fd))
            need(stat.S_ISREG(before[5]) and before[3:7] == [SERVICE_UID, SERVICE_GID, 33152, 1] and (0 < before[2] <= CAP), 'owner_decision_private_leaf')
            raw = os.pread(fd, before[2] + 1, 0)
            need(len(raw) == before[2] and before == f9(os.fstat(fd)) == f9(os.stat(name, dir_fd=self.fd, follow_symlinks=False)), 'owner_decision_held_named_fullF9')
            value = strict(raw)
        finally:
            os.close(fd)
        self.check_directory()
        return (value, {'sha256': sha(raw), 'F9': before})

    def write(self, name, value):
        need(self._read_only is False, 'owner_decision_readonly_never_writes')
        need(name in NAMES, 'owner_decision_fixed_leaf')
        self.check_directory()
        raw = encode(value)
        need(0 < len(raw) <= CAP, 'owner_decision_leaf_cap')
        self.fault('before_' + name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.fd)
        try:
            os.fchmod(fd, 384)
            offset = 0
            while offset < len(raw):
                wrote = os.write(fd, raw[offset:])
                need(wrote > 0, 'owner_decision_write_progress')
                offset += wrote
            self.fault('after_write_' + name)
            os.fsync(fd)
            self.fault('after_file_fsync_' + name)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        self.fault('after_directory_fsync_' + name)
        actual, ref = self.read(name)
        need(actual == value, 'owner_decision_exact_readback')
        return ref

    def prepare(self, binding):
        self.create()
        need(type(binding) is dict and set(binding) == {'operation', 'stage', 'prepared_closure_sha256', 'initial_identity', 'original_deadline_monotonic', 'old_terminal_sha256'}, 'owner_decision_prepared_binding')
        need(binding['operation'] == self.name, 'owner_decision_same_operation')
        return self.write('prepared.json', {'schema': 'owner-decision-prepared/v1', 'state': 'PREPARED', 'binding': binding})

    def commit(self, payload, clock_check, finish_maintenance, restore_held):
        """The decision is durable before physical finish; post-clock stays30.

        Every post-decision error restores the original block. A complete file
        seen after a failed write is only FINISH_WITNESS_PRESENT, not evidence
        its file+directory barriers completed. Only a new cold entry may confirm
        that fixed metadata under the existing scheduler lock, never re-finish.
        """
        prepared, ref = self.read('prepared.json')
        need(self.state()['state'] == 'PREPARED', 'owner_decision_unspent_prepared')
        clock_failed = False
        decision_ref = None

        def checked_clock():
            nonlocal clock_failed
            try:
                return clock_check()
            except ValueError:
                clock_failed = True
                raise
        try:
            before = checked_clock()
            decision = {'schema': 'owner-decision/v1', 'prepared': ref, 'payload': payload, 'before_durable_write': before}
            decision_ref = self.write('decision.json', decision)
            durable = checked_clock()
            finish_maintenance()
            self.fault('after_physical_finish')
            after = checked_clock()
            need(after['PC_boot_id'] == before['PC_boot_id'] and after['PC_monotonic_observed'] >= before['PC_monotonic_observed'], 'owner_decision_same_boot_durable_observation')
            witness = {'schema': 'owner-decision-durability-witness/v1', 'decision': decision_ref, 'durability_observed': durable, 'maintenance_finish_observed': after, 'state': 'COMMITTED'}
            witness_ref = self.write('durability-witness.json', witness)
            self._metadata_confirmed = witness_ref
            self.fault('before_final_state')
            result = self.state()
            need(result['state'] == 'COMMITTED', 'owner_decision_complete_tail')
            return result
        except BaseException:
            self._metadata_confirmed = None
            self._failed_commit = True
            restore_held()
            if clock_failed and decision_ref is not None:
                self.write('expired.json', {'schema': 'owner-decision-expired/v1', 'decision': decision_ref, 'state': 'EXPIRED'})
            raise

    def confirm_metadata_durability(self, scheduler_lock):
        """Cold-only durability barrier for a past, already complete finish.

        The Recovery caller must be in its constructor under this same real
        scheduler RLock. No RPC exposes this method. A same-process failed
        commit is deliberately not repairable through this object.
        """
        need(self._read_only is False, 'owner_decision_service_cold_barrier_only')
        need(isinstance(scheduler_lock, type(threading.RLock())) and scheduler_lock._is_owned(), 'owner_decision_existing_scheduler_lock')
        need(not self._failed_commit, 'owner_decision_failed_process_not_cold_reentry')
        before = self.state()
        need(before['state'] in ('FINISH_WITNESS_PRESENT', 'COMMITTED'), 'owner_decision_complete_finish_witness_before_barrier')
        witness, ref = self.read('durability-witness.json')
        self._metadata_confirmed = None
        try:
            leaf = os.open('durability-witness.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                need(f9(os.fstat(leaf)) == ref['F9'], 'owner_decision_barrier_same_leaf')
                self.fault('before_cold_witness_fsync')
                os.fsync(leaf)
                self.fault('after_cold_witness_fsync')
            finally:
                os.close(leaf)
            os.fsync(self.fd)
            self.fault('after_cold_directory_fsync')
            os.fsync(self.parent)
            self.fault('after_cold_parent_fsync')
            after, after_ref = self.read('durability-witness.json')
            need(after == witness and after_ref == ref, 'owner_decision_barrier_same_fullraw_F9_after')
            self._metadata_confirmed = after_ref
            result = self.state()
            need(result['state'] == 'COMMITTED', 'owner_decision_cold_barrier_confirmed')
            return result
        except BaseException:
            self._metadata_confirmed = None
            raise

    def state(self):
        if self.fd is None:
            return {'state': 'ABSENT', 'held': True}
        self.check_directory()
        names = set(os.listdir(self.fd))
        if 'prepared.json' not in names:
            return {'state': 'UNKNOWN_HELD', 'held': True}
        prepared, pref = self.read('prepared.json')
        need(prepared['schema'] == 'owner-decision-prepared/v1' and prepared['state'] == 'PREPARED' and (prepared['binding']['operation'] == self.name), 'owner_decision_prepared_schema')
        if names & {'expired.json', 'aborted.json'}:
            need(not {'expired.json', 'aborted.json'} <= names and 'durability-witness.json' not in names and ('projections.json' not in names), 'owner_decision_conflicting_outcomes')
            name = 'expired.json' if 'expired.json' in names else 'aborted.json'
            value, _ = self.read(name)
            need(value['state'] == ('EXPIRED' if name == 'expired.json' else 'ABORTED'), 'owner_decision_failed_outcome')
            if name == 'expired.json':
                _, dref = self.read('decision.json')
                need(value['decision'] == dref, 'owner_decision_expiry_exact_decision')
            return {'state': value['state'], 'held': True}
        if 'decision.json' not in names:
            need(names == {'prepared.json'}, 'owner_decision_no_orphan_witness')
            return {'state': 'PREPARED', 'held': True}
        decision, dref = self.read('decision.json')
        need(decision['schema'] == 'owner-decision/v1' and decision['prepared'] == pref, 'owner_decision_full_prepared_ref')
        if 'durability-witness.json' not in names:
            return {'state': 'UNKNOWN_HELD', 'held': True}
        witness, wref = self.read('durability-witness.json')
        need(witness['schema'] == 'owner-decision-durability-witness/v1' and witness['state'] == 'COMMITTED' and (witness['decision'] == dref), 'owner_decision_full_durable_ref')
        before = decision['before_durable_write']
        durable = witness['durability_observed']
        after = witness['maintenance_finish_observed']
        need(after['PC_boot_id'] == before['PC_boot_id'] and before['PC_monotonic_sent'] == after['PC_monotonic_sent'] and (before['PC_monotonic_observed'] <= durable['PC_monotonic_observed'] <= after['PC_monotonic_observed']) and (durable['PC_boot_id'] == after['PC_boot_id']) and (durable['PC_monotonic_sent'] == after['PC_monotonic_sent']) and (0 <= after['PC_monotonic_elapsed'] <= 30) and (after['PC_monotonic_elapsed'] == after['PC_monotonic_observed'] - after['PC_monotonic_sent']) and (after['PC_monotonic_observed'] < after['permit_deadline_monotonic']), 'owner_decision_original_deadline_durable_witness')
        result = {'state': 'COMMITTED' if self._metadata_confirmed == wref and (not self._failed_commit) else 'FINISH_WITNESS_PRESENT', 'held': True, 'decision': decision, 'decision_ref': dref, 'witness': witness}
        if 'projections.json' in names:
            projection, _ = self.read('projections.json')
            need(set(projection) == {'schema', 'decision', 'witness', 'refs'} and projection['schema'] == 'owner-decision-projections/v1' and (projection['decision'] == dref) and (projection['witness'] == wref), 'owner_decision_exact_projection_authority')
            result['projections'] = projection['refs']
        return result

    def record_projections(self, refs):
        state = self.state()
        need(state['state'] == 'COMMITTED' and 'projections' not in state, 'owner_decision_projection_once_after_legal_finish')
        need(type(refs) is dict and set(refs) == {'actor', 'source'} and (set(refs['actor']) == {'terminal.json', 'completed.json', 'fence-released.json'}) and (set(refs['source']) == {'intent.json', 'completed.json', 'fence-released.json'}), 'owner_decision_exact_projection_names')
        _, witness_ref = self.read('durability-witness.json')
        return self.write('projections.json', {'schema': 'owner-decision-projections/v1', 'decision': state['decision_ref'], 'witness': witness_ref, 'refs': refs})

    def classify(self):
        """Cold diagnostic admission never promotes invalid journal to release.

        Partial/O_EXCL-created records remain intact. The fixed diagnostic is
        deliberately not a proof that their contents or outcome were accepted.
        Directory/leaf reads stay bounded and use the same held/named checks.
        """
        try:
            return self.state()
        except (DecisionRefused, ValueError, KeyError, TypeError, OverflowError, FileNotFoundError):
            return {'state': 'UNKNOWN_HELD', 'held': True, 'reason_code': 'owner_decision_state_unverified'}

    def abort(self, reason):
        need(reason in ('explicit_before_BEGIN_abort', 'uncommitted_permit_expired'), 'owner_decision_fixed_abort_reason')
        need(self.state()['state'] == 'PREPARED', 'owner_decision_abort_only_uncommitted')
        return self.write('aborted.json', {'schema': 'owner-decision-aborted/v1', 'state': 'ABORTED', 'reason': reason})
