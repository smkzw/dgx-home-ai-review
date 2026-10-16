# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual Root readonly IO reuse for a new PID; never constructs a Runtime."""
import os, time, stat, re
from pathlib import Path
from native import RootNative
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, HeldParent
from current_epoch import consume_installation
from restart_qualification import provisional, finalize, paths
APPROVED_C_RENEWAL_MODULE_SHA = None

def readable_directory(path, *, create):
    """Fixed Root receipt directory, exact 0:989/0750 despite UMask0077."""
    with HeldParent(path) as h:
        h.recheck()
        if create:
            os.mkdir(path.name, mode=488, dir_fd=h.parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=h.parent_fd)
        try:
            if create:
                os.fchown(fd, 0, 989)
                os.fchmod(fd, 488)
                os.fsync(fd)
                os.fsync(h.parent_fd)
            z = os.fstat(fd)
            named = os.stat(path.name, dir_fd=h.parent_fd, follow_symlinks=False)
            need(stat.S_ISDIR(z.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488) and ((z.st_dev, z.st_ino) == (named.st_dev, named.st_ino)), 'exact_Root_readable_directory_identity')
            h.recheck()
        finally:
            os.close(fd)

class RenewalNative(RootNative):

    def __init__(self, packet):
        self.fixed_Root_identity()
        self.packet = packet
        self.command_count = 0
        self.old = False
        self.stopped_mode = False
        self.after_cas = True
        self.before_cas = {}
        self.current = self.reader(False)

    def root_uid(self):
        return os.geteuid()

    def capture_current(self, end):
        return self.current.capture(end)

    def current_idle_status(self):
        v = self.current_unarmed_idle(time.monotonic() + 60)
        value = strict(v['reply_raw_utf8'])['result']
        need(value['schema'] == 'registry-R26-source-current-status/v1', 'actual_standby_same_Rootpeer_status')
        need(value['source118'] == self.current.config['PC_source_pins'], 'current_status_not_installation_identity')
        return value

    def exclusive(self, path, raw, *, mode=288, gid=989):
        self.current.io.fresh(path, raw, mode=mode, gid=gid)

    def scope_identity(self):
        identity = self.capture_current(time.monotonic() + 30)['manager_identity']
        return {'unit': 'dgx-v4-mimo-source-renewal-entryclock-r1-' + identity['invocation_id'] + '.service'}

    def source_originals(self):
        raw, st = protected_read(PC_ROOT / 'epoch-index.json')
        index = strict(raw)
        result = {}
        need(index['review_sha256'] == APPROVED_REVIEW, 'closed_same_reviewed_epoch_index')
        for name, pin in index['files'].items():
            body, meta = protected_read(PC_ROOT / name, limit=2097152)
            need(sha(body) == pin, 'complete_Root_renewal_source_before_publish')
            result[name] = {'sha256': pin, 'stat': meta}
        return result

    def C_current(self, read, config, identity, now):
        need(APPROVED_C_RENEWAL_MODULE_SHA is not None, 'new_C_current_renewal_source_pending')
        m = self.module('fixed_C_renewal', 'C_renewal_receiver.py')
        return m.consume(read, config, identity, now)

    def collect_provisional(self):
        current = self.capture_current(time.monotonic() + 60)
        identity = current['manager_identity']
        cfg = self.current.config
        installation = consume_installation(protected_read, cfg, self.wall())
        parent, _, _ = paths(identity)
        need(not parent.exists(), 'new_Runtime_PID_qualification_once')
        if parent.parent.exists():
            readable_directory(parent.parent, create=False)
            need(all((re.fullmatch('[0-9a-f]{32}', name) for name in os.listdir(parent.parent))), 'only_prior_actual_Runtime_invocations')
            for name in os.listdir(parent.parent):
                readable_directory(parent.parent / name, create=False)
        else:
            readable_directory(parent.parent, create=True)
        readable_directory(parent, create=True)
        self.current.io.fresh(parent / 'intent.json', encode({'schema': 'registry-R26-R6-runtime-qualification-intent/v1', 'identity': identity, 'source_review_sha256': APPROVED_REVIEW, 'observed_at': self.wall(), 'automatic_retry': False}), mode=288, gid=989)
        try:
            body = provisional(self, cfg, identity, installation, self.C_current, protected_read)
            raw = encode(body)
            self.exclusive(parent / 'provisional.json', raw)
            return {'body_sha256': sha(raw), 'manager_identity': identity, 'observed_at': body['observed_at']}
        except BaseException as e:
            self.exclusive(parent / 'failed.json', encode({'error_type': type(e).__name__, 'automatic_retry': False, 'partial_preserved': True, 'observed_at': self.wall()}))
            raise
