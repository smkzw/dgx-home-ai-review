# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One new parent finite1800; no native intent during SOURCE/late publication."""
import hashlib, json, math, os, re, subprocess, sys, time
from pathlib import Path
OPERATION = 'ed7021db9df4c839d02f3271361924de'
APPROVED_CONTEXT = None
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

class Refused(ValueError):
    pass

def need(v, c):
    if not v:
        raise Refused(c)

def boot():
    need(sys.platform == 'darwin', 'actual_parent_Mac_only')
    r = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], capture_output=True, timeout=5)
    need(r.returncode == 0 and (not r.stderr), 'actual_parent_boot')
    v = r.stdout.decode('ascii').strip().lower()
    need(re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', v) is not None, 'actual_Mac_boot_uuid')
    return v

class Window:

    def __init__(self):
        need(type(APPROVED_CONTEXT) is dict, 'late_actual_current_context_None')
        root = Path(__file__).resolve().parent
        self.boot = boot()
        self.m = time.monotonic()
        self.w = time.time()
        self.end = self.m + 1800
        self.cutoff = self.w + 1800
        self.last = (self.w, self.m)
        body = dict(schema='registry-new-parent-finite-invoke/v1', operation=OPERATION, issued_at=self.w, monotonic_origin=self.m, deadline_monotonic=self.end, deadline_wall=self.cutoff, Mac_boot_id=self.boot, whole_seconds=1800, automatic_retry=False, current_context=APPROVED_CONTEXT)
        parent = root / 'parent-finite-invoke'
        parent.mkdir(mode=448)
        self.path = parent / 'intent.json'
        raw = (json.dumps(body, sort_keys=True, separators=(',', ':')) + '\n').encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        try:
            os.fchmod(fd, 384)
            v = memoryview(raw)
            while v:
                n = os.write(fd, v)
                need(n > 0, 'full_parent_intent_write')
                v = v[n:]
            os.fsync(fd)
            self.stat = [getattr(os.fstat(fd), k) for k in FIELDS]
        finally:
            os.close(fd)
        dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        self.pin = hashlib.sha256(raw).hexdigest()
        self.check()

    def check(self, *, cleanup=False):
        need(boot() == self.boot, 'parent_boot_changed')
        w = time.time()
        m = time.monotonic()
        need(all((type(x) in (float, int) and math.isfinite(x) for x in (w, m, self.w, self.m))) and w >= self.last[0] and (m >= self.last[1]) and (abs(w - self.w - (m - self.m)) <= 30), 'parent_clock_backward_or_drift')
        need(cleanup or (w < self.cutoff and m < self.end), 'new_parent_finite_expired_no_reset')
        self.last = (w, m)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            z = os.fstat(fd)
            need([getattr(z, k) for k in FIELDS] == self.stat == [getattr(self.path.lstat(), k) for k in FIELDS], 'parent_intent_full_F9')
            raw = os.pread(fd, z.st_size + 1, 0)
            need(hashlib.sha256(raw).hexdigest() == self.pin, 'parent_intent_fullSHA')
        finally:
            os.close(fd)
        return min(self.end - m, self.cutoff - w)

    def check_cleanup(self):
        self.check(cleanup=True)
        return True
