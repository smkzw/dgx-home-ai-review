# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import fcntl, hashlib, math, os, re, stat, time
from dataclasses import dataclass
from range_catalog import load as fixed_catalog, Blob, CHUNK, RATE, RESERVE, need, Refused
MAX_RANGE = 64 * 1024 ** 2
ACTUAL_AUTHORITY = None
ACTUAL_GRANT = None
ACTUAL_NAMESPACE = None
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def metadata(s):
    return [getattr(s, k) for k in FIELDS]

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def valid_f9(s, *, directory=False):
    need(type(s) is list and len(s) == 9 and all((type(v) is int for v in s)) and (s[0] > 0) and (s[1] > 0) and (s[2] >= 0) and (s[3:5] == [0, 0]) and (s[7] >= 0) and (s[8] >= 0), 'strict_full_F9')
    need(stat.S_ISDIR(s[5]) and s[5] & 511 == 448 if directory else s[5] == 33152 and s[6] == 1, 'private_original_metadata')

def descriptor(blob):
    need(type(blob) is Blob and blob in fixed_catalog().unique, 'fixed_original_63_descriptor_required')
    return blob

class Deadline:
    """Injected ORIGINAL absolute monotonic window. Never creates/extends one."""

    def __init__(self, original_started, original_deadline, *, clock=time.monotonic, sleep=time.sleep, observer=None):
        need(all((type(v) in (int, float) and math.isfinite(v) for v in (original_started, original_deadline))) and 0 <= original_started and (0 < original_deadline - original_started <= 1800), 'original_finite_window')
        self._window = (original_started, original_deadline)
        self.clock, self.sleep, self.observer = (clock, sleep, observer)
        self._last_clock = None
        self.io_bytes = 0
        self.left()
        self.io_started = self.clock()

    @property
    def started(self):
        return self._window[0]

    @property
    def deadline(self):
        return self._window[1]

    @deadline.setter
    def deadline(self, value):
        need(type(value) in (int, float) and math.isfinite(value) and (self.started < value <= self._window[1]), 'original_deadline_can_only_shorten')
        self._window = (self.started, value)

    def left(self):
        if self.observer is not None:
            self.observer()
        now = self.clock()
        need(type(now) in (int, float) and math.isfinite(now) and (self.started <= now < self.deadline) and (self._last_clock is None or now >= self._last_clock), 'original_window_expired_or_clock_invalid')
        self._last_clock = now
        return self.deadline - now

    def charge(self, count):
        need(type(count) is int and 0 < count <= 2 * CHUNK, 'bounded_IO_charge')
        self.left()
        self.io_bytes += count
        delay = self.io_bytes / RATE - (self.clock() - self.io_started)
        if delay > 0:
            need(delay < self.left(), 'original_window_insufficient_for_IO_cap')
            self.sleep(delay)
        self.left()

    def wait(self, seconds):
        need(type(seconds) in (int, float) and 0 <= seconds < self.left(), 'bounded_original_wait')
        target = self.clock() + seconds
        while self.clock() < target:
            self.left()
            self.sleep(min(0.1, target - self.clock()))
        self.left()

@dataclass(repr=False)
class Held:
    fd: int
    parent_fd: int
    name: str
    expected_f9: list
    parent_f9: list

    def check(self, *, empty=False, writable=False):
        valid_f9(self.expected_f9)
        valid_f9(self.parent_f9, directory=True)
        need(type(self.fd) is int and type(self.parent_fd) is int and (self.fd >= 0) and (self.parent_fd >= 0) and (type(self.name) is str) and re.fullmatch('[0-9a-f]{64}(?:\\.part)?', self.name), 'fixed_digest_leaf_not_external_path')
        need(metadata(os.fstat(self.parent_fd)) == self.parent_f9, 'held_original_parent_drift')
        actual = metadata(os.fstat(self.fd))
        named = metadata(os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False))
        need(actual == named == self.expected_f9, 'held_named_full_F9_drift')
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        access = flags & os.O_ACCMODE
        need(access == os.O_RDWR and (not flags & os.O_APPEND) if writable else access == os.O_RDONLY, 'exact_held_access_mode')
        if empty:
            need(actual[2] == 0, 'new_output_must_be_empty')
        return actual

    def check_after_write(self, size):
        actual = metadata(os.fstat(self.fd))
        valid_f9(actual)
        need(actual[0:2] == self.expected_f9[0:2] and actual[3:7] == self.expected_f9[3:7] and (actual[2] == size) and (actual == metadata(os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False))) and (metadata(os.fstat(self.parent_fd)) == self.parent_f9), 'new_output_named_identity_or_size_drift')
        return actual

def hash_fd(fd, size, budget):
    h = hashlib.sha256()
    offset = 0
    while offset < size:
        budget.left()
        raw = os.pread(fd, min(CHUNK, size - offset), offset)
        need(type(raw) is bytes and 0 < len(raw) <= min(CHUNK, size - offset), 'original_FD_truncation')
        h.update(raw)
        offset += len(raw)
        budget.charge(len(raw))
    need(os.pread(fd, 1, size) == b'', 'original_FD_extra_EOF')
    budget.left()
    return h.hexdigest()

def disk_reserve(fd, remaining):
    s = os.fstatvfs(fd)
    need(s.f_bavail * s.f_frsize >= RESERVE + remaining, 'original_disk_reserve100GiB')

def write_chunk(fd, raw, offset, budget):
    view = memoryview(raw)
    while view:
        budget.left()
        n = os.pwrite(fd, view, offset)
        need(n > 0, 'new_output_write_progress')
        view = view[n:]
        offset += n
        budget.charge(n)
    return offset
