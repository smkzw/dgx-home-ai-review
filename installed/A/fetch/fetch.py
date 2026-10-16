# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Bounded file-only download algorithm. Native admission/launch is deliberately absent."""
import fcntl
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from contract import CHUNK, RATE, RESERVE, Refused, load, need
from transport import TokenPool

def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def directory_identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)

def write_all(fd, data):
    while data:
        n = os.write(fd, data)
        need(n > 0, 'write_progress')
        data = data[n:]

class Store:
    """One pre-created private directory, one persistent flock, no silent overwrite."""

    def __init__(self, root):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.lock = None
        try:
            s = os.fstat(self.fd)
            need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and (stat.S_IMODE(s.st_mode) == 448), 'private_store_owner_mode')
            self.root_identity = directory_identity(s)
            self.lock = os.open('writer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 384, dir_fd=self.fd)
            ls = os.fstat(self.lock)
            need(stat.S_ISREG(ls.st_mode) and ls.st_uid == os.geteuid() and (stat.S_IMODE(ls.st_mode) == 384) and (ls.st_nlink == 1), 'persistent_writer_lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_identity = identity(ls)
        except Exception:
            self.close()
            raise Refused('store_admission_failed') from None

    def check(self):
        need(directory_identity(os.fstat(self.fd)) == self.root_identity, 'held_store_drift')
        need(identity(os.fstat(self.lock)) == self.lock_identity and identity(os.stat('writer.lock', dir_fd=self.fd, follow_symlinks=False)) == self.lock_identity, 'writer_lock_drift')

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if getattr(self, 'fd', None) is not None:
            os.close(self.fd)
            self.fd = None

    def record(self, name, value):
        self.check()
        need(name in ('operation.started.json', 'operation.failed.json', 'operation.completed.json') or (name.startswith('verified-') and name.endswith('.json') and (len(name) == 78)), 'fixed_receipt_name')
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        need(len(raw) <= 4096, 'receipt_cap')
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.fd)
        try:
            write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)

    @contextmanager
    def verified(self, blob, budget, verify=True):
        self.check()
        fd = os.open(blob.digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and (before.st_nlink == 1) and (stat.S_IMODE(before.st_mode) == 384) and (before.st_size == blob.size), 'held_blob_metadata')
            if verify:
                h = hashlib.sha256()
                while True:
                    budget.left()
                    data = os.read(fd, CHUNK)
                    if not data:
                        break
                    h.update(data)
                need(h.hexdigest() == blob.digest, 'held_blob_fullSHA')
            need(identity(os.fstat(fd)) == identity(before) and identity(os.stat(blob.digest, dir_fd=self.fd, follow_symlinks=False)) == identity(before), 'held_blob_fullSHA_stable')
            self.check()
            os.lseek(fd, 0, os.SEEK_SET)
            yield (fd, identity(before))
            need(identity(os.fstat(fd)) == identity(before) and identity(os.stat(blob.digest, dir_fd=self.fd, follow_symlinks=False)) == identity(before), 'held_blob_changed_after_use')
            self.check()
        finally:
            os.close(fd)

    def exists(self, blob):
        try:
            os.stat(blob.digest, dir_fd=self.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def receive(self, blob, chunks, budget):
        self.check()
        fd = os.open(blob.digest + '.part', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.fd)
        count, h = (0, hashlib.sha256())
        started = budget.clock()
        try:
            for data in chunks:
                budget.left()
                need(type(data) is bytes and 0 < len(data) <= CHUNK and (count + len(data) <= blob.size), 'bounded_blob_chunk')
                count += len(data)
                h.update(data)
                write_all(fd, data)
                delay = count / RATE - (budget.clock() - started)
                if delay > 0:
                    budget.wait(delay)
                need(os.fstatvfs(self.fd).f_bavail * os.fstatvfs(self.fd).f_frsize >= RESERVE, 'disk_reserve')
            need(count == blob.size and h.hexdigest() == blob.digest, 'full_blob_size_SHA')
            os.fsync(fd)
            before = os.fstat(fd)
            need(before.st_nlink == 1 and before.st_size == count and (identity(os.stat(blob.digest + '.part', dir_fd=self.fd, follow_symlinks=False)) == identity(before)), 'part_identity_before_publish')
            self.check()
            os.link(blob.digest + '.part', blob.digest, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            need(os.stat(blob.digest, dir_fd=self.fd, follow_symlinks=False).st_ino == before.st_ino, 'published_same_inode')
            os.fsync(self.fd)
            os.unlink(blob.digest + '.part', dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.fsync(fd)
            os.close(fd)

class Fetcher:

    def __init__(self, image, store, transport, supplier, budget):
        need(image == load(), 'fixed_image_all_descriptors_required')
        self.image, self.store, self.transport, self.budget = (image, store, transport, budget)
        self.tokens = TokenPool(supplier, budget)
        self.requested = set()
        self.poisoned = False

    def run(self):
        need(not self.poisoned, 'operation_poisoned')
        self.store.record('operation.started.json', {'state': 'STARTED', 'native_authorization': False, 'unique_blobs': len(self.image.unique), 'retry': 0})
        try:
            free = os.fstatvfs(self.store.fd)
            need(free.f_bavail * free.f_frsize >= self.image.unique_bytes + RESERVE, 'initial_payload_disk_budget')
            for b in self.image.unique:
                self.budget.left()
                if self.store.exists(b):
                    with self.store.verified(b, self.budget):
                        pass
                    continue
                need(b.digest not in self.requested, 'one_logical_blob_GET')
                seconds = 30
                token = self.tokens.acquire(seconds + 30)
                self.requested.add(b.digest)
                try:
                    chunks = self.transport.chunks(b, token, seconds)
                    try:
                        self.store.receive(b, chunks, self.budget)
                    finally:
                        close = getattr(chunks, 'close', None)
                        if close:
                            close()
                finally:
                    self.tokens.release()
                self.store.record('verified-' + b.digest + '.json', {'digest': b.digest, 'bytes': b.size, 'fullSHA': True})
            self.store.record('operation.completed.json', {'state': 'BLOBS_FULL_SHA_VERIFIED', 'logical_blob_requests_claimed': len(self.requested), 'token_supplies': self.tokens.supplies, 'OCI_import': False, 'ABI_verified': False})
        except Exception:
            self.poisoned = True
            try:
                self.store.record('operation.failed.json', {'state': 'FAILED_STICKY', 'reason_code': 'fetch_failed', 'logical_blob_requests_claimed': len(self.requested), 'retry': 0, 'partial_preserved': True})
            except Exception:
                pass
            raise Refused('fetch_failed_sticky') from None
