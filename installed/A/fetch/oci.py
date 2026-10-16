# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Stream a deterministic OCI archive; no extraction, import, or executable launch."""
import hashlib
import io
import json
import os
import tarfile
from contract import CHUNK, CONFIG, MANIFEST, RESERVE, load, need, sha
from fetch import write_all

class Payload:

    def __init__(self, fd, blob, budget):
        self.fd, self.blob, self.budget = (fd, blob, budget)
        self.count, self.h = (0, hashlib.sha256())

    def read(self, n):
        self.budget.left()
        need(0 <= n <= CHUNK, 'bounded_tar_read')
        data = os.read(self.fd, n)
        self.count += len(data)
        self.h.update(data)
        return data

    def finish(self):
        need(self.count == self.blob.size and self.h.hexdigest() == self.blob.digest and (os.read(self.fd, 1) == b''), 'OCI_stream_fullSHA')

class Sink:

    def __init__(self, writer, budget):
        self.writer, self.budget = (writer, budget)
        self.bytes, self.h = (0, hashlib.sha256())

    def write(self, data):
        self.budget.left()
        need(len(data) <= CHUNK, 'bounded_tar_write')
        need(self.writer(data) == len(data), 'tar_sink_write')
        self.bytes += len(data)
        self.h.update(data)
        return len(data)

def entry(archive, name, size, reader):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.uid, info.gid, info.mtime = (size, 384, 0, 0, 0)
    info.uname = info.gname = ''
    archive.addfile(info, reader)

def assemble(image, store, budget, writer):
    need(image == load(), 'OCI_fixed_all_descriptors_required')
    need(sha(image.manifest_raw) == MANIFEST and sha(image.config_raw) == CONFIG, 'OCI_fixed_inputs')
    sink = Sink(writer, budget)
    from plan import oci_index_bytes
    index = oci_index_bytes(image.manifest_raw)
    with tarfile.open(fileobj=sink, mode='w|', format=tarfile.USTAR_FORMAT, bufsize=10240) as archive:
        for name, data in [('oci-layout', b'{"imageLayoutVersion":"1.0.0"}'), ('index.json', index), ('blobs/sha256/' + MANIFEST, image.manifest_raw), ('blobs/sha256/' + CONFIG, image.config_raw)]:
            entry(archive, name, len(data), io.BytesIO(data))
        for blob in image.unique:
            with store.verified(blob, budget, verify=False) as (fd, _):
                payload = Payload(fd, blob, budget)
                entry(archive, 'blobs/sha256/' + blob.digest, blob.size, payload)
                payload.finish()
    return {'archive_bytes': sink.bytes, 'archive_sha256': sink.h.hexdigest(), 'unique_layer_blobs': len(image.unique), 'descriptors_preserved': len(image.layers), 'compressed_SHA': True, 'uncompressed_diff_ids_verified': False, 'imported': False, 'ARM_ABI_numeric_media_accepted': False}

def archive_file(image, store, budget):
    """Publish only a fully rehashed archive. Failure leaves its partial intact."""
    free = os.fstatvfs(store.fd)
    need(free.f_bavail * free.f_frsize >= image.unique_bytes + RESERVE + 1024 ** 2, 'archive_disk_reserve')
    store.check()
    fd = os.open('image.oci.tar.part', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=store.fd)
    try:

        def writer(data):
            write_all(fd, data)
            return len(data)
        receipt = assemble(image, store, budget, writer)
        os.fsync(fd)
        before = os.fstat(fd)
        need(before.st_nlink == 1 and before.st_size == receipt['archive_bytes'] and (os.stat('image.oci.tar.part', dir_fd=store.fd, follow_symlinks=False).st_ino == before.st_ino), 'archive_part_identity')
        store.check()
        os.link('image.oci.tar.part', 'image.oci.tar', src_dir_fd=store.fd, dst_dir_fd=store.fd, follow_symlinks=False)
        os.fsync(store.fd)
        os.unlink('image.oci.tar.part', dir_fd=store.fd)
        os.fsync(store.fd)
        return receipt
    finally:
        os.fsync(fd)
        os.close(fd)
