# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Immutable disjoint fixed-image segments; never copies a previous prefix."""
import hashlib, os, re, stat
from pathlib import Path
from range_catalog import load, need, sha, CHUNK, RESERVE
from range_component import Deadline, metadata, hash_fd, write_chunk, disk_reserve
APPROVED_LEGACY_REFS = [None, None]
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
SOURCE_ROOT = '/opt/dgx-v4/mimo-registry-r16'
STORE_ROOT = '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14'
MAX_SEGMENT = 64 * 1024 ** 2
MAX_BATCH = 256 * 1024 ** 2

def exact_ranges(rows):
    catalog = {b.digest: b for b in load().unique}
    need(type(rows) is list and 1 <= len(rows) <= 8, 'bounded_fixed_ranges')
    seen = []
    for r in rows:
        need(type(r) is dict and set(r) == {'digest', 'start', 'count'} and (r['digest'] in catalog), 'fixed63_range_descriptor')
        a, n = (r['start'], r['count'])
        need(type(a) is int and type(n) is int and (0 <= a < catalog[r['digest']].size) and (0 < n <= MAX_SEGMENT) and (a + n <= catalog[r['digest']].size), 'bounded_fixed_interval')
        need(not any((d == r['digest'] and max(a, s) < min(a + n, e) for d, s, e in seen)), 'no_duplicate_or_overlapping_ranges')
        seen.append((r['digest'], a, a + n))
    need(sum((r['count'] for r in rows)) <= MAX_BATCH, 'bounded_stage_bytes')
    return rows

def leaf_name(r):
    return r['digest'] + '.' + str(r['start']) + '-' + str(r['start'] + r['count'] - 1) + '.segment'

def private_dir(p):
    p = Path(p)
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    s = os.fstat(fd)
    try:
        need(s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 448 and (metadata(s) == metadata(p.lstat())), 'Root_private_segment_directory')
    except BaseException:
        os.close(fd)
        raise
    return fd

def readonly(ref, budget):
    from root_io import held
    need(type(ref) is dict and set(ref) in ({'path', 'sha256', 'F9', 'digest', 'start', 'count'}, {'path', 'sha256', 'F9', 'digest', 'start', 'count', 'receipt_ref'}) and re.fullmatch('[0-9a-f]{64}', ref['sha256']) and re.fullmatch('[0-9a-f]{64}', ref['digest']), 'complete_segment_reference')
    p = Path(ref['path'])
    need(APPROVED_LEGACY_REFS is not None and STORE_ROOT is not None, 'readonly_accepted_segment_sources_pending')
    if {k: ref[k] for k in ref if k != 'receipt_ref'} not in APPROVED_LEGACY_REFS:
        root = Path(STORE_ROOT)
        rel = p.relative_to(root)
        need(len(rel.parts) == 5 and rel.parts[0] == 'stages' and re.fullmatch('[0-9a-f]{32}', rel.parts[1]) and (rel.parts[2] == 'range') and (rel.parts[3] == 'segments') and (p.name == leaf_name(ref)), 'only_fixed_new_stage_segment_path')
        receipt = ref['receipt_ref']
        need(type(receipt) is dict and set(receipt) == {'path', 'sha256', 'F9'} and (receipt['path'] == str(p) + '.json'), 'accepted_segment_receipt_origin')
        rr, rs = held(Path(receipt['path']), receipt['sha256'], mode=384)
        need(rs == receipt['F9'], 'segment_receipt_original_fullF9')
        v = __import__('range_catalog').parse(rr)
        need(v['schema'] == 'fixed-image-immutable-range-segment/v1' and v['stage_operation'] == rel.parts[1] and (v['segment'] == {k: ref[k] for k in ('path', 'sha256', 'F9', 'digest', 'start', 'count')}) and (v['source_review_sha256'] == APPROVED_REVIEW) and re.fullmatch('[0-9a-f]{64}', v['plan_sha256']), 'source_operation_interval_bound_accepted_receipt')
        planraw, ps = held(Path(SOURCE_ROOT) / 'stages' / rel.parts[1] / 'plan.json', v['plan_sha256'], mode=384)
        pplan = __import__('range_catalog').parse(planraw)
        need(pplan['stage_operation'] == rel.parts[1] and pplan['review_sha256'] == APPROVED_REVIEW and ({k: ref[k] for k in ('digest', 'start', 'count')} in pplan['ranges']), 'source_held_original_stage_plan_for_segment')
    _, expected = held(p, mode=384, stat_only=True)
    need(expected == ref['F9'], 'Root_ancestry_segment_fullF9')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    meta = metadata(os.fstat(fd))
    try:
        need(meta == expected == metadata(p.lstat()) and meta[2] == ref['count'], 'immutable_original_segment_FD_named')
        need(hash_fd(fd, meta[2], budget) == ref['sha256'] and metadata(os.fstat(fd)) == meta == held(p, mode=384, stat_only=True)[1], 'immutable_original_segment_fullSHA')
        return fd
    except BaseException:
        os.close(fd)
        raise

def acquire(folder, ranges, budget, supply, *, binding):
    """One fixed Range invocation per interval. New output retained on failure."""
    ranges = exact_ranges(ranges)
    folder = Path(folder)
    need(type(binding) is dict and set(binding) == {'operation_family', 'stage_operation', 'source_review_sha256', 'plan_sha256'} and all((type(binding[k]) is str and re.fullmatch('[0-9a-f]{32}' if k in ('operation_family', 'stage_operation') else '[0-9a-f]{64}', binding[k]) for k in binding)), 'fixed_worker_segment_source_binding')
    dfd = private_dir(folder)
    before = metadata(os.fstat(dfd))
    out = []
    catalog = {b.digest: b for b in load().unique}
    try:
        need(os.listdir(dfd) == [], 'new_stage_segment_directory_empty')
        for r in ranges:
            budget.left()
            disk_reserve(dfd, sum((v['count'] for v in ranges)))
            n = leaf_name(r)
            fd = os.open(n, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=dfd)
            os.fchmod(fd, 384)
            stream = None
            try:
                s = metadata(os.fstat(fd))
                need(s[2] == 0 and s[3:7] == [0, 0, 33152, 1], 'new_owned_empty_segment')
                stream = supply(catalog[r['digest']], r['start'], r['count'])
                offset = 0
                h = hashlib.sha256()
                for chunk in stream:
                    budget.left()
                    need(type(chunk) is bytes and 0 < len(chunk) <= CHUNK and (offset + len(chunk) <= r['count']), 'bounded_segment_body')
                    h.update(chunk)
                    offset = write_chunk(fd, chunk, offset, budget)
                need(offset == r['count'], 'segment_exact_EOF')
                os.fsync(fd)
                budget.left()
                after = metadata(os.fstat(fd))
                need(after[0:2] == s[0:2] and after[2] == r['count'] and (after[3:7] == s[3:7]) and (after == metadata(os.stat(n, dir_fd=dfd, follow_symlinks=False))), 'segment_held_named_F9')
                digest = hash_fd(fd, offset, budget)
                need(digest == h.hexdigest() and metadata(os.fstat(fd)) == after, 'segment_readback_fullSHA')
                item = dict(r, path=str(folder / n), sha256=digest, F9=after)
                from root_io import fresh, held
                receipt = folder / (n + '.json')
                rr = (__import__('json').dumps(dict(schema='fixed-image-immutable-range-segment/v1', segment=item, **binding), sort_keys=True, separators=(',', ':')) + '\n').encode()
                fresh(receipt, rr, mode=384)
                saved, rs = held(receipt, mode=384)
                need(saved == rr, 'durable_segment_receipt_readback')
                out.append(dict(item, receipt_ref={'path': str(receipt), 'sha256': sha(rr), 'F9': rs}))
            finally:
                if stream is not None and hasattr(stream, 'close'):
                    stream.close()
                os.close(fd)
        need(sorted(os.listdir(dfd)) == sorted([x for r in ranges for x in (leaf_name(r), leaf_name(r) + '.json')]) and all((metadata(os.fstat(dfd))[i] == before[i] for i in (0, 1, 3, 4, 5))), 'stage_only_selected_outputs')
        os.fsync(dfd)
        return out
    finally:
        os.close(dfd)

def verify_blob(digest, refs, budget, sink=None):
    """Stream readonly ranges under descriptor SHA; incomplete stays PENDING."""
    blobs = {b.digest: b for b in load().unique}
    need(digest in blobs and type(refs) is list and (len(refs) <= 4096), 'fixed_blob_stream')
    parts = sorted(refs, key=lambda r: r['start'])
    offset = 0
    total = blobs[digest].size
    h = hashlib.sha256()
    for ref in parts:
        need(ref['digest'] == digest and type(ref['start']) is int and (type(ref['count']) is int) and (ref['count'] > 0) and (ref['start'] >= offset) and (ref['start'] + ref['count'] <= total), 'ordered_disjoint_blob_segments')
        if ref['start'] != offset:
            return {'state': 'BLOB_SEGMENTS_INCOMPLETE', 'digest': digest, 'whole_blob_verified': False}
        fd = readonly(ref, budget)
        try:
            pos = 0
            while pos < ref['count']:
                budget.left()
                raw = os.pread(fd, min(CHUNK, ref['count'] - pos), pos)
                need(raw, 'segment_read_progress')
                h.update(raw)
                pos += len(raw)
                budget.charge(len(raw))
                if sink is not None:
                    sink(raw)
            need(metadata(os.fstat(fd)) == ref['F9'] == metadata(Path(ref['path']).lstat()), 'readonly_segments_unchanged')
        finally:
            os.close(fd)
        offset += ref['count']
    if offset != total:
        return {'state': 'BLOB_SEGMENTS_INCOMPLETE', 'digest': digest, 'whole_blob_verified': False}
    need(h.hexdigest() == digest, 'whole_compressed_descriptor_SHA')
    return {'state': 'BLOB_FULL_SHA_VERIFIED', 'digest': digest, 'bytes': total, 'whole_blob_verified': True, 'image_imported': False, 'models_started': 0}

def archive_segments(fd, ordered_descriptors, by_digest, budget):
    """Readonly full-SHA segments into bounded deterministic OCI tar; no import."""
    import io, tarfile, json
    image = load()
    need(os.fstat(fd).st_size == 0 and ordered_descriptors == [(b.digest, b.size) for b in image.unique], 'fixed_complete_OCI_descriptor_order')
    for d, _ in ordered_descriptors:
        result = verify_blob(d, by_digest.get(d, []), budget)
        if not result['whole_blob_verified']:
            return {'state': 'OCI_SEGMENTS_INCOMPLETE', 'OCI_archive_built': False, 'image_imported': False}

    class Writer:

        def __init__(self):
            self.offset = 0

        def write(self, raw):
            need(type(raw) is bytes and self.offset + len(raw) <= 80 * 1024 ** 3, 'bounded_OCI_workspace')
            self.offset = write_chunk(fd, raw, self.offset, budget)
            return len(raw)

        def flush(self):
            budget.left()

    class Reader:

        def __init__(self, digest, refs):
            self.digest = digest
            self.parts = iter(sorted(refs, key=lambda r: r['start']))
            self.fd = None
            self.row = None
            self.pos = 0
            self.h = hashlib.sha256()
            self.total = 0

        def read(self, n):
            out = bytearray()
            while len(out) < n:
                if self.fd is None:
                    try:
                        self.row = next(self.parts)
                    except StopIteration:
                        break
                    need(self.row['start'] == self.total, 'stream_ordered_segments')
                    self.fd = readonly(self.row, budget)
                    self.pos = 0
                raw = os.pread(self.fd, min(CHUNK, n - len(out), self.row['count'] - self.pos), self.pos)
                need(raw, 'stream_segment_progress')
                self.pos += len(raw)
                self.total += len(raw)
                self.h.update(raw)
                out.extend(raw)
                budget.charge(len(raw))
                if self.pos == self.row['count']:
                    need(metadata(os.fstat(self.fd)) == self.row['F9'] == metadata(Path(self.row['path']).lstat()), 'OCI_stream_named_F9_unchanged')
                    os.close(self.fd)
                    self.fd = None
            return bytes(out)

        def close(self):
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
    writer = Writer()

    def add(tar, name, size, stream):
        info = tarfile.TarInfo(name)
        info.size = size
        info.mode = 420
        info.uid = info.gid = info.mtime = 0
        tar.addfile(info, stream)
    manifest = __import__('range_catalog').MANIFEST
    config = __import__('range_catalog').CONFIG
    index = (json.dumps({'schemaVersion': 2, 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': 'sha256:' + manifest, 'size': len(image.manifest_raw), 'platform': {'architecture': 'arm64', 'os': 'linux'}}]}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    with tarfile.open(fileobj=writer, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
        for name, raw in [('oci-layout', b'{"imageLayoutVersion":"1.0.0"}\n'), ('index.json', index), ('blobs/sha256/' + manifest, image.manifest_raw), ('blobs/sha256/' + config, image.config_raw)]:
            add(tar, name, len(raw), io.BytesIO(raw))
        for digest, size in ordered_descriptors:
            stream = Reader(digest, by_digest[digest])
            try:
                add(tar, 'blobs/sha256/' + digest, size, stream)
                need(stream.total == size and stream.h.hexdigest() == digest, 'actual_OCI_stream_full_descriptor_SHA')
            finally:
                stream.close()
    os.fsync(fd)
    return {'state': 'OCI_ARCHIVE_FULL_BLOBS_VERIFIED', 'bytes': writer.offset, 'all63_fullSHA_verified': True, 'OCI_archive_built': True, 'image_imported': False, 'models_started': 0}
