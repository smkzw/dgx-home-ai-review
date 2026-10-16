# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Read-only structural/fullSHA cache checker; never equates model health to cache success.

Future parent calls only AFTER original Manager positively stops the exact ranks.
Native full --bytes 1 evidence is an additional required gate, not synthesized here.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
DTYPES = {'bfloat16': 2, 'float16': 2, 'float32': 4, 'int16': 2, 'int32': 4, 'int64': 8, 'uint8': 1, 'float8_e4m3fn': 1}
MAX_CACHE = 120000000000
MAX_INDEX = 8 * 1024 ** 2
CHECK_SHA = 'bd4fa969387ccda419ce42f0b93c841f05dc5b8556ed469a88ac857aebca3f1e'
TOKEN_SHA = 'de40bcdd71f24430ba82752ef385093be962adbf845a1c97db39161597d5dc28'

class Refusal(ValueError):
    pass

def need(ok, why):
    if not ok:
        raise Refusal(why)

def strict(raw):

    def pairs(rows):
        out = {}
        for k, v in rows:
            need(k not in out, 'duplicate_key')
            out[k] = v
        return out

    def finite(value):
        v = float(value)
        need(math.isfinite(v), 'nonfinite_JSON')
        return v
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=lambda _: (_ for _ in ()).throw(Refusal('nonfinite_JSON')))

def uint(x):
    return type(x) is int and 0 <= x < 2 ** 64

def identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def check_cache(directory, rank):
    need(type(rank) is int and rank in (0, 1), 'rank_required')
    root = Path(directory)
    need(all((not p.is_symlink() for p in (root, *root.parents))), 'symlink_parent')
    files = list(root.iterdir())
    need(len(files) == 1 and files[0].is_file() and (not files[0].is_symlink()), 'one_final_cache_no_partial')
    p = files[0]
    need(re.fullmatch('rank' + str(rank) + 'of2-[0-9a-f]{20}\\.bin', p.name), 'exact_rank_cache_name')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and 16 <= st.st_size <= MAX_CACHE, 'file_size_bound')
        f.seek(-16, 2)
        tail = f.read(16)
        need(tail[8:] == b'TFDSRK01', 'cache_magic')
        at = struct.unpack('<Q', tail[:8])[0]
        n = st.st_size - at - 16
        need(0 <= at <= st.st_size - 16 and 0 < n <= MAX_INDEX, 'bounded_index')
        f.seek(at)
        rows = strict(f.read(n))
        need(isinstance(rows, list) and 0 < len(rows) <= 100000, 'index_rows')
        seen = set()
        end = 0
        for row in rows:
            need(isinstance(row, list) and len(row) == 5, 'row_shape')
            key, dt, shape, offset, count = row
            need(isinstance(key, str) and 0 < len(key) <= 1024 and (key not in seen), 'unique_tensor_key')
            seen.add(key)
            need(isinstance(dt, str) and dt in DTYPES and isinstance(shape, list) and (len(shape) <= 4) and all((uint(v) for v in shape)), 'dtype_shape')
            expected = DTYPES[dt] * math.prod(shape)
            need(expected < 2 ** 64 and uint(offset) and uint(count) and (count == expected) and (offset == end) and (offset + count <= at), 'contiguous_exact_tensor_bytes')
            end = offset + count
        need(end == at, 'complete_data_coverage')
        f.seek(0)
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
        need(identity(os.fstat(f.fileno())) == identity(st) and identity(p.stat()) == identity(st), 'cache_changed_during_read')
    return {'file': p.name, 'sha256': h.hexdigest(), 'size': st.st_size, 'entries': len(rows), 'bytes': at, 'index_at': at, 'fd_identity': identity(st), 'native_bytes_verified': False}

def check_token_map(path, compressed_vocab):
    p = Path(path)
    need(all((not q.is_symlink() for q in (p, *p.parents))), 'token_map_symlink')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_size <= 4 * 1024 ** 2, 'map_size_bound')
        raw = f.read(4 * 1024 ** 2 + 1)
        need(identity(st) == identity(os.fstat(f.fileno())) == identity(p.stat()), 'map_changed')
    need(hashlib.sha256(raw).hexdigest() == TOKEN_SHA, 'actual_map_raw_SHA_not_verified')
    tm = strict(raw)
    need(isinstance(tm, list) and len(tm) == 129280, 'token_map_len')
    need(type(compressed_vocab) is int and 0 < compressed_vocab <= 129280 and all((type(v) is int and 0 <= v < compressed_vocab for v in tm)) and (set(tm) == set(range(compressed_vocab))), 'token_map_vocab')
    return {'sha256': TOKEN_SHA, 'length': len(tm), 'size': len(raw)}

def verify_native_check(result, cache, rank, engine_sha, model_path, cache_path):
    """Require the parent-captured actual exact command, rc and complete JSON output."""
    need(result.get('argv') == [model_path, cache_path, str(rank), '2', '--bytes', '1'], 'exact_native_full_bytes_argv')
    need(engine_sha == CHECK_SHA and result.get('binary_sha256') == CHECK_SHA and (type(result.get('rc')) is int) and (result['rc'] == 0), 'native_identity_exit')
    out = result.get('stdout')
    need(isinstance(out, str) and len(out.encode()) <= 65536, 'native_output_bound')
    v = strict(out)
    need(v.get('ok') is True and v.get('file') == cache['file'], 'native_exact_cache')
    for k in ('entries', 'planned', 'compared'):
        need(type(v.get(k)) is int and v[k] == cache['entries'], 'all_entries_compared')
    for k in ('mismatches', 'layout_mismatches', 'byte_mismatches'):
        need(type(v.get(k)) is int and v[k] == 0, 'native_mismatch')
    for k in ('bytes', 'index_at', 'compared_bytes'):
        need(type(v.get(k)) is int and v[k] == cache['bytes'], 'all_bytes_compared')
    return v
