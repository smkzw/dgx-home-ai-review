# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed new A source-origin receipt. No source installation or asset launch."""
import base64, os, stat
from pathlib import Path
from root_io import held, sha, f9, fresh
from plan import need, strict, encode
APPROVED = None
ROOT = None
PC_ROOT = None

def validate(raw):
    need(type(APPROVED) is dict and ROOT is not None and (PC_ROOT is not None), 'A_origin_SOURCE_None')
    v = strict(raw)
    need(set(v) == {'schema', 'source_root', 'source_epoch', 'review_sha256', 'files', 'boot_original'} and v['schema'] == 'R12-A-source-held-original/v1' and (v['source_root'] == ROOT) and (v['source_epoch'] == APPROVED['operation']) and (v['review_sha256'] == APPROVED['review']) and (set(v['files']) == set(APPROVED['source_pins'])), 'A_origin_exact_source_domain')
    for name, row in v['files'].items():
        s = row['F9']
        need(set(row) == {'sha256', 'F9'} and row['sha256'] == APPROVED['source_pins'][name] and (type(s) is list) and (len(s) == 9) and all((type(x) is int and x >= 0 for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[2] == APPROVED['source_sizes'][name]) and (s[3:7] == [0, 0, 33152, 1]), 'A_origin_full_source_SHA_F9')
    b = v['boot_original']
    r = base64.b64decode(b['raw_b64'], validate=True)
    s = b['F9']
    need(set(b) == {'raw_b64', 'sha256', 'F9'} and sha(r) == b['sha256'] and (len(r) == 37) and (s[3] == 0) and (s[2] == 0) and (s[6] == 1) and (r.decode().strip().count('-') == 4), 'A_origin_kernel_boot_actual_proc_zero_size')
    return v

def collect():
    need(os.getuid() == os.geteuid() == 0 and type(APPROVED) is dict, 'A_origin_Root_fixed_source')
    files = {}
    for name, pin in APPROVED['source_pins'].items():
        raw, s = held(Path(ROOT) / name, pin, cap=2097152, mode=384)
        need(len(raw) == APPROVED['source_sizes'][name], 'A_origin_source_size')
        files[name] = {'sha256': sha(raw), 'F9': s}
    p = Path('/proc/sys/kernel/random/boot_id')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = f9(os.fstat(fd))
        raw = os.read(fd, 128)
        need(before == f9(os.fstat(fd)) == f9(p.lstat()) and len(raw) == 37, 'A_origin_boot_full_F9')
        boot = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': before}
    finally:
        os.close(fd)
    v = {'schema': 'R12-A-source-held-original/v1', 'source_root': ROOT, 'source_epoch': APPROVED['operation'], 'review_sha256': APPROVED['review'], 'files': files, 'boot_original': boot}
    validate(encode(v))
    for name, row in files.items():
        need(held(Path(ROOT) / name, row['sha256'], mode=384)[1] == row['F9'], 'A_origin_source_after_collection')
    out = Path(ROOT) / 'source-origin.json'
    fresh(out, encode(v), mode=384)
    raw, s = held(out, sha(encode(v)), mode=384)
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}

def publish(original, current):
    need(os.getuid() == os.geteuid() == 0, 'A_origin_PC_Root_publisher')
    need(type(original) is dict and set(original) == {'raw_b64', 'sha256', 'F9'}, 'A_origin_exact_Root_original')
    raw = base64.b64decode(original['raw_b64'], validate=True)
    s = original['F9']
    need(sha(raw) == original['sha256'] and s[2] == len(raw) <= 2097152 and (s[3:7] == [0, 0, 33152, 1]), 'A_origin_actual_remote_Root_raw_F9')
    v = validate(raw)
    need(current['review_sha256'] == APPROVED['review'] and len(current['source118']) == 118, 'A_origin_new_qualified_current_binding')
    body = encode({'schema': 'R12-PC-held-A-source-origin/v1', 'current': current, 'A_original': original})
    out = Path(PC_ROOT) / 'A-source-origin.json'
    fresh(out, body, mode=288)
    os.chown(out, 0, 989)
    os.chmod(out, 288)
    held(out, sha(body), mode=288)
    return {'path': str(out), 'sha256': sha(body), 'source_files': len(v['files'])}
