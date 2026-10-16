# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed raw history -> independent lossless data packet. No Root metadata fake."""
from source_io import base, load_source, HERE, sha, encode, need

def materialize():
    codec = load_source(base('PC/service/receipt_codec.py'), 'pure_exact_receipt_codec', HERE / 'receipt_codec.py')
    files = {}
    pins = {}
    for name in ('pc', 'a', 'sources'):
        raw = base('INPUTS/zero-history-' + name + '.raw')
        packed = encode(codec.pack(raw))
        need(codec.unpack(__import__('json').loads(packed)) == raw, 'full_lossless_old_history_readback')
        need(len(packed) <= 2097152, 'single_history_data_leaf_cap')
        files[name] = packed
        pins[name] = {'packed_sha256': sha(packed), 'raw_sha256': sha(raw)}
    need(sum(map(len, files.values())) <= 4194304, 'independent_data_batch4MiB')
    return (files, pins)
