# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Lossless bounded receipt wire envelope. No authority, timestamp or field edits."""
import base64, binascii, hashlib, json, re, zlib
RAW_CAP = 4 * 1024 ** 2
COMPRESSED_CAP = 1024 ** 2
B64_CAP = 4 * ((COMPRESSED_CAP + 2) // 3)
SCHEMA = 'reserved-parent-RPC-lossless/v1'
KEYS = {'schema', 'encoding', 'raw_bytes', 'raw_sha256', 'compressed_bytes', 'compressed_sha256', 'payload_b64'}

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def integer(v):
    return type(v) is int

def pack(raw):
    need(type(raw) is bytes and 0 < len(raw) <= RAW_CAP, 'receipt_raw_exactbytes_fixed4MiB')
    comp = zlib.compress(raw, 9)
    need(0 < len(comp) <= COMPRESSED_CAP, 'receipt_compressed_fixed1MiB')
    return {'schema': SCHEMA, 'encoding': 'zlib+base64', 'raw_bytes': len(raw), 'raw_sha256': sha(raw), 'compressed_bytes': len(comp), 'compressed_sha256': sha(comp), 'payload_b64': base64.b64encode(comp).decode('ascii')}

def unpack(envelope):
    need(type(envelope) is dict and set(envelope) == KEYS and (envelope['schema'] == SCHEMA) and (envelope['encoding'] == 'zlib+base64'), 'exact_lossless_envelope_no_extra')
    n = envelope['raw_bytes']
    size = envelope['compressed_bytes']
    text = envelope['payload_b64']
    need(integer(n) and 0 < n <= RAW_CAP and integer(size) and (0 < size <= COMPRESSED_CAP) and (type(text) is str) and (len(text) <= B64_CAP), 'bounded_sizes_and_payload_type')
    for key in ('raw_sha256', 'compressed_sha256'):
        need(type(envelope[key]) is str and re.fullmatch('[0-9a-f]{64}', envelope[key]), 'exact_hex_receipt_SHA')
    try:
        comp = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise Refused('strict_receipt_base64') from e
    need(len(comp) == size and base64.b64encode(comp).decode('ascii') == text and (sha(comp) == envelope['compressed_sha256']), 'exact_compressed_original_bytes_SHA')
    try:
        obj = zlib.decompressobj(zlib.MAX_WBITS)
        raw = obj.decompress(comp, n + 1)
    except zlib.error as e:
        raise Refused('receipt_zlib_CRC_or_stream') from e
    need(len(raw) == n and len(raw) <= RAW_CAP and obj.eof and (obj.unused_data == obj.unconsumed_tail == b''), 'receipt_EOF_no_trailing_no_bomb')
    need(sha(raw) == envelope['raw_sha256'], 'exact_unmodified_full_receipt_SHA')
    return raw
