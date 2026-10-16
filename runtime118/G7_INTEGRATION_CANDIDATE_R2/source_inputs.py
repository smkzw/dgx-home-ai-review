# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed public authoritative file set; 49+4+222, including kit/MANIFEST."""
import json
from pathlib import Path
from .durable import need
DATA = json.loads((Path(__file__).parent / 'WEIGHT_INPUTS.json').read_bytes())
PYTHON = json.loads((Path(__file__).parent / 'PYTHON_INPUTS.json').read_bytes())

def rows(kind):
    if kind == 'python':
        return [dict(path=k, size=v['bytes'], sha256=v['sha256'], git_blob_oid=v['git_blob_oid'], is_lfs=False) for k, v in PYTHON['files'].items()]
    return DATA['groups'][kind]['files']

def verify_rows(kind, actual):
    expected = {x['path']: x for x in rows(kind)}
    need({x['path'] for x in actual} == set(expected) and len(actual) == len(expected), 'complete_official_weight_input_set')
    for row in actual:
        e = expected[row['path']]
        need(row['size'] == e['size'] and (e['sha256'] is None or row['sha256'] == e['sha256']), 'official_weight_size_LFS_SHA')
    return expected
