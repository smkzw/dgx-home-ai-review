# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed before/after/release envelope, never a caller-selected program."""
import re
from pathlib import Path
from plan import need, strict, encode
from root_io import sha
import prelaunch_negative as negative
OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
PHASES = ('before-stop', 'after-stop')
ROOTS = {'before-stop': '/opt/dgx-v4/r16-normal-before', 'after-stop': '/opt/dgx-v4/r16-normal-after'}

def unit(phase, nonce):
    need(phase in PHASES and type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'R11_fixed_phase_nonce')
    return 'dgx-v4-prelaunch-' + phase + '-' + nonce + '.service'

def request(raw, current, worker_pin, phase):
    r = strict(raw)
    need(type(r) is dict and set(r) == {'schema', 'operation', 'phase', 'nonce', 'root', 'unit', 'worker_sha256', 'collector_request', 'PC_context_sha256'} and (r['schema'] == 'R11-normal-prestart-request/v1') and (r['operation'] == OPERATION) and (phase in PHASES) and (r['phase'] == phase) and (r['root'] == ROOTS[phase]) and (r['unit'] == unit(phase, r['nonce'])) and (r['worker_sha256'] == worker_pin), 'R11_exact_new_phase_request')
    need(type(r['PC_context_sha256']) is str and re.fullmatch('[0-9a-f]{64}', r['PC_context_sha256']), 'R11_protected_PC_phase_context_SHA')
    inner = negative.checked_request(encode(r['collector_request']), current)
    need(inner['nonce'] == r['nonce'] and inner['operation'] == r['operation'], 'R11_inner_outer_same_nonce_operation')
    return r

def make(phase, current, worker_pin, context, nonce):
    inner = {'schema': 'stage-not-launched-request/v1', 'operation': OPERATION, 'nonce': nonce, 'current': current, 'history_sha256': negative.APPROVED_POLICY['history_sha256']}
    r = {'schema': 'R11-normal-prestart-request/v1', 'operation': OPERATION, 'phase': phase, 'nonce': nonce, 'root': ROOTS[phase], 'unit': unit(phase, nonce), 'worker_sha256': worker_pin, 'collector_request': inner, 'PC_context_sha256': sha(encode(context))}
    raw = encode(r)
    request(raw, current, worker_pin, phase)
    return raw
