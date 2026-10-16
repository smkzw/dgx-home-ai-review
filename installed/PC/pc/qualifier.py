# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Independent actual Root positive installed-source qualifier. Never restarts."""
import time, types
from pathlib import Path
from contract import *
from managed_scope import positive
from epoch_transaction import idle, unchanged
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_WORKER_SHA = '9dfad7bd5c531ce5ddc05b57383f43c4b282a05a954cf975df190eb06a487350'

def finalize(native, scope, read=protected_read):
    need(APPROVED_REVIEW is not None and APPROVED_WORKER_SHA is not None, 'new_current_qualifier_SOURCE_pending')
    indexraw, ix = read(PC_ROOT / 'epoch-index.json')
    index = strict(indexraw)
    need(index['review_sha256'] == APPROVED_REVIEW, 'full_final_review_identity')
    returnedraw, rs = read(PC_ROOT / 'epoch-scope/once/returned-zero.json')
    returned = strict(returnedraw)
    positive(scope, returned, APPROVED_WORKER_SHA)
    need(returned['loader_sha256'] == index['files']['epoch-scope/loader.py'], 'actual_scope_loader_in_complete_final_source_index')
    for name, pin in index['files'].items():
        source, st = read(PC_ROOT / name, limit=2097152)
        need(sha(source) == pin, 'final_root_source_closed_before_qualification')
    raw, st = read(STATE / 'installed-unqualified.json', limit=4194304)
    inst = strict(raw)
    need(inst['schema'] == 'registry-R26-PC-installed-unqualified/v1' and inst['review_sha256'] == APPROVED_REVIEW and (inst['normal_stop_calls'] == inst['normal_start_calls'] == 1) and (inst['CAS_calls'] == 2) and (inst['socket_unlink_calls'] in (0, 1)) and (inst['models_started'] == 0) and (sha(raw) == returned['result']['installed_body_sha256']), 'actual_transaction_output_bound_to_native_return')
    gate = native.module('R11_qualified_phase_gate', 'r11-gate/gate_loader.py')
    gate.verify_installed(inst)
    limit = time.monotonic() + 90
    current = idle(native.capture(limit, old=False))
    unchanged(inst['before'], current, newmap=inst['current']['current_source118'], new_config_sha=inst['current']['config_sha256'])
    need(all((current[k] == inst['current'][k] for k in ('manager_identity', 'current_source118', 'source_files', 'config_sha256', 'config_stat', 'Cleaf', 'lease_full_F9', 'socket'))), 'new_current_same_live_epoch_full_identity')
    status = native.current_unarmed_idle(limit)
    mirror = PC_ROOT / 'current-installed-original.json'
    native.current.io.fresh(mirror, raw, mode=288, gid=989)
    mirrorraw, mirrormeta = read(mirror, limit=4194304)
    need(mirrorraw == raw, 'new_mirror_exact_original_raw_no_time_rewrite')
    sources = {}
    for name in ('worker.py', 'loader.py'):
        code, ss = read(PC_ROOT / 'epoch-scope' / name)
        sources[name] = {'sha256': sha(code), 'stat': ss}
    body = {'schema': 'registry-R26-current118-source-qualified/v1', 'operation': EPOCH_OPERATION, 'grant_operation': OPERATION, 'qualifier_sha256': sha(Path(__file__).read_bytes()), 'review_sha256': APPROVED_REVIEW, 'current': current, 'ancestor': inst['ancestor'], 'actual_installer_scope': scope, 'returned_original': returned, 'returned_original_raw_sha256': sha(returnedraw), 'returned_original_F9': rs, 'installed_original': {'sha256': sha(raw), 'stat': st}, 'installed_mirror': {'sha256': sha(mirrorraw), 'stat': mirrormeta}, 'scope_sources': sources, 'final_index_sha256': sha(indexraw), 'final_index_F9': ix, 'fresh_status_original': status, 'models_started': 0, 'grant_reserved': False, 'old_failures_preserved': True, 'observed_at': time.time()}
    native.current.io.fresh(PC_ROOT / 'current-source-qualified.json', encode(body), mode=288, gid=989)
    native.current.io.fresh(PC_ROOT / 'current-qualification-completed.json', encode({'schema': 'registry-R26-current118-qualified-completed/v1', 'qualifier_sha256': body['qualifier_sha256'], 'receipt_sha256': sha(encode(body)), 'manager_identity': current['manager_identity'], 'observed_at': time.time()}), mode=288, gid=989)
    return body

def finalize_history(scope, read=protected_read, write=None):
    need(APPROVED_REVIEW is not None and write is not None, 'history_qualifier_actual_Root_IO_pending')
    raw, st = read(PC_ROOT / 'historical-private/body.json')
    body = strict(raw)
    returnedraw, rs = read(HISTORY_ROOT / 'history-scope/once/returned-zero.json')
    returned = strict(returnedraw)
    indexraw, ix = read(HISTORY_ROOT / 'history-index.json')
    index = strict(indexraw)
    need(index['review_sha256'] == APPROVED_REVIEW, 'historical_review_source')
    positive(scope, returned, index['files']['history-scope/worker.py'], unit=HISTORY_UNIT)
    need(returned['result']['qualified_body_sha256'] == sha(raw) and body['producer_review_sha256'] == APPROVED_REVIEW, 'full_actual_historical_producer_result_bound')
    for name, pin in index['files'].items():
        code, cs = read(HISTORY_ROOT / name, limit=2097152)
        need(sha(code) == pin, 'actual_historical_final_source_closure')
    q = dict(body, schema='registry-R26-historical-qualified/v1', actual_readonly_scope=scope, returned_original=returned, qualified_body_sha256=sha(raw))
    write(PC_ROOT / 'historical/qualified.json', encode(q))
    write(PC_ROOT / 'historical/completed.json', encode({'schema': 'registry-R26-historical-completed/v1', 'qualified_sha256': sha(encode(q)), 'producer_sha256': body['producer_sha256'], 'observed_at': time.time()}))
    return q
