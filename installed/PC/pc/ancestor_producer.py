# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Full original frozen ancestor consume under a NEW isolated Root readonly worker.
No service restart, Core/DB write, negative callback, model or resource release.
"""
import os, sys, time, types
from pathlib import Path
from contract import *
from B_OWNER_RECOVERY_R25_WIRING import common
MODULES = None
APPROVED_OLD_ROOT_SOURCE_PINS = None
BODY = PC_ROOT / 'historical-private/body.json'
RAW = PC_ROOT / 'historical/raw'
APPROVED_PRODUCER_REVIEW = None

def produce(old_config_raw, old_identity, *, read=common.protected_read, write=None, now=time.time):
    need(APPROVED_PRODUCER_REVIEW is not None and APPROVED_OLD_ROOT_SOURCE_PINS is not None and (MODULES is not None) and (ANCESTOR_SPEC is not None), 'ancestor_actual_qualified_Source_pins_pending')
    cfg = strict(old_config_raw)
    cfg['_config_sha256'] = sha(old_config_raw)
    need(len(cfg['PC_source_pins']) == 118, 'old_actual118')
    originals = {}
    total = 0

    def record(name, path, raw, st):
        nonlocal total
        need(type(raw) is bytes and type(st) is list and (len(st) == 9) and (st[2] == len(raw)) and (st[6] == 1), 'origin_full_raw_F9')
        if name in originals:
            need(originals[name]['sha256'] == sha(raw) and originals[name]['origin_F9'] == st, 'same_origin_stable_across_full_consume')
            return
        total += len(raw)
        need(total <= 32 * 1024 ** 2 and len(originals) < 128, 'bounded_full_historical_batch')
        item = {'origin_path': str(path), 'sha256': sha(raw), 'origin_F9': st}
        need(write is not None, 'actual_Readonly_Root_archive_IO_required')
        item['mirror_F9'] = write(RAW / name, raw)
        originals[name] = item

    def wrapped(path, limit=4194304):
        raw, st = read(path, limit=limit)
        text = str(path)
        need(text.startswith((ANCESTOR_SPEC['epoch_root'] + '/', ANCESTOR_SPEC['negative_root'] + '/', str(CPU_ROOT) + '/', str(OPERATOR) + '/30f3c284a90b32bcd05e0380b381bfb7/')), 'no_credential_or_arbitrary_root_read')
        record('raw-' + sha(text.encode())[:24], path, raw, st)
        return (raw, st)
    previous = {name: sys.modules.get(name) for name, _ in MODULES}
    previous_read = common.protected_read
    try:
        mods = {}
        for name, path in MODULES:
            raw, st = read(path, limit=2097152)
            need(sha(raw) == APPROVED_OLD_ROOT_SOURCE_PINS[str(path)], 'exact_actual_original_ancestor_module_source')
            record('source-' + name, path, raw, st)
            m = types.ModuleType(name)
            m.__file__ = str(path)
            sys.modules[name] = m
            mods[name] = m
            exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        common.protected_read = wrapped
        for m in mods.values():
            if m.__dict__.get('protected_read') is previous_read:
                m.protected_read = wrapped
        epoch = mods['epoch_qualification'].consume(wrapped, cfg)
        negative = mods['negative_qualification'].consume_negative(wrapped, cfg, old_identity, now())
        need(epoch['receipt']['manager_identity'] == old_identity and negative['state'] == 'NEGATIVE_RELEASED' and (negative['CPU_success'] is False) and (negative['manager_identity'] == old_identity) and (negative['current_source118'] == cfg['PC_source_pins']), 'both_full_original_consumers_same_oldcfg_oldPID')
        for name, path in (('ancestor-epoch', Path(ANCESTOR_SPEC['epoch_receipt'])), ('ancestor-epoch-completed', Path(ANCESTOR_SPEC['epoch_completed'])), ('negative', Path(ANCESTOR_SPEC['negative_receipt'])), ('negative-completed', Path(ANCESTOR_SPEC['negative_completed']))):
            raw, st = wrapped(path)
            record(name, path, raw, st)
        for name in ('negative-released.json', 'maintenance-released.json'):
            raw, st = mods['private_originals'].read_private(name, negative=True)
            record('private-' + name, OPERATOR / '30f3c284a90b32bcd05e0380b381bfb7/negative-release-r25-r1' / name, raw, st)
        cfgraw, cs = read(CONFIG)
        need(cfgraw == old_config_raw, 'original_live_old_config_stable_before_stop')
        record('old-config', CONFIG, cfgraw, cs)
        body = {'schema': 'registry-R26-historical-body/v1', 'producer_review_sha256': APPROVED_PRODUCER_REVIEW, 'producer_sha256': sha(Path(__file__).read_bytes()), 'old_config_sha256': sha(old_config_raw), 'old_manager_identity': old_identity, 'old_source118': cfg['PC_source_pins'], 'physical_lease': LEASE, 'negative_state': 'NEGATIVE_RELEASED', 'CPU_success': False, 'ancestor_epoch_schema': epoch['receipt']['schema'], 'ancestor_root': ANCESTOR_SPEC['epoch_root'], 'originals': originals, 'old_failures_preserved': True, 'models_started': 0, 'observed_at': now()}
        return body
    finally:
        common.protected_read = previous_read
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
