# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def origin_readback(launcher, plan, receipt):
    """Read actual archived origin after true retained EXIT0 and owned stop."""
    root = Path(plan['root'])
    raw, meta = launcher.read(root / 'readonly-qualified.json', 4194304)
    need(raw == launcher.encoded(receipt) and len(meta) == 9 and all((type(x) is int for x in meta)) and (meta[2] == len(raw)) and (meta[3:7] == [0, 0, stat.S_IFREG | 384, 1]), 'actual_Spark_origin_raw_F9_not_PC_mirror')
    originals = {}
    for name in ('owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'):
        body, st = launcher.read(root / name, 4194304)
        need(len(st) == 9 and all((type(x) is int for x in st)) and (st[2] == len(body)) and (st[3:7] == [0, 0, stat.S_IFREG | 384, 1]), 'actual_owned_stop_original_Root_F9')
        originals[name] = {'path': str(root / name), 'raw_b64': base64.b64encode(body).decode(), 'sha256': hashlib.sha256(body).hexdigest(), 'stat': st}
    intent = strict(base64.b64decode(originals['owned-stop-intent.json']['raw_b64']))
    result = strict(base64.b64decode(originals['owned-stop-result.json']['raw_b64']))
    after = strict(base64.b64decode(originals['owned-stop-observed.json']['raw_b64']))
    need(intent['unit'] == plan['unit'] and intent['invocation_id'] == receipt['intent']['invocation_id'] and (intent['owned_scope_stop_calls'] == 1) and (result['rc'] == 0) and (base64.b64decode(result['stderr_b64']) == b'') and (after['unit']['MainPID'] == '0') and (after['unit']['ActiveState'] == 'inactive') and (after['cgroup_procs'] == []) and (after['boot_id'] == receipt['actual_retained_EXIT0']['boot_id']), 'actual_owned_stop_not_pending_flag_rewrite')
    need(receipt['observed_at'] <= intent['issued_at'] <= result['observed_at'] <= after['observed_at'], 'original_owned_stop_time_order')
    return {'schema': 'C-renewal-origin-readback/v1', 'receipt_path': str(root / 'readonly-qualified.json'), 'receipt_raw_b64': base64.b64encode(raw).decode(), 'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'receipt_stat': meta, 'owned_stop_originals': originals}
