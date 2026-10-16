# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""R3 post-CAS/start0 lineage. Definitions only; old full consumer stays immutable."""
import ast, base64, builtins, copy, hashlib, json, os, pathlib, re, stat, types
from pathlib import Path
APPROVED_SPEC_PATH = '/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3/lineage-source/actual-postcas-spec.json'
APPROVED_SPEC_SHA = '5e72b5317c8b4c17e48908f1c65042ca6102bffb78c309e45f2b127a3f91b1ad'
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3')
SPEC_PATH = str(ROOT / 'lineage-source/actual-postcas-spec.json')
QUALIFIED = ROOT / 'lineage-qualified'
OLD_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-history-import-r11-r2')
OLD_MODULE_SHA = 'f062d9a0be018ebe9cb68596144718f9d47f2110b6ec614ff2cf67d9ea2faee9'
OLD_SPEC_SHA = '0c24a14cacc1bcabfbcbd9caf85a06913e658cb0f02f3e4b669b3120b5a554d2'
PHASE = 'STOPPED_POSTCAS_C24_FAILED_BEFORE_START'
MAX_LEAF = 2097152
MAX_PACKET = 4194304
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

class Refused(RuntimeError):
    pass

def need(v, code):
    if not v:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'duplicate_JSON')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_JSON'))

def f9(meta, raw=None, owner=None):
    need(type(meta) is list and len(meta) == 9 and all((type(x) is int for x in meta)), 'full_F9')
    if raw is not None:
        need(type(raw) is bytes and len(raw) == meta[2] and (len(raw) <= MAX_LEAF) and stat.S_ISREG(meta[5]) and (meta[6] == 1), 'whole_regular_bounded_raw')
    if owner is not None:
        need(meta[3:7] == owner, 'exact_owner_mode_nlink')
    return meta

def original(read, path, pin, meta=None, owner=None):
    raw, actual = read(Path(path), limit=MAX_LEAF)
    f9(actual, raw, owner)
    need(sha(raw) == pin and (meta is None or actual == meta), 'original_full_SHA_F9')
    return (raw, actual)

def get_spec(read):
    need(APPROVED_SPEC_PATH == SPEC_PATH and type(APPROVED_SPEC_SHA) is str and re.fullmatch('[0-9a-f]{64}', APPROVED_SPEC_SHA), 'future_source_binding_pending')
    raw, _ = original(read, SPEC_PATH, APPROVED_SPEC_SHA, owner=[0, 989, 33056, 1])
    s = strict(raw)
    b = s['baseline']
    need(s['schema'] == 'R11-R3-postCAS-C24-failed-lineage/v1' and s['phase'] == b['owner_state'] == PHASE and (s['future_Root'] == str(ROOT)) and (s['Root'] == str(OLD_ROOT)), 'exact_postCAS_case_roots')
    need(s['operation'] == '3e38d054d32cc1015edfc26ae2ae5f78' and s['prior_operation'] == '25c40150c3e1e3e9793d10fc743de494' and (s['historical_only'] is True) and (s['future_admission'] is False), 'source_history_not_fresh_admission')
    need(b['manager_identity'] == {'pid': 1803917, 'start_ticks': None, 'boot_id': 'redacted-2606f3e07a03', 'invocation_id': 'e9783ff9daca70ae8c675d598b14b360'} and s['prior_config_started_by_old_PID'] is False, 'old180_negative_only_not_current_cfg_execution')
    need(s['config_sha256'] == b['config_sha256'] == '004bc553effb4bd89118b620f511cbc7fe4227fdafb8e5fce1ea78470bd7880f' and s['wire_sha256'] == 'fa33cb77a7098e0176597e24196c86748f7a8c88ef02c8f075f1539c48305cae', 'current004bc_fa33_not_rebased95aa')
    need(len(s['Root117']) == 117 and len(b['source_files']) == len(b['current_source118']) == 118 and (len(s['originals']) == 17) and (b['lease_full_F9'][:2] == [2096, 69257]) and (b['socket'] is None), 'complete_source_and_originals')
    need(s['prior_C24_consumed_failure'] is True and s['own_stop_calls'] == s['own_unlink_calls'] == s['prior_start_calls'] == 0 and (s['prior_stop_calls'] == 1) and (s['prior_CAS_calls'] == 2), 'preserve6279_stop0_CAS2_start0')
    return s

def private_module(raw, path):
    """Exact held bytes, private globals, fixed stdlib object map; no sys.modules alias."""
    need(sha(raw) == OLD_MODULE_SHA, 'exact_old_consumer_bytes_no_overlay')
    tree = ast.parse(raw, filename=str(path))
    allowed = {'base64': base64, 'hashlib': hashlib, 'json': json, 'os': os, 're': re, 'stat': stat, 'pathlib': pathlib}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            need(all((a.name in allowed for a in n.names)), 'unknown_old_import')
        if isinstance(n, ast.ImportFrom):
            need(n.level == 0 and n.module == 'pathlib' and ([a.name for a in n.names] == ['Path']), 'unknown_old_from_import')

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        need(level == 0 and name in allowed, 'unknown_private_import')
        return allowed[name]
    env = vars(builtins).copy()
    env['__import__'] = fixed_import
    module = types.ModuleType('_R11_R2_private_consumer_f062d9a0')
    module.__file__ = str(path)
    module.__dict__['__builtins__'] = env
    exec(compile(tree, str(path), 'exec'), module.__dict__)
    need(module.APPROVED_SPEC_PATH == str(OLD_ROOT / 'lineage-source/actual-stopped-spec.json') and module.APPROVED_SPEC_SHA == OLD_SPEC_SHA, 'old_source_binding_unchanged')
    return module

def prior_consumer(read, s):
    row = s['prior_module']
    need(row['path'] == str(OLD_ROOT / 'service/lineage.py') and row['sha256'] == OLD_MODULE_SHA and (row == {'path': row['path'], **s['Root117']['service/lineage.py']}), 'fixed_old_module_path_pin')
    raw, _ = original(read, row['path'], OLD_MODULE_SHA, row['F9'], [0, 989, 33056, 1])
    old = private_module(raw, row['path'])
    v = s['prior_spec']
    need(v['path'] == str(OLD_ROOT / 'lineage-source/actual-stopped-spec.json') and v['sha256'] == OLD_SPEC_SHA, 'old_spec_not_rebased')
    original(read, v['path'], v['sha256'], v['F9'], [0, 989, 33056, 1])
    ref = s['prior_index']
    need(ref['path'] == str(OLD_ROOT / 'lineage-qualified/index.json'), 'fixed_original_prior_index')
    prior = old.consume_actual_stopped_summary(read, ref)
    need(prior['spec_sha256'] == OLD_SPEC_SHA and prior['summary_ref'] == ref and (prior['baseline']['config_sha256'] == '95aa3578ea5a7c155266890b321420c38dc88a54715e9edffba06f17123da964'), 'prior95aa_historical_not_current004bc')
    return (old, prior)

def live_actor(old, s, read):
    oldspec = old.get_spec(read)
    old._directories(oldspec)
    actor = old.actor_original(oldspec)
    need(old.directory_original(oldspec['actor_parent']['path']) == s['actor_parent'] and old.directory_original(oldspec['actor']['path']) == s['actor_directory'], 'actual_actor_directory_same_old_three')
    need(set(actor) == set(s['actor3']), 'all_actor_three')
    for name, (raw, meta) in actor.items():
        need(sha(raw) == s['actor3'][name]['sha256'] and meta == s['actor3'][name]['F9'], 'actual_actor3_F9_full_SHA')

def C24_original(raw):
    d = strict(raw)
    need(d['schema'] == 'R11-R2-first-partial-readonly/v1' and d['role'] == 'C24' and (d['operation'] == '25c40150c3e1e3e9793d10fc743de494') and (d['replay'] is False) and (d['controls'] == 0), 'actual_C24_failed_MAC_origin')
    need(set(d['files']) == {'once/failed.json', 'once/intent.json', 'once/returned.json', 'once/stderr.raw', 'once/stdout.raw'}, 'no_C24_completed_or_omitted_original')
    bodies = {}
    for name, row in d['files'].items():
        b = base64.b64decode(row['raw_b64'], validate=True)
        f9(row['F9'], b, [0, 0, 33152, 1])
        need(row['present'] is True and row['stable'] is True and (sha(b) == row['sha256']), 'C24_MAC_embedded_original_F9_SHA')
        bodies[name] = b
    returned = strict(bodies['once/returned.json'])
    failed = strict(bodies['once/failed.json'])
    intent = strict(bodies['once/intent.json'])
    need(returned['child_rc'] == 1 and returned['worker_pid'] == failed['worker_pid'] == intent['worker_pid'] == 181988 and (returned['invocation_id'] == failed['invocation_id'] == intent['invocation_id'] == '8e394a178a1f23725084f4e3d99679db'), 'actual_C24_rc1_identity')
    need(sha(bodies['once/stderr.raw']) == returned['stderr_sha256'] == 'f654b18eaf7afa539a3451434e0682c7319be1e968215942615d8a0e032ac850' and bodies['once/stdout.raw'] == b'' and (sha(b'') == returned['stdout_sha256']), 'C24_actual_stderr_stdout_not_success')
    need(b'FileNotFoundError' in bodies['once/stderr.raw'] and b"'/var/lib/dgx-v4/g8-c-finite-disarm-r24'" in bodies['once/stderr.raw'] and (b'/var/lib/dgx-v4/g8-c-finite-disarm-r23/ARM_envelope.py' in bodies['once/stderr.raw']), 'exact_historical_r23_path_error_not_model_failure')
    u = d['units']['dgx-v4-c-unarmed-before-pc-r24-readonly.service']['unit']
    need(u['ExecMainPID'] == '181988' and u['InvocationID'] == '8e394a178a1f23725084f4e3d99679db' and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '1') and (u['ActiveState'] == 'failed'), 'MAC_C24_terminal')

def semantics(s, raws, prior):
    value = lambda n: strict(raws[n])
    intent = value('epoch-private/intent.json')
    stopped = value('epoch-private/stopped.json')
    failed = value('epoch-private/failed.json')
    scope = value('epoch-scope/once/failed.json')
    scope_intent = value('epoch-scope/once/intent.json')
    need(intent['operation'] == scope['operation'] == s['prior_operation'] and intent['before'] == prior['baseline'] and (intent['actual_stopped_spec_sha256'] == OLD_SPEC_SHA), '6279_adopted_exact_old_history_not_rewritten')
    need(stopped['own_stop_calls'] == 0 and stopped['prior_stop_calls'] == 1 and (stopped['prior_normal_stop_original'] == prior['prior_normal_stopped_original']) and (stopped['current_failed_start_unit'] == prior['failed_start_unit_original']), '6279_failed180_same_old95aa_identity')
    need(failed['normal_stop_calls'] == failed['socket_unlink_calls'] == failed['normal_start_calls'] == failed['models_started'] == 0 and failed['committed'] == [s['wire_path'], s['config_path']] and (failed['source_reason_code'] == scope['source_reason'] == 'hidden_nonliteral') and (failed['automatic_retry'] is False) and (failed['automatic_rollback'] is False), '6279_actual_CAS2_start0_failure_no_inferred_cause')
    need(scope['worker_pid'] == scope_intent['worker_pid'] == 1822878 and scope['invocation_id'] == scope_intent['invocation_id'] == 'caec087925d975e36a630214557dfbae' and (scope['error_type'] == 'Refused') and (scope['partial_preserved'] is True), 'exact_failed6279_scope')
    for n, path, oldpin, newpin in [('1', s['wire_path'], '7d74021a39ec2506c9084bfb1ddf73b98358417c85bd486b0983683c0c53de21', s['wire_sha256']), ('2', s['config_path'], prior['baseline']['config_sha256'], s['config_sha256'])]:
        a = value('epoch-private/CAS-' + n + '-intent.json')
        b = value('epoch-private/CAS-' + n + '-completed.json')
        need(a == {'path': path, 'old_sha256': oldpin, 'new_sha256': newpin} and b == {'path': path, 'new_sha256': newpin}, 'positive_actual_CAS_old_to_new_exact')
    need(value('epoch-private/socket-original-absent.json') == {'calls': 0} and sha(raws['epoch-private/old-config.raw']) == prior['baseline']['config_sha256'] and (sha(raws['epoch-private/old-wire.raw']) == '7d74021a39ec2506c9084bfb1ddf73b98358417c85bd486b0983683c0c53de21'), 'prior_old_bytes_not_rebased')
    check = value('epoch-private/command-4.json')
    need(check['rc'] == 0 and check['stderr_raw_utf8'] == '' and (check['argv'][-1] == '--check'), 'actual_check_not_service_start')
    u = value('epoch-private/original-unit.json')
    need(u['sha256'] == s['unit']['sha256'] and u['stat'] == s['unit']['stat'] and (sha(u['raw_utf8'].encode()) == s['unit']['sha256']), 'R2_private_original_unit_whole_bytes_stat')
    b = s['baseline']
    rows = b['rows_original']
    need(sha(rows['raw_utf8'].encode()) == rows['sha256'] and strict(rows['raw_utf8']) == rows['rows'], 'whole_rows_original')
    r = rows['rows']
    p = prior['baseline']
    need(r['requests'] == p['rows_original']['rows']['requests'] == stopped['current']['rows_original']['rows']['requests'] and len(r['requests']) == 96 and (r['historical_terminal_uncertain_count'] == 9) and (r['active_jobs'] == r['active_requests'] == []), 'whole96_history9_not_projection')
    need(all((b['commands'][k] == p['commands'][k] for k in ('canonical_utf8', 'sha256', 'original_file_stat'))) and b['Cleaf'] == p['Cleaf'], 'C3_Cleaf_unchanged')
    for row in r['profiles'].values():
        need(row['state'] == 'STOPPED' and row['owner'] is None and (row.get('quarantined_at') is None), 'all_profiles_stopped')
    for row in r['nodes']:
        need(row['quarantine'] == 0 and all((row[k] is None for k in ('hold_profile', 'hold_owner', 'hold_generation', 'hold_operation'))), 'all_nodes_unheld')
    C24_original(raws['MAC/first-partial-C24-original.json'])
    j = value('MAC/new-failed-PC-first-journal-original.json')
    need(j['invocation_id'] == 'caec087925d975e36a630214557dfbae' and j['journal_raw_b64'] == '' and (j['journal_sha256'] == sha(b'')) and (j['unit_queries'] == j['old6508_journal_queries'] == j['control'] == 0) and (j['lease_F9'] == b['lease_full_F9']) and all((j['sameboot_PIDs_gone'].get(str(pid)) is True for pid in (1789097, 1803579, 1803917, 1822878))), 'original_first_PC_journal_empty_no_specific_PC_cause')

def private_inventory(s):
    """Root producer: exact old private names, held directory F9; never service bypass."""
    out = {}
    for sub in ('epoch-private', 'epoch-scope/once'):
        path = OLD_ROOT / sub
        expected = sorted((Path(n).name for n in s['originals'] if str(Path(n).parent) == sub))
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            z = [getattr(os.fstat(fd), k) for k in FIELDS]
            f9(z)
            need(stat.S_ISDIR(z[5]) and z[3] == 0 and (not z[5] & 18) and (sorted(os.listdir(fd)) == expected) and (z == [getattr(path.lstat(), k) for k in FIELDS]), 'exact_old_private_namespace_no_start_intent')
            out[sub] = {'F9': z, 'entries': expected}
        finally:
            os.close(fd)
    return out

def validate(read, *, check_private=True):
    s = get_spec(read)
    inventory = private_inventory(s) if check_private else None
    old, prior = prior_consumer(read, s)
    for name, row in s['Root117'].items():
        original(read, OLD_ROOT / name, row['sha256'], row['F9'], [0, 989, 33056, 1])
    for path, row in s['baseline']['source_files'].items():
        need(s['baseline']['current_source118'][path] == row['sha256'], 'current118_exact_map')
        original(read, path, row['sha256'], row['stat'])
    original(read, s['config_path'], s['config_sha256'], s['baseline']['config_stat'])
    live_actor(old, s, read)
    raws = {}
    origins = {}
    for name, row in s['originals'].items():
        raw, meta = original(read, row['path'], row['sha256'], row['F9'], [0, 0, 33152, 1])
        raws[name] = raw
        origins[name] = {'path': row['path'], 'sha256': row['sha256'], 'F9': meta, 'origin_kind': 'actual_R2_Root_private_original'}
    for name, row in s['MAC_originals'].items():
        raw, meta = original(read, row['path'], row['sha256'], owner=[0, 989, 33056, 1])
        raws['MAC/' + name] = raw
        origins['MAC/' + name] = {'path': row['path'], 'sha256': row['sha256'], 'F9': meta, 'origin_kind': row['origin_kind']}
    unit, _ = original(read, '/etc/systemd/system/dgx-v4-hx-manager.service', s['unit']['sha256'], s['unit']['stat'])
    need(strict(raws['epoch-private/original-unit.json'])['raw_utf8'].encode() == unit, 'actual_original_unit_independent_bytes_F9')
    need(sum(map(len, raws.values())) <= MAX_PACKET, 'packet4MiB_unchanged')
    semantics(s, raws, prior)
    if check_private:
        need(private_inventory(s) == inventory, 'old_private_directory_changed')
    return (s, raws, origins, prior)

def result(s, prior, ref=None):
    out = {'baseline': s['baseline'], 'prior_normal_stopped_original': prior['prior_normal_stopped_original'], 'failed_start_unit_original': prior['failed_start_unit_original'], 'spec_sha256': APPROVED_SPEC_SHA, 'phase': PHASE, 'prior_summary_ref': s['prior_index'], 'own_stop_calls': 0, 'own_unlink_calls': 0, 'prior_stop_calls': 1, 'prior_start_calls': 0, 'prior_CAS_calls': 2, 'historical_only': True, 'future_admission': False}
    if ref is not None:
        out['summary_ref'] = ref
    return out

def actual_stopped_originals(read):
    s, _, _, prior = validate(read)
    return result(s, prior)

def qualified_begin():
    need(os.getuid() == os.geteuid() == 0, 'new_qualified_Root_only')
    parents = []
    for path in QUALIFIED.parents:
        z = path.lstat()
        need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18), 'protected_existing_parent')
        parents.append((path, [z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode]))
    p = os.open(QUALIFIED.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    c = None
    try:
        os.mkdir(QUALIFIED.name, 488, dir_fd=p)
        c = os.open(QUALIFIED.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=p)
        os.fchown(c, 0, 989)
        os.fchmod(c, 488)
        os.fsync(c)
        os.fsync(p)
        z = os.fstat(c)
        token = (p, c, [z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode], parents)
        qualified_recheck(token, [])
        return token
    except BaseException:
        if c is not None:
            os.close(c)
        os.close(p)
        raise

def qualified_recheck(token, names):
    p, c, before, parents = token
    z = os.fstat(p)
    need([z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode] == parents[0][1], 'held_parent')
    z = os.fstat(c)
    n = os.stat(QUALIFIED.name, dir_fd=p, follow_symlinks=False)
    need([z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode] == [n.st_dev, n.st_ino, n.st_uid, n.st_gid, n.st_mode] == before and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488) and (sorted(os.listdir(c)) == sorted(names)), 'held_new_directory_exact_leaf_set')
    for path, v in parents:
        z = path.lstat()
        need([z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode] == v, 'parent_changed')

def qualified_close(token):
    os.close(token[1])
    os.close(token[0])

def share_actual_stopped(read, write):
    s, raws, origins, prior = validate(read)
    inventory = private_inventory(s)
    for name, path, pin, meta in [('current-wire', s['wire_path'], s['wire_sha256'], s['baseline']['source_files'][s['wire_path']]['stat']), ('current-config', s['config_path'], s['config_sha256'], s['baseline']['config_stat'])]:
        raw, meta = original(read, path, pin, meta)
        raws[name] = raw
        origins[name] = {'path': path, 'sha256': pin, 'F9': meta, 'origin_kind': 'actual_current_postCAS_never_started_source'}
    need(sum(map(len, raws.values())) <= MAX_PACKET, 'new_shared_raw4MiB')
    token = qualified_begin()
    entries = {}
    try:
        for i, name in enumerate(sorted(raws)):
            path = QUALIFIED / ('leaf-' + str(i).zfill(3) + '.raw')
            raw = raws[name]
            write(path, raw, mode=288, gid=989)
            body, meta = read(path, limit=MAX_LEAF)
            f9(meta, body, [0, 989, 33056, 1])
            need(body == raw, 'shared_complete_readback')
            entries[name] = {'source': origins[name], 'path': str(path), 'sha256': sha(body), 'F9': meta}
            qualified_recheck(token, [Path(r['path']).name for r in entries.values()])
        index = {'schema': 'R11-R3-qualified-postCAS-index/v1', 'operation': s['operation'], 'phase': PHASE, 'spec_sha256': APPROVED_SPEC_SHA, 'prior_summary_ref': s['prior_index'], 'private_original_directories': inventory, 'entries': entries}
        need(private_inventory(s) == inventory, 'original_directories_unchanged_at_share')
        raw = encode(index)
        need(len(raw) <= MAX_LEAF, 'small_index')
        path = QUALIFIED / 'index.json'
        write(path, raw, mode=288, gid=989)
        body, meta = read(path, limit=MAX_LEAF)
        f9(meta, body, [0, 989, 33056, 1])
        need(body == raw, 'index_readback')
        qualified_recheck(token, [Path(r['path']).name for r in entries.values()] + ['index.json'])
        return {'path': str(path), 'sha256': sha(body), 'F9': meta}
    finally:
        qualified_close(token)

def consume_actual_stopped_summary(read, ref):
    s = get_spec(read)
    need(type(ref) is dict and set(ref) == {'path', 'sha256', 'F9'} and (ref['path'] == str(QUALIFIED / 'index.json')), 'fixed_new_summary_ref')
    raw, _ = original(read, ref['path'], ref['sha256'], ref['F9'], [0, 989, 33056, 1])
    index = strict(raw)
    need(index['schema'] == 'R11-R3-qualified-postCAS-index/v1' and index['operation'] == s['operation'] and (index['phase'] == PHASE) and (index['spec_sha256'] == APPROVED_SPEC_SHA) and (index['prior_summary_ref'] == s['prior_index']), 'source_bound_new_and_old_summary')
    expected = {n: r['path'] for n, r in s['originals'].items()}
    expected.update({'MAC/' + n: r['path'] for n, r in s['MAC_originals'].items()})
    expected.update({'current-wire': s['wire_path'], 'current-config': s['config_path']})
    need(set(index['entries']) == set(expected), 'complete_new_shared_leaf_set')
    mapping = {}
    for i, name in enumerate(sorted(expected)):
        row = index['entries'][name]
        need(row['path'] == str(QUALIFIED / ('leaf-' + str(i).zfill(3) + '.raw')) and row['source']['path'] == expected[name] and (row['source']['sha256'] == row['sha256']), 'fixed_new_leaf_origin')
        body, _ = original(read, row['path'], row['sha256'], row['F9'], [0, 989, 33056, 1])
        f9(row['source']['F9'], body)
        mapping[expected[name]] = (body, row['source']['F9'])

    def shared_read(path, limit=MAX_LEAF):
        return mapping[str(path)] if str(path) in mapping else read(path, limit=limit)
    for sub, row in index['private_original_directories'].items():
        f9(row['F9'])
        need(stat.S_ISDIR(row['F9'][5]) and row['F9'][3] == 0 and (not row['F9'][5] & 18) and (row['entries'] == sorted((Path(n).name for n in s['originals'] if str(Path(n).parent) == sub))), 'qualified_original_directory_full_provenance')
    need(set(index['private_original_directories']) == {'epoch-private', 'epoch-scope/once'}, 'both_original_private_directories')
    actual, _, origins, prior = validate(shared_read, check_private=False)
    for key, row in origins.items():
        need(index['entries'][key]['source'] == row, 'shared_distinct_physical_F9_and_exact_source_origin')
    return result(actual, prior, ref)

def continuation_counts(inst):
    need(APPROVED_SPEC_SHA is not None and inst['schema'] == 'registry-R26-PC-installed-unqualified/v1', 'source_bound_counts')
    keys = ('normal_stop_calls', 'own_normal_stop_calls', 'socket_unlink_calls', 'prior_normal_stop_calls', 'total_normal_stop_calls', 'normal_start_calls', 'CAS_calls', 'models_started')
    need(all((type(inst[k]) is int for k in keys)), 'integer_not_boolean_counters')
    need([inst[k] for k in keys] == [0, 0, 0, 1, 1, 1, 2, 0], 'new_ownstop0_unlink0_CAS2_start1_not_replay6279')
    p = inst['prior_stopped_evidence']
    r = p['summary_ref']
    need(type(r) is dict and set(r) == {'path', 'sha256', 'F9'} and (type(r['sha256']) is str) and re.fullmatch('[0-9a-f]{64}', r['sha256']), 'complete_qualified_reference')
    f9(r['F9'])
    need(p['phase'] == PHASE and p['spec_sha256'] == APPROVED_SPEC_SHA and (inst['before'] == p['baseline']) and (p['baseline']['owner_state'] == PHASE) and (p['baseline']['manager_identity']['start_ticks'] is None) and (p['prior_start_calls'] == 0) and (p['prior_CAS_calls'] == 2) and (p['summary_ref']['path'] == str(QUALIFIED / 'index.json')), 'postCAS_lineage_small_ref_full_consumer_still_required')
    return True
