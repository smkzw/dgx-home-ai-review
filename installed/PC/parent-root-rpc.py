# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed PC Rootpeer facade/publication. No second Manager/SQL/model request."""
import base64, os, platform, re, socket, struct, sys, time, types
from pathlib import Path
PC_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16')
SOCKET = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/operator.sock')
APPROVED_PC_RPC = {'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9', 'helper_pins': {'plan.py': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'state.py': '00c4cf4af1a768b995c0f07ce1a99f4b2dc53e5d11e78455d5298d1eb7f2f9e4', 'contract.py': '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8', 'lineage.py': 'b999a26d489e00ed7feedffd154cb1e3739073d2afa9420e6d7db32bd4511478', 'managed_scope.py': '13277133c0670097e0e8aac1877a99c39ed3899cbe108e25312c5bb5cb8b266f', 'ancestor.py': 'fc6d353080ac2b2eca2457665d5e69049e626d89cde53022ba1f8e5b2356ade2', 'history_bootstrap.py': '1b54e5976c115ed5058e674a129cae61cd3ecda1575d5bccdc078251002f8643', 'prelaunch_stop.py': 'e7975c01de8561a99dbbbf8e4870717c0624485e7f6f23287ca48a71745e4e9e', 'live_idle.py': '0e9b31ca5cc387bfb60200d8a676b720d16b052645945c75892661838388d19f', 'restart_qualification.py': '60c5f89a6c613bfa2d118e3ad56752b29c2c9d0230429ae2e3273f49fcb50466', 'current_epoch.py': 'a0607d40dd0535199068d72091fed15ee5dd1dbe32413baf476b11d3e94ced12', 'observer.py': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef', 'stage_naming.py': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d', 'entry_clock.py': '4549c760c0a90471b06509d5b526050ceb7eab8219ea9e61acd72b297e2bf69c', 'entry_clock_store.py': '37152e0b47b81670b6c45dd4bdd83884a59fd69754a3a296664dd84ed996d095', 'budget_contract.py': '5c4ad06e9dbaa3175da44a5678ae04daeb3efb4a4b62c6e1dc0542efcd0f37ae', 'safe_error.py': '2359d58a5357eb65e4a61940470c798f4e514e537029b023f24ac5c83565b203', 'terminal.py': 'edd10b0cc0cfdef9a1f1b7b2c827eadf3a7dbb5982b0e5ce55f4ba5702f272cb', 'negative_contract.py': 'abbf8c1be3b4c1f0d1f6080b0346ba7e5df3e5da1f589287528309478cca9fef', 'history_namespace.py': 'feb2331fb9df9d87c4478e3a16422f59a42f4b27aa40b4ce9204b112df2c0186', 'prelaunch_legacy.py': 'e397ff2f4e354d47aa6fed58d9c468db36794782447750cc5ccca5de5db93675', 'proc_lifetime.py': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d', 'old_failed_kernel.py': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd', 'prelaunch_history.py': 'da7c07360adafad2c28feb50e07e0260ba13b0409425729c3b404a53c50e8822', 'prelaunch_readonly.py': '3723bbd78602a684a188d2d1068b8ae23f6c6fb1fd12e9af132109b4c6b4a3f1', 'prelaunch_proof.py': '114a454cbf68e14f74b47465cf374e4c53ab8495509d5d7a1247eaabd8a045ef', 'recovered_history.py': '17b23a8a078b40fed2827d2429cffd3896da0cbd2f29528b7c429aaf95193243', 'released_stage_history.py': 'a4454b08e462ad69866b183803d612b7547b8e9215f01d625c1781cda1ded86a', 'legacy_stage.py': 'b16faa894d235a719d918737e19ed514c40488fe1b395c53934c5fde19955cc2', 'receipt_codec.py': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312', 'ready_history.py': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5', 'prelaunch_negative.py': '674ba1e45dfceff77a2abbdfc8b65993448417956aba00b3f1514b072688eed7', 'gate_protocol.py': 'bc9e38540640dc8ce7a6489099ab24f6c649e80ed943395830dacc72be9a4f3e', 'scope_receipt.py': '486fe94dbdb31db662807864e2b3f696418a2efea6f42da7037870dcb7c5a1bb', 'legacy_actor.py': '4fff2fb255f9775b0d2f5e97f8b8dee47a14d31a401f18013ae54f56f3c030eb', 'pc_clock.py': 'cb5b36e640faf8323b1d5b217b0be32aa5c63d8b9f38294a41bd84804184df06', 'pc_recovery.py': '359ec98c2d7667627f9c06b679131ddae7ec03c3bc572385baf63f5f418132a6', 'prestart_history.py': '935e30c6879dc682f685d34db611cef4db036b6c14b7a2f4ed44e87a8dcb4fd5', 'prelaunch_recovery.py': '6bd659dcaaef0769fb2ce95b6619676a5747e1cc96128c41d7112c47d523040b', 'failed_terminal.py': '3221cd26165654504ca8bd6c904440f8c92c4149e4a21bcd962c0788eb3cbd55', 'range_catalog.py': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde', 'range_transport.py': 'ae0e06e60226dc4759a95df8281115fbcaf84f4a2147de19be109b7d9f85433c', 'range_fetch.py': '4ab3dca44b7db63471f873f82f5da282580dfc6189950f0e34bb513aebc2b8a0', 'range_http.py': 'c1888164e00a619f7316ace69952484b43903667fe5b931193abd96964240762', 'range_component.py': '46ea4378229ada599beecb4e4c1b78d4d9be0ef77bb9d43ba32bec8e3c5233ad', 'asset_segments.py': '6fc4aad206356c587e5830c267b89a16f9b796c87db829c0208db69ae16bde10', 'stage_entry_clock.py': '07a409988b4905fea479ac58d71eea8010791c67d39ca94be82f28e500952a0f', 'segment_clock.py': '4fcbb8a297ed980ade98f6e4fe3b8bf4060e1fe35334c8141a94b6bb19f443b3', 'segment_terminal.py': '22b2941a926e2ea7cce37f9d8ba8884302de0e5778e80c7c4f8c84bd3eb46d43', 'asset_stage.py': '8960088fa6cea502c52db75ece7aa1969c3b255cc988e0169cc8c7effdb7850c', 'segment_publication.py': '38b98806cd695012b618383e5171d454214ed6dacad05c72bb3d7edcd7db07db', 'callbacks.py': '8b23b3342c855b5607fa43ce0ffeb40942c1d9fa98d7d0cf2504c35be796fb78', 'grant.py': '5ddec1dc173999fe76fe08dbbb4c88719b5695c3dc88e6e2f05e50e1c3bf69e2', 'history_reader.py': '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8', 'not_launched_history.py': 'cca5257979a91ddbd906eb34547c764963b8eef3de5a520962513e2810899f81', 'zero_negative.py': '5cf0471bb32ace417eef015d1a30729ff6e9b4eacdc70db9b3253d15be275679', 'zero_scope.py': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16', 'zero_qualified.py': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86', 'zero_recovery.py': '68e92923e6294d801255b1edc79e6760da03dba8aafa0666412ceca080bbbc74', 'retired_family.py': 'b0ad75aa200233143c874c0e3fac86e2443a2684f8478b96f493afd2b9e279d4', 'ffc2_history.py': '38a3448dc22f547859dca1cf8c7c4a0e57ea4fcd615776130c9d200dc1adb3fc', 'late_scope_context.py': '0e829a61212ac1089a9eb75377492ca719304c423f7cc99f92610ca45094eb92', 'known_prior_assets.py': 'f04e2c1bb7a5331bd1bec41d32530e3cebbb31495b42e630587e07b273b03c47', 'current_negative.py': '5187857874f57fc384934a40b8a06357ab735f95d6733239e16f4cf93fb872fc', 'current_prebind.py': '9ebcfd7ce75f0cb647420b4446f3b2622fdb7e8fe4ec77e3d91f47e293c2a550', 'empty_range_repair.py': '53c3959fdd766d9f3ced8ffcfeff98043a95dce97a5ecdb6b92d23b5fc497f93'}, 'entry_producer_sha256': 'c5fa8dcb08f08462a40c672eb74cf546f67e4ba2ef48d9d408c3d8f8cef0e7f7', 'terminal_producer_sha256': '74555b3a46f63530eeb785da2eb3ae93bd51e9ee7a3e099f1f583449ae55e8d8', 'entry_nonce': 'e21f830185b7e1ffbd0ca049a040b4a2', 'renewal_loader_sha256': '9f167ba3df25c753500f01e267aa1db0492f43334d7728d3b1ead9b469751906'}
sys.path.insert(0, str(PC_ROOT / 'service'))
import plan
import entry_clock_store, safe_error
import segment_publication
from root_io import held, sha, fresh

def read(path, limit=4194304):
    return held(path, cap=limit)
ASSET_ACTIONS = {'reserve-asset-stage', 'pulse-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage', 'prepare-empty-asset-range-repair', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage', 'publish-asset-plan', 'begin-asset-entry-clock', 'publish-asset-entry-clock', 'publish-asset-terminal', 'begin-asset-terminal-clock'}
ACTIONS = {'publish-empty-asset-range-repair-contract'} | ASSET_ACTIONS | {'reserve-registry-directfetch', 'pulse-registry-directfetch', 'finish-registry-directfetch', 'begin-entry-clock', 'publish-entry-clock', 'status-entry-clock', 'publish-terminal', 'status-registry-source', 'activate-registry-source', 'source-context', 'publish-failed-terminal', 'finish-failed-registry', 'recover-failed-registry'}

def current():
    plan.need(APPROVED_PC_RPC is not None, 'PC_rpc_SOURCE_default_None')
    raw, st = held('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
    config = plan.strict(raw)
    config['_config_sha256'] = sha(raw)
    plan.need(config['review_sha256'] == APPROVED_PC_RPC['review_sha256'], 'current_source_root_review_not_arbitrary_config')
    loaderraw, ls = held(PC_ROOT / 'renewal-loader.py', APPROVED_PC_RPC['renewal_loader_sha256'])
    lm = types.ModuleType('held_current_Root_RPC_loader')
    lm.__file__ = str(PC_ROOT / 'renewal-loader.py')
    exec(compile(loaderraw, lm.__file__, 'exec'), lm.__dict__)
    snapshot = lm.main('inspect-current')
    identity = snapshot['manager_identity']
    for name, pin in APPROVED_PC_RPC['helper_pins'].items():
        held(PC_ROOT / 'service' / name, pin)
    from current_epoch import consume
    consume(read, config, identity, time.time())
    pid = identity['pid']
    path = Path('/proc') / str(pid)
    tail = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    plan.need(tail[19] == str(identity['start_ticks']) and (path / 'environ').read_bytes().split(b'\x00').count(('INVOCATION_ID=' + identity['invocation_id']).encode()) == 1, 'actual_current_same_PID_ticks_inv')
    plan.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == identity['boot_id'], 'actual_current_same_boot')
    return (config, identity)

class PrivateReplyRefused(plan.Refused):

    def __init__(self, original):
        super().__init__('actual_private_Rootpeer_refused')
        self.original = original

def archive_private(action, nonce, body, reply, sent, received, elapsed):
    plan.need(action in ('reserve-registry-directfetch', 'pulse-registry-directfetch', 'finish-registry-directfetch', 'finish-failed-registry', 'recover-failed-registry', 'status-registry-source', 'activate-registry-source', 'reserve-asset-stage', 'pulse-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage', 'prepare-empty-asset-range-repair', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage'), 'only_nonsecret_private_reply_evidence')
    root = PC_ROOT / 'rpc-evidence'
    if not root.exists():
        root.mkdir(mode=448)
        os.chmod(root, 448)
    z = root.lstat()
    plan.need(__import__('stat').S_ISDIR(z.st_mode) and z.st_uid == z.st_gid == 0 and (z.st_mode & 511 == 448), 'fixed_private_reply_evidence_directory')
    path = root / (action + '-' + nonce + '.json')
    bodyraw = plan.encode({'schema': 'registry-R26-private-first-response-original/v1', 'action': action, 'request_raw_b64': base64.b64encode(plan.encode(body)).decode(), 'response_raw_b64': base64.b64encode(reply).decode(), 'response_sha256': sha(reply), 'PC_sent_at': sent, 'PC_received_at': received, 'PC_monotonic_elapsed': elapsed, 'automatic_retry': False})
    fresh(path, bodyraw, mode=384)
    source, st = held(path)
    plan.need(source == bodyraw and st[3:7] == [0, 0, 33152, 1], 'actual_first_reply_original_readback')
    return {'path': str(path), 'raw_b64': base64.b64encode(source).decode(), 'sha256': sha(source), 'stat': st}

def dispatch(action, nonce, payload=None):
    plan.need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'fixed_private_evidence_nonce')
    config, identity = current()
    z = SOCKET.lstat()
    plan.need(z.st_uid == 999 and z.st_gid == 989 and (z.st_mode & 511 == 384), 'current_private_operator_owner')
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    before = time.time()
    started = time.monotonic()
    out = bytearray()
    try:
        conn.settimeout(5)
        conn.connect(str(SOCKET))
        pid, uid, gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        plan.need((pid, uid, gid) == (identity['pid'], 999, 989), 'same_actual_original_Manager_Rootpeer')
        conn.settimeout(90)
        body = {'action': action, 'operation': plan.EPOCH_OPERATION if action == 'activate-registry-source' else plan.OPERATION, 'request_nonce': nonce}
        body.update(payload or {})
        conn.sendall(plan.encode(body))
        while len(out) <= 1048576:
            b = conn.recv(min(65536, 1048577 - len(out)))
            plan.need(b, 'original_private_response_EOF')
            out.extend(b)
            if b'\n' in out:
                break
        plan.need(len(out) <= 1048576 and out.count(b'\n') == 1 and out.endswith(b'\n'), 'exact_bounded_original_private_frame')
    finally:
        conn.close()
        received = time.time()
        elapsed = time.monotonic() - started
        original = archive_private(action, nonce, body, bytes(out), before, received, elapsed)
    v = plan.strict(out)
    if v.get('ok') is not True:
        raise PrivateReplyRefused(original)
    plan.need(elapsed <= 90, 'actual_private_roundtrip_budget')
    if action in ('pulse-registry-directfetch', 'pulse-asset-stage'):
        p = v['pulse']
        raw = plan.encode(p)
        return {'operation': plan.OPERATION, 'original_raw_b64': base64.b64encode(raw).decode(), 'original_sha256': sha(raw), 'PC_sent_at': before, 'PC_received_at': received, 'PC_monotonic_elapsed': elapsed, 'original_reply_raw_b64': base64.b64encode(bytes(out)).decode(), 'original_reply_sha256': sha(bytes(out))}
    return {'original_reply_raw_b64': base64.b64encode(bytes(out)).decode(), 'original_reply_sha256': sha(bytes(out)), 'PC_sent_at': before, 'PC_received_at': received, 'PC_monotonic_elapsed': elapsed}

def publish(action, value):
    if action == 'publish-entry-clock':
        cfg, identity = current()
        plan.need(set(value) == {'response_raw_b64', 'response_sha256', 'owned_stop_calls'}, 'fixed_A_entry_clock_response_origin')
        raw = base64.b64decode(value['response_raw_b64'], validate=True)
        plan.need(sha(raw) == value['response_sha256'] and type(value['owned_stop_calls']) is int and (value['owned_stop_calls'] == 1), 'full_actual_A_clock_response')
        certificate = entry_clock_store.finish(cfg, identity, raw)
        v = entry_clock_store.consume(cfg, identity, time.time())
        return {'certificate': certificate, 'entry_sha256': sha(plan.encode(v)), 'models_started': 0}
    cfg, identity = current()
    if action == 'publish-failed-terminal':
        import failed_terminal
        plan.need(set(value) == {'qualified_raw_b64', 'sha256', 'stat', 'actual_retained_EXIT1', 'models_started'} and value['actual_retained_EXIT1'] is True and (type(value['models_started']) is int) and (value['models_started'] == 0), 'fixed_failed_A_publication')
        raw = base64.b64decode(value['qualified_raw_b64'], validate=True)
        plan.need(sha(raw) == value['sha256'] and value['stat'][2] == len(raw) and (value['stat'][3:7] == [0, 0, 33152, 1]), 'failed_A_original_raw_F9')
        v = plan.strict(raw)
        failed_terminal.validate(v, cfg, identity, time.time(), worker_sha=failed_terminal.APPROVED_FETCH_WORKER_SHA, producer_sha=failed_terminal.APPROVED_FAILURE_PRODUCER_SHA, index_sha=failed_terminal.APPROVED_FETCH_INDEX_SHA)
        path = failed_terminal.PATH
        fresh(path, raw, mode=288)
        os.chown(path, 0, 989)
        os.chmod(path, 288)
        checked = failed_terminal.consume(read, cfg, identity, time.time())
        return {'path': str(path), 'sha256': sha(raw), 'state': 'FAILED_REGISTRY_QUIESCENT', 'CPU_success': False, 'image_imported': False}
    raw = base64.b64decode(value['qualified_raw_b64'], validate=True)
    plan.need(sha(raw) == value['sha256'] and value['stat'][2] == len(raw) and (value['stat'][3:7] == [0, 0, 33152, 1]) and (value['owned_stop_calls'] == 1), 'actual_A_Root_origin_raw_F9_not_usercopy')
    v = plan.strict(raw)
    plan.need(v['operation'] == plan.OPERATION and v['manager_identity'] == identity and (v['current_PC_source118'] == cfg['PC_source_pins']) and (v['PC_config_sha256' if action == 'publish-entry' else 'config_sha256'] == cfg['_config_sha256']), 'same_actual_current_epoch_for_A_original')
    import terminal
    if action == 'publish-entry':
        from observer import positive
        positive(v['actual_readonly_scope'], plan.ENTRY_UNIT, v['readonly_worker_sha256'], True)
        plan.need(v['producer_sha256'] == APPROVED_PC_RPC['entry_producer_sha256'], 'reviewed_A_entry_producer')
        name = 'native-entry-qualified.json'
    else:
        plan.need(v['producer_sha256'] == APPROVED_PC_RPC['terminal_producer_sha256'], 'reviewed_A_terminal_producer')
        name = 'fetch-qualified.json'
    path = PC_ROOT / name
    fresh(path, raw, mode=288)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchown(fd, 0, 989)
        os.fchmod(fd, 288)
        os.fsync(fd)
    finally:
        os.close(fd)
    source, st = held(path)
    plan.need(source == raw, 'samebyte_PC_Root_mirror')
    if action == 'publish-terminal':
        terminal.consume(read, path, cfg, identity, time.time())
    else:
        terminal.consume_entry_ready(read, cfg, identity, time.time())
    return {'path': str(path), 'sha256': sha(source), 'stat': st, 'Root_origin_A': value['stat'], 'models_started': 0}

def run(p):
    plan.need(APPROVED_PC_RPC is not None and os.getuid() == os.geteuid() == 0 and (platform.node() == 'vicky') and (sys.platform == 'linux'), 'PC_root_SOURCE_default_None')
    plan.need(set(p) == {'action', 'operation', 'nonce', 'payload'} and p['operation'] == (plan.EPOCH_OPERATION if p['action'] == 'activate-registry-source' else plan.OPERATION) and (p['action'] in ACTIONS) and re.fullmatch('[0-9a-f]{32}', p['nonce']), 'fixed_private_scope_not_generic_admin')
    if p['action'] == 'publish-empty-asset-range-repair-contract':
        import empty_range_repair
        cfg, identity = current()
        return empty_range_repair.publish_contract(cfg, identity, p['payload'])
    if p['action'] in ASSET_ACTIONS:
        if p['action'].startswith(('publish-', 'begin-')):
            cfg, identity = current()
            return segment_publication.publish(p['action'], p['payload'], cfg, identity)
        plan.need(set(p['payload']) == {'stage_operation'}, 'fixed_stage_dispatch_payload')
        return dispatch(p['action'], p['nonce'], p['payload'])
    if p['action'] == 'source-context':
        cfg, identity = current()
        raw, st = held(PC_ROOT / 'current-source-qualified.json')
        done, ds = held(PC_ROOT / 'current-qualification-completed.json')
        return {'qualified_raw_b64': base64.b64encode(raw).decode(), 'qualified_sha256': sha(raw), 'qualified_F9': st, 'completed_raw_b64': base64.b64encode(done).decode(), 'completed_sha256': sha(done), 'completed_F9': ds, 'config_raw_b64': base64.b64encode(held('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')[0]).decode(), 'manager_identity': identity, 'RPC_source_sha256': sha(Path(__file__).read_bytes()), 'qualifier_source': {'sha256': sha(held(PC_ROOT / 'pc/qualifier.py')[0]), 'stat': held(PC_ROOT / 'pc/qualifier.py')[1]}, 'worker_source': {'sha256': sha(held(PC_ROOT / 'epoch-scope/worker.py')[0]), 'stat': held(PC_ROOT / 'epoch-scope/worker.py')[1]}, 'observed_at': time.time()}
    if p['action'] == 'begin-entry-clock':
        plan.need(p['payload'] == {}, 'fixed_entry_clock_begin_no_callbacks')
        cfg, identity = current()
        return entry_clock_store.begin(cfg, identity)
    if p['action'] == 'status-entry-clock':
        plan.need(p['payload'] == {}, 'readonly_clock_status')
        cfg, identity = current()
        v = entry_clock_store.consume(cfg, identity, time.time())
        return {'entry_sha256': sha(plan.encode(v)), 'models_started': 0}
    if p['action'].startswith('publish-'):
        return publish(p['action'], p['payload'])
    allowed = {'request_nonce', 'duration_seconds'} if p['action'] == 'reserve-registry-directfetch' else {'request_nonce'}
    plan.need(set(p['payload']) <= allowed, 'no_source_path_or_profile_from_request')
    duration = {}
    if p['action'] == 'reserve-registry-directfetch':
        seconds = p['payload'].get('duration_seconds')
        plan.need(type(seconds) is int and 1 <= seconds <= 1800, 'strict_parent_duration_before_private_request')
        duration = {'duration_seconds': seconds}
    return dispatch(p['action'], p['payload'].get('request_nonce', p['nonce']), duration)
if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(4194305)
        plan.need(len(raw) <= 4194304, 'PC_frame_cap')
        p = plan.strict(raw)
        sys.stdout.buffer.write(plan.encode(run(p)))
    except BaseException as e:
        action = p.get('action') if 'p' in globals() else None
        failure = safe_error.original_safe_error(action, e)
        if type(e) is PrivateReplyRefused:
            failure['original_private_reply'] = e.original
        sys.stdout.buffer.write(plan.encode(failure))
        raise SystemExit(1)
