# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""No-ambient Root renewal loader. Fixed sources, no Runtime constructor."""
import os, sys, types
from pathlib import Path
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16')
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_PACKET_SHA = '739f71df746d966e6937427197887d14bb774e69375a03cf1bb7daff0d6af19c'
APPROVED_SERVICE_PINS = {'plan.py': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'state.py': '00c4cf4af1a768b995c0f07ce1a99f4b2dc53e5d11e78455d5298d1eb7f2f9e4', 'contract.py': '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8', 'lineage.py': 'b999a26d489e00ed7feedffd154cb1e3739073d2afa9420e6d7db32bd4511478', 'managed_scope.py': '13277133c0670097e0e8aac1877a99c39ed3899cbe108e25312c5bb5cb8b266f', 'ancestor.py': 'fc6d353080ac2b2eca2457665d5e69049e626d89cde53022ba1f8e5b2356ade2', 'history_bootstrap.py': '1b54e5976c115ed5058e674a129cae61cd3ecda1575d5bccdc078251002f8643', 'prelaunch_stop.py': 'e7975c01de8561a99dbbbf8e4870717c0624485e7f6f23287ca48a71745e4e9e', 'live_idle.py': '0e9b31ca5cc387bfb60200d8a676b720d16b052645945c75892661838388d19f', 'restart_qualification.py': '60c5f89a6c613bfa2d118e3ad56752b29c2c9d0230429ae2e3273f49fcb50466', 'current_epoch.py': 'a0607d40dd0535199068d72091fed15ee5dd1dbe32413baf476b11d3e94ced12', 'observer.py': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef', 'stage_naming.py': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d', 'entry_clock.py': '4549c760c0a90471b06509d5b526050ceb7eab8219ea9e61acd72b297e2bf69c', 'entry_clock_store.py': '37152e0b47b81670b6c45dd4bdd83884a59fd69754a3a296664dd84ed996d095', 'budget_contract.py': '5c4ad06e9dbaa3175da44a5678ae04daeb3efb4a4b62c6e1dc0542efcd0f37ae', 'safe_error.py': '2359d58a5357eb65e4a61940470c798f4e514e537029b023f24ac5c83565b203', 'terminal.py': 'edd10b0cc0cfdef9a1f1b7b2c827eadf3a7dbb5982b0e5ce55f4ba5702f272cb', 'negative_contract.py': 'abbf8c1be3b4c1f0d1f6080b0346ba7e5df3e5da1f589287528309478cca9fef', 'history_namespace.py': 'feb2331fb9df9d87c4478e3a16422f59a42f4b27aa40b4ce9204b112df2c0186', 'prelaunch_legacy.py': 'e397ff2f4e354d47aa6fed58d9c468db36794782447750cc5ccca5de5db93675', 'proc_lifetime.py': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d', 'old_failed_kernel.py': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd', 'prelaunch_history.py': 'da7c07360adafad2c28feb50e07e0260ba13b0409425729c3b404a53c50e8822', 'prelaunch_readonly.py': '3723bbd78602a684a188d2d1068b8ae23f6c6fb1fd12e9af132109b4c6b4a3f1', 'prelaunch_proof.py': '114a454cbf68e14f74b47465cf374e4c53ab8495509d5d7a1247eaabd8a045ef', 'recovered_history.py': '17b23a8a078b40fed2827d2429cffd3896da0cbd2f29528b7c429aaf95193243', 'released_stage_history.py': 'a4454b08e462ad69866b183803d612b7547b8e9215f01d625c1781cda1ded86a', 'legacy_stage.py': 'b16faa894d235a719d918737e19ed514c40488fe1b395c53934c5fde19955cc2', 'receipt_codec.py': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312', 'ready_history.py': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5', 'prelaunch_negative.py': '674ba1e45dfceff77a2abbdfc8b65993448417956aba00b3f1514b072688eed7', 'gate_protocol.py': 'bc9e38540640dc8ce7a6489099ab24f6c649e80ed943395830dacc72be9a4f3e', 'scope_receipt.py': '486fe94dbdb31db662807864e2b3f696418a2efea6f42da7037870dcb7c5a1bb', 'legacy_actor.py': '4fff2fb255f9775b0d2f5e97f8b8dee47a14d31a401f18013ae54f56f3c030eb', 'pc_clock.py': 'cb5b36e640faf8323b1d5b217b0be32aa5c63d8b9f38294a41bd84804184df06', 'pc_recovery.py': '359ec98c2d7667627f9c06b679131ddae7ec03c3bc572385baf63f5f418132a6', 'prestart_history.py': '935e30c6879dc682f685d34db611cef4db036b6c14b7a2f4ed44e87a8dcb4fd5', 'prelaunch_recovery.py': '6bd659dcaaef0769fb2ce95b6619676a5747e1cc96128c41d7112c47d523040b', 'failed_terminal.py': '3221cd26165654504ca8bd6c904440f8c92c4149e4a21bcd962c0788eb3cbd55', 'range_catalog.py': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde', 'range_transport.py': 'ae0e06e60226dc4759a95df8281115fbcaf84f4a2147de19be109b7d9f85433c', 'range_fetch.py': '4ab3dca44b7db63471f873f82f5da282580dfc6189950f0e34bb513aebc2b8a0', 'range_http.py': 'c1888164e00a619f7316ace69952484b43903667fe5b931193abd96964240762', 'range_component.py': '46ea4378229ada599beecb4e4c1b78d4d9be0ef77bb9d43ba32bec8e3c5233ad', 'asset_segments.py': '6fc4aad206356c587e5830c267b89a16f9b796c87db829c0208db69ae16bde10', 'stage_entry_clock.py': '07a409988b4905fea479ac58d71eea8010791c67d39ca94be82f28e500952a0f', 'segment_clock.py': '4fcbb8a297ed980ade98f6e4fe3b8bf4060e1fe35334c8141a94b6bb19f443b3', 'segment_terminal.py': '22b2941a926e2ea7cce37f9d8ba8884302de0e5778e80c7c4f8c84bd3eb46d43', 'asset_stage.py': '8960088fa6cea502c52db75ece7aa1969c3b255cc988e0169cc8c7effdb7850c', 'segment_publication.py': '38b98806cd695012b618383e5171d454214ed6dacad05c72bb3d7edcd7db07db', 'callbacks.py': '8b23b3342c855b5607fa43ce0ffeb40942c1d9fa98d7d0cf2504c35be796fb78', 'grant.py': '5ddec1dc173999fe76fe08dbbb4c88719b5695c3dc88e6e2f05e50e1c3bf69e2', 'history_reader.py': '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8', 'not_launched_history.py': 'cca5257979a91ddbd906eb34547c764963b8eef3de5a520962513e2810899f81', 'zero_negative.py': '5cf0471bb32ace417eef015d1a30729ff6e9b4eacdc70db9b3253d15be275679', 'zero_scope.py': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16', 'zero_qualified.py': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86', 'zero_recovery.py': '68e92923e6294d801255b1edc79e6760da03dba8aafa0666412ceca080bbbc74', 'retired_family.py': 'b0ad75aa200233143c874c0e3fac86e2443a2684f8478b96f493afd2b9e279d4', 'ffc2_history.py': '38a3448dc22f547859dca1cf8c7c4a0e57ea4fcd615776130c9d200dc1adb3fc', 'late_scope_context.py': '0e829a61212ac1089a9eb75377492ca719304c423f7cc99f92610ca45094eb92', 'known_prior_assets.py': 'f04e2c1bb7a5331bd1bec41d32530e3cebbb31495b42e630587e07b273b03c47', 'current_negative.py': '5187857874f57fc384934a40b8a06357ab735f95d6733239e16f4cf93fb872fc', 'current_prebind.py': '9ebcfd7ce75f0cb647420b4446f3b2622fdb7e8fe4ec77e3d91f47e293c2a550', 'empty_range_repair.py': '53c3959fdd766d9f3ced8ffcfeff98043a95dce97a5ecdb6b92d23b5fc497f93'}
APPROVED_ROOT_PINS = {'pc/native.py': '8574ac66813bc2dd96f905d2adba9694a7c3c9468f7b154a224e0b7da7813465', 'pc/current_reader.py': '4d9331fa6e3f7de1f4fef7beee2f3ad9007b3f68bf1a25f19f660f8c89250eab', 'pc/bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'pc/managed_scope.py': '13277133c0670097e0e8aac1877a99c39ed3899cbe108e25312c5bb5cb8b266f', 'pc/root_renewal.py': '3e52d4a4a066969c1231e51766d811e437bd486f181a0bf881721d628f8edf06'}
APPROVED_C_RENEWAL_MODULE_SHA = '0a81bec37a7eb8bcccefa6efb65cc6327f897b6fd2dcf6bc80b4fd672ecf0b10'
ORDER = ('plan.py', 'bounded_process.py', 'root_io.py', 'state.py', 'contract.py', 'lineage.py', 'managed_scope.py', 'ancestor.py', 'history_bootstrap.py', 'prelaunch_stop.py', 'live_idle.py', 'restart_qualification.py', 'current_epoch.py', 'observer.py', 'stage_naming.py', 'entry_clock.py', 'entry_clock_store.py', 'budget_contract.py', 'safe_error.py', 'terminal.py', 'negative_contract.py', 'history_namespace.py', 'prelaunch_legacy.py', 'proc_lifetime.py', 'old_failed_kernel.py', 'prelaunch_history.py', 'prelaunch_readonly.py', 'prelaunch_proof.py', 'recovered_history.py', 'released_stage_history.py', 'legacy_stage.py', 'receipt_codec.py', 'ready_history.py', 'prelaunch_negative.py', 'gate_protocol.py', 'scope_receipt.py', 'legacy_actor.py', 'pc_clock.py', 'pc_recovery.py', 'ffc2_history.py', 'prestart_history.py', 'history_reader.py', 'not_launched_history.py', 'zero_negative.py', 'zero_scope.py', 'zero_qualified.py', 'late_scope_context.py', 'zero_recovery.py', 'retired_family.py', 'prelaunch_recovery.py', 'failed_terminal.py', 'range_catalog.py', 'range_transport.py', 'range_fetch.py', 'range_http.py', 'range_component.py', 'asset_segments.py', 'stage_entry_clock.py', 'segment_clock.py', 'segment_terminal.py', 'known_prior_assets.py', 'current_negative.py', 'current_prebind.py', 'empty_range_repair.py', 'asset_stage.py', 'segment_publication.py', 'callbacks.py', 'grant.py')

def main(mode, **data):
    if any((v is None for v in (APPROVED_REVIEW, APPROVED_PACKET_SHA, APPROVED_SERVICE_PINS, APPROVED_ROOT_PINS, APPROVED_C_RENEWAL_MODULE_SHA))):
        raise RuntimeError('renewal_loader_SOURCE_pending')
    if os.getuid() != os.geteuid() or os.geteuid() != 0 or sys.platform != 'linux':
        raise RuntimeError('Root_renewal_only')
    sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
    from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, need, sha, strict
    names = {n[:-3] for n in ORDER} | {'native', 'current_reader', 'root_renewal'}
    previous = {n: sys.modules.get(n) for n in names}
    loaded = {}
    _declared = {n[:-3] for n in ORDER}
    import builtins
    _base_import = builtins.__import__
    _approved_external = {'B_OWNER_RECOVERY_R25_WIRING.common': ('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py', 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'), 'B_OWNER_RECOVERY_R25_WIRING.collector': ('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/collector.py', '3dce410687504747982d7280c709f996a96cb7f7ee0077f077944d4a75b37aa5'), 'node_adapter': ('/opt/dgx-v4/hx/runtime/node_adapter/__init__.py', 'c52939a70b86fb48139a1813b1fd2bb36305dea6b48af4040a6c8142717dc5c3'), 'node_adapter.client': ('/opt/dgx-v4/hx/runtime/node_adapter/client.py', '979444d64b0c36bc1608a0b280c9d90ee50ccda4f1a92ceb258a3d7ccf129f60'), 'node_adapter.protocol': ('/opt/dgx-v4/hx/runtime/node_adapter/protocol.py', '0af77b01e289b90544a0a07955b5ffcf794896e39a3dc68aa882c3123f39146a')}

    def held_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('R11_service_relative_import_not_reviewed')
        key = name + ''
        if key in _declared:
            if key not in loaded:
                raise ImportError('R11_service_dependency_order')
            return loaded[key]
        if name.split('.', 1)[0] in sys.stdlib_module_names:
            return _base_import(name, globals, locals, fromlist, level)
        if name not in _approved_external:
            raise ImportError('R11_service_unknown_nonstdlib_import')
        check = [name]
        if name == 'node_adapter':
            if tuple(fromlist) != ('protocol',):
                raise ImportError('R11_service_exact_node_protocol_import')
            check.append('node_adapter.protocol')
        for dependency in check:
            obj = sys.modules.get(dependency)
            path, pin = _approved_external[dependency]
            if obj is None or getattr(obj, '__file__', None) != path:
                raise ImportError('R11_service_external_module_origin')
            body, source_F9 = protected_read(path, limit=2097152)
            if sha(body) != pin:
                raise ImportError('R11_service_external_module_SHA')
        if name == 'node_adapter' and getattr(sys.modules[name], 'protocol', None) is not sys.modules.get('node_adapter.protocol'):
            raise ImportError('R11_service_exact_node_protocol_module')
        return sys.modules[name]
    try:
        for name in ORDER:
            raw, st = protected_read(ROOT / 'service' / name, limit=2097152)
            need(sha(raw) == APPROVED_SERVICE_PINS[name], 'new_current_service_source_before_renewal')
            m = types.ModuleType(name[:-3])
            m.__file__ = str(ROOT / 'service' / name)
            sys.modules[name[:-3]] = m
            loaded[name[:-3]] = m
            m.__dict__['__builtins__'] = dict(vars(builtins), __import__=held_import)
            exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        for name in ('pc/current_reader.py', 'pc/native.py', 'pc/root_renewal.py'):
            raw, st = protected_read(ROOT / name, limit=2097152)
            need(sha(raw) == APPROVED_ROOT_PINS[name], 'complete_actual_Root_renewal_IO')
            key = Path(name).stem
            m = types.ModuleType(key)
            m.__file__ = str(ROOT / name)
            sys.modules[key] = m
            exec(compile(raw, m.__file__, 'exec'), m.__dict__)
            loaded[key] = m
        packetraw, ps = protected_read(ROOT / 'epoch-packet.json', limit=2097152)
        need(sha(packetraw) == APPROVED_PACKET_SHA, 'exact_same_epoch_packet')
        p = strict(packetraw)
        n = loaded['native']
        n.APPROVED_INPUT_PINS = p['input_pins']
        n.APPROVED_OLD_CONFIG_SHA = sha(p['old_config_raw_utf8'].encode())
        n.APPROVED_NEW_CONFIG_SHA = sha(p['new_config_raw_utf8'].encode())
        rn = loaded['root_renewal']
        rn.APPROVED_C_RENEWAL_MODULE_SHA = APPROVED_C_RENEWAL_MODULE_SHA
        io = rn.RenewalNative(p)
        if mode == 'inspect-current':
            return io.capture_current(__import__('time').monotonic() + 30)
        if mode == 'collect':
            return io.collect_provisional()
        C = io.module('held_actual_C_renewal', 'C_renewal_receiver.py')
        if mode == 'C-begin':
            return C.begin(io)
        if mode == 'C-publish':
            return C.publish_envelope(io, data['nonce'], data['envelope_raw'])
        if mode == 'C-select':
            return C.select(io, data['nonce'])
        if mode == 'finalize':
            cfg = io.current.config
            installation = loaded['current_epoch'].consume_installation(protected_read, cfg, io.wall())
            return loaded['restart_qualification'].finalize(io, data['scope'], data['returned'], installation, protected_read)
        raise RuntimeError('unknown_fixed_renewal_mode')
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
