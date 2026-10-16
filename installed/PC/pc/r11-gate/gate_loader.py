# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Protected isolated module set; current state never comes from a request."""
import hashlib, os, stat, sys, types
from pathlib import Path
ROOT = '/opt/dgx-v4/hx/mimo-registry-r16/pc/r11-gate'
APPROVED_FILES = {'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'observer.py': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef', 'old_failed_kernel.py': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd', 'proc_lifetime.py': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d', 'receipt_codec.py': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312', 'ready_history.py': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5', 'legacy_actor.py': '4fff2fb255f9775b0d2f5e97f8b8dee47a14d31a401f18013ae54f56f3c030eb', 'history_namespace.py': 'feb2331fb9df9d87c4478e3a16422f59a42f4b27aa40b4ce9204b112df2c0186', 'plan.py': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f', 'history_reader.py': '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8', 'pc_recovery.py': '02dd5a50c67eff80cd2f18d5fd01df6283e9bc7c518ca696da8cfffc7ea839f8', 'prelaunch_negative.py': '59cb1f7fadb65146fd2c881ff8a66aa7275626b861124518e668abaf7f1bdefc', 'prelaunch_stop.py': 'e7975c01de8561a99dbbbf8e4870717c0624485e7f6f23287ca48a71745e4e9e', 'gate_protocol.py': '92236924459e681694bd269043aad1c27b01ab3d59dca29ada7ef77375594e14', 'scope_receipt.py': '486fe94dbdb31db662807864e2b3f696418a2efea6f42da7037870dcb7c5a1bb', 'pc_gate.py': '1a8ea39ecc1e2f11455a230962cc4ca4d17503de8c56c96ab77896876d476d52', 'phase_history.py': '912e56a54f2f08cfe98527847ab4c694b0fe35514bda664c45f34b3b19acbbf3'}
PHASES = ('before-stop', 'after-stop')
ORDER = ('plan', 'root_io', 'bounded_process', 'observer', 'old_failed_kernel', 'proc_lifetime', 'receipt_codec', 'ready_history', 'legacy_actor', 'history_namespace', 'history_reader', 'prelaunch_negative', 'pc_recovery', 'prelaunch_stop', 'gate_protocol', 'scope_receipt', 'pc_gate', 'phase_history')
APPROVED_COMMON_SHA = 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'
APPROVED_CONTRACT_SHA = '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8'

def load(phase):
    if ROOT is None or APPROVED_FILES is None or set(APPROVED_FILES) != {n + '.py' for n in ORDER} or (phase not in PHASES):
        raise RuntimeError('R11_protected_gate_SOURCE_pending')
    from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
    mods = {}
    held = {}
    original_import = __import__
    common = sys.modules.get('B_OWNER_RECOVERY_R25_WIRING.common')
    common_path = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py'
    if common is None or getattr(common, '__file__', None) != common_path:
        raise ImportError('R11_gate_protected_common_origin')
    common_raw, common_F9 = protected_read(common_path, limit=2097152)
    if hashlib.sha256(common_raw).hexdigest() != APPROVED_COMMON_SHA:
        raise ImportError('R11_gate_protected_common_SHA')

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in (*ORDER, 'contract'):
            if name not in mods:
                raise ImportError('R11_gate_dependency_order')
            return mods[name]
        if name == 'B_OWNER_RECOVERY_R25_WIRING.common' and (not level):
            return common
        if level or name.split('.', 1)[0] not in sys.stdlib_module_names:
            raise ImportError('R11_gate_unknown_nonstdlib_import')
        return original_import(name, globals, locals, fromlist, level)

    def one(name, path, pin):
        raw, f = protected_read(path, limit=2097152)
        if f[3:7] != [0, 989, 33056, 1] or hashlib.sha256(raw).hexdigest() != pin:
            raise RuntimeError('R11_actual_PC_gate_source_SHA_F9')
        held[path] = (raw, f)
        m = types.ModuleType('_R11_private_gate_' + name)
        m.__file__ = str(path)
        import builtins
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        exec(compile(raw, str(path), 'exec'), m.__dict__)
        mods[name] = m
    one('contract', Path(ROOT).parent.parent / 'contract.py', APPROVED_CONTRACT_SHA)
    for n in ORDER:
        one(n, Path(ROOT).parent.parent / APPROVED_SOURCE_PATHS[n + '.py'], APPROVED_FILES[n + '.py'])
    mods['prelaunch_negative'].ROOT = Path(mods['gate_protocol'].ROOTS[phase])
    return (mods, {}, held)

def restore(old):
    if old:
        raise RuntimeError('R11_private_gate_no_global_module_restore')

def run(native, packet, before, phase, end):
    mods, old, held = load(phase)
    try:
        result = mods['pc_gate'].await_phase(native, packet, before, phase, end)
        from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
        if any((protected_read(path, limit=2097152) != value for path, value in held.items())):
            raise RuntimeError('R11_gate_source_F9_after_phase')
        return result
    finally:
        restore(old)

def verify_installed(installed):
    result = []
    for phase in ('before-stop', 'after-stop'):
        mods, old, held = load(phase)
        try:
            result.append(mods['phase_history'].consume(installed, phase))
            from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
            if any((protected_read(path, limit=2097152) != value for path, value in held.items())):
                raise RuntimeError('phase_history_gate_full_source_F9_after')
        finally:
            restore(old)
    return result
APPROVED_SOURCE_PATHS = {'root_io.py': 'service/root_io.py', 'bounded_process.py': 'service/bounded_process.py', 'observer.py': 'service/observer.py', 'old_failed_kernel.py': 'service/old_failed_kernel.py', 'proc_lifetime.py': 'service/proc_lifetime.py', 'receipt_codec.py': 'service/receipt_codec.py', 'ready_history.py': 'service/ready_history.py', 'legacy_actor.py': 'service/legacy_actor.py', 'history_namespace.py': 'service/history_namespace.py', 'plan.py': 'service/plan.py', 'history_reader.py': 'service/history_reader.py', 'pc_recovery.py': 'pc/r11-gate/pc_recovery.py', 'prelaunch_negative.py': 'pc/r11-gate/prelaunch_negative.py', 'prelaunch_stop.py': 'service/prelaunch_stop.py', 'gate_protocol.py': 'pc/r11-gate/gate_protocol.py', 'scope_receipt.py': 'service/scope_receipt.py', 'pc_gate.py': 'pc/r11-gate/pc_gate.py', 'phase_history.py': 'pc/r11-gate/phase_history.py'}
