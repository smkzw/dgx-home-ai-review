# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact Rootheld module DAG. SOURCE literal defaults cannot be JSON enabled."""
import os, sys, types
from pathlib import Path
from contract import *
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
MODE = 'epoch'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
APPROVED_PACKET_SHA = '739f71df746d966e6937427197887d14bb774e69375a03cf1bb7daff0d6af19c'
APPROVED_MODULE_PINS = {'contract.py': '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8', 'pc/managed_scope.py': '13277133c0670097e0e8aac1877a99c39ed3899cbe108e25312c5bb5cb8b266f', 'pc/ancestor.py': 'fc6d353080ac2b2eca2457665d5e69049e626d89cde53022ba1f8e5b2356ade2', 'pc/ancestor_producer.py': 'c385eb7c82242e589bd55c63fd2c5594e4ff04eeecb7b5d1cfca76d853558bef', 'pc/bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'pc/prelaunch_stop.py': 'e7975c01de8561a99dbbbf8e4870717c0624485e7f6f23287ca48a71745e4e9e', 'pc/prelaunch_barrier.py': '5bb66da37dbdd4a823eae3508265f575fb22d20155d6c4bc62567aa258fcb29f', 'pc/current_reader.py': '4d9331fa6e3f7de1f4fef7beee2f3ad9007b3f68bf1a25f19f660f8c89250eab', 'pc/native.py': '8574ac66813bc2dd96f905d2adba9694a7c3c9468f7b154a224e0b7da7813465', 'pc/epoch_transaction.py': 'c537aaff97d3596828301d956e9df9d7325265d423908ec35ef80e0f125da111', 'pc/qualifier.py': '217a5cb2fd3970678f98da5feaa934aa53d249ec372a2db946914b4d75df0a1e'}
MODULE_ORDER = ('contract.py', 'pc/managed_scope.py', 'pc/ancestor.py', 'pc/ancestor_producer.py', 'pc/bounded_process.py', 'pc/prelaunch_stop.py', 'pc/prelaunch_barrier.py', 'pc/current_reader.py', 'pc/native.py', 'pc/epoch_transaction.py', 'pc/qualifier.py')

def restore_modules(previous):
    for name, value in previous.items():
        if value is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = value

def load_modules(source_root):
    loaded = {}
    previous = {Path(name).stem: sys.modules.get(Path(name).stem) for name in MODULE_ORDER}
    try:
        need(type(APPROVED_MODULE_PINS) is dict and set(APPROVED_MODULE_PINS) == set(MODULE_ORDER), 'full_fixed_root_module_closure')
        for relative in MODULE_ORDER:
            raw, st = protected_read(source_root / relative, limit=2097152)
            need(sha(raw) == APPROVED_MODULE_PINS[relative], 'source_closed_Root_module')
            name = Path(relative).stem
            m = types.ModuleType(name)
            m.__file__ = str(source_root / relative)
            sys.modules[name] = m
            loaded[name] = m
            exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        return (loaded, previous)
    except BaseException:
        restore_modules(previous)
        raise

def main():
    need(APPROVED_REVIEW is not None and APPROVED_PACKET_SHA is not None and (APPROVED_MODULE_PINS is not None), 'finite_registry_loader_default_None')
    need(MODE in ('history', 'epoch', 'history-finalize', 'epoch-finalize') and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux'), 'literal_only_Root_PC_mode')
    source_root = HISTORY_ROOT if MODE.startswith('history') else PC_ROOT
    packetraw, st = protected_read(source_root / ('history-packet.json' if MODE.startswith('history') else 'epoch-packet.json'))
    need(sha(packetraw) == APPROVED_PACKET_SHA, 'held_fixed_packet')
    p = strict(packetraw)
    loaded, previous = load_modules(source_root)
    try:
        native = loaded['native']
        native.APPROVED_INPUT_PINS = p['input_pins']
        native.APPROVED_OLD_CONFIG_SHA = sha(p['old_config_raw_utf8'].encode())
        native.APPROVED_NEW_CONFIG_SHA = sha(p.get('new_config_raw_utf8', p['old_config_raw_utf8']).encode())
        if MODE == 'history':
            producer = loaded['ancestor_producer']
            producer.APPROVED_OLD_ROOT_SOURCE_PINS = p['old_root_source_pins']
            from inputs import io_utils as io
            if not PC_ROOT.exists():
                PC_ROOT.mkdir(mode=488)
                os.chown(PC_ROOT, 0, 989)
                os.chmod(PC_ROOT, 488)
            for path in (PC_ROOT / 'historical-private', PC_ROOT / 'historical', PC_ROOT / 'historical/raw'):
                need(not path.exists() and (not path.is_symlink()), 'new_immutable_history_archive_only')
                path.mkdir(mode=488)
                os.chown(path, 0, 989)
                os.chmod(path, 488)

            def write(path, raw):
                io.fresh(path, raw, mode=288, gid=989)
                return protected_read(path)[1]
            body = producer.produce(p['old_config_raw_utf8'].encode(), p['old_identity'], write=write)
            io.fresh(PC_ROOT / 'historical-private/body.json', encode(body))
            return {'qualified_body_sha256': sha(encode(body))}
        if MODE == 'epoch':
            result = loaded['epoch_transaction'].transaction(native.RootNative(p, old=True), packetraw)
            return {'installed_body_sha256': sha(encode(result))}
        from scope_observer import observe
        if MODE == 'history-finalize':
            from inputs import io_utils as io

            def write(path, raw):
                io.fresh(path, raw, mode=288, gid=989)
            q = loaded['qualifier'].finalize_history(observe('history'), write=write)
            return {'qualified_sha256': sha(encode(q))}
        q = loaded['qualifier'].finalize(native.RootNative(p, old=False), observe('epoch'))
        return {'qualified_sha256': sha(encode(q))}
    finally:
        restore_modules(previous)
