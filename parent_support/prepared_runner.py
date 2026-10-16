# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Parent-only once stage entry. Inert until exact source and actual originals.
It uses the existing IO/Window/Mux and attaches only the typed prebind close.
No Runtime/Manager/Adapter is constructed on this Mac or outside the sole owner.
"""
import builtins
import json
import os
from pathlib import Path
import stat
import sys
import types
import uuid
from binding import load_parent_modules, need, sha

def held(path, pin):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and (stat.S_IMODE(s.st_mode) == 384) and (s.st_nlink == 1) and (s.st_size <= 4194304), 'actual_private_parent_source_identity')
        raw = os.pread(fd, s.st_size + 1, 0)
        need(len(raw) == s.st_size and sha(raw) == pin and all((getattr(s, k) == getattr(os.fstat(fd), k) == getattr(path.lstat(), k) for k in keys)), 'actual_private_parent_source_SHA_F9')
        return raw
    finally:
        os.close(fd)

class Packet:
    """Same private complete-byte loader used by the caller and CPU preflight."""

    def __init__(self, root, expected_files):
        self.root = Path(root)
        need(type(expected_files) is dict and 'parent_entry.py' in expected_files and ('parent-final-index.json' in expected_files), 'actual_accepted_complete_parent_source_table')
        self.sources = {name: held(self.root / name, pin) for name, pin in expected_files.items()}
        index = json.loads(self.sources['parent-final-index.json'])
        need(all((expected_files[n] == pin for n, pin in index['files'].items())), 'actual_parent_index_and_physical_source_table')
        self.prefix = '_R12_parent_stage_' + uuid.uuid4().hex
        self.original_path = list(sys.path)
        self.loaded = {}
        self.registered = []

    def imports(self, name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name + '.py' in self.sources:
            return self.get(name)
        need(not level and name.split('.')[0] in sys.stdlib_module_names, 'fixed_parent_packet_unknown_import')
        return builtins.__import__(name, globals, locals, fromlist, level)

    def get(self, name):
        if name in self.loaded:
            return self.loaded[name]
        need(name + '.py' in self.sources, 'closed_parent_module_table')
        m = types.ModuleType(self.prefix + '.' + name)
        m.__file__ = str(self.root / (name + '.py'))
        m.__package__ = self.prefix
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=self.imports)
        self.loaded[name] = m
        sys.modules[m.__name__] = m
        self.registered.append(m.__name__)
        exec(compile(self.sources[name + '.py'], m.__file__, 'exec'), m.__dict__)
        return m

    def close(self):
        for name in self.registered:
            sys.modules.pop(name, None)
        sys.path[:] = self.original_path

def bind_io(io, support, once, emitted, RPC_original, A_original):
    """Bind the one private Mac IO before its real initializer is called."""
    original = io.IO
    need(not getattr(original, '_R12_prebind_bound', False), 'private_IO_hook_not_rebound')

    class BoundIO(original):
        _R12_prebind_bound = True

        def __init__(self, end):
            super().__init__(end)
            support['segment_hook'].attach(self, once, emitted, RPC_original, A_original, tag='R12-prebind-close')
    io.IO = BoundIO
    return BoundIO

def run(root, expected_files, once, emitted, RPC_original, A_original):
    """Native caller is the coordinating parent after final/fresh acceptance.
    CPU callers must explicitly project IO/Mux/transport; this is not a permit.
    """
    packet = Packet(root, expected_files)
    try:
        support = load_parent_modules()
        support['late_rpc'].validate_policy(emitted.graph, RPC_original)
        support['prebind_failure'].source_policy(emitted, A_original)
        context = json.loads(packet.sources['runtime-context.json'])
        need(context['manager_identity'] == RPC_original['current']['manager_identity'] and context['PC_config_sha256'] == sha(emitted.graph['config']) == RPC_original['policy']['config_sha256'], 'actual_same_new_qualified_owner_not_old_parent')
        bind_io(packet.get('parent_io'), support, once, emitted, RPC_original, A_original)
        return packet.get('parent_entry').main()
    finally:
        packet.close()
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_requires_actual_qualified_parent_binding')
