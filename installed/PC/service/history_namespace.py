# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Closed, per-consumption historical module graph; never an ambient importer.
Frozen module/embedded bytes are not rewritten. sys.modules used by those bytes
is a private table. Only dataclass initialization gets a unique, temporary real
module key, with exact object removal; canonical aliases are never installed.
"""
import ast, base64, builtins, hashlib, secrets, sys, types
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, need, sha
APPROVED_EXTERNAL_PINS = {'B_OWNER_RECOVERY_R25_WIRING': {'path': '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/__init__.py', 'sha256': '26f933b08466de8bd8b44301ed43b4dab141eff71bc133e6b6e4190366c53232'}, 'B_OWNER_RECOVERY_R25_WIRING.common': {'path': '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py', 'sha256': 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'}, 'B_OWNER_RECOVERY_R25_WIRING.collector': {'path': '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/collector.py', 'sha256': '3dce410687504747982d7280c709f996a96cb7f7ee0077f077944d4a75b37aa5'}, 'node_adapter': {'path': '/opt/dgx-v4/hx/runtime/node_adapter/__init__.py', 'sha256': 'c52939a70b86fb48139a1813b1fd2bb36305dea6b48af4040a6c8142717dc5c3'}, 'node_adapter.client': {'path': '/opt/dgx-v4/hx/runtime/node_adapter/client.py', 'sha256': '979444d64b0c36bc1608a0b280c9d90ee50ccda4f1a92ceb258a3d7ccf129f60'}, 'node_adapter.protocol': {'path': '/opt/dgx-v4/hx/runtime/node_adapter/protocol.py', 'sha256': '0af77b01e289b90544a0a07955b5ffcf794896e39a3dc68aa882c3123f39146a'}}

class Namespace:

    def __init__(self, root, pins):
        need(type(root) is str and root.startswith('/opt/dgx-v4/hx/') and (type(pins) is dict) and pins and all((type(n) is str and n.endswith('.py') and ('/' not in n) and (type(v) is str) and (len(v) == 64) for n, v in pins.items())), 'historical_exact_fixed_source_namespace')
        need(type(APPROVED_EXTERNAL_PINS) is dict, 'historical_external_source_pending')
        self.root = root.rstrip('/')
        self.pins = dict(pins)
        self.table = {}
        self.embedded = {}
        self.embedded_held = {}
        self.unique = '__R11_history_' + secrets.token_hex(16) + '_'
        self.real_import = builtins.__import__
        self.proxy = types.ModuleType('sys')
        self.proxy.__dict__.update(vars(sys))
        self.proxy.modules = self.table
        self.builtins = dict(vars(builtins), __import__=self.importer)
        self.external = {}
        for name, ref in APPROVED_EXTERNAL_PINS.items():
            obj = sys.modules.get(name)
            need(obj is not None and getattr(obj, '__file__', None) == ref['path'], 'historical_external_exact_module')
            raw, f9 = protected_read(ref['path'], limit=2097152)
            need(sha(raw) == ref['sha256'], 'historical_external_source_SHA')
            self.external[name] = obj

    def importer(self, name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('historical_relative_import_not_reviewed')
        if name == 'sys':
            return self.proxy
        origin = (globals or {}).get('__file__', '')
        for parent, children in self.embedded.items():
            if origin.startswith(parent + ':') and name in children:
                obj = self.embedded_held.get(parent, {}).get(name) or self.table.get(name)
                need(type(obj) is types.ModuleType and getattr(obj, '__file__', None) == parent + ':' + name, 'historical_embedded_dependency_order_origin')
                return obj
        if name + '.py' in self.pins:
            obj = self.table.get(name)
            need(type(obj) is types.ModuleType and getattr(obj, '__file__', None) == self.root + '/' + name + '.py', 'historical_dependency_order_origin')
            return obj
        if name.split('.', 1)[0] in sys.stdlib_module_names:
            return self.real_import(name, globals, locals, fromlist, 0)
        if name in self.external:
            obj = self.external[name]
            if name == 'node_adapter':
                need(tuple(fromlist or ()) == ('protocol',) and getattr(obj, 'protocol', None) is self.external.get('node_adapter.protocol'), 'historical_fixed_node_protocol')
            if fromlist:
                return obj
            parent = self.external.get(name.split('.', 1)[0])
            need(parent is not None, 'historical_external_package_origin')
            return parent
        raise ImportError('historical_unknown_nonstdlib_import')

    def _embedded(self, raw, path):
        tree = ast.parse(raw)
        values = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ('_sources', '_pins'):
                        values[target.id] = ast.literal_eval(node.value)
        if not values:
            return
        expected = {'plan', 'root_io', 'old_failed_kernel', 'prepayload', 'scope', 'pc_consumer'}
        need(path == self.root + '/prepayload_negative.py' and set(values) == {'_sources', '_pins'} and (set(values['_sources']) == set(values['_pins']) == expected), 'historical_exact_R9_embedded_namespace')
        for name, encoded in values['_sources'].items():
            body = base64.b64decode(encoded, validate=True)
            need(sha(body) == values['_pins'][name], 'historical_embedded_full_source_SHA')
        self.embedded[path] = dict(values['_pins'])

    def load(self, name, raw, path):
        need(name in self.pins and path == self.root + '/' + name and (sha(raw) == self.pins[name]), 'historical_module_exact_raw_SHA')
        self._embedded(raw, path)
        key = name[:-3]
        unique = self.unique + key
        m = types.ModuleType(unique)
        m.__file__ = path
        m.__dict__['__builtins__'] = self.builtins
        self.table[key] = m
        need(unique not in sys.modules, 'historical_unique_module_collision')
        sys.modules[unique] = m
        try:
            exec(compile(raw, path, 'exec'), m.__dict__)
        finally:
            need(sys.modules.get(unique) is m, 'historical_unique_module_replaced')
            del sys.modules[unique]
        if path in self.embedded:
            held = m.__dict__.get('_mods')
            need(type(held) is dict and set(held) == set(self.embedded[path]), 'historical_embedded_complete_original_modules')
            for k, obj in held.items():
                need(type(obj) is types.ModuleType and obj.__file__ == path + ':' + k, 'historical_embedded_held_origin')
            self.embedded_held[path] = dict(held)
        return m
