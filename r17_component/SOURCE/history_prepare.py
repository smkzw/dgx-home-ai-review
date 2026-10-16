# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Selected R16 old two-FAILED history kernel, prepared before paired BEGIN.

Original source bodies execute in fresh private dictionaries. The selected
historical kernel receives no OS/clock/process/network capability. Catalog reads
are exact preheld bytes. An unselected branch requiring those capabilities
refuses; a trace does not grant an implicit capability.
"""
import ast
import __future__
import builtins
import hashlib
import json
import pathlib
import sys
import types
CAP = 2 * 1024 ** 2
PURE_LIBS = frozenset(('__future__', 'ast', 'base64', 'copy', 'dataclasses', 'errno', 'hashlib', 'json', 'math', 're', 'stat', 'struct', 'typing', 'zlib'))
DENIED_LIBS = frozenset(('fcntl', 'io', 'os', 'select', 'subprocess', 'tarfile', 'time'))

class PreparationRefused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise PreparationRefused(reason)

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def denied(*args, **kwargs):
    raise PreparationRefused('prepared_history_dynamic_capability_refused')

class NoCapability(types.ModuleType):

    def __getattr__(self, name):
        if self.__name__ == 'os' and name.startswith(('O_', 'SEEK_')):
            import os
            value = getattr(os, name)
            if type(value) is int:
                return value
        return denied

class PreparedBridge:
    """Private bytes only, not a shared Bridge/module or an authorization token."""

    def __init__(self, value, dependencies, code_pins, flags, optimize):
        self._raw = encode(value)
        self._dependencies = encode(dependencies)
        self._codes = dict(code_pins)
        self._flags = flags
        self._optimize = optimize

    def recheck(self, read):
        for path, ref in json.loads(self._dependencies).items():
            raw, f = read(path, limit=CAP)
            need(type(raw) is bytes and type(f) is list and (len(f) == 9) and (len(raw) == f[2] <= CAP) and (f[3:7] == [0, 989, 33056, 1]) and (sha(raw) == ref['sha256']) and (f == ref['F9']), 'prepared_history_fresh_fullSHA_F9_protection')
        return json.loads(self._raw)

    def code(self, raw, filename):
        key = (sha(raw), filename, sys.implementation.cache_tag, sys.version_info[:3], self._flags, self._optimize)
        need(key in self._codes, 'prepared_history_exact_compilation_key')
        return self._codes[key]

    @property
    def dependency_refs(self):
        return json.loads(self._dependencies)

def prepare_bridge(read, history, current_config):
    """Internal SOURCE function, never caller JSON or whole mixed-consumer cache.

    history is the existing privately loaded/pinned history_reader. The full
    original epoch_load/epoch_consume_snapshot/typed terminal predicates remain.
    Root IO uses fresh `read`; only semantic evaluation has restricted imports.
    """
    dependencies = {}
    codes = {}
    catalog_bytes = {}
    future_mask = 0
    for name in __future__.all_feature_names:
        future_mask |= getattr(__future__, name).compiler_flag
    inherited_flags = history.epoch_OldContext.module.__code__.co_flags & future_mask
    optimize = sys.flags.optimize
    binding = history.epoch_APPROVED_BINDING
    need(type(binding) is dict and set(binding) == {'snapshot', 'source_bundle', 'old_metadata'}, 'prepared_history_bound_complete_binding')

    def held(path, pin=None, cap=4 * 1024 ** 2, mode=None, *, stat_only=False):
        need(not stat_only and 0 < cap <= 4 * 1024 ** 2 and (mode in (None, 288)), 'prepared_history_only_original_Root_inputs')
        raw, f = read(path, limit=min(cap, CAP))
        key = str(path)
        need(type(raw) is bytes and type(f) is list and (len(f) == 9) and (f[2] == len(raw) <= CAP) and (f[3:7] == [0, 989, 33056, 1]) and (pin is None or sha(raw) == pin), 'prepared_history_actual_Root_input')
        ref = {'sha256': sha(raw), 'F9': f}
        need(key not in dependencies or dependencies[key] == ref, 'prepared_history_dependency_changed_during_prepare')
        dependencies[key] = ref
        return (raw, f)
    for name, ref in binding['old_metadata'].items():
        raw, f = held(ref['path'], ref['sha256'], mode=288)
        need(f == ref['F9'], 'prepared_history_catalog_fullF9')
        catalog_bytes[ref['path']] = raw
    need(set(binding['old_metadata']) == {'manifest-original.json', 'config-original.json'}, 'prepared_history_exact_two_catalog_inputs')

    class CatalogPath(pathlib.PurePosixPath):

        def resolve(self, *args, **kwargs):
            return self

        def read_bytes(self):
            need(str(self) in catalog_bytes, 'prepared_history_no_undeclared_catalog_read')
            return catalog_bytes[str(self)]
    path_module = types.ModuleType('pathlib')
    path_module.Path = CatalogPath
    path_module.PurePosixPath = pathlib.PurePosixPath

    class Context(history.epoch_OldContext):

        def imports(self, name, gl=None, lo=None, fromlist=(), level=0):
            need(not level, 'prepared_history_no_relative_ambient_import')
            if name + '.py' in self.sources:
                return self.module(name)
            if name == 'B_OWNER_RECOVERY_R25_WIRING':
                package = types.ModuleType(name)
                package.common = self.module(name + '.common')
                return package
            if name == 'pathlib':
                return path_module
            if name in DENIED_LIBS:
                return NoCapability(name)
            need(name in PURE_LIBS, 'prepared_history_closed_pure_stdlib_import')
            return builtins.__import__(name, gl, lo, fromlist, level)

        def module(self, name):
            if name in self.loaded:
                return self.loaded[name]
            key = name + '.py'
            need(key in self.sources, 'prepared_history_closed_source_member')
            raw = self.sources[key]
            filename = str(self.code_root / key)
            codekey = (sha(raw), filename, sys.implementation.cache_tag, sys.version_info[:3], inherited_flags, optimize)
            if codekey not in codes:
                codes[codekey] = compile(raw, filename, 'exec', flags=inherited_flags, dont_inherit=True, optimize=optimize)
            private = '_owner_prepared_' + str(id(self)) + '_' + name.replace('.', '_')
            module = types.ModuleType(private)
            module.__file__ = filename
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=self.imports, open=denied, input=denied, eval=denied)
            self.loaded[name] = module
            absent = object()
            previous = sys.modules.get(private, absent)
            sys.modules[private] = module
            try:
                exec(codes[codekey], module.__dict__)
            except BaseException:
                self.loaded.pop(name, None)
                raise
            finally:
                if previous is absent:
                    sys.modules.pop(private, None)
                else:
                    sys.modules[private] = previous
            return module
    namespace = dict(vars(history), epoch_OldContext=Context, epoch_held_root=held)
    original_consume = history.epoch_consume_snapshot
    consume = types.FunctionType(original_consume.__code__, namespace, original_consume.__name__)
    calls = []

    def consume_selected(snapshot, sources, code_root):
        states = {stage: history.epoch_strict(history.epoch_raw(records['terminal.json'], [999, 989, 33152, 1]))['state'] for stage, records in snapshot['actors'].items()}
        need(set(states) == {'b7a518bbefa903b6c43c44b9a2f6f6cf', '69b0a7b8356ae276839c3cc43044096c'}, 'prepared_history_selected_exact_actor_set')
        need(set(states.values()) == {'FAILED_REGISTRY_QUIESCENT'}, 'prepared_history_unselected_branch_not_cached')
        value = consume(snapshot, sources, code_root)
        calls.append(value)
        return value
    namespace['epoch_consume_snapshot'] = consume_selected

    class Bridge(history.epoch_Bridge):

        def __init__(self, snapshot, sources, code_root):
            self.snapshot = snapshot
            self.result = consume_selected(snapshot, sources, code_root)
    namespace['epoch_Bridge'] = Bridge
    load = types.FunctionType(history.epoch_load.__code__, namespace, 'epoch_load')
    bridge = load(current_config)
    source_raw, _ = held(binding['source_bundle']['path'], binding['source_bundle']['sha256'], mode=288)
    sources = history.epoch_open_bundle(source_raw)
    snapshot_raw = encode(bridge.snapshot)
    source_sha = sha(source_raw)

    def same_result(snapshot, given, root):
        need(encode(snapshot) == snapshot_raw and given == sources and (root == history.epoch_PC_ROOT + '/service'), 'prepared_history_same_exact_semantic_arguments')
        return json.loads(encode(bridge.result))
    domain_ns = dict(namespace, epoch_consume_snapshot=same_result)
    domain = types.FunctionType(history.old_domain_from_snapshot.__code__, domain_ns, 'old_domain_from_snapshot')(bridge.snapshot, sources)
    value = {'schema': 'owner-prepared-selected-old-history/v1', 'snapshot': bridge.snapshot, 'result': bridge.result, 'domain': domain, 'snapshot_sha256': sha(snapshot_raw), 'source_bundle_sha256': source_sha, 'historical_only': True, 'resource_authorized': False, 'source_activation_authorized': False}
    token = PreparedBridge(value, dependencies, codes, inherited_flags, optimize)
    token.recheck(read)
    return token

def restore_bridge(history, token, read):
    need(type(token) is PreparedBridge, 'prepared_history_internal_token_type')
    value = token.recheck(read)
    bridge = object.__new__(history.epoch_Bridge)
    bridge.snapshot = value['snapshot']
    bridge.result = value['result']
    return (bridge, value['domain'])
