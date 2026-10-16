# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure frozen R16 derivation. Unfilled pins deny all use; no remote actions."""
import builtins, hashlib, json, sys, types
from pathlib import Path
P = Path(__file__).resolve().parent
R = P.parents[2]
H = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
NATIVE = R / 'parent_checks/R21_CONTINUE_NATIVE_R1/native_parent.py'
NATIVE_SHA = 'dcdd599f2f672cced4c494b5e5934510f0d64f6034fa32c4a094e40ea0acc237'
WARNING_SHA = 'b280c454d6f559e56eb3f5ed39f3ba084b8d1744a3ff7fe016b21ff86dea1aca'
MANIFEST_SHA = 'c613f2887de430fbd23569a9831c43cf766e268f5cb17b2c0de32a8c619ce8d5'
REVIEW_SHA = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
PHYSICAL_SHA = '8ec72a07ec0e27df8825177c0aaa5afb860d069403c10770c989bd7ed31c6b8a'
ADAPTER_SHA = '4c2b5ad7840f06b33f844281074f9ca772fb2c132c86995cdc74ff6395877910'
FINAL_DIRECTORY = 'FINAL_GRAPH'
ENTRY_NONCE = 'e21f830185b7e1ffbd0ca049a040b4a2'
EPOCH = '2b9e9b631cebc13ae6b1550ee59c13ed'
FAMILY = 'ed7021db9df4c839d02f3271361924de'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def enc(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def need(v, r):
    if not v:
        raise ValueError(r)

def module(path, name):
    m = types.ModuleType(name)
    m.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), m.__dict__)
    return m

def stderr_ok(native, tag, node):
    b = (native.HERE / tag / 'actual.stderr').read_bytes()
    need(b == b'' or (node == 'pc' and len(b) == 132 and (sha(b) == WARNING_SHA)), 'R16_exact_empty_or_original_WSL_warning')
    return {'bytes': len(b), 'sha256': sha(b)}

def load(*, publish_local_parent_sources=False):
    need(all((type(v) is str and len(v) == 64 for v in (MANIFEST_SHA, REVIEW_SHA, PHYSICAL_SHA, ADAPTER_SHA))) and type(FINAL_DIRECTORY) is str and (type(ENTRY_NONCE) is str) and (len(ENTRY_NONCE) == 32), 'R16_parent_final_source_pins_None')
    raw = (H / 'SOURCE_MANIFEST.json').read_bytes()
    need(sha(raw) == MANIFEST_SHA, 'R16_exact_frozen_manifest')
    manifest = json.loads(raw)
    need(manifest['schema'] == 'R16-failed-owner-joint-frozen-source/v1' and manifest['actual_slots'] is None and (manifest['native_eligible'] is False) and (manifest['review_sha256'] == REVIEW_SHA), 'R16_frozen_source_not_permission')
    for n, row in manifest['own'].items():
        path = H / n
        need(not path.is_symlink(), 'R16_no_ambient_source_symlink')
        b = path.read_bytes()
        need(sha(b) == row['sha256'] and len(b) == row['bytes'], 'R16_all_frozen_own_' + n)
    for n, row in manifest['external'].items():
        b = Path(n).read_bytes()
        need(sha(b) == row['sha256'] and len(b) == row['bytes'], 'R16_all_frozen_external')
    sources = {p.stem: p.read_bytes() for p in (H / 'recipes').glob('*.py') if 'recipes/' + p.name in manifest['own']}
    loaded = {}

    def get(name):
        if name in loaded:
            return loaded[name]

        def imports(n, g=None, l=None, f=(), level=0):
            if not level and n in sources:
                return get(n)
            if not level and n == 'source_tools' and (n in sys.modules):
                return sys.modules[n]
            need(not level and n.split('.')[0] in sys.stdlib_module_names, 'R16_no_ambient_recipe_import_' + n)
            return builtins.__import__(n, g, l, f, level)
        m = types.ModuleType('R16_parent_recipe_' + name)
        m.__file__ = str(H / 'recipes' / (name + '.py'))
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        loaded[name] = m
        exec(compile(sources[name], m.__file__, 'exec'), m.__dict__)
        return m
    builder = get('builder')
    io = get('source_io')
    review = io.encode(builder.source_review())
    need(sha(review) == REVIEW_SHA, 'R16_exact_source_review')
    g = builder.materialize(review, ENTRY_NONCE)
    need(g['packet']['operation'] == EPOCH and g['packet']['grant_operation'] == FAMILY, 'R16_fixed_epoch_and_family')
    root = H / FINAL_DIRECTORY
    pr = (root / 'PHYSICAL_PINS.json').read_bytes()
    need(sha(pr) == PHYSICAL_SHA, 'R16_final_physical_table')
    observed = {role + '/' + n: {'sha256': sha(b), 'bytes': len(b)} for role, files in (('PC', g['PC']), ('A', g['A']['files']), ('C_static9', g['C_static9'])) for n, b in files.items()}
    need(observed == json.loads(pr) == manifest['physical'] and len(g['PC']) == 128 and (g['serialized_PC_source_bundle_bytes'] <= 4194304), 'R16_exact_all_final_bytes_and_original_caps')
    for name, row in observed.items():
        need((root / name).read_bytes() == {'PC': g['PC'], 'A': g['A']['files'], 'C_static9': g['C_static9']}[name.split('/', 1)[0]][name.split('/', 1)[1]], 'R16_final_disk_bytes')
    owner = g['owner_scope']
    need(owner['pins'] == {n: sha(b) for n, b in owner['files'].items()} and owner['worker_sha256'] == sha(owner['files']['worker.py']), 'R16_owner_scope_final_wrapped_bytes')
    owner_pins = {n: {'sha256': sha(b), 'bytes': len(b)} for n, b in owner['files'].items()}
    need(len(owner_pins) == 8 and owner_pins == manifest['owner_scope'], 'R16_separate_eight_owner_scope_pins')
    for n, b in owner['files'].items():
        need((root / 'owner_scope' / n).read_bytes() == b, 'R16_separate_owner_scope_final_disk_bytes')
    ap = H / 'parent_adapter_r16.py'
    need(sha(ap.read_bytes()) == ADAPTER_SHA, 'R16_final_parent_adapter')
    adapter = module(ap, 'R16_fixed_parent_adapter')
    destination = P / 'R16-native-parent-modules'
    derived = adapter.materialize(destination, g)
    files = derived['files']
    mods = {}
    if publish_local_parent_sources:
        if not destination.exists():
            destination.mkdir(mode=448)
            for name, b in files.items():
                with (destination / name).open('xb') as f:
                    f.write(b)
                (destination / name).chmod(384)
        need(sorted((p.name for p in destination.iterdir())) == sorted(files) and all(((destination / n).read_bytes() == b for n, b in files.items())), 'R16_exact_existing_or_new_local_parent_sources')

    def parent(name):
        if name in mods:
            return mods[name]

        def imports(n, g=None, l=None, f=(), level=0):
            if not level and n + '.py' in files:
                return parent(n)
            need(not level and n.split('.')[0] in sys.stdlib_module_names, 'R16_no_ambient_parent_import')
            return builtins.__import__(n, g, l, f, level)
        m = types.ModuleType('R16_private_parent_' + name)
        m.__file__ = str(destination / (name + '.py'))
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        mods[name] = m
        exec(compile(files[name + '.py'], m.__file__, 'exec'), m.__dict__)
        return m
    e = parent('emission')
    baseline = json.loads((H / 'R16_BASELINE_IMMUTABLE.json').read_bytes())
    package = {path: row for path, row in baseline['source_files'].items() if path in {e.PACKAGE_ROOT + n for n in ('__init__.py', 'common.py', 'collector.py')}}
    emitted = e.Emission(g, package, base_source=io.BASE)
    need(sha(NATIVE.read_bytes()) == NATIVE_SHA, 'R16_existing_parent_transport_pin')
    native = module(NATIVE, 'R16_existing_native_parent_definitions')
    return types.SimpleNamespace(graph=g, review=review, builder=builder, source_io=io, recipes=get, emission=e, emitted=emitted, get=parent, adapter=adapter, parent_sources=files, parent_pins=derived['pins'], parent_destination=destination, baseline=baseline, native=native, manifest=manifest, native_eligible=False)
