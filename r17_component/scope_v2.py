# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Definition-only copied readonly scope v2 materializer, never a native plan.
Original R16 builders/observer/kernel/worker algorithms remain source-pinned.
Only the new send/A-body version and explicit PC boot cross-binding change.
"""
import ast, builtins, hashlib, pathlib, sys, types
HERE = pathlib.Path(__file__).resolve().parent
FROZEN = HERE.parent / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
PINS = {'recipes/source_io.py': '8434e60b2769e4cef379b3cbc7cfd7e01092493c568e940a025b75f596ce7c15', 'recipes/policy.py': '7ad33153f8a75069e3bb36a938468825014b584249fbe4705d6b54425ecd2029', 'recipes/owner_builder.py': '1a3b0a6869f7a4f1274c060a6cd07fa616a7ec612140d9f8ab02d2463a01472b', 'recipes/owner_scope_builder.py': 'd28182487db617c36a760fe9c0589a128eb4a081b3816348b030d9af6b8e7c45', 'recipes/BASE_PINS.json': '746f59a833d63b739a8a50b88272af45d79131321c4b1eca6c58a4bfce2612fc', 'SOURCE_CONTRACT.json': 'ee84c02caef85652edba0f6386460b167f60395f39e957dec2f23a5f0441c188', 'OWNER_POLICY.unbound.json': '287bbd2e86fa5df15535c3e815785fd5a3b83686aabe397396a6d48af152ef4e', 'owner_readonly_worker.py': '8b898ef6b47f00de94f9998e7946b045d0e23ff46306ef837ae5851a635d282e', 'owner_worker_main.py': 'ad47ee905efc74c9793fd7ecd0d1d3461f896d75433569478d7dee67b2d02012', 'owner_scope_run.py': '86697c2d5135f00b0839bb88b12187ffb0f5fa2b11d144384664ca9205d69143'}

def sha(b):
    return hashlib.sha256(b).hexdigest()

def source(rel):
    raw = (FROZEN / rel).read_bytes()
    if sha(raw) != PINS[rel]:
        raise ValueError('owner_v2_exact_frozen_builder_source')
    return raw

def materialize_cpu(nonce):
    if type(nonce) is not str or len(nonce) != 32 or any((x not in '0123456789abcdef' for x in nonce)):
        raise ValueError('owner_v2_simulated_nonce')
    modules = {}

    def imports(name, g=None, l=None, fromlist=(), level=0):
        if not level and name in modules:
            return modules[name]
        if level or name.split('.')[0] not in sys.stdlib_module_names:
            raise ImportError('owner_v2_builder_closed_import')
        return builtins.__import__(name, g, l, fromlist, level)

    def load(name, rel, raw=None):
        m = types.ModuleType('_r17_v2_builder_' + name)
        m.__file__ = str(FROZEN / rel)
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        modules[name] = m
        exec(compile(source(rel) if raw is None else raw, m.__file__, 'exec'), m.__dict__)
        return m
    for rel in PINS:
        source(rel)
    io = load('source_io', 'recipes/source_io.py')
    load('policy', 'recipes/policy.py')
    owner = load('owner_builder', 'recipes/owner_builder.py')
    old_body = owner.readonly_body

    def body(n):
        raw = old_body(n)
        text = raw.decode()
        for before, after in [('failed-owner-terminal-PC-send/v1', 'failed-owner-terminal-PC-send/v2'), ('failed-owner-terminal-A-readonly/v1', 'failed-owner-terminal-A-readonly/v2')]:
            if text.count(before) != 1:
                raise ValueError('owner_v2_A_source_exact_schema_preimage')
            text = text.replace(before, after, 1)
        before = "and bm['request_original']['sha256']==sha(request_raw)"
        if text.count(before) != 1:
            raise ValueError('owner_v2_A_source_boot_preimage')
        text = text.replace(before, "and bm['PC_boot_id']==r['new_current']['manager_identity']['boot_id']" + before, 1)
        compile(text, 'owner_v2_actual_A_body', 'exec')
        return text.encode()
    owner.readonly_body = body
    raw = source('recipes/owner_scope_builder.py')
    old = b"'/opt/dgx-v4/r16-owner-readonly-'"
    new = b"'/opt/dgx-v4/r17-owner-readonly-cpu-'"
    if raw.count(old) != 1:
        raise ValueError('owner_v2_scope_cpu_root_preimage')
    scope = load('owner_scope_builder', 'recipes/owner_scope_builder.py', raw.replace(old, new, 1))
    plan = scope.build(nonce)
    plan.update(actual=None, native_eligible=False, CPU_simulated_event_only=True)
    if sha(plan['files']['worker.py']) != plan['worker_sha256'] or sha(body(nonce)) != plan['body_sha256']:
        raise ValueError('owner_v2_final_wrapper_body_SHA')
    return (plan, scope)
