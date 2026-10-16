# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Freeze explicit component files only; never scan/copy historical CPU trees."""
import ast, difflib, hashlib, importlib.util, json, pathlib
H = pathlib.Path(__file__).resolve().parent
R = H.parent
S = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
P = R / 'parent_checks/R25_RESUME/R26_R11_R3_FIRST_SUFFIX_PARENT'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def ref(p):
    b = p.read_bytes()
    return {'sha256': sha(b), 'bytes': len(b)}

def load(name, p):
    spec = importlib.util.spec_from_file_location(name, p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
d = load('component_derive', H / 'derive.py')
candidates = d.materialize()
for name, b in candidates.items():
    p = H / 'CANDIDATE' / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b)
(H / 'CANDIDATE_PINS.json').write_bytes(encode({k: ref(H / 'CANDIDATE' / k) for k in candidates}))
sv = load('component_scope_v2', H / 'scope_v2.py')
ev = json.loads((H / 'CPU_V2_SCOPE_FIRST/V2_ORIGINALS.json').read_bytes())
plan, scope = sv.materialize_cpu(ev['policy']['probe_nonce'])
assert plan['worker_sha256'] == ev['policy']['probe_worker_sha']
for name, b in plan['files'].items():
    p = H / 'V2_SCOPE_SOURCE' / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b)
code = [*sorted((H / 'SOURCE').glob('*.py')), H / 'derive.py', H / 'scope_v2.py']
review = {'schema': 'R17-owner-convergence-component-source-review/v1', 'sources': {str(p.relative_to(H)): ref(p) for p in code}, 'actual_slots': None, 'native_eligible': False}
(H / 'COMPONENT_SOURCE_REVIEW.json').write_bytes(encode(review))
defs = []
for p in code:
    raw = p.read_bytes()
    tree = ast.parse(raw)
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
            text = ast.get_source_segment(raw.decode(), n)
            defs.append(f'### {p.relative_to(H)}:{n.lineno}-{n.end_lineno} {n.name} SOURCE_SHA={sha(raw)}\n{text}\n')
(H / 'COMPLETE_DEFINITIONS.txt').write_text('\n'.join(defs))
diff = []
for name, raw in candidates.items():
    if name in d.PINS:
        before = d.original(name).decode()
        diff += difflib.unified_diff(before.splitlines(True), raw.decode().splitlines(True), fromfile='R16/' + name, tofile='COMPONENT/' + name)
(H / 'CANDIDATE_DIFF.patch').write_text(''.join(diff))
required_results = ['BRIDGE_RESULT.json', 'PHASE_RESULT.json', 'CLOCK_RESULT.json', 'COMPILE_FLAGS_RESULT.json', 'DECISION_RESULT.json', 'BARRIER_RESULT.json', 'WITNESS_REF_RESULT.json', 'COLD_RESULT.json', 'PRIVATE_IDENTITY_RESULT.json', 'V2_SCOPE_FIRST_RESULT.json', 'FINISH_PROJECTION_RESULT.json', 'PROJECTION_V2_RESULT.json', 'V2_COLD_THIRD_RESULT.json', 'V2_HISTORY_RESULT.json']
for name in required_results:
    json.loads((H / name).read_bytes())
report = {'schema': 'R17-owner-convergence-component-report/v1', 'status': 'COMPONENT_ONLY_NOT_F1_F4_CLOSED_NOT_INSTALLABLE', 'source_review_sha256': sha((H / 'COMPONENT_SOURCE_REVIEW.json').read_bytes()), 'actual_slots': None, 'native_eligible': False, 'results': {n: ref(H / n) for n in required_results}, 'passed_boundaries': ['selected two immutable old FAILED actors and actual future-flags compiler semantics', '43 protected phase dependencies rechecked on hot use', 'new-PID renewal-before-live-owner causal cut only', 'sameboot direct PC send monotonic30 kernel', 'Journal fault/barrier/exact witness inode reference', 'fixed projection OEXCL/fullSHA/F9 and actual witness finish timestamps', 'saved v2 permit/BEGIN/A-worker-observer/finish/eligibility chain', 'actual Recovery ctor plus full original Stages ctor with complete/missing projection/unknown/broken witness', 'service and Root sealed historical reader with no write/barrier/finish'], 'pending': ['Root prepare-before-BEGIN production entry and prepared closure binding', 'v2 owner_activate hot producer and actual Grant/Runtime lifecycle integration', 'valid full new-PID renewal receipt positive', 'final private-loader co-location and explicit-delta service consumer', 'full two-contract DAG/changed-set graph/physical serialized caps', 'target real cost and final independent/native admission'], 'cold_limits': ['complete old owner historical recovery leaves distinct new source fence held', 'existing partial/wrongraw projection is never overwritten; UNKNOWN_HELD', 'write-induced partial projection may reject constructor due original snapshot drift gate', 'CPU recipe current is nonauthority and no full live current proof was manufactured'], 'old_failures_preserved': {n: ref(H / n) for n in ['V2_COLD_FIRST.stderr', 'V2_COLD_SECOND.stderr', 'V2_COLD_DIAGNOSTIC.stderr', 'V2_HISTORY.stderr']}, 'historical_reports_not_final_source_acceptance': ['COLD_RESULT.json before owner_state wiring', 'early PROJECTION_RESULT.json before witness-time interface', 'F2 causal receipt without valid renewal positive'], 'source_delta_binder_reference': {'manifest': str(R / 'R17_EXPLICIT_DELTA_DAG_BINDER_SOURCE_R1/MANIFEST.json'), 'phase_contract_ref': 'service/contract.py exact path AND SHA; Root fulltable late only'}, 'native': 0}
(H / 'COMPONENT_REPORT.json').write_bytes(encode(report))
static = [H / 'build_component.py', H / 'verify_component.py', H / 'COMPONENT_INTERFACE.md', H / 'COMPONENT_SOURCE_REVIEW.json', H / 'COMPLETE_DEFINITIONS.txt', H / 'CANDIDATE_DIFF.patch', H / 'COMPONENT_REPORT.json', H / 'CANDIDATE_PINS.json', *code, *sorted((H / 'tests').glob('*.py')), *[H / 'CANDIDATE' / n for n in candidates], *[H / 'V2_SCOPE_SOURCE' / n for n in plan['files']], *[H / n for n in required_results], H / 'CPU_V2_SCOPE_FIRST/V2_ORIGINALS.json', H / 'CPU_V2_SCOPE_FIRST/SCOPE_PINS.json', *[H / 'CPU_V2_SCOPE_FIRST/PC-originals' / n for n in ('permit.json', 'request.json', 'send-moment.json', 'received.json', 'qualified.json')]]
external = [S / 'SOURCE_MANIFEST.json', S / 'CPU/OWNER_EIGHTH/machine-capsule.json', S / 'CPU/OWNER_EIGHTH/PC/current-source-qualified.json', S / 'cpu_owner_child_r16.py', S / 'cpu_world_r16.py', R / 'R26_R11_R1_FINAL_JOINT_COLD_RUNTIME_CPU_SOURCE_R1/cpu_fs.py', R / 'R26_R11_R1_FINAL_JOINT_COLD_RUNTIME_CPU_SOURCE_R1/cpu_runtime.py', R / 'R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12/cpu_world_r12.py', R / 'R17_EXPLICIT_DELTA_DAG_BINDER_SOURCE_R1/MANIFEST.json', R / 'R17_LIVE_OWNER_RENEWAL_CPU_SOURCE_R1/MANIFEST.json', P / 'R15-d46e-family-actor-history-protected-read-r2-once/complete-actor-history.raw.json', P / 'R15-d46e-original-terminal-four-readonly-once/complete-four-originals.raw.json', P / 'R15-history-data-publish-prepared/packet.json', P / 'R15-history-data-publish-prepared/native-original.json', P / 'R15-history-data-publish-prepared/index.json', S / 'DATA/R16-normal-history.json', *[d.BASE / n for n in d.PINS]]
external += [S / n for n in sv.PINS]
external += [S / 'cpu_world_r16_base.py', S / 'ROLE_FIXTURE_REFERENCES.json']
role_refs = json.loads((S / 'ROLE_FIXTURE_REFERENCES.json').read_bytes())
external += [pathlib.Path(v['path']) for v in role_refs.values()]
external += [R / 'R26_ASSET_PROTOCOL_FAILED_EMPTY_RANGE_RECOVERY_SOURCE_R13/cpu_world_r13.py', R / 'R26_ASSET_PROTOCOL_FAILED_EMPTY_RANGE_RECOVERY_SOURCE_R13/SOURCE_MANIFEST.json', R / 'R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12/cpu_refs.py']
external += [R / 'R26_R11_R1_FINAL_JOINT_COLD_RUNTIME_CPU_SOURCE_R1' / n for n in ('cpu_world.py', 'actual118.py')]
external += [R / 'R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12/BASE/ZERO_EMITTER/external/B_OWNER_RECOVERY_R25_WIRING.common.py']
manifest = {'schema': 'R17-owner-convergence-component-manifest/v1', 'status': report['status'], 'own': {str(p.relative_to(H)): ref(p) for p in sorted(set(static))}, 'external': {str(p): ref(p) for p in sorted(set(external))}, 'upstream_readonly_catalogue': 'R16 manifest plus explicit machine-capsule mappings, no historical CPU tree copied', 'actual_slots': None, 'native_eligible': False}
(H / 'COMPONENT_MANIFEST.json').write_bytes(encode(manifest))
print(json.dumps({'manifest_sha256': sha(encode(manifest)), 'own': len(manifest['own']), 'external': len(manifest['external']), 'bytes': sum((x['bytes'] for x in manifest['own'].values())), 'status': manifest['status']}, sort_keys=True))
