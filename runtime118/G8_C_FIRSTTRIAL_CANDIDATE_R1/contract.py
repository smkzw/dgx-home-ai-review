# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite C Comfy RPC contract. No arbitrary method, URL, graph, path or argv."""
import copy, hashlib, json, math, re, uuid
PROFILE = 'image-turbo-c'
OWNER = 'dgx-hx-service'
NODE = 'spark-c'
IMAGE = 'sha256:deb877df825701c8a299996ac4374bc47f6bb082a011d4f9a156a4a6e57d6f06'
MAX_MEDIA = 50 * 1024 ** 2
CHUNK = 24 * 1024
MAX_INFO = 8 * 1024 ** 2
REQUIRED = ('UNETLoader', 'CLIPLoader', 'VAELoader', 'TextEncodeQwenImage21', 'QwenImage21Cache', 'CFGGuider', 'RandomNoise', 'KSamplerSelect', 'ManualSigmas', 'SamplerCustomAdvanced', 'VAEDecode', 'SaveImage', 'LoadImage')
PINS = {'image.generate.v1': 'd2705c1172ced106bb8161634e57adba9282736519f47b11c6dd024ba93acd6a', 'image.edit.v1': '10b4eed775675080b22d772bd25a340b07ab543e8057cf4cef106c8d5ac78aaf'}
MODELS = {'UNETLoader': ('unet_name', 'qwen_image_2.1_turbo_bf16.safetensors'), 'CLIPLoader': ('clip_name', 'qwen3vl_8b_bf16.safetensors'), 'VAELoader': ('vae_name', 'qwen_image_2.1_vae_bf16.safetensors')}
SIGMAS = '1.0, 0.978453, 0.95418, 0.926626, 0.89508, 0.845148, 0.704534, 0.414568, 0.0'

class Refusal(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refusal(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def loads(raw):

    def pairs(rows):
        out = {}
        for k, v in rows:
            need(k not in out, 'duplicate_JSON_key')
            out[k] = v
        return out

    def finite(s):
        n = float(s)
        need(math.isfinite(n), 'nonfinite_JSON')
        return n
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=lambda _: need(False, 'nonfinite_JSON'))

def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None

def pid(value):
    need(type(value) is str and re.fullmatch('[0-9a-f-]{36}', value) is not None and (str(uuid.UUID(value)) == value), 'canonical_prompt_UUID')
    return value

def object_schema(info):
    need(type(info) is dict and all((n in info and type(info[n]) is dict for n in REQUIRED)), 'required_Comfy_classes_missing')
    for n in REQUIRED:
        v = info[n]
        need(type(v.get('input')) is dict and type(v.get('output')) is list, 'Comfy_node_schema_invalid')
    enums = {}
    for node, (field, name) in MODELS.items():
        value = info[node]['input'].get('required', {}).get(field)
        need(type(value) in (list, tuple) and bool(value) and (type(value[0]) in (list, tuple)) and (name in value[0]), 'Comfy_required_weight_enum_missing')
        enums[node] = list(value[0])
    return ({n: info[n] for n in REQUIRED}, enums)

def qualified_plan(plan):
    need(plan.get('api_kind') == 'comfy_turbo_v1' and plan.get('launch_enabled') is True and (plan.get('image') == IMAGE) and (plan.get('nodes') == [NODE]) and (plan.get('model_id') == 'qwen-image-2.1-turbo') and (plan.get('api') == {'host': '127.0.0.1', 'port': 8188, 'path': '/object_info'}), 'qualified_fixed_Comfy_plan_required')
    q = plan.get('creative_ready')
    need(type(q) is dict and set(q) == {'object_info_sha256', 'model_enums_sha256', 'parent_qualification_receipt_sha256', 'workflow_pins', 'eight_sigma_quality_accepted', 'VRAM_calibrated'}, 'creative_ready_contract_required')
    need(all((digest(q[k]) for k in ('object_info_sha256', 'model_enums_sha256', 'parent_qualification_receipt_sha256'))) and q['workflow_pins'] == PINS and (q['eight_sigma_quality_accepted'] is q['VRAM_calibrated'] is True), 'native_qualification_receipts_required')
    return q

def ready_proof(info, plan, cid, generation, observed_at):
    q = qualified_plan(plan)
    subset, enums = object_schema(info)
    need(sha(canonical(subset)) == q['object_info_sha256'] and sha(canonical(enums)) == q['model_enums_sha256'], 'actual_Comfy_schema_or_enum_changed')
    need(digest(cid) and type(generation) is int and (generation > 0), 'exact_CID_generation_required')
    return {'kind': 'comfy_turbo_v1', 'container_id': cid, 'image_id': IMAGE, 'object_info_sha256': q['object_info_sha256'], 'model_enums_sha256': q['model_enums_sha256'], 'workflow_pins': PINS, 'parent_qualification_receipt_sha256': q['parent_qualification_receipt_sha256'], 'profile': PROFILE, 'owner': OWNER, 'generation': generation, 'observed_at': observed_at}

def proof_valid(proof, plan, cid, generation, now):
    q = qualified_plan(plan)
    expected = {'kind': 'comfy_turbo_v1', 'container_id': cid, 'image_id': IMAGE, 'object_info_sha256': q['object_info_sha256'], 'model_enums_sha256': q['model_enums_sha256'], 'workflow_pins': PINS, 'parent_qualification_receipt_sha256': q['parent_qualification_receipt_sha256'], 'profile': PROFILE, 'owner': OWNER, 'generation': generation, 'observed_at': None}
    need(type(proof) is dict and set(proof) == set(expected), 'typed_Comfy_readiness_required')
    need(all((type(proof[k]) is type(v) and proof[k] == v for k, v in expected.items() if k != 'observed_at')), 'typed_Comfy_readiness_identity_mismatch')
    t = proof['observed_at']
    need(type(t) in (int, float) and math.isfinite(t) and (0 <= now - t <= 30), 'fresh_nonfuture_Comfy_readiness_required')
    return proof

def validate_graph(graph, marker, templates):
    need(type(marker) is dict and set(marker) == {'job_id', 'owner_sha256', 'payload_digest', 'template_sha256'}, 'fixed_job_marker_required')
    jid = marker['job_id']
    need(type(jid) is str and re.fullmatch('job_[0-9a-f]{32}', jid) and all((digest(marker[k]) for k in ('owner_sha256', 'payload_digest', 'template_sha256'))), 'job_marker_identity')
    candidates = [value for workflow, value in templates.items() if PINS[workflow] == marker['template_sha256']]
    need(len(candidates) == 1 and type(graph) is dict and (len(canonical(graph)) <= 56 * 1024), 'fixed_workflow_required')
    base = copy.deepcopy(candidates[0])
    need(type(graph.get('4')) is dict and type(graph.get('7')) is dict and (type(graph.get('12')) is dict), 'fixed_graph_nodes_required')
    prompt = graph['4']['inputs'].get('prompt')
    seed = graph['7']['inputs'].get('noise_seed')
    prefix = graph['12']['inputs'].get('filename_prefix')
    need(type(prompt) is str and bool(prompt.strip()) and (len(prompt) <= 12000) and (type(seed) is int) and (0 <= seed < 2 ** 63) and (prefix == 'hx-' + jid), 'fixed_graph_parameters')
    base['4']['inputs']['prompt'] = prompt
    base['7']['inputs']['noise_seed'] = seed
    base['12']['inputs']['filename_prefix'] = prefix
    if '13' in base:
        image = graph.get('13', {}).get('inputs', {}).get('image')
        need(type(image) is str and re.fullmatch('hx-[0-9a-f]{32}\\.(png|jpg|webp)', image), 'fixed_uploaded_input_filename')
        base['13']['inputs']['image'] = image
    need(graph == base, 'arbitrary_graph_or_schedule_refused')
    return jid
