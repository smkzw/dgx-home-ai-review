# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict root-owned creative configuration; stdlib-only while disabled."""
import copy, math
from pathlib import Path
from deployment_integrations.composition import _read_trusted_json
from . import comfy_contract as cc
GATES = ('CPU_required_nodes_cache', 'native_object_info_enums', 'eight_sigma_actual_trace', 'synthetic_quality', 'native_VRAM_calibration', 'runtime_guard', 'private_transport', 'orderly_Qwen_yield', 'output_bounds', 'MCP_actual_stdio')
CONFIG_KEYS = {'schema', 'enabled', 'api_enabled', 'bind_host', 'bind_port', 'allowed_owners', 'profile', 'image_id', 'record_root', 'node_plan', 'gates', 'qualification_receipt_file', 'qualification_receipt_sha256'}

def validate_config(v, *, state_root):
    cc.need(type(v) is dict and set(v) == CONFIG_KEYS and (v['schema'] == 'g8-sole-creative-runtime/v2'), 'exact_creative_config_schema')
    cc.need(type(v['enabled']) is type(v['api_enabled']) is bool and v['bind_host'] == '127.0.0.1' and (v['bind_port'] == 4010) and (v['profile'] == cc.PROFILE) and (v['image_id'] == cc.IMAGE), 'fixed_private_creative_runtime')
    cc.need(v['record_root'] == str(Path(state_root) / 'creative'), 'same_private_service_state_root')
    cc.need(type(v['allowed_owners']) is list and len(set(v['allowed_owners'])) == len(v['allowed_owners']) and all((type(n) is str and __import__('re').fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', n) for n in v['allowed_owners'])), 'existing_registry_owners_only')
    cc.need(type(v['gates']) is dict and set(v['gates']) == set(GATES) and all((type(x) is bool for x in v['gates'].values())), 'explicit_native_gates_required')
    plan = v['node_plan']
    cc.need(type(plan) is dict and plan.get('api_kind') == 'comfy_turbo_v1' and (plan.get('image') == cc.IMAGE) and (plan.get('nodes') == [cc.NODE]), 'fixed_node_Comfy_plan')
    if v['enabled']:
        cc.need(all(v['gates'].values()) and bool(v['allowed_owners']) and v['api_enabled'], 'actual_G8_acceptance_required')
        cc.qualified_plan(plan)
        cc.need(cc.digest(v['qualification_receipt_sha256']) and type(v['qualification_receipt_file']) is str and Path(v['qualification_receipt_file']).is_absolute(), 'immutable_native_qualification_receipt_required')
    else:
        cc.need(plan.get('launch_enabled') is False and v['qualification_receipt_file'] is v['qualification_receipt_sha256'] is None and (not any(v['gates'].values())), 'disabled_pending_gates_not_promoted')
    return copy.deepcopy(v)

def load_candidate_config(path, *, state_root):
    v = validate_config(_read_trusted_json(Path(path), 'creative runtime configuration'), state_root=state_root)
    if v['enabled']:
        receipt_path = Path(v['qualification_receipt_file'])
        receipt = _read_trusted_json(receipt_path, 'G8 native qualification receipt')
        raw = receipt_path.read_bytes()
        cc.need(cc.sha(raw) == v['qualification_receipt_sha256'] and receipt.get('state') == 'G8_PARENT_NATIVE_CALIBRATED_ACCEPTED' and (receipt.get('profile') == cc.PROFILE) and (receipt.get('image_id') == cc.IMAGE) and (receipt.get('workflow_pins') == cc.PINS) and (receipt.get('gates') == v['gates']) and (receipt.get('node_ready_contract') == v['node_plan']['creative_ready']), 'actual_parent_receipt_contract_changed')
    return v

def validate_bindings(config, service, node_config, core_profiles):
    """Pure static cross-check; Turbo is an extra core/adapter profile only."""
    need = cc.need
    need(service.service_owner == cc.OWNER, 'same_existing_service_owner_required')
    core = core_profiles.get(cc.PROFILE)
    plan = node_config.profiles.get(cc.PROFILE)
    need(type(core) is dict and core.get('nodes') == [cc.NODE] and (core.get('source') == 'qwen_image_turbo'), 'exact_extra_Turbo_core_profile_required')
    need(plan is not None and plan.nodes == (cc.NODE,) and (plan.model_id == 'qwen-image-2.1-turbo') and (plan.api_host == '127.0.0.1') and (plan.api_port == 8188) and (plan.api_path == '/object_info'), 'exact_extra_Turbo_adapter_profile_required')
    need(cc.PROFILE not in service.profiles, 'Turbo_must_not_be_a_chat_activation')
    if not config['enabled']:
        need(core.get('hardware_validated') is False and core.get('min_start_available_gib') is None and (core.get('runtime_floor_gib') is None), 'disabled_Turbo_core_calibration_must_remain_pending')
    else:
        need(core.get('hardware_validated') is True, 'actual_Turbo_core_calibration_required')
        for key in ('min_start_available_gib', 'runtime_floor_gib'):
            value = core.get(key)
            need(type(value) is dict and set(value) == {cc.NODE} and (type(value[cc.NODE]) in (int, float)) and math.isfinite(value[cc.NODE]) and (value[cc.NODE] > 0), 'actual_Turbo_core_thresholds_required')
