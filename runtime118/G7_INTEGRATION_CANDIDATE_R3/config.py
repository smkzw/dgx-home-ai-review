# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed private root config, separate from immutable one-shot root permit."""
import re
from pathlib import Path
from deployment_integrations.composition import _read_trusted_json
from G7_INTEGRATION_CANDIDATE_R2.durable import need
SCHEMA = 'g7-private-qualification-r3/v1'
KEYS = {'schema', 'enabled', 'parent_accepted', 'caller_owner', 'run_id', 'run_root', 'permit_sha256'}
PATH = Path('/etc/dgx-home-ai/g7-qualification-command.json')

def validate(v):
    need(type(v) is dict and set(v) == KEYS and (v['schema'] == SCHEMA), 'qualification_command_config_schema')
    need(type(v['enabled']) is bool and type(v['parent_accepted']) is bool, 'explicit_qualification_gates')
    need(type(v['caller_owner']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', v['caller_owner']), 'fixed_derived_caller')
    need(type(v['run_id']) is str and re.fullmatch('[0-9a-f]{32}', v['run_id']), 'fixed_root_run')
    need(type(v['run_root']) is str, 'fixed_private_run_root')
    p = Path(v['run_root'])
    need(p.is_absolute() and '..' not in p.parts and (str(p) == str(Path('/srv/dgx-home-ai/runtime/hx-service-state/g7/qualification') / v['run_id'])), 'existing_unit_private_RW_root')
    need(type(v['permit_sha256']) is str and re.fullmatch('[0-9a-f]{64}', v['permit_sha256']), 'actual_raw_root_permit_SHA')
    return v

def load():
    return validate(_read_trusted_json(PATH, 'private qualification command config'))
