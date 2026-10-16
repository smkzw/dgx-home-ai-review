# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Reuse the existing restricted node channel and its full owner/generation journal.

No new transport, resource manager or rollback. Existing profiles are unchanged.
The parent must install and qualify this candidate before enabling DeepSeek.
"""
from node_adapter.client import NodeAdapter, ConfigError
PROFILE = 'deepseek-zig-ab'
MODEL = 'DeepSeek-V4.1-Flash-TF'
NODES = ('spark-a', 'spark-b')
ROLES = {'spark-a': 'api_leader', 'spark-b': 'worker'}

class DeepSeekNodeAdapter(NodeAdapter):

    def __init__(self, config, **kwargs):
        plan = config.profiles.get(PROFILE)
        if plan is not None and (plan.nodes != NODES or plan.model_id != MODEL or plan.roles != ROLES):
            raise ConfigError('DeepSeek requires exact AB/rank0 leader/rank1 worker identity')
        super().__init__(config, **kwargs)

    def _checked_nodes(self, profile, nodes):
        checked = super()._checked_nodes(profile, nodes)
        return ['spark-b', 'spark-a'] if profile == PROFILE else checked
