# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One restricted existing node channel. No transport, retry or scheduler added."""
from G7_PROFILE_CANDIDATE_R1.deepseek_profile.adapter import DeepSeekNodeAdapter
from node_adapter.client import ConfigError
from .compiler import PREP, PREP_MODEL, NODES

class IntegrationNodeAdapter(DeepSeekNodeAdapter):

    def __init__(self, config, **kwargs):
        plan = config.profiles.get(PREP)
        if plan is not None and (plan.nodes != NODES or plan.model_id != PREP_MODEL or plan.roles != {'spark-a': 'api_leader', 'spark-b': 'worker'}):
            raise ConfigError('cache prep requires exact AB rank identity')
        super().__init__(config, **kwargs)

    def _checked_nodes(self, profile, nodes):
        checked = super()._checked_nodes(profile, nodes)
        return list(NODES) if profile == PREP else checked
