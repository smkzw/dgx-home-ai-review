# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Existing restricted transport plus one read-only qualification observation.

No new wire action, transport, executable argv, credential or retry. Production
factory must alias this subclass at its existing single adapter constructor.
"""
from G7_INTEGRATION_CANDIDATE_R1.adapter import IntegrationNodeAdapter
from . import permit as qp

class QualificationNodeAdapter(IntegrationNodeAdapter):

    def observe_qualification(self, *, document):
        self._require_usable()
        v = document.value
        self._checked_nodes(v['profile'], list(qp.c.NODES))
        self._check_recorded_owner(v['profile'], v['generation'], v['owner'])
        result = {}
        for node in qp.c.NODES:
            reply, meta = self._exchange(node, 'probe')
            item = {'verified': False, 'observed_at': meta['received_at'], 'reason_code': meta.get('reason') or 'qualification_observation_unknown'}
            if reply is not None and reply.get('status') == 'ok':
                q = reply.get('qualification')
                fields = {'schema', 'run_id', 'permit_sha256', 'profile', 'owner', 'generation', 'guard_state', 'reason_code', 'observed_at'}
                if type(q) is dict and set(q) == fields and (q['schema'] == 'g7-qualification-observation/v1'):
                    if all((q[k] == v[k] and type(q[k]) is type(v[k]) for k in ('run_id', 'profile', 'owner', 'generation'))) and q['permit_sha256'] == document.sha256:
                        try:
                            stamp = qp.c.number(q['observed_at'])
                            remote = qp.c.number(reply['observed_at'])
                            qp.c.need(0 <= remote - stamp <= 10.0, 'root_guard_observation_stale')
                            item.update(q, verified=True, observed_at=meta['received_at'], remote_observed_at=stamp)
                        except (ValueError, KeyError):
                            pass
            result[node] = item
        return result
