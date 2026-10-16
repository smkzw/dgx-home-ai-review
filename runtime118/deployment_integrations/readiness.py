# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Bind engine counts to fresh, held Manager and node identities."""
import math
import re
import time
CID = re.compile('[0-9a-f]{64}\\Z')

class ReadinessUnavailable(RuntimeError):
    pass

class ManagerReadinessBinding:

    def __init__(self, runtime, *, clock=time.time, max_age=10):
        if type(max_age) not in (int, float) or not math.isfinite(max_age) or max_age <= 0:
            raise ValueError('invalid proof age')
        self.runtime = runtime
        self.clock = clock
        self.max_age = max_age

    def __call__(self, profile):
        manager, adapter = (self.runtime.manager, self.runtime.adapter)
        binding = self.runtime.facade.profiles.get(profile)
        if binding is None or not binding.enabled:
            raise ReadinessUnavailable('profile_disabled')
        before = manager.store.profile_view(profile)
        owner, generation = (before.get('owner'), before.get('generation'))
        if before.get('state') != 'READY' or owner != self.runtime.facade.service_owner or type(generation) is not int or (generation <= 0) or (before.get('hardware_validated') is not True) or (tuple(before.get('nodes', ())) != tuple(binding.nodes)) or (not manager.store.still_owned(profile, owner=owner, generation=generation)):
            raise ReadinessUnavailable('held_ready_identity_unknown')
        proof = adapter.probe_ready(profile, nodes=list(binding.nodes), owner=owner, generation=generation)
        now = self.clock()
        stamp = proof.get('observed_at') if isinstance(proof, dict) else None
        if type(now) not in (int, float) or not math.isfinite(now) or type(stamp) not in (int, float) or (not math.isfinite(stamp)) or (not 0 <= now - stamp <= self.max_age) or (proof.get('healthy') is not True) or (proof.get('profile') != profile) or (proof.get('owner') != owner) or (type(proof.get('generation')) is not int) or (proof['generation'] != generation) or (proof.get('model_id') != binding.expected_model_id) or (not isinstance(proof.get('nodes'), dict)) or (set(proof['nodes']) != set(binding.nodes)):
            raise ReadinessUnavailable('positive_node_proof_unknown')
        containers = {}
        for node, item in proof['nodes'].items():
            cid = item.get('container_id') if isinstance(item, dict) else None
            if not isinstance(item, dict) or item.get('healthy') is not True or (not isinstance(cid, str)) or (not CID.fullmatch(cid)):
                raise ReadinessUnavailable('exact_node_container_unknown')
            containers[node] = cid
        if len(set(containers.values())) != len(containers):
            raise ReadinessUnavailable('container_identity_collision')
        after = manager.store.profile_view(profile)
        if after.get('state') != 'READY' or after.get('owner') != owner or type(after.get('generation')) is not int or (after['generation'] != generation) or (tuple(after.get('nodes', ())) != tuple(binding.nodes)) or (after.get('hardware_validated') is not True) or (not manager.store.still_owned(profile, owner=owner, generation=generation)):
            raise ReadinessUnavailable('identity_changed_during_probe')
        return {'profile': profile, 'owner': owner, 'generation': generation, 'model_id': binding.expected_model_id, 'containers': containers, 'state': 'READY', 'ready': True, 'observed_at': stamp}
