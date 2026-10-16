# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Current installation event evaluation before BEGIN; hot use reads every input.

This cut deliberately does not claim current actor/lease/nonce/resource authority.
The original dynamically mixed actor_parent consumer is a separate obligation.
"""
import hashlib
import json
import stat
CAP = 2 * 1024 ** 2

class PhasePreparationRefused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise PhasePreparationRefused(reason)

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

class PreparedInstallation:

    def __init__(self, config, output, dependencies, gate, bridge, bridge_restore):
        self._config = encode(config)
        self._output = encode(output)
        self._dependencies = encode(dependencies)
        self._gate = gate
        self._bridge = bridge
        self._restore = bridge_restore

    def installation(self, read, config):
        need(encode(config) == self._config, 'prepared_installation_exact_config_not_new_authority')
        for path, ref in json.loads(self._dependencies).items():
            raw, f = read(path, limit=CAP)
            need(len(raw) == f[2] <= CAP and f[3] == 0 and (f[6] == 1) and stat.S_ISREG(f[5]) and (not f[5] & 18) and (sha(raw) == ref['sha256']) and (f == ref['F9']), 'prepared_installation_fresh_dependency_fullSHA_F9')
        return json.loads(self._output)

    def current_owner(self, read, identity, actual_identity):
        self.installation(read, json.loads(self._config))
        return self._gate.verify_current_owner(identity, actual_identity=actual_identity, input_read=read, prepared_history=lambda mods: install_history_view(mods, self._bridge, self._restore))

    @property
    def dependencies(self):
        return json.loads(self._dependencies)

def install_history_view(mods, bridge, bridge_restore):
    hr = mods['history_reader']
    pc = mods['pc_recovery']

    def prepared_full_history(read):
        ref = pc.APPROVED_NORMAL_HISTORY
        raw, f = read(ref['path'], limit=CAP)
        pc.need(pc.sha(raw) == ref['sha256'] and f == ref['F9'] and (f[3:7] == [0, 989, 33056, 1]), 'R16_normal_data_actual_Root_SHA_fullF9')
        value = pc.strict(raw)
        policy = hr.owner_policy()
        pc.need(value['schema'] == 'R16-failed-owner-normal-history/v1' and value['old_records'] == policy['old_records'] and (value['old_completed'] == policy['old_completed']) and (value['old_terminal'] == policy['old_terminal']) and (value['old_plan'] == policy['old_plan']) and (value['current_A_source'] == policy['old_A_sources']), 'R16_normal_data_exact_owner_Source_binding')
        restored, domain = bridge_restore(hr, bridge, read)
        pc.need(domain == value['old_domain'], 'R16_normal_full_original_bridge_algorithms')
        pc.need(read(ref['path'], limit=CAP) == (raw, f), 'R16_normal_data_held_after_full_history')
        return (raw, value, restored)
    pc.full_history = prepared_full_history

def prepare(read, config, initial_identity, event_now, consume_initial, gate, bridge, bridge_restore):
    """Internal pinned-definition inputs, no generic evaluator/caller closure flag.

    gate is the SOURCE-copied private loader. Caller supplies the original
    initial consumer with only its phase callback selecting the historical API.
    Real current PID/renew/lease/actors remain outside this historical result.
    """
    dependencies = {}

    def record(path, *, limit=CAP, owner=0):
        need(owner == 0 and 0 < limit <= 4 * 1024 ** 2, 'prepared_installation_Root_read_capability')
        raw, f = read(path, limit=limit)
        key = str(path)
        need(len(raw) == f[2] <= CAP and f[3] == 0 and (f[6] == 1) and stat.S_ISREG(f[5]) and (not f[5] & 18), 'prepared_installation_protected_original')
        ref = {'sha256': sha(raw), 'F9': f}
        need(key not in dependencies or dependencies[key] == ref, 'prepared_installation_input_raced_during_semantics')
        dependencies[key] = ref
        return (raw, f)
    phases = []

    def verify(installed):
        for phase in ('before-stop', 'after-stop'):
            mods, old, held = gate.load(phase, input_read=record)
            try:
                install_history_view(mods, bridge, bridge_restore)
                result = mods['phase_history'].consume_event_history(installed, phase)
                need(all((record(path, limit=CAP) == value for path, value in held.items())), 'prepared_installation_phase_source_fullF9_after')
                phases.append(result)
            finally:
                gate.restore(old)
    value = consume_initial(record, config, initial_identity, event_now, phase_verify=verify)
    need(set(phases and [p['phase'] for p in phases]) == {'before-stop', 'after-stop'}, 'prepared_installation_both_original_phase_consumers')
    for path, ref in bridge.dependency_refs.items():
        raw, f = record(path, limit=CAP)
        need({'sha256': sha(raw), 'F9': f} == ref, 'prepared_installation_complete_bridge_refs')
    token = PreparedInstallation(config, dict(value, initial_identity=initial_identity, historical_only=True), dependencies, gate, bridge, bridge_restore)
    token.installation(read, config)
    return token
