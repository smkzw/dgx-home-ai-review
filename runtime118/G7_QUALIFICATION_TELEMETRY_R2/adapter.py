# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same restricted transport; additive validated actual fields, no new action."""
import copy
import re
from G7_QUALIFICATION_IMPLEMENTATION_R1.adapter import QualificationNodeAdapter as OriginalAdapter
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
FIELDS = {'schema', 'run_id', 'permit_sha256', 'record', 'guard', 'memory', 'memory_started_at', 'memory_observed_at', 'sample_issued_at', 'launch_consumed', 'complete', 'missing'}
RECORD = {'state', 'profile', 'owner', 'generation', 'container_id'}
GUARD = {'guard_pid', 'state', 'observed_at', 'profile', 'owner', 'generation', 'container_id', 'image', 'reason_code', 'source'}
MISSING = {'bound_guard_unknown', 'actual_memory_unknown', 'record_not_running', 'current_full_CID_unknown', 'launch_not_consumed'}

def validate_telemetry(reply, *, document, node):
    """The node envelope was already validated by original _exchange()."""
    v = document.value
    qp.c.need(type(reply) is dict and reply.get('status') == 'ok' and (reply.get('node') == node), 'actual_ok_node_envelope')
    t = reply.get('qualification_telemetry')
    qp.c.need(type(t) is dict and set(t) == FIELDS and (t['schema'] == 'g7-qualification-telemetry/v1'), 'explicit_telemetry_v1_fields')
    qp.c.need(t['run_id'] == v['run_id'] and t['permit_sha256'] == document.sha256, 'actual_run_permit_binding')
    r = t['record']
    qp.c.need(type(r) is dict and set(r) == RECORD, 'exact_current_record_fields')
    qp.c.need(all((r[k] == v[k] and type(r[k]) is type(v[k]) for k in ('profile', 'owner', 'generation'))), 'actual_current_owner_generation')
    qp.c.need(r['state'] in ('CLAIMED', 'RUNNING', 'CLEAR', 'QUARANTINED'), 'actual_current_record_state')
    cid = r['container_id']
    qp.c.need(cid is None or (type(cid) is str and re.fullmatch('[0-9a-f]{64}', cid)), 'current_full_CID_or_null')
    memory = t['memory']
    qp.c.need(type(memory) is dict and set(memory) in ({'source', 'mem_total_bytes', 'mem_available_bytes'}, {'source', 'mem_total_bytes', 'mem_available_bytes', 'reason'}) and (memory['source'] == 'proc_meminfo'), 'actual_memory_source_fields')
    total, available = (memory['mem_total_bytes'], memory['mem_available_bytes'])
    mem_valid = type(total) is int and total == v['host_facts'][node]['total_bytes'] and (type(available) is int) and (0 <= available <= total)
    if not mem_valid:
        qp.c.need(total is None and available is None or (type(total) is int and type(available) is int and (0 <= available <= total)), 'unknown_or_actual_memory_only')
    if memory.get('reason') is not None:
        qp.c.need(type(memory['reason']) is str and re.fullmatch('[a-z0-9_]{1,128}', memory['reason']), 'bounded_memory_reason')
    start = qp.c.number(t['memory_started_at'])
    observed = qp.c.number(t['memory_observed_at'])
    issued = qp.c.number(t['sample_issued_at'])
    envelope = qp.c.number(reply['observed_at'])
    qp.c.need(start <= observed <= issued <= envelope, 'ordered_distinct_node_timestamps')
    guard = t['guard']
    if guard is not None:
        qp.c.need(type(guard) is dict and set(guard) == GUARD and (guard['source'] == 'qualified_root_guard_status'), 'actual_guard_fields_source')
        qp.c.need(type(guard['guard_pid']) is int and guard['guard_pid'] > 1, 'actual_guard_PID')
        qp.c.need(all((guard[k] == v[k] and type(guard[k]) is type(v[k]) for k in ('profile', 'owner', 'generation'))) and guard['container_id'] == cid, 'guard_current_record_binding')
        qp.c.need(guard['image'] == v['image'] if cid is not None else guard['image'] in (None, v['image']), 'actual_guard_image_binding')
        qp.c.need(type(guard['state']) is str and re.fullmatch('[A-Z_]{1,64}', guard['state']) and (type(guard['reason_code']) is str) and re.fullmatch('[a-z0-9_]{1,128}', guard['reason_code']), 'bounded_actual_guard_codes')
        qp.c.need(0 <= issued - qp.c.number(guard['observed_at']) <= 10.0, 'fresh_actual_guard_timestamp')
    qp.c.need(type(t['launch_consumed']) is bool and type(t['complete']) is bool, 'explicit_boolean_completeness')
    missing = []
    if guard is None:
        missing.append('bound_guard_unknown')
    if not mem_valid:
        missing.append('actual_memory_unknown')
    if r['state'] != 'RUNNING':
        missing.append('record_not_running')
    if cid is None:
        missing.append('current_full_CID_unknown')
    if not t['launch_consumed']:
        missing.append('launch_not_consumed')
    qp.c.need(type(t['missing']) is list and t['missing'] == missing and (t['complete'] == (not missing)), 'actual_completeness_no_inference')
    return copy.deepcopy(t)

class QualificationNodeAdapter(OriginalAdapter):

    def observe_telemetry(self, *, document, node):
        self._require_usable()
        v = document.value
        self._checked_nodes(v['profile'], list(qp.c.NODES))
        qp.c.need(node in qp.c.NODES, 'fixed_AB_node')
        self._check_recorded_owner(v['profile'], v['generation'], v['owner'])
        reply, meta = self._exchange(node, 'probe')
        item = {'verified': False, 'reason_code': 'telemetry_observation_unknown', 'local_received_at': meta['received_at'], 'node_remote_observed_at': meta.get('remote_observed_at'), 'telemetry': None}
        if reply is None:
            item['reason_code'] = 'existing_transport_failure'
            return item
        try:
            item.update(verified=True, reason_code='actual_readonly_observation', telemetry=validate_telemetry(reply, document=document, node=node))
        except (ValueError, KeyError, TypeError):
            pass
        return item

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
            observation = {'verified': False, 'reason_code': 'telemetry_observation_unknown', 'local_received_at': meta['received_at'], 'node_remote_observed_at': meta.get('remote_observed_at'), 'telemetry': None}
            if reply is None:
                observation['reason_code'] = 'existing_transport_failure'
            else:
                try:
                    observation.update(verified=True, reason_code='actual_readonly_observation', telemetry=validate_telemetry(reply, document=document, node=node))
                except (ValueError, KeyError, TypeError):
                    pass
            item['telemetry_observation'] = observation
            result[node] = item
        return result
