# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite action over this runtime's existing restricted transport, no retry."""
import secrets
from node_adapter import protocol
from .permit import cc, NODENAME, PROFILE, OWNER

def call(adapter, operation, document, *, container_id=None):
    cc.need(operation in ('preflight', 'claim', 'start', 'schema', 'submit', 'status', 'trace', 'result'), 'finite_C_trial_operation')
    adapter._require_usable()
    v = document.value
    adapter._checked_nodes(PROFILE, [NODENAME])
    rid = secrets.token_hex(16)
    request = {'schema': protocol.SCHEMA, 'request_id': rid, 'action': 'c_firsttrial', 'node': NODENAME, 'profile': PROFILE, 'owner': OWNER, 'generation': v['generation'], 'operation': operation}
    sent = adapter._clock()
    r = adapter._transport.exchange(adapter.config.hosts[NODENAME], protocol.encode_request(request, max_bytes=adapter.config.max_request_bytes))
    received = adapter._clock()
    cc.need(not r.spawn_error and (not r.timed_out) and (not r.output_exceeded) and (r.returncode == 0), 'C_trial_transport_unknown_no_replay')
    reply = protocol.validate_reply(r.stdout, expect_action='c_firsttrial', expect_node=NODENAME, expect_request_id=rid, identity=(PROFILE, OWNER, v['generation']), max_bytes=adapter.config.max_output_bytes, sent_at=sent, received_at=received, max_skew_seconds=adapter.config.max_clock_skew_seconds)
    cc.need(reply.get('status') == 'ok' and reply.get('permit_sha256') == document.sha256 and (reply.get('run_id') == v['run_id']), 'C_trial_actual_root_binding')
    if container_id is not None:
        cc.need(reply.get('container_id') == container_id, 'C_trial_CID_changed')
    return reply
