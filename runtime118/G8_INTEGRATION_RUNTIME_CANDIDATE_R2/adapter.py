# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Typed Comfy readiness/RPC on the same existing restricted NodeAdapter SSH."""
import base64, copy, secrets, threading
from G7_QUALIFICATION_TELEMETRY_R2.adapter import QualificationNodeAdapter as NodeAdapter
from node_adapter import protocol
from . import comfy_contract as cc

class CreativeNodeAdapter(NodeAdapter):

    def bind_comfy_plan(self, plan):
        cc.need(not hasattr(self, 'comfy_plan'), 'Comfy_contract_already_bound')
        cc.need(type(plan) is dict and plan.get('api_kind') == 'comfy_turbo_v1', 'fixed_Comfy_contract_required')
        self.comfy_plan = copy.deepcopy(plan)

    def _ready_node(self, node, reply, meta, plan, *, profile, owner, generation):
        item = super()._ready_node(node, reply, meta, plan, profile=profile, owner=owner, generation=generation)
        if profile != cc.PROFILE:
            return item
        try:
            cc.need(node == cc.NODE and owner == cc.OWNER and hasattr(self, 'comfy_plan'), 'sole_Comfy_contract_binding_required')
            cc.need(item.get('healthy') is True and reply.get('observed_at') <= meta['received_at'], 'Comfy_positive_nonfuture_reply_required')
            record = reply.get('record', {})
            cc.need(record.get('profile') == cc.PROFILE and record.get('owner') == cc.OWNER and (type(record.get('generation')) is int) and (record['generation'] == generation) and cc.digest(record.get('container_id')), 'typed_record_owner_generation_required')
            proof = cc.proof_valid(reply.get('creative_proof'), self.comfy_plan, item['container_id'], generation, meta['received_at'])
            item.update(creative_proof=proof, reason='typed_Comfy_schema_models_qualified')
        except Exception:
            item.update(healthy=False, reason='typed_Comfy_readiness_refused')
        return item

    def comfy_rpc(self, operation, payload, *, generation, container_id):
        self._require_usable()
        self._check_recorded_owner(cc.PROFILE, generation, cc.OWNER)
        cc.need(hasattr(self, 'comfy_plan'), 'sole_Comfy_contract_binding_required')
        cc.qualified_plan(self.comfy_plan)
        cc.need(cc.digest(container_id) and type(generation) is int and (generation > 0), 'exact_RPC_CID_generation')
        request_id = secrets.token_hex(16)
        request = {'schema': protocol.SCHEMA, 'request_id': request_id, 'action': 'comfy_rpc', 'node': cc.NODE, 'profile': cc.PROFILE, 'owner': cc.OWNER, 'generation': generation, 'operation': operation, 'payload': payload}
        raw = protocol.encode_request(request, max_bytes=self.config.max_request_bytes)
        sent = self._clock()
        result = self._transport.exchange(self.config.hosts[cc.NODE], raw)
        received = self._clock()
        cc.need(not result.spawn_error and (not result.timed_out) and (not result.output_exceeded) and (result.returncode == 0), 'Comfy_RPC_exchange_unknown')
        reply = protocol.validate_reply(result.stdout, expect_action='comfy_rpc', expect_node=cc.NODE, expect_request_id=request_id, identity=(cc.PROFILE, cc.OWNER, generation), max_bytes=min(self.config.max_output_bytes, 262144), sent_at=sent, received_at=received, max_skew_seconds=self.config.max_clock_skew_seconds)
        cc.need(reply.get('status') == 'ok' and reply.get('container_id') == container_id and (sent - self.config.max_clock_skew_seconds <= reply['observed_at'] <= received), 'exact_fresh_nonfuture_Comfy_RPC_reply')
        return reply['result']

class PrivateComfy:
    """The creative component's existing interface, without a C HTTP listener."""

    def __init__(self, adapter):
        self.adapter = adapter
        self.generation = None
        self.container_id = None
        self.lock = threading.RLock()
        self.closing = threading.Event()

    def quiesce(self):
        self.closing.set()

    def bind(self, generation, container_id):
        cc.need(type(generation) is int and generation > 0 and cc.digest(container_id), 'private_Comfy_pin_required')
        with self.lock:
            self.generation = generation
            self.container_id = container_id

    def call(self, operation, value):
        with self.lock:
            cc.need(not self.closing.is_set(), 'private_Comfy_service_closing')
            cc.need(self.generation is not None, 'private_Comfy_lease_not_bound')
            generation, cid = (self.generation, self.container_id)
        return self.adapter.comfy_rpc(operation, value, generation=generation, container_id=cid)

    def object_info(self):
        return self.call('object_info', {})

    def queue(self):
        return self.call('queue', {})

    def history(self, pid):
        return self.call('history', {'prompt_id': cc.pid(pid)})

    def cancel(self, pid):
        return self.call('cancel', {'prompt_id': cc.pid(pid)})

    def submit(self, pid, client, marker, graph):
        return self.call('submit', {'prompt_id': cc.pid(pid), 'client_id': cc.pid(client), 'marker': marker, 'graph': graph})

    def upload(self, raw, media):
        cc.need(type(raw) is bytes and 0 < len(raw) <= cc.MAX_MEDIA, 'bounded_private_media')
        r = self.call('upload_begin', {'size': len(raw), 'sha256': cc.sha(raw), 'media_type': media})
        tid = r['transfer_id']
        cc.need(cc.digest(tid) and r['size'] == len(raw) and (r['sha256'] == cc.sha(raw)), 'upload_begin_identity')
        for offset in range(0, len(raw), cc.CHUNK):
            part = raw[offset:offset + cc.CHUNK]
            v = self.call('upload_chunk', {'transfer_id': tid, 'offset': offset, 'data_b64': base64.b64encode(part).decode()})
            cc.need(v == {'offset': offset + len(part)}, 'upload_chunk_ack')
        return self.call('upload_finish', {'transfer_id': tid})['name']

    def result(self, output):
        r = self.call('result_begin', output)
        cc.need(type(r['size']) is int and 0 < r['size'] <= cc.MAX_MEDIA and cc.digest(r['transfer_id']) and cc.digest(r['sha256']), 'result_transfer_identity')
        raw = bytearray()
        while len(raw) < r['size']:
            part = self.call('result_chunk', {'transfer_id': r['transfer_id'], 'offset': len(raw)})
            cc.need(part['offset'] == len(raw) and part['total_sha256'] == r['sha256'], 'result_chunk_identity')
            data = base64.b64decode(part['data_b64'], validate=True)
            cc.need(0 < len(data) <= cc.CHUNK and len(raw) + len(data) <= r['size'], 'result_chunk_bound')
            raw.extend(data)
        cc.need(cc.sha(raw) == r['sha256'], 'full_result_SHA_required')
        cc.need(self.call('transfer_release', {'transfer_id': r['transfer_id']}) == {'released': True}, 'result_receipt_release_required')
        return bytes(raw)
