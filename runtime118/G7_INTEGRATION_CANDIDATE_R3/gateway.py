# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Authenticated fixed qualification route alongside unchanged R2 cacheprep route."""
from G7_INTEGRATION_CANDIDATE_R2.gateway import MaintenanceGatewayServer
from G7_INTEGRATION_CANDIDATE_R2.durable import Refusal
from G7_QUALIFICATION_IMPLEMENTATION_R1.permit import c as contract
from llm_gateway.errors import ForbiddenError, GatewayError
from llm_gateway.validation import parse_json_object
from control_plane.errors import ControlPlaneError

class QualificationGatewayServer(MaintenanceGatewayServer):
    qualification = None

    def route(self, method, segments, query, identity, handler):
        if segments == ['v1', 'maintenance', 'qualification']:
            c = self.qualification
            if c is None or c.config['enabled'] is not True:
                raise GatewayError('qualification disabled', code='qualification_disabled', http_status=503)
            if identity.name != c.config['caller_owner']:
                raise ForbiddenError('qualification owner denied', code='qualification_owner_denied')
            identity.require('models')
            if method != 'POST' or query:
                raise GatewayError('fixed POST endpoint only', code='qualification_shape', http_status=400)
            raw = handler._read_raw_body(limit=4096)
            body = parse_json_object(raw, max_bytes=4096)
            try:
                return (200, c.command(body, identity.name), {'Cache-Control': 'no-store'})
            except (Refusal, contract.Refusal, ControlPlaneError) as exc:
                raise GatewayError('qualification refused', code='qualification_refused', http_status=409) from exc
            finally:
                c.runtime.control_store.close_thread_connection()
        return super().route(method, segments, query, identity, handler)
