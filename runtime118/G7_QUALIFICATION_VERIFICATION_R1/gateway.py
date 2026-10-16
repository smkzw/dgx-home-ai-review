# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same existing authenticated gateway; extra fixed evidence-only route."""
from G7_INTEGRATION_CANDIDATE_R3.gateway import QualificationGatewayServer
from G7_INTEGRATION_CANDIDATE_R2.durable import Refusal
from G7_QUALIFICATION_IMPLEMENTATION_R1.permit import c as contract
from llm_gateway.errors import ForbiddenError, GatewayError
from llm_gateway.validation import parse_json_object
from control_plane.errors import ControlPlaneError

class VerificationGatewayServer(QualificationGatewayServer):
    verification = None

    def route(self, method, segments, query, identity, handler):
        if segments == ['v1', 'maintenance', 'qualification-verification']:
            c = self.verification
            if c is None or c.config['enabled'] is not True:
                raise GatewayError('verification disabled', code='qualification_verification_disabled', http_status=503)
            if identity.name != c.config['caller_owner']:
                raise ForbiddenError('verification owner denied', code='qualification_verification_owner_denied')
            identity.require('models')
            if method != 'POST' or query:
                raise GatewayError('fixed POST endpoint only', code='qualification_verification_shape', http_status=400)
            body = parse_json_object(handler._read_raw_body(limit=4096), max_bytes=4096)
            try:
                return (200, c.command(body, identity.name), {'Cache-Control': 'no-store'})
            except (Refusal, contract.Refusal, ControlPlaneError) as exc:
                raise GatewayError('verification refused', code='qualification_verification_refused', http_status=409) from exc
            finally:
                c.runtime.control_store.close_thread_connection()
        return super().route(method, segments, query, identity, handler)
