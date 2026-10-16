# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Single existing gateway plus private caller-bound first-trial endpoint."""
from G8_INTEGRATION_RUNTIME_CANDIDATE_R2.gateway import GatewayServer as OriginalGateway
from G7_INTEGRATION_CANDIDATE_R2.durable import Refusal
from llm_gateway.errors import GatewayError, ForbiddenError
from llm_gateway.validation import parse_json_object
from control_plane.errors import ControlPlaneError
from .permit import cc

class GatewayServer(OriginalGateway):
    c_firsttrial = None

    def route(self, method, segments, query, identity, handler):
        if segments != ['v1', 'maintenance', 'creative-firsttrial']:
            return super().route(method, segments, query, identity, handler)
        controller = self.c_firsttrial
        if controller is None:
            raise GatewayError('C first trial disabled', code='C_firsttrial_disabled', http_status=503)
        identity.require('models')
        if method != 'POST' or query:
            raise GatewayError('fixed POST only', code='C_firsttrial_shape', http_status=400)
        body = parse_json_object(handler._read_raw_body(limit=4096), max_bytes=4096)
        try:
            return (200, controller.command(body, identity.name), {'Cache-Control': 'no-store'})
        except (cc.Refusal, Refusal, ControlPlaneError) as exc:
            raise GatewayError('C trial refused, holds retained', code='C_firsttrial_refused', http_status=409) from exc
        finally:
            controller.runtime.control_store.close_thread_connection()
