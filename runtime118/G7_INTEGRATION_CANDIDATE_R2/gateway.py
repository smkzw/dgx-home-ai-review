# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One private action route on the existing authenticated loopback gateway."""
from llm_gateway.server import GatewayServer
from llm_gateway.errors import ForbiddenError, GatewayError
from .durable import Refusal
from G7_INTEGRATION_CANDIDATE_R1.coordinator import Refusal as PreparationRefusal
from llm_gateway.validation import parse_json_object

class MaintenanceGatewayServer(GatewayServer):
    maintenance = None

    def route(self, method, segments, query, identity, handler):
        if segments == ['v1', 'maintenance', 'cacheprep']:
            c = self.maintenance
            if c is None or not c.config['enabled']:
                raise GatewayError('maintenance disabled', code='maintenance_disabled', http_status=503)
            if identity.name != c.config['caller_owner']:
                raise ForbiddenError('maintenance owner denied', code='maintenance_owner_denied')
            identity.require('models')
            if method != 'POST' or query:
                raise GatewayError('fixed POST endpoint only', code='maintenance_shape', http_status=400)
            raw = handler._read_raw_body(limit=4096)
            body = parse_json_object(raw, max_bytes=4096)
            try:
                return (200, c.command(body, identity.name), {'Cache-Control': 'no-store'})
            except (Refusal, PreparationRefusal) as exc:
                raise GatewayError(str(exc), code=str(exc), http_status=409) from exc
            finally:
                c.runtime.control_store.close_thread_connection()
        return super().route(method, segments, query, identity, handler)
