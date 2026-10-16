# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""QV1 routes and current chat/alias relay, with one shared Scheduler.

Only the complete original constructor is copied to inject the shared scheduler
before the listening socket exists. Route/relay/cancel/auth/shutdown definitions
are inherited from the fixed QV1/current gateway, without a second gateway.
"""
from __future__ import annotations
import threading
import time
from typing import Any
from llm_gateway.server import GatewayConfig, TokenRegistry, GatewayStore, LOOPBACK_HOSTS, require_facade, upstream, _ManagedHTTPServer
from llm_gateway.errors import GatewayError
from G7_QUALIFICATION_VERIFICATION_R1.gateway import VerificationGatewayServer
from .shared_scheduler import Scheduler

class GatewayServer(VerificationGatewayServer):

    def __init__(self, *, config: GatewayConfig, registry: TokenRegistry, store: GatewayStore, facade: Any, probe_backend: Any | None=None, clock: Any=time.time, creative_manager: Any=None):
        if config.enabled is not True:
            raise GatewayError('gateway_disabled: configuration must explicitly enable the gateway; the default is disabled until the parent integrates a verified facade', code='gateway_disabled', http_status=503)
        if config.host not in LOOPBACK_HOSTS:
            raise GatewayError('non_loopback_bind_refused: refusing to bind a non-loopback address in this core', code='non_loopback_bind_refused', http_status=400)
        self.config = config
        self.registry = registry
        self.store = store
        self.facade = require_facade(facade)
        self.clock = clock
        self.shutdown_timeout_seconds = 10.0
        self.shutdown_safe = True
        self._stopping = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._shutdown_started = False
        self._shutdown_complete = threading.Event()
        self._shutdown_error: BaseException | None = None
        self._probe_connections = upstream.ConnectionRegistry()
        self.recovery = store.recover_after_restart()
        if probe_backend is None or probe_backend is upstream.probe_backend_models:
            backend_probe = lambda backend: upstream.probe_backend_models(backend, connection_registry=self._probe_connections)
        else:
            backend_probe = probe_backend
        self.scheduler = Scheduler(store=store, facade=self.facade, config=config, probe_backend=backend_probe, clock=clock)
        self.scheduler.bind_creative_manager(creative_manager)
        self._build_time = int(clock())
        handler = self._handler_class()
        self.httpd = _ManagedHTTPServer((config.host, config.port), handler)
        self.httpd.shutdown_timeout_seconds = self.shutdown_timeout_seconds
        self.httpd.register_cancellation(self._stopping.set)
        self.httpd.register_cancellation(self._probe_connections.cancel_all)
        self.host, self.port = (self.httpd.server_address[0], self.httpd.server_address[1])
        self._thread: threading.Thread | None = None
