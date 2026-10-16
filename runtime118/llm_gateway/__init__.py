# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""``runtime/llm_gateway`` — bounded LLM queue/relay entry inside the manager.

Scope (V4, E05 work item ``dgx-v4-llm-gateway``):

- A transparent OpenAI surface on loopback: ``GET /v1/models`` and
  ``POST /v1/chat/completions`` (JSON and SSE byte relay) to backends that the
  parent has pinned to loopback SSH tunnels.
- Server-authoritative fair queue, session/lease coordination and persistent
  request metadata (SQLite WAL) inside the single manager process.
- Lifecycle (model start/stop) is **only** reached through an injected
  :class:`~llm_gateway.facade.BackendFacade`; the fail-closed default refuses
  everything. The parent integrates the reviewed control-plane ``Manager`` and
  the node adapter behind that seam.

Explicit non-goals: assets, Comfy workflows, a second job API, any direct
shell/SSH/Docker/node RPC, cloud fallback, prompt persistence, hardware
validation. The gateway ships **disabled** (``enabled: false``) and is not a G6
acceptance: real deployment and verification remain with the parent.
"""
from __future__ import annotations
from .config import GatewayConfig, config_summary, load_gateway_config
from .facade import BackendFacade, NullBackendFacade, require_facade
from .registry import Identity, TokenRegistry
from .scheduler import Scheduler
from .server import GATEWAY_CONTRACT_VERSION, SERVICE_NAME, GatewayServer
from .state import GatewayStore, OwnerLock, open_gateway_store
__version__ = '0.1-inert'
__all__ = ['BackendFacade', 'GATEWAY_CONTRACT_VERSION', 'GatewayConfig', 'GatewayServer', 'GatewayStore', 'Identity', 'NullBackendFacade', 'OwnerLock', 'SERVICE_NAME', 'Scheduler', 'TokenRegistry', '__version__', 'config_summary', 'load_gateway_config', 'open_gateway_store', 'require_facade']

def describe() -> dict[str, object]:
    """Small, non-secret summary of what this module can do (parent wiring aid)."""
    return {'service': SERVICE_NAME, 'contract_version': GATEWAY_CONTRACT_VERSION, 'version': __version__, 'surfaces': ['/v1/models', '/v1/chat/completions', '/v1/sessions', '/v1/requests/{id}', '/v1/gateway/status'], 'declared_unavailable': ['/v1/assets', '/v1/jobs', '/v1/comfy', '/v1/images', '/api/v1/*'], 'lifecycle': 'facade-only (ensure_ready/safe_drain_and_stop/get_generation/health)', 'persistence': 'SQLite WAL request/session metadata only; no prompts or completions', 'default_enabled': False}
