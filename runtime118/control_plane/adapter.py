# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import threading
import time
from typing import Any
from .errors import AdapterUnavailableError, ValidationError

class NullAdapter:
    """Fail-closed default. Nothing is configured, so nothing can be started."""
    name = 'null'
    available = False

    def capabilities(self) -> dict[str, Any]:
        return {'adapter': self.name, 'available': False, 'fixture_only': False, 'reason': 'no node adapter configured; lifecycle operations refused (fail closed)'}

    def _refuse(self, action: str, **details: Any) -> None:
        raise AdapterUnavailableError(f'no node adapter configured: refusing to {action}', details={'adapter': self.name, **details})

    def probe(self, node: str) -> dict[str, Any]:
        self._refuse('probe a node', node=node)

    def preflight(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        self._refuse('run a start preflight', profile=profile, generation=generation)

    def start(self, profile: str, *, nodes: list[str], generation: int, env: dict[str, Any]) -> dict[str, Any]:
        self._refuse('start a profile', profile=profile, generation=generation)

    def probe_ready(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        self._refuse('probe model readiness', profile=profile, generation=generation)

    def stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        self._refuse('claim any process stopped', profile=profile, generation=generation)

    def confirm_stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        self._refuse('confirm a stop observation', profile=profile, generation=generation)

class TestAdapter:
    """Deterministic test fixture. Never a default; no hardware actions.

    ``instances`` maps ``(profile, generation)`` -> set of running node names.
    Observations are deliberately *honest about ignorance*:

    - a node the fixture was never told about is ``unknown`` and every
      observation about it is negative (never "stopped");
    - ``confirm_stop`` reports ``stopped`` only when the fixture can positively
      see that no process of that profile+generation remains on a known node;
    - ``preflight`` refuses when any older generation of the same profile, or any
      other profile, still runs on a requested node, and refuses unknown nodes.

    Failure knobs (``unreachable``, ``model_healthy``, ``start_error``) exist so
    tests can exercise refusal paths; they never make the fixture optimistic.
    """
    name = 'test-fixture'
    available = True

    def __init__(self, *, nodes: list[str] | None=None):
        self._lock = threading.RLock()
        self._known = set(nodes or [])
        self.instances: dict[tuple[str, int], set[str]] = {}
        self.calls: list[tuple[str, str, int]] = []
        self.unreachable: set[str] = set()
        self.model_healthy = True
        self.model_id = 'fixture-model'
        self.start_error: str | None = None
        self.stop_noop = False

    def add_known_nodes(self, nodes: list[str]) -> None:
        """Declare the nodes this fixture adapter manages.

        A node the fixture manages but sees no matching process on can be
        positively confirmed stopped; a node it was never told about stays
        ``unknown`` and every observation about it is negative.
        """
        with self._lock:
            self._known.update(nodes)

    def seed_running(self, profile: str, generation: int, nodes: list[str]) -> None:
        with self._lock:
            self.instances[profile, int(generation)] = set(nodes)
            self._known.update(nodes)

    def stopped_nodes(self, profile: str, generation: int) -> set[str]:
        """Diagnostic helper for tests. NOT used by Manager evidence derivation."""
        with self._lock:
            return set(self.instances.get((profile, int(generation)), set()))

    def _running_on(self, node: str) -> list[dict[str, Any]]:
        return [{'profile': profile, 'generation': generation} for (profile, generation), node_set in self.instances.items() if node in node_set]

    def capabilities(self) -> dict[str, Any]:
        return {'adapter': self.name, 'available': True, 'fixture_only': True, 'reason': 'deterministic test fixture; never a production adapter'}

    def probe(self, node: str) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('probe', node, -1))
            if node in self.unreachable:
                return {'node': node, 'reachable': False, 'healthy': False}
            if node not in self._known:
                return {'node': node, 'reachable': True, 'healthy': False, 'reason': 'unknown_node_state'}
            return {'node': node, 'reachable': True, 'healthy': True}

    def preflight(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('preflight', profile, int(generation)))
            observed = time.time()
            per_node: dict[str, Any] = {}
            for node in nodes:
                if node not in self._known:
                    per_node[node] = {'clear': False, 'reason': 'unknown_node_state', 'observed_at': observed}
                    continue
                if node in self.unreachable:
                    per_node[node] = {'clear': False, 'reason': 'unreachable', 'observed_at': observed}
                    continue
                running = self._running_on(node)
                same_profile = [item for item in running if item['profile'] == profile]
                foreign = [item for item in running if item['profile'] != profile]
                if same_profile or foreign:
                    per_node[node] = {'clear': False, 'reason': 'processes_still_running', 'observed_at': observed, 'running': running}
                else:
                    per_node[node] = {'clear': True, 'reason': 'no_known_processes', 'observed_at': observed}
            clear = all((item.get('clear') is True for item in per_node.values()))
            return {'clear': clear, 'profile': profile, 'owner': owner, 'generation': int(generation), 'nodes': per_node, 'observed_at': observed}

    def start(self, profile: str, *, nodes: list[str], generation: int, env: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('start', profile, int(generation)))
            if self.start_error:
                raise RuntimeError(self.start_error)
            self.instances.setdefault((profile, int(generation)), set()).update(nodes)
            self._known.update(nodes)
            return {'started': True, 'profile': profile, 'generation': int(generation), 'nodes': list(nodes)}

    def probe_ready(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('probe_ready', profile, int(generation)))
            observed = time.time()
            running = self.instances.get((profile, int(generation)), set())
            per_node: dict[str, Any] = {}
            for node in nodes:
                if node in self.unreachable:
                    per_node[node] = {'healthy': False, 'reason': 'unreachable', 'observed_at': observed}
                elif node not in running:
                    per_node[node] = {'healthy': False, 'reason': 'no_matching_instance', 'observed_at': observed}
                elif not self.model_healthy:
                    per_node[node] = {'healthy': False, 'reason': 'model_unhealthy', 'observed_at': observed}
                else:
                    per_node[node] = {'healthy': True, 'model_id': self.model_id, 'reason': 'model_serving', 'observed_at': observed}
            healthy = all((item.get('healthy') is True for item in per_node.values()))
            return {'healthy': healthy, 'profile': profile, 'owner': owner, 'generation': int(generation), 'model_id': self.model_id if healthy else None, 'nodes': per_node, 'observed_at': observed}

    def stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('stop', profile, int(generation)))
            if self.stop_noop:
                return {'stopped': False, 'reason': 'stop_ineffective', 'profile': profile, 'generation': int(generation)}
            key = (profile, int(generation))
            if key not in self.instances:
                return {'stopped': False, 'reason': 'no_matching_process_record', 'profile': profile, 'generation': int(generation)}
            stopped = sorted(self.instances.pop(key))
            return {'stopped': True, 'profile': profile, 'generation': int(generation), 'stopped_nodes': stopped}

    def confirm_stop(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        with self._lock:
            self.calls.append(('confirm_stop', profile, int(generation)))
            observed = time.time()
            remaining = self.instances.get((profile, int(generation)), set())
            per_node: dict[str, Any] = {}
            for node in nodes:
                if node not in self._known:
                    per_node[node] = {'stopped': False, 'reason': 'unknown_node_state', 'observed_at': observed}
                elif node in self.unreachable:
                    per_node[node] = {'stopped': False, 'reason': 'unreachable', 'observed_at': observed}
                elif node in remaining:
                    per_node[node] = {'stopped': False, 'reason': 'process_still_running', 'observed_at': observed}
                else:
                    per_node[node] = {'stopped': True, 'reason': 'no_matching_process', 'observed_at': observed}
            stopped = all((item['stopped'] is True for item in per_node.values()))
            return {'stopped': stopped, 'profile': profile, 'generation': int(generation), 'nodes': per_node, 'unknown_nodes': [n for n, item in per_node.items() if item['reason'] in {'unknown_node_state', 'unreachable'}], 'observed_at': observed}

def require_adapter(adapter: Any | None) -> Any:
    """Resolve the injected adapter and require the full v2 contract surface."""
    if adapter is None:
        adapter = NullAdapter()
    for method in ('probe', 'preflight', 'start', 'probe_ready', 'stop', 'confirm_stop', 'capabilities'):
        if not callable(getattr(adapter, method, None)):
            raise ValidationError(f'adapter lacks required method: {method}; the v2 contract needs preflight, confirm_stop and probe_ready so evidence is never inferred', code='invalid_adapter', details={'adapter': getattr(adapter, 'name', type(adapter).__name__), 'missing': method})
    return adapter
