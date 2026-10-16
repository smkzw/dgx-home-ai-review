# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed native Zig /stats count adapter; no lifecycle or synthetic idle inference.

The current Python-engine health parser cannot consume native Zig health. Native
/stats requires --dashboard, remains loopback only, and supplies running+waiting.
Existing front auth, bounded GET, redirect refusal, two fresh Manager readiness
proofs and container/model identity checks are reused unchanged.
"""
import json
from engine_front import front as base
from .adapter import PROFILE, MODEL, NODES

class NativeStatsProbe(base.ActiveWorkProbe):

    def _native_health(self):
        raw, _ = self._native_get('/stats')
        doc = base._strict_json(raw)
        if not isinstance(doc, dict) or any((type(doc.get(k)) is not int or doc[k] < 0 for k in ('running', 'waiting'))):
            raise base._FrontFailure('native_stats_counts_unknown')
        total = doc['running'] + doc['waiting']
        normalized = {'requests_running': total, 'busy': total > 0, 'running': doc['running'], 'waiting': doc['waiting'], 'count_source': 'native_zig_stats'}
        return (json.dumps(normalized, allow_nan=False).encode(), normalized)

def make_server(config, *, readiness_binding, bind_host='127.0.0.1', bind_port=0, clock=base.time.time):
    if config.profile != PROFILE:
        return base.create_server(config, readiness_binding=readiness_binding, bind_host=bind_host, bind_port=bind_port, clock=clock)
    if config.expected_model_id != MODEL or tuple(config.expected_nodes) != NODES:
        raise base.EngineFrontConfigError('DeepSeek front identity mismatch')
    base._require_numeric_loopback(bind_host, field='bind_host')
    if type(bind_port) is not int or not 0 <= bind_port <= 65535:
        raise base.EngineFrontConfigError('invalid frontend port')
    return base._EngineFrontServer((bind_host, bind_port), NativeStatsProbe(config, readiness_binding, clock=clock))
