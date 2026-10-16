# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Private fsynced observed samples only, no instantaneous peak claims."""
import os
import re
import time
from pathlib import Path
from .permit import cc

class Samples:

    def __init__(self, root, document):
        run = document.value.get('run_id')
        cc.need(type(run) is str and re.fullmatch('[0-9a-f]{32}', run), 'validated_C_sample_run_required')
        self.path = Path(root) / ('observed-memory-' + run + '.jsonl')
        self.doc = document
        self.fd = None
        self.bytes = 0
        self.rows = []

    def append(self, reply):
        v = self.doc.value
        m = reply.get('memory', {})
        cc.need(m.get('source') == 'proc_meminfo' and m.get('mem_total_bytes') == v['host_facts']['total_bytes'] and (type(m.get('mem_available_bytes')) is int) and (0 <= m['mem_available_bytes'] <= m['mem_total_bytes']), 'actual_C_memory_required')
        row = {'schema': 'g8-c-observed-memory/v1', 'run_id': v['run_id'], 'permit_sha256': self.doc.sha256, 'generation': v['generation'], 'node': 'spark-c', 'HX_monotonic_ns': time.monotonic_ns(), 'native_issued_at': reply['observed_at'], 'container_id': reply.get('container_id'), 'guard_state': reply.get('guard_state'), 'actual_memory': m, 'sample_only': True}
        raw = cc.canonical(row) + b'\n'
        cc.need(self.bytes + len(raw) <= 1024 ** 2 and len(self.rows) < 1000, 'C_memory_series_budget')
        if self.fd is None:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        view = memoryview(raw)
        while view:
            n = os.write(self.fd, view)
            cc.need(n > 0, 'C_memory_write_failed')
            view = view[n:]
        os.fsync(self.fd)
        self.bytes += len(raw)
        self.rows.append(row)

    def summary(self):
        available = [r['actual_memory']['mem_available_bytes'] for r in self.rows]
        gaps = [(b['HX_monotonic_ns'] - a['HX_monotonic_ns']) / 1000000000.0 for a, b in zip(self.rows, self.rows[1:])]
        return {'sample_count': len(available), 'sampled_min_available_bytes': min(available) if available else None, 'sampled_max_total_minus_available_bytes': self.doc.value['host_facts']['total_bytes'] - min(available) if available else None, 'max_observed_gap_s': max(gaps) if gaps else None, 'complete_continuous_peak_proven': False, 'private_path': str(self.path)}

    def close(self):
        if self.fd is not None:
            os.fsync(self.fd)
            os.close(self.fd)
            self.fd = None
