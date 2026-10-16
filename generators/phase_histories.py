# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Normal-update historical originals only; no current permission or time stamp."""
from pathlib import Path
from plan import need
import not_launched_history as original
APPROVED_ROOT = None

def packed_histories(read, root):
    need(APPROVED_ROOT is not None and str(root) == APPROVED_ROOT, 'phase_history_fixed_data_root')
    pc, a, s = original.histories()
    original.history(pc, a, s)
    return ({'PC': pc, 'A': a, 'sources': s}, {})

def history(pc_raw):
    pc, a, s = original.histories()
    need(pc_raw == pc, 'phase_exact_old_PC_history_argument')
    v = original.history(pc, a, s)['PC']
    p = original.APPROVED_POLICY
    return {'actor': {'path': p['actor']['path'], 'directory_F9': v['directory_F9'], 'entries': sorted(v['files']), 'files': v['files']}}
