# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Candidate same existing unit entrypoint interface, parent install only."""
import sys
if len(sys.argv) != 2 or sys.argv[1] not in ('--check', '--serve'):
    raise SystemExit(126)
sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
from G8_C_FIRSTTRIAL_CANDIDATE_R1.composition_entry import main
if __name__ == '__main__':
    raise SystemExit(main(['--config', '/etc/dgx-home-ai/composition.json', '--maintenance-config', '/etc/dgx-home-ai/g7-maintenance.json', sys.argv[1]]))
