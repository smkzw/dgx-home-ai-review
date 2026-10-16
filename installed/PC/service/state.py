# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Held service-999 once originals below the existing legacy ancestor contract."""
import os
import re
import stat
from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, need, metadata, directory_identity

class Originals:

    def __init__(self, root):
        self.root = root

    def snapshot(self, expected=None):
        with HeldParent(self.root.parent / '.registry-ancestry', legacy=True) as chain:
            fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
            try:
                s = os.fstat(fd)
                need((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 989, 448), 'registry_private_service_directory')
                before = directory_identity(s)
                rows = {}
                for name in sorted(os.listdir(fd)):
                    need(name in ('intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-finished.json', 'failed-terminal.json', 'failed-completed.json', 'failed-fence-released.json', 'negative-completed.json', 'negative-fence-released.json') or re.fullmatch('pulse-[1-9][0-9]{0,3}\\.json', name), 'registry_exact_once_entries')
                    leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        st = os.fstat(leaf)
                        need(stat.S_ISREG(st.st_mode) and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink) == (999, 989, 384, 1) and (st.st_size <= 4194304), 'registry_original_999_leaf')
                        raw = os.pread(leaf, st.st_size + 1, 0)
                        need(len(raw) == st.st_size and metadata(st) == metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'registry_original_fullF9_stable')
                        if expected is not None:
                            need(name in expected and metadata(st) == expected[name]['F9'] and (__import__('hashlib').sha256(raw).hexdigest() == expected[name]['sha256']), 'expected_original_fullSHA_F9')
                        rows[name] = raw
                    finally:
                        os.close(leaf)
                need(before == directory_identity(os.fstat(fd)) == directory_identity(os.stat(self.root.name, dir_fd=chain.parent_fd, follow_symlinks=False)), 'registry_held_directory_drift')
                chain.recheck()
                return rows
            finally:
                os.close(fd)
