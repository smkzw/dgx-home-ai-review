# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Unchanged accepted service999 FD reader, no Root-private path substitution."""
import os, base64
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, metadata, directory_identity
from plan import need
from root_io import sha
APPROVED_PARENT = None

def parent_original(path):
    need(type(APPROVED_PARENT) is dict, 'prestart_actor_parent_SOURCE_pending')
    p = APPROVED_PARENT
    if Path(path).parent != Path(p['path']):
        return None
    parent = Path(p['path'])
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = metadata(os.fstat(fd))
        names = sorted(os.listdir(fd))
        need(before == p['F9'] == metadata(parent.lstat()) and before[3:6] == [999, 989, 16832] and (names == p['entries'] == [Path(path).name]), 'prestart_only_exact_old_stage_no_unknown_sibling')
        need(metadata(os.stat(Path(path).name, dir_fd=fd, follow_symlinks=False)) == p['child_directory_F9'], 'prestart_exact_old_child_directory')
        need(metadata(os.fstat(fd)) == metadata(parent.lstat()) == before and sorted(os.listdir(fd)) == names, 'prestart_old_parent_held_named_stable')
        return {'F9': before, 'entries': names}
    finally:
        os.close(fd)

def held_actor(path, *, expected=None):
    path = Path(path)
    parent = parent_original(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = metadata(os.fstat(fd))
        need(before == metadata(path.lstat()) and before[3:7] == [999, 989, 16832, 2], 'legacy_stage_owned_directory_exact')
        names = sorted(os.listdir(fd))
        need(len(names) <= 32 and all(('/' not in n and n not in ('.', '..') for n in names)), 'legacy_stage_flat_bounded_entries')
        if expected is not None:
            need(before == expected['directory_F9'] and names == sorted(expected['entries']), 'legacy_stage_fixed_directory_F9_entries')
        rows = {}
        total = 0
        for name in names:
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                f9 = metadata(os.fstat(leaf))
                need(f9 == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) and f9[3:7] == [999, 989, 33152, 1] and (0 < f9[2] <= 4194304), 'legacy_stage_actual_leaf_owner_FD')
                body = bytearray()
                while len(body) <= f9[2]:
                    chunk = os.read(leaf, min(65536, f9[2] + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                raw = bytes(body)
                total += len(raw)
                need(len(raw) == f9[2] and total <= 8388608, 'legacy_stage_complete_original_cap')
                need(metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) == f9, 'legacy_stage_held_named_stable_after_read')
                if expected is not None:
                    need({'sha256': sha(raw), 'F9': f9} == expected['files'][name], 'legacy_stage_original_exact_SHA_F9')
                rows[name] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': f9}
            finally:
                os.close(leaf)
        need(metadata(os.fstat(fd)) == metadata(path.lstat()) == before and sorted(os.listdir(fd)) == names, 'legacy_stage_directory_FD_named_entries_after')
        need(parent_original(path) == parent, 'prestart_old_parent_stable_across_actor')
        return {'path': str(path), 'directory_F9': before, 'entries': names, 'files': rows}
    finally:
        os.close(fd)
