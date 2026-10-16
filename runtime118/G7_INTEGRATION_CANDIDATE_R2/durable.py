# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Private crash-durable command ledger; an unresolved intent is never replayed."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from G7_INTEGRATION_CANDIDATE_R1.cache_checks import strict

class Refusal(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Refusal(code)

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def private_dir(path):
    p = Path(path)
    need(p.is_absolute(), 'absolute_private_path')
    for q in (p, *p.parents):
        need(not q.is_symlink(), 'symlink_directory')
    st = p.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and (stat.S_IMODE(st.st_mode) == 448), 'private_owned_directory')
    return p

def fsync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def exclusive(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fsync_dir(Path(path).parent)
    return hashlib.sha256(raw).hexdigest()

class Ledger:

    def __init__(self, root):
        self.root = private_dir(root)
        self.path = self.root / 'commands.sqlite3'
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 384)
            os.close(fd)
            fsync_dir(self.root)
        st = self.path.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and (stat.S_IMODE(st.st_mode) == 384), 'private_ledger')
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS commands(key TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL, action TEXT NOT NULL, state TEXT NOT NULL, result TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS run(id TEXT PRIMARY KEY, identity TEXT NOT NULL, phase TEXT NOT NULL, generation INTEGER, attempted INTEGER NOT NULL DEFAULT 0)')
        fsync_dir(self.root)

    def close(self):
        self.db.close()

    def initialize(self, run, identity):
        prior = self.db.execute('SELECT identity FROM run WHERE id=?', (run,)).fetchone()
        if prior:
            need(prior[0] == digest(identity), 'run_identity_changed')
        else:
            self.db.execute('INSERT INTO run(id,identity,phase) VALUES(?,?,?)', (run, digest(identity), 'PREPARED'))

    def view(self, run):
        r = self.db.execute('SELECT phase,generation,attempted FROM run WHERE id=?', (run,)).fetchone()
        need(r is not None, 'unknown_run')
        return {'phase': r[0], 'generation': r[1], 'attempted': bool(r[2])}

    def mark(self, run, phase, generation=None, attempted=None):
        v = self.view(run)
        self.db.execute('UPDATE run SET phase=?,generation=?,attempted=? WHERE id=?', (phase, generation if generation is not None else v['generation'], int(v['attempted'] if attempted is None else attempted), run))

    def begin(self, key, owner, body):
        old = self.db.execute('SELECT owner,digest,state,result FROM commands WHERE key=?', (key,)).fetchone()
        if old:
            need(old[0] == owner, 'command_owner_mismatch')
            need(old[1] == digest(body), 'same_key_different_payload')
            need(old[2] == 'FINISHED', 'unresolved_command_no_replay')
            return strict(old[3])
        self.db.execute('INSERT INTO commands VALUES(?,?,?,?,?,NULL)', (key, owner, digest(body), body['action'], 'INTENT'))
        return None

    def finish(self, key, result):
        raw = json.dumps(result, sort_keys=True, allow_nan=False)
        self.db.execute("UPDATE commands SET state='FINISHED',result=? WHERE key=? AND state='INTENT'", (raw, key))

def publish_exclusive(path, value):
    """Fully synchronize unaccepted staging before the accepted name exists.

    Hard-link is same-filesystem O_EXCL publication. A failed fsync preserves
    its staging artifact; callers retain PUBLISH_INTENT and never auto-replay.
    """
    path = Path(path)
    staging = path.with_name(path.name + '.unpublished')
    h = exclusive(staging, value)
    os.link(staging, path, follow_symlinks=False)
    fsync_dir(path.parent)
    return h
