# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Domain-only delegated service topology. No effects at import.
Only writes: this fixed service's new child directories/procs/subtree_control.
Systemd aggregate limits, ancestors and shared daemons are never written.
"""
import os, re, stat
from pathlib import Path
import plan as p
REQUIRED = {'cpu', 'io', 'memory', 'pids'}
SUPERVISOR = 'supervisor'
PAYLOAD = 'containers'
LIMITS = ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'io.max')

def membership(text):
    rows = [s[3:] for s in text.splitlines() if s.startswith('0::')]
    p.need(len(rows) == 1 and (not rows[0].endswith(' (deleted)')), 'unified_live_membership')
    return rows[0]

def unit(properties, version):
    p.need(version >= 236 and properties['ControlGroup'] == p.CG and (properties['MainPID'] == str(os.getpid())) and (properties['Delegate'] == 'yes') and (REQUIRED <= set(properties['DelegateControllers'].split())), 'actual_installed_systemd_delegation')
    p.need(not any((properties.get(k, '') for k in ('ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost', 'DelegateSubgroup'))), 'no_unknown_control_or_implicit_subgroup')

class KernelIO:

    def __init__(self, check=lambda: None):
        self.check = check
        self.check()
        rows = [s.split() for s in Path('/proc/self/mountinfo').read_text().splitlines()]
        p.need(any((x[4] == '/sys/fs/cgroup' and x[x.index('-') + 1] == 'cgroup2' and (x[3] == '/') for x in rows)), 'actual_host_unified_cgroup_mount')
        self.path = Path('/sys/fs/cgroup' + p.CG)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = os.fstat(self.fd)
        p.need(self.identity.st_uid == 0, 'actual_Root_delegated_directory')

    def directory(self, rel):
        self.check()
        now = self.path.lstat()
        current = os.fstat(self.fd)
        p.need(all((getattr(now, k) == getattr(current, k) == getattr(self.identity, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode'))), 'delegated_top_directory_identity_changed')
        p.need(rel == '' or all((re.fullmatch('[A-Za-z0-9_.-]+', n) and n not in ('.', '..') for n in rel.split('/'))), 'fixed_subtree_relative_path')
        fd = os.dup(self.fd)
        try:
            for n in filter(None, rel.split('/')):
                self.check()
                new = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = new
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, rel, name):
        fd = self.directory(rel)
        try:
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                raw = os.read(f, 65537)
                p.need(len(raw) <= 65536, 'bounded_cgroup_attribute')
                return raw.decode().strip()
            finally:
                os.close(f)
        finally:
            os.close(fd)

    def write(self, rel, name, text):
        p.need(name in ('cgroup.procs', 'cgroup.subtree_control'), 'no_aggregate_or_ancestor_control_write')
        fd = self.directory(rel)
        try:
            f = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                raw = text.encode()
                p.need(os.write(f, raw) == len(raw), 'whole_cgroup_write')
            finally:
                os.close(f)
        finally:
            os.close(fd)

    def mkdir(self, rel):
        p.need(rel in (SUPERVISOR, PAYLOAD), 'only_new_owned_topology_children')
        os.mkdir(rel, mode=493, dir_fd=self.fd)

    def children(self, rel):
        fd = self.directory(rel)
        try:
            return sorted((n for n in os.listdir(fd) if stat.S_ISDIR(os.stat(n, dir_fd=fd, follow_symlinks=False).st_mode)))
        finally:
            os.close(fd)

    def process(self, pid):
        self.check()
        path = Path('/proc') / str(pid)
        raw = (path / 'stat').read_text()
        tail = raw.rsplit(')', 1)[1].split()
        cg = (path / 'cgroup').read_text()
        argv = (path / 'cmdline').read_bytes().split(b'\x00')
        exe = os.readlink(path / 'exe')
        again = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        p.need(tail[19] == again[19] and cg == (path / 'cgroup').read_text(), 'PID_starttick_membership_changed')
        return {'pid': pid, 'ppid': int(tail[1]), 'starttick': tail[19], 'cgroup': membership(cg), 'argv': [x.decode() for x in argv if x], 'exe': exe}

    def private_processes(self):
        out = []
        for path in Path('/proc').iterdir():
            self.check()
            if not path.name.isdigit():
                continue
            try:
                raw = (path / 'cmdline').read_bytes()
            except FileNotFoundError:
                continue
            if p.ROOT.encode() in raw:
                out.append(self.process(int(path.name)))
        return out

    def close(self):
        os.close(self.fd)

class Topology:

    def __init__(self, io, pid, device):
        p.need(device == '259:0', 'originating_whole_NVMe_IO_device_only')
        self.io = io
        self.pid = pid
        self.device = device
        self.initial = io.process(pid)
        self.ready = False
        self.payload_rel = None

    def row(self, rel):
        return {'cgroup': p.CG + ('/' + rel if rel else ''), **{n: self.io.read(rel, n) for n in LIMITS}, 'cgroup.type': self.io.read(rel, 'cgroup.type'), 'cgroup.procs': self.io.read(rel, 'cgroup.procs'), 'cgroup.controllers': self.io.read(rel, 'cgroup.controllers'), 'cgroup.subtree_control': self.io.read(rel, 'cgroup.subtree_control')}

    def aggregate(self):
        r = self.row('')
        p.kernel(r)
        p.need(r['cgroup.type'] == 'domain', 'no_threaded_memory_workaround')
        p.need(REQUIRED <= set(r['cgroup.controllers'].split()), 'required_controllers_available_not_just_Delegate')
        io = [x.split() for x in r['io.max'].splitlines()]
        p.need(len(io) == 1 and io[0][0] == self.device, 'exact_aggregate_NVMe_device')
        bounds = dict((s.split('=', 1) for s in io[0][1:]))
        p.need(all((bounds.get(k, 'max') != 'max' and 0 < int(bounds[k]) <= 60 * 1024 ** 2 for k in ('rbps', 'wbps'))), 'actual_aggregate_io60M')
        return r

    def bootstrap(self):
        before = self.aggregate()
        p.need(self.initial['cgroup'] == p.CG and before['cgroup.procs'].split() == [str(self.pid)] and (self.io.children('') == []) and (not before['cgroup.subtree_control']), 'initial_only_supervisor_top_no_reentry')
        self.io.mkdir(SUPERVISOR)
        self.io.write(SUPERVISOR, 'cgroup.procs', str(self.pid))
        current = self.io.process(self.pid)
        p.need(current['starttick'] == self.initial['starttick'] and current['cgroup'] == p.CG + '/' + SUPERVISOR and (not self.io.read('', 'cgroup.procs')) and (self.io.read(SUPERVISOR, 'cgroup.procs').split() == [str(self.pid)]), 'migrate_exact_self_and_empty_top_before_enable')
        self.io.mkdir(PAYLOAD)
        self.io.write('', 'cgroup.subtree_control', ' '.join(('+' + x for x in sorted(REQUIRED))))
        p.need(REQUIRED <= set(self.io.read('', 'cgroup.subtree_control').split()), 'top_controller_enable_actual_readback')
        self.io.write(PAYLOAD, 'cgroup.subtree_control', ' '.join(('+' + x for x in sorted(REQUIRED))))
        self.ready = True
        after = self.verify()
        return {'before': before, 'after': after, 'self_starttick': current['starttick'], 'ancestor_or_aggregate_writes': 0}

    def verify(self):
        p.need(self.ready, 'topology_not_bootstrapped')
        top = self.aggregate()
        current = self.io.process(self.pid)
        p.need(current['starttick'] == self.initial['starttick'] and current['cgroup'] == p.CG + '/' + SUPERVISOR and (not top['cgroup.procs']) and (REQUIRED <= set(top['cgroup.subtree_control'].split())), 'runtime_top_empty_supervisor_unchanged')
        p.need(self.io.children('') == [PAYLOAD, SUPERVISOR], 'no_unknown_top_level_cgroup')
        rows = []
        todo = ['', SUPERVISOR, PAYLOAD]
        while todo:
            rel = todo.pop()
            r = self.row(rel)
            p.need(r['cgroup.type'] == 'domain', 'every_cgroup_same_domain')
            if rel:
                p.need(REQUIRED <= set(r['cgroup.controllers'].split()), 'child_controller_files_available')
            if rel == SUPERVISOR:
                p.need(not r['cgroup.subtree_control'] and (not self.io.children(rel)), 'supervisor_leaf_only')
            elif rel == PAYLOAD:
                p.need(not r['cgroup.procs'] and REQUIRED <= set(r['cgroup.subtree_control'].split()), 'empty_payload_parent_controllers_enabled')
            elif rel:
                p.need(rel.startswith(PAYLOAD + '/'), 'only_owned_payload_descendants')
            if r['cgroup.subtree_control']:
                p.need(not r['cgroup.procs'], 'no_internal_process')
            if rel not in ('', SUPERVISOR):
                todo.extend((rel + '/' + n for n in self.io.children(rel)))
            rows.append(r)
        return rows

    def runtime(self, known, cid=None, container_pid=None, shim=None):
        rows = self.verify()
        seeds = dict(known)
        seeds[self.pid] = self.initial['starttick']
        if container_pid:
            r = self.io.process(container_pid)
            p.need(cid and r['cgroup'].startswith(p.CG + '/' + PAYLOAD + '/'), 'actual_owned_container_PID_path')
            self.payload_rel = r['cgroup'][len(p.CG) + 1:]
            p.kernel(self.row(r['cgroup'][len(p.CG) + 1:]), True)
            seeds[container_pid] = r['starttick']
        for pid, tick in known.items():
            try:
                r = self.io.process(pid)
            except FileNotFoundError:
                continue
            p.need(r['starttick'] == tick and (r['cgroup'] == p.CG + '/' + SUPERVISOR or r['cgroup'].startswith(p.CG + '/' + PAYLOAD + '/')), 'known_daemon_PID_escaped_or_reused')
        for r in self.io.private_processes():
            p.need(r['cgroup'] == p.CG + '/' + SUPERVISOR or r['cgroup'].startswith(p.CG + '/' + PAYLOAD + '/'), 'private_namespace_process_escaped')
        observed = {}
        for row in rows:
            rel = row['cgroup'][len(p.CG) + 1:]
            if rel.startswith(PAYLOAD + '/'):
                p.need(cid and self.payload_rel and (rel == self.payload_rel or rel.startswith(self.payload_rel + '/')), 'unknown_payload_cgroup')
            for token in row['cgroup.procs'].split():
                pid = int(token)
                r = self.io.process(pid)
                p.need(r['cgroup'] == row['cgroup'], 'tree_PID_membership_changed')
                observed[pid] = r
        for pid, r in observed.items():
            n = pid
            visited = set()
            owned = False
            while n and n not in visited:
                visited.add(n)
                if n in seeds:
                    actual = self.io.process(n)
                    p.need(actual['starttick'] == seeds[n], 'owned_PID_starttick_changed')
                    owned = True
                    break
                parent = self.io.process(n)
                n = parent['ppid']
                if n == 1:
                    break
            if not owned and cid and shim:
                a = r['argv']
                owned = r['exe'] == shim['path'] and a[1:] == ['-namespace', 'mimo-r25-cgroup-r1', '-id', cid, '-address', p.ROOT + '/containerd.sock'] and (r['cgroup'] == p.CG + '/' + SUPERVISOR)
            p.need(owned, 'unknown_process_or_shim_membership')
            if r['cgroup'].startswith(p.CG + '/' + PAYLOAD + '/'):
                p.need(cid and container_pid and (container_pid in observed), 'unbound_payload_PID')
        return {'rows': rows, 'processes': list(observed.values()), 'effective_aggregate_caps': self.aggregate(), 'only_domain': True}
