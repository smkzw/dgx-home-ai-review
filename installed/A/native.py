# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Owned A kernel/process IO. No commands at import; never shared daemon."""
import os, stat, subprocess, time
from pathlib import Path
import plan
from root_io import held, fresh, f9, sha
from bounded_process import capture
from topology import KernelIO, Topology, unit as unit_contract
CLEAN = {'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': plan.ROOT + '/home', 'CONTAINERD_DISABLE_PIGZ': 'true', 'CONTAINERD_DISABLE_IGZIP': 'true'}

class Native:

    def __init__(self, context, end):
        self.c, self.end = (context, end)
        self.children = []
        self.known = {}
        self.top = None
        self.output = 0
        self.pulse_callback = None
        self.last_pulse = None

    def tool(self, name):
        t = self.c['tools'][name]
        plan.need(name in ('containerd', 'ctr', 'openssl', 'systemctl', 'ip') and t['path'] == {'containerd': '/usr/bin/containerd', 'ctr': '/usr/bin/ctr', 'openssl': '/usr/bin/openssl', 'systemctl': '/usr/bin/systemctl', 'ip': '/usr/bin/ip'}[name], 'fixed_tool_paths_no_foreign_binary')
        if name == 'containerd':
            plan.need(t['sha256'] == '95619dc645d8bf6c9b26ad881d62bbe17ed03004588a095bac0aba232e3555ce', 'fixed_containerd225')
        if name == 'ctr':
            plan.need(t['sha256'] == plan.CTR_SHA, 'fixed_ctr225')
        _, s = held(t['path'], t['sha256'], cap=128 * 1024 ** 2)
        plan.need(s == t['stat'], 'current_tool_fullSHA_F9')
        return t['path']

    def unit(self, unit=plan.UNIT):
        r = capture([self.tool('systemctl'), 'show', unit], env=CLEAN, deadline=min(self.end, time.monotonic() + 5), cap=262144)
        plan.need(r.returncode == 0 and (not r.stderr), 'owned_actual_unit_show')
        return (r.stdout, dict((s.split('=', 1) for s in r.stdout.decode().splitlines())))

    def bootstrap(self):
        raw, u = self.unit()
        unit_contract(u, self.c['actual_systemd_version'])
        from observer import duration
        runtime = plan.strict(held(Path(getattr(plan, 'STAGE_CONTROL', plan.STAGE)) / 'runtime-max-original.json')[0])
        plan.need(type(runtime['runtime_max_seconds']) is int and 30 < runtime['runtime_max_seconds'] <= 1800 and (duration(u['RuntimeMaxUSec']) == runtime['runtime_max_seconds']) and (runtime['context_sha256'] == sha(held(Path(getattr(plan, 'STAGE_CONTROL', plan.STAGE)) / 'context.json')[0])), 'actual_systemd_runtime_bound_to_original_context')
        plan.need(u['Id'] == plan.UNIT and u['InvocationID'] == os.environ['INVOCATION_ID'], 'same_actual_owned_invocation')
        plan.need(resource_unbounded(), 'supervisor_Go_not_inherit_Python_AS192')
        plan.need(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/REDACTED_PID/ns/mnt') and (not list(Path('/dev').glob('nvidia*'))) and (not Path('/dev/infiniband').exists()), 'actual_private_mnt_devices_noGPU')
        plan.context_nvme(self.c)
        self.top = Topology(KernelIO(self.clock_only), os.getpid(), self.c['NVMe_IO_major_minor'])
        v = self.top.bootstrap()
        return {'unit_raw_utf8': raw.decode(), 'unit': u, 'topology': v}

    def clock_only(self):
        plan.need(time.monotonic() < self.end, 'original_grant_absolute_deadline')

    def check(self):
        self.clock_only()
        if self.pulse_callback is not None and (self.last_pulse is None or time.monotonic() - self.last_pulse >= 5):
            self.pulse_callback()
            self.last_pulse = time.monotonic()
        free = os.statvfs(plan.ROOT)
        plan.need(free.f_bavail * free.f_frsize >= plan.RESERVE, 'actual_disk100GiB_reserve')
        plan.need(self.c['initial_free_bytes'] - free.f_bavail * free.f_frsize <= plan.WORKSPACE, 'bounded_workspace80GiB')
        if self.top:
            self.top.runtime(self.known)
        for child, out, err in self.children:
            plan.need(os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size <= 1048576, 'bounded_owned_daemon_logs')

    def call(self, args, seconds, tag):
        self.check()
        r = capture(args, env=CLEAN, deadline=min(self.end, time.monotonic() + seconds), cap=1048576, check=self.check)
        fresh(Path(plan.ROOT) / (tag + '.json'), plan.encode({'argv': args, 'rc': r.returncode, 'stdout_b64': __import__('base64').b64encode(r.stdout).decode(), 'stderr_b64': __import__('base64').b64encode(r.stderr).decode(), 'observed_at': time.time()}))
        plan.need(r.returncode == 0 and (not r.stderr), 'owned_command_nonzero_or_stderr_no_retry')
        return r.stdout

    def spawn(self, args, tag, stdin=False):
        self.check()
        plan.need(resource_unbounded(), 'Go_not_AS192')
        out = open(Path(plan.ROOT) / (tag + '.stdout'), 'xb')
        err = open(Path(plan.ROOT) / (tag + '.stderr'), 'xb')
        try:
            child = subprocess.Popen(args, env=dict(CLEAN, INVOCATION_ID=os.environ['INVOCATION_ID']), stdin=subprocess.PIPE if stdin else subprocess.DEVNULL, stdout=out, stderr=err, cwd=plan.ROOT)
        except BaseException:
            out.close()
            err.close()
            raise
        self.children.append((child, out, err))
        self.known[child.pid] = self.top.io.process(child.pid)['starttick']
        self.check()
        return child

    def wait(self, child, seconds):
        end = min(self.end, time.monotonic() + seconds)
        while child.poll() is None:
            self.check()
            plan.need(time.monotonic() < end, 'owned_process_wait_deadline')
            time.sleep(0.1)
        self.check()
        plan.need(child.returncode == 0, 'owned_process_nonzero')
        return child.returncode

    def socket(self, child):
        end = min(self.end, time.monotonic() + 30)
        path = Path(plan.ROOT) / 'containerd.sock'
        while time.monotonic() < end:
            self.check()
            plan.need(child.poll() is None, 'private_containerd_terminal_before_ready')
            if path.exists():
                z = path.lstat()
                plan.need(stat.S_ISSOCK(z.st_mode) and z.st_uid == z.st_gid == 0 and (not z.st_mode & 18), 'owned_containerd_socket')
                return {'path': str(path), 'stat': f9(z), 'PID': child.pid, 'start_tick': self.known[child.pid]}
            time.sleep(0.1)
        raise plan.Refused('private_containerd_socket_timeout')

    def cleanup(self):
        errors = []
        end = min(self.end, time.monotonic() + 30)
        for child, out, err in reversed(self.children):
            try:
                if child.poll() is None:
                    actual = self.top.io.process(child.pid)
                    plan.need(actual['starttick'] == self.known[child.pid], 'exact_owned_TERM_PID_not_reused')
                    child.terminate()
                    child.wait(timeout=max(0.001, end - time.monotonic()))
            except BaseException as e:
                errors.append(type(e).__name__)
            finally:
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
                out.close()
                err.close()
        plan.need(not errors and all((p.poll() is not None for p, _, _ in self.children)), 'owned_child_alive_or_cleanup_unknown_no_force')
        state = self.top.runtime({}) if self.top else None
        plan.need(state is not None and {p['pid'] for p in state['processes']} == {os.getpid()}, 'after_cleanup_only_original_supervisor')
        result = {'all_owned_children_exited': True, 'kernel_after_cleanup': state, 'global_signals': 0, 'force_kill': 0, 'observed_at': time.time()}
        fresh(Path(plan.ROOT) / 'owned-cleanup.json', plan.encode(result))
        return result

    def archive(self):
        names = ['containerd-data', 'containerd-exec', 'private-opt', 'private-overlay', 'tmp', 'home', 'blobs']
        for name in names:
            path = Path(plan.ROOT) / name
            path.mkdir(mode=448)
            os.chmod(path, 448)

    def registry_original(self):
        import hashlib
        path = Path(plan.ROOT) / 'containerd-data/io.containerd.metadata.v1.bolt/meta.db'
        raw, st = held(path, cap=16 * 1024 ** 2)
        self.check()
        plan.need(0 < len(raw) <= 16 * 1024 ** 2, 'bounded_initialized_private_metadata_db')
        dest = Path(plan.ROOT) / 'initialized-registry.raw'
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        try:
            os.fchmod(fd, 384)
            view = memoryview(raw)
            while view:
                self.check()
                n = os.write(fd, view)
                plan.need(n > 0, 'whole_registry_original_archive')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        archived, ar = held(dest, cap=16 * 1024 ** 2)
        plan.need(archived == raw, 'samebyte_initialized_registry_snapshot')
        return {'path': str(path), 'sha256': sha(raw), 'stat': st, 'archive_path': str(dest), 'archive_sha256': sha(archived), 'archive_stat': ar, 'after_owned_daemon_exit': True, 'Bolt_interpretation_performed': False, 'observed_at': time.time()}

    def verify_content(self, image):
        import hashlib
        base = Path(plan.ROOT) / 'containerd-data/io.containerd.content.v1.content/blobs/sha256'
        wanted = plan.imported_content_sizes(image)
        plan.need(base.is_dir() and set((p.name for p in base.iterdir())) == set(wanted), 'exact_imported_content_names_no_unknown')
        result = {}
        for digest, size in wanted.items():
            self.check()
            path = base / digest
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                before = os.fstat(fd)
                plan.need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and (before.st_nlink == 1) and (before.st_size == size) and (not before.st_mode & 18), 'owned_imported_content_leaf')
                h = hashlib.sha256()
                count = 0
                while True:
                    self.check()
                    b = os.read(fd, 65536)
                    if not b:
                        break
                    count += len(b)
                    h.update(b)
                plan.need(count == size and h.hexdigest() == digest and (f9(before) == f9(os.fstat(fd)) == f9(path.lstat())), 'actual_imported_content_fullSHA_F9_stable')
                result[digest] = {'path': str(path), 'bytes': size, 'stat': f9(before), 'fullSHA': True}
            finally:
                os.close(fd)
        return result

def resource_unbounded():
    return __import__('resource').getrlimit(__import__('resource').RLIMIT_AS) == (-1, -1)
