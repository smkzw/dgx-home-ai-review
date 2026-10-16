# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed parent-only SSH pooling. Does not grant remote execution admission.

Prepare inside the invoking parent's absolute deadline, before clock sampling.
The caller separately validates every actual clock/pulse and resource permit.
Only two exact emitted commands can use these private, newly owned masters.
"""
import json
import math
import os
import secrets
import shlex
import stat
import subprocess
import time
from pathlib import Path
APPROVED_COMMANDS = None
UID = 501
BASE = ('/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=1', '-o', 'ControlPersist=no', '-o', 'PermitLocalCommand=no')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C'}

class Refused(ValueError):
    pass

def need(value, reason):
    if not value:
        raise Refused(reason)

def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False

def socket_identity(path):
    s = path.lstat()
    need(stat.S_ISSOCK(s.st_mode) and stat.S_IMODE(s.st_mode) == 384 and (s.st_uid == UID) and (s.st_nlink == 1), 'owned_private_socket_policy')
    return (s.st_dev, s.st_ino)

class PrivateMux:

    def __init__(self, output, deadline):
        need(type(APPROVED_COMMANDS) is dict and set(APPROVED_COMMANDS) == {'pc', 'a'} and all((type(x) is str and x and ('\x00' not in x) for x in APPROVED_COMMANDS.values())), 'fixed_emitted_commands_pending')
        need(len(APPROVED_COMMANDS['pc']) < 8191, 'real_PC_command_limit')
        self.commands = dict(APPROVED_COMMANDS)
        need(os.getuid() == os.geteuid() == UID, 'parent_Mac_UID')
        now = time.monotonic()
        need(type(deadline) in (float, int) and math.isfinite(deadline) and (0 < deadline - now <= 1800), 'caller_absolute_remaining_not_new_window')
        self.output = Path(output)
        s = self.output.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == UID and (stat.S_IMODE(s.st_mode) == 448), 'new_private_output_directory')
        self.output_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held = os.fstat(self.output_fd)
        need((held.st_dev, held.st_ino) == (s.st_dev, s.st_ino), 'held_output_directory')
        self.output_identity = (s.st_dev, s.st_ino)
        self.deadline, self.masters, self.checks = (deadline, {}, 0)
        self.started, self.closed = (False, False)
        self.root = Path('/private/tmp') / ('dgxmux-' + secrets.token_hex(8))
        self.root_identity = None
        try:
            self.save('intent.json', {'schema': 'fixed-private-mux-once/v1', 'local_directory': str(self.root), 'deadline_monotonic': deadline, 'created_monotonic': now, 'remote_controls': 0, 'global_config_or_keys_changed': False, 'automatic_retry': False})
        except BaseException:
            os.close(self.output_fd)
            raise

    def remaining(self, cap):
        left = self.deadline - time.monotonic()
        need(left > 0 and cap > 0, 'private_transport_parent_deadline')
        return min(cap, left)

    def save(self, name, value):
        need('/' not in name and name not in ('', '.', '..'), 'fixed_evidence_leaf')
        s = self.output.lstat()
        need((s.st_dev, s.st_ino) == self.output_identity and s.st_uid == UID and (stat.S_IMODE(s.st_mode) == 448), 'output_directory_drift')
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.output_fd)
        try:
            os.fchmod(fd, 384)
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)

    def root_check(self):
        s = self.root.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == UID and (stat.S_IMODE(s.st_mode) == 448) and ((s.st_dev, s.st_ino) == self.root_identity), 'private_master_directory_drift')

    def route(self, node, path, *, master=False, control=None):
        need(node in ('pc', 'a') and path == self.root / node, 'fixed_route_socket')
        flags = ['-o', 'ControlPath=' + str(path), '-o', 'ControlMaster=yes' if master else 'ControlMaster=no']
        if master:
            flags += ['-N']
        if control is not None:
            need(not master and control in ('check', 'exit'), 'owned_control_only')
            flags += ['-O', control]
        if node == 'pc':
            return list(BASE) + flags + ['control-host']
        need('pc' in self.masters, 'owned_existing_PC_jump_required')
        proxy = shlex.join(['/usr/bin/ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no', '-o', 'ControlPath=' + str(self.masters['pc']['path']), '-W', '%h:%p', 'control-host'])
        return list(BASE) + flags + ['-o', 'ProxyJump=none', '-o', 'ProxyCommand=' + proxy, '-o', 'HostName=192.0.2.10', '-o', 'HostKeyAlias=gpu-a.example.invalid', 'spark-a']

    def pid_identity(self, process, *, cleanup=False):
        need(process.poll() is None, 'owned_master_not_live')
        q = subprocess.run(['/bin/ps', '-p', str(process.pid), '-o', 'uid=', '-o', 'lstart=', '-o', 'comm='], capture_output=True, timeout=2 if cleanup else self.remaining(2), env=ENV)
        need(q.returncode == 0 and (not q.stderr) and (len(q.stdout) < 8192) and (q.stdout.split()[0] == str(UID).encode()) and q.stdout.rstrip().endswith(b'/usr/bin/ssh'), 'owned_master_PID_UID_executable')
        return q.stdout

    def check(self, node):
        self.root_check()
        m = self.masters[node]
        need(self.pid_identity(m['process']) == m['identity'] and socket_identity(m['path']) == m['socket_identity'], 'master_PID_or_socket_replaced')
        q = subprocess.run(self.route(node, m['path'], control='check'), capture_output=True, timeout=self.remaining(3), env=ENV)
        self.checks += 1
        self.save('check-' + str(self.checks) + '.json', {'node': node, 'PID': m['process'].pid, 'rc': q.returncode, 'stdout_hex': q.stdout.hex(), 'stderr_hex': q.stderr.hex(), 'socket_identity': m['socket_identity']})
        need(q.returncode == 0 and ('pid=' + str(m['process'].pid)).encode() in q.stderr, 'owned_ssh_master_control_identity')

    def start(self):
        need(not self.started and (not self.closed), 'new_transport_once_no_replay')
        self.started = True
        try:
            os.mkdir(self.root, 448)
            s = self.root.lstat()
            self.root_identity = (s.st_dev, s.st_ino)
            self.root_check()
            for node in ('pc', 'a'):
                if node == 'a':
                    self.check('pc')
                path = self.root / node
                need(absent(path), 'new_owned_control_path')
                argv = self.route(node, path, master=True)
                fd = os.open(node + '-master.log', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 384, dir_fd=self.output_fd)
                try:
                    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fd, stderr=fd, start_new_session=True, env=ENV)
                finally:
                    os.close(fd)
                self.masters[node] = m = {'path': path, 'process': process, 'argv': argv}
                self.save(node + '-start.json', {'PID': process.pid, 'argv': argv, 'observed_at': time.time()})
                end = time.monotonic() + self.remaining(15)
                while absent(path):
                    need(process.poll() is None and time.monotonic() < end, 'private_master_not_ready_no_retry')
                    time.sleep(0.05)
                m['identity'] = self.pid_identity(process)
                m['socket_identity'] = socket_identity(path)
                self.check(node)
        except BaseException:
            self.close()
            raise
        return self

    def argv(self, node, command):
        need(self.started and (not self.closed) and (node in ('pc', 'a')) and (command == self.commands[node]), 'exact_emitted_command_no_general_RPC')
        self.remaining(1)
        self.check('pc')
        if node == 'a':
            self.check('a')
        return self.route(node, self.masters[node]['path']) + [command]

    def close(self):
        need(not self.closed, 'owned_close_once_no_replay')
        self.closed = True
        rows = []
        for node in ('a', 'pc'):
            if node not in self.masters:
                continue
            m = self.masters[node]
            process = m['process']
            row = {'node': node, 'owned_PID': process.pid, 'remote_controls': 0}
            try:
                if process.poll() is None and 'identity' in m:
                    self.check(node)
                    q = subprocess.run(self.route(node, m['path'], control='exit'), capture_output=True, timeout=self.remaining(3), env=ENV)
                    row.update(exit_request_rc=q.returncode, stdout_hex=q.stdout.hex(), stderr_hex=q.stderr.hex())
                    need(q.returncode == 0, 'owned_exit_request_failed')
                    row['actual_master_rc'] = process.wait(timeout=self.remaining(3))
                    row['owned_child_reaped'] = True
                else:
                    row['actual_master_rc'] = process.poll()
            except BaseException as error:
                row['close_error_type'] = type(error).__name__
            finally:
                if process.poll() is None:
                    try:
                        ident = self.pid_identity(process, cleanup=True)
                        need('identity' not in m or ident == m['identity'], 'no_foreign_PID_TERM')
                        process.terminate()
                        process.wait(timeout=3)
                        row['owned_local_transport_SIGTERM'] = True
                    except BaseException as error:
                        row['remaining_live_error_type'] = type(error).__name__
                row['actual_master_rc'] = process.poll()
                row['owned_child_reaped'] = process.poll() is not None
                row['socket_absent'] = absent(m['path'])
                rows.append(row)
        try:
            self.save('closed-originals.json', rows)
            need(all((r['owned_child_reaped'] and r['socket_absent'] for r in rows)), 'owned_transport_terminal_unknown')
        finally:
            os.close(self.output_fd)
        return rows
