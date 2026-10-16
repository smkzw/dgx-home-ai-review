# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Bounded read-only Linux process-lifetime observation; no signals or fallback.

pidfd_open(flags=0) refers to a thread group. A held proc directory cannot be
retargeted to its numeric PID's replacement. An unclassified exit remains an
unclassified exit, never a claimed known non-target. This is an observation
interval, not an atomic snapshot or proof about processes born afterwards.
"""
import base64
import errno
import hashlib
import os
import select
import stat
import time
from pathlib import Path
SCHEMA = 'registry-prelaunch-pidfd-lifetime-scan/v1'
PROC = Path('/proc')
MAX_PIDS = 4096
MAX_ROUNDS = 3
MAX_EVENTS = 8192
MAX_RAW = 2 * 1024 ** 2
MAX_SECONDS = 8

class Refused(RuntimeError):
    pass

def need(ok, code):
    if not ok:
        raise Refused(code)

def original(raw):
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': hashlib.sha256(raw).hexdigest()}

def identity(z):
    return [z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode]

def start(raw, pid):
    try:
        head, tail = raw.rsplit(b')', 1)
        number, _comm = head.split(b' (', 1)
        ticks_raw = tail.split()[19]
        ticks = ticks_raw.decode('ascii')
    except (ValueError, UnicodeError, IndexError):
        raise Refused('proc_stat_malformed') from None
    need(number == str(pid).encode('ascii') and ticks.isascii() and ticks.isdecimal(), 'proc_stat_pid_unsigned_starttime')
    return ticks

class Kernel:
    """Only this syscall boundary is projected by CPU fixtures."""

    def acquire(self, pid):
        need(hasattr(os, 'pidfd_open') and hasattr(select, 'poll'), 'pidfd_poll_unsupported_no_fallback')
        return os.pidfd_open(pid, 0)

    def exited(self, fd):
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP)
        events = poller.poll(0)
        need(all((n == fd and mask and (not mask & ~(select.POLLIN | select.POLLHUP)) for n, mask in events)), 'pidfd_poll_unknown_event')
        return bool(events)

    def pids(self, root):
        names = [n for n in os.listdir(root) if n.isascii() and n.isdecimal()]
        pids = sorted((int(n) for n in names))
        need(len(pids) <= MAX_PIDS and len(pids) == len(set(pids)) and all((0 < n < 2 ** 31 for n in pids)), 'bounded_proc_enumeration')
        return pids

    def leaf(self, directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), 'proc_leaf_not_regular')
            raw = bytearray()
            while True:
                part = os.read(fd, min(16384, 65537 - len(raw)))
                if not part:
                    return bytes(raw)
                raw.extend(part)
                need(len(raw) <= 65536, 'proc_leaf_raw_cap')
        finally:
            os.close(fd)

def scan(root):
    markers = (str(root), '/var/lib/dgx-v4/mimo-registry-native-r26-configpaths-r1', '/system.slice/dgx-v4-mimo-registry-native-configpaths-r1.service')
    need(type(root) is Path or isinstance(root, Path), 'fixed_process_root_path')
    need(root.is_absolute(), 'fixed_absolute_process_root')
    kernel = Kernel()
    end = time.monotonic() + MAX_SECONDS
    events, rounds, live = ([], [], {})
    budget = 0
    root_fd = os.open(PROC, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_identity = identity(os.fstat(root_fd))

    def bounded():
        need(time.monotonic() < end, 'bounded_proc_lifetime_deadline')

    def exit_event(event, syscall):
        event['state'] = 'exited_after_identity' if event['complete_identity'] else 'exited_before_identity'
        event['exit_evidence'] = {'syscall': syscall, 'pidfd_poll_exited': True}

    def collect(pid, event):
        nonlocal budget
        fd = None
        try:
            if kernel.exited(event['_fd']):
                exit_event(event, 'pidfd_poll_before_identity')
                return False
            fd = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
            di = identity(os.fstat(fd))
            need(stat.S_ISDIR(di[4]) and di == identity(os.stat(str(pid), dir_fd=root_fd, follow_symlinks=False)), 'proc_directory_identity')
            before = event.get('row')
            event['proc_directory_observation'] = di
            event['partial_executable'] = []
            originals = {}
            for moment in ('first', 'second'):
                for name in ('stat', 'cmdline', 'cgroup'):
                    bounded()
                    raw = kernel.leaf(fd, name)
                    budget += len(raw)
                    need(budget <= MAX_RAW, 'bounded_complete_proc_raw')
                    if name == 'stat':
                        start(raw, pid)
                    originals[name + '_' + moment] = original(raw)
                    event['partial'] = originals.copy()
                    if name in ('cmdline', 'cgroup'):
                        need(not any((m.encode() in raw for m in markers)), 'owned_target_process_observed')
                argv = base64.b64decode(originals['cmdline_' + moment]['raw_b64'])
                exe = os.readlink('exe', dir_fd=fd) if argv else None
                event['partial_executable'].append(exe)
                need(exe is None or not any((m in exe for m in markers)), 'owned_target_executable_observed')
                if moment == 'first':
                    first_exe = exe
                else:
                    need(first_exe == exe, 'process_executable_drift')
            one = start(base64.b64decode(originals['stat_first']['raw_b64']), pid)
            two = start(base64.b64decode(originals['stat_second']['raw_b64']), pid)
            need(one == two and all((originals[n + '_first'] == originals[n + '_second'] for n in ('cmdline', 'cgroup'))), 'process_identity_drift_unknown')
            need(di == identity(os.fstat(fd)) == identity(os.stat(str(pid), dir_fd=root_fd, follow_symlinks=False)), 'proc_directory_drift')
            row = {'pid': pid, 'start_ticks': one, 'exe': exe, 'proc_directory_identity': di, 'originals': originals}
            if kernel.exited(event['_fd']):
                exit_event(event, 'pidfd_poll_after_identity')
                return False
            if before is not None:
                need(all((before[n] == row[n] for n in ('pid', 'start_ticks', 'exe', 'proc_directory_identity'))) and all((before['originals'][n] == row['originals'][n] for n in ('cmdline_first', 'cgroup_first'))), 'known_live_identity_drift')
            event.update(row=row, partial={}, partial_executable=[], complete_identity=True, state='live')
            return True
        except OSError as e:
            if e.errno not in (errno.ENOENT, errno.ESRCH):
                raise Refused('proc_identity_IO_or_permission_unknown') from None
            need(kernel.exited(event['_fd']), 'proc_missing_while_handle_live_unknown')
            exit_event(event, 'relative_proc_read_then_pidfd_poll')
            return False
        finally:
            if fd is not None:
                os.close(fd)
    try:
        need(stat.S_ISDIR(root_identity[4]) and root_identity[2] == 0, 'actual_proc_root_directory')
        for round_no in range(MAX_ROUNDS):
            bounded()
            listed = kernel.pids(root_fd)
            accounting = {}
            for pid in listed:
                bounded()
                previous = live.get(pid)
                if previous is not None and kernel.exited(previous['_fd']):
                    exit_event(previous, 'pidfd_poll_before_reuse')
                    os.close(previous.pop('_fd'))
                    live.pop(pid)
                    previous = None
                if previous is None:
                    need(len(events) < MAX_EVENTS, 'bounded_proc_identity_events')
                    previous = {'id': len(events) + 1, 'pid': pid, 'state': 'acquiring', 'complete_identity': False, 'partial': {}, 'exit_evidence': None, 'row': None, 'proc_directory_observation': None, 'partial_executable': []}
                    events.append(previous)
                    try:
                        previous['_fd'] = kernel.acquire(pid)
                    except OSError as e:
                        need(e.errno == errno.ESRCH, 'pidfd_acquire_unsupported_or_unknown')
                        previous.update(state='absent_at_acquire', exit_evidence={'syscall': 'pidfd_open', 'errno': errno.ESRCH})
                        accounting[str(pid)] = previous['id']
                        continue
                    live[pid] = previous
                accounting[str(pid)] = previous['id']
                if kernel.exited(previous['_fd']):
                    exit_event(previous, 'pidfd_poll_before_identity')
                    os.close(previous.pop('_fd'))
                    live.pop(pid)
                elif not collect(pid, previous):
                    os.close(previous.pop('_fd'))
                    live.pop(pid)
            closing = kernel.pids(root_fd)
            for pid, event in list(live.items()):
                if kernel.exited(event['_fd']):
                    exit_event(event, 'pidfd_poll_closing')
                    os.close(event.pop('_fd'))
                    live.pop(pid)
            rounds.append({'enumerated': listed, 'accounted': accounting, 'closing_enumerated': closing, 'closing_live_ids': {str(p): v['id'] for p, v in live.items()}})
            need(root_identity == identity(os.fstat(root_fd)) == identity(os.stat(PROC, follow_symlinks=False)), 'proc_root_identity_drift')
            if round_no and set(live) == set(closing) == set(listed):
                result = {'schema': SCHEMA, 'complete': True, 'matches': [], 'events': [{k: v for k, v in e.items() if k != '_fd'} for e in events], 'rounds': rounds, 'live_ids': {str(p): v['id'] for p, v in live.items()}, 'root_identity': root_identity, 'scope': 'bounded_interval_not_future_or_atomic_snapshot'}
                validate(result, root)
                return result
        raise Refused('proc_churn_not_closed_within_bound')
    finally:
        for event in live.values():
            if '_fd' in event:
                os.close(event.pop('_fd'))
        os.close(root_fd)

def validate(value, root):
    """Typed consumer for source-held producer originals, not a new authority."""
    need(type(value) is dict and set(value) == {'schema', 'complete', 'matches', 'events', 'rounds', 'live_ids', 'root_identity', 'scope'}, 'proc_lifetime_schema')
    need(value['schema'] == SCHEMA and value['complete'] is True and (value['matches'] == []) and (value['scope'] == 'bounded_interval_not_future_or_atomic_snapshot'), 'proc_lifetime_current_no_target')
    need(type(value['events']) is list and 0 < len(value['events']) <= MAX_EVENTS and (type(value['rounds']) is list) and (2 <= len(value['rounds']) <= MAX_ROUNDS), 'proc_lifetime_complete_bounded_events')
    markers = (str(root), '/var/lib/dgx-v4/mimo-registry-native-r26-configpaths-r1', '/system.slice/dgx-v4-mimo-registry-native-configpaths-r1.service')
    di = value['root_identity']
    need(type(di) is list and len(di) == 5 and all((type(x) is int and x >= 0 for x in di)) and (di[2] == 0) and stat.S_ISDIR(di[4]), 'proc_lifetime_rootFD_identity')
    events = {}
    raw_total = 0
    for i, event in enumerate(value['events'], 1):
        need(type(event) is dict and set(event) == {'id', 'pid', 'state', 'complete_identity', 'partial', 'exit_evidence', 'row', 'proc_directory_observation', 'partial_executable'} and (type(event['id']) is int) and (event['id'] == i) and (type(event['pid']) is int) and (0 < event['pid'] < 2 ** 31) and (type(event['complete_identity']) is bool), 'proc_lifetime_event_identity')
        events[i] = event
        observed_directory = event['proc_directory_observation']
        need(observed_directory is None or (type(observed_directory) is list and len(observed_directory) == 5 and all((type(x) is int and x >= 0 for x in observed_directory)) and stat.S_ISDIR(observed_directory[4])), 'proc_lifetime_observed_directory_not_handle_binding')
        need(type(event['partial_executable']) is list and len(event['partial_executable']) <= 2 and all((x is None or (type(x) is str and (not any((m in x for m in markers)))) for x in event['partial_executable'])), 'proc_lifetime_partial_executable')
        originals = event['row']['originals'] if event['complete_identity'] else event['partial']
        need(type(originals) is dict and set(originals) <= {n + '_' + m for n in ('stat', 'cmdline', 'cgroup') for m in ('first', 'second')}, 'proc_lifetime_exact_partial_originals')
        decoded = {}
        captures = [originals] + ([event['partial']] if event['complete_identity'] else [])
        for capture_index, capture in enumerate(captures):
            need(type(capture) is dict and set(capture) <= {n + '_' + m for n in ('stat', 'cmdline', 'cgroup') for m in ('first', 'second')}, 'proc_lifetime_retained_partial_keys')
            for name, item in capture.items():
                need(type(item) is dict and set(item) == {'raw_b64', 'sha256'} and (type(item['raw_b64']) is str) and (type(item['sha256']) is str), 'proc_lifetime_original_type')
                try:
                    raw = base64.b64decode(item['raw_b64'], validate=True)
                except (ValueError, TypeError):
                    raise Refused('proc_lifetime_original_base64') from None
                raw_total += len(raw)
                need(len(raw) <= 65536 and raw_total <= MAX_RAW and (base64.b64encode(raw).decode() == item['raw_b64']) and (hashlib.sha256(raw).hexdigest() == item['sha256']), 'proc_lifetime_original_SHA_cap')
                need(not name.startswith(('cmdline_', 'cgroup_')) or not any((m.encode() in raw for m in markers)), 'proc_lifetime_target_original')
                if name.startswith('stat_'):
                    start(raw, event['pid'])
                if capture_index == 0:
                    decoded[name] = raw
        if event['complete_identity']:
            row = event['row']
            need(type(row) is dict and set(row) == {'pid', 'start_ticks', 'exe', 'proc_directory_identity', 'originals'} and (row['pid'] == event['pid']) and (set(originals) == {n + '_' + m for n in ('stat', 'cmdline', 'cgroup') for m in ('first', 'second')}), 'proc_lifetime_full_identity')
            need(row['start_ticks'] == start(decoded['stat_first'], row['pid']) == start(decoded['stat_second'], row['pid']) and decoded['cmdline_first'] == decoded['cmdline_second'] and (decoded['cgroup_first'] == decoded['cgroup_second']) and (type(row['exe']) is str if decoded['cmdline_first'] else row['exe'] is None), 'proc_lifetime_stable_complete_originals')
            need(row['exe'] is None or not any((m in row['exe'] for m in markers)), 'proc_lifetime_target_exe')
            di = row['proc_directory_identity']
            need(type(di) is list and len(di) == 5 and all((type(x) is int and x >= 0 for x in di)) and stat.S_ISDIR(di[4]), 'proc_lifetime_procFD_identity')
        else:
            need(event['row'] is None, 'unclassified_exit_not_known_non_target')
        if event['state'] == 'live':
            need(event['complete_identity'] and event['exit_evidence'] is None, 'proc_lifetime_live_complete')
        elif event['state'] == 'absent_at_acquire':
            need(not event['complete_identity'] and event['partial'] == {} and (event['exit_evidence'] == {'syscall': 'pidfd_open', 'errno': errno.ESRCH}), 'proc_lifetime_kernel_ESRCH_required')
        else:
            need(event['state'] == ('exited_after_identity' if event['complete_identity'] else 'exited_before_identity') and type(event['exit_evidence']) is dict and (set(event['exit_evidence']) == {'syscall', 'pidfd_poll_exited'}) and (event['exit_evidence']['pidfd_poll_exited'] is True) and (event['exit_evidence']['syscall'] in {'pidfd_poll_after_identity', 'relative_proc_read_then_pidfd_poll', 'pidfd_poll_before_reuse', 'pidfd_poll_before_identity', 'pidfd_poll_closing'}), 'proc_lifetime_positive_exit_required')
    for row in value['rounds']:
        need(type(row) is dict and set(row) == {'enumerated', 'accounted', 'closing_enumerated', 'closing_live_ids'}, 'proc_lifetime_round_schema')
        for field in ('enumerated', 'closing_enumerated'):
            pids = row[field]
            need(type(pids) is list and len(pids) <= MAX_PIDS and all((type(p) is int and 0 < p < 2 ** 31 for p in pids)) and (pids == sorted(set(pids))), 'proc_lifetime_round_pid_set')
        need(type(row['accounted']) is dict and set(row['accounted']) == {str(p) for p in row['enumerated']}, 'proc_lifetime_no_skipped_enumerated_PID')
        for field in ('accounted', 'closing_live_ids'):
            need(type(row[field]) is dict and all((type(eid) is int and eid in events and (str(events[eid]['pid']) == p) for p, eid in row[field].items())), 'proc_lifetime_accounting_full_identity')
    final = value['rounds'][-1]
    need(type(value['live_ids']) is dict and value['live_ids'] == final['closing_live_ids'] and (value['live_ids'] == final['accounted']) and ({eid for eid, e in events.items() if e['state'] == 'live'} == set(value['live_ids'].values())) and (set(value['live_ids']) == {str(p) for p in final['closing_enumerated']} == {str(p) for p in final['enumerated']}) and all((events[eid]['state'] == 'live' for eid in value['live_ids'].values())), 'proc_lifetime_current_replacements_closed')
    need({eid for row in value['rounds'] for eid in row['accounted'].values()} == set(events), 'proc_lifetime_every_event_accounted')
    return value
