# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import math, stat
import base64, errno, hashlib, os, re, stat, time
from pathlib import Path
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, k):
    if not v:
        raise RuntimeError(k)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def meta(z):
    return [getattr(z, k) for k in FIELDS]

def stable_directory(a, b):
    return all((a[i] == b[i] for i in (0, 1, 3, 4, 5)))

def kernel_leaf(directory, name, path):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = meta(os.fstat(fd))
        need(stat.S_ISREG(before[5]) and before[3] == 0 and (before[6] == 1) and (not before[5] & 18), 'fixed_kernel_leaf_identity')
        raw = bytearray()
        while True:
            part = os.read(fd, min(16384, 65537 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= 65536, 'kernel_original_cap')
        need(before == meta(os.fstat(fd)) == meta(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'kernel_leaf_FD_named_identity')
        return {'path': path, 'raw_utf8': bytes(raw).decode(), 'sha256': sha(bytes(raw)), 'stat': before}
    finally:
        os.close(fd)

def kernel_after_stop(unit, pid, boot, end):
    need(type(pid) is int and pid > 1 and (unit == ALLOWED_UNIT), 'fixed_owned_kernel_target')
    started = time.time()
    fds = []

    def directory(path):
        need(time.monotonic() < end, 'readonly_phase_absolute_budget')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append((fd, path, meta(os.fstat(fd))))
        z = os.fstat(fd)
        need(z.st_uid == 0 and stat.S_ISDIR(z.st_mode) and (not z.st_mode & 18), 'kernel_anchor_Root_directory')
        return fd

    def boot_original():
        fd = directory('/proc/sys/kernel/random')
        return kernel_leaf(fd, 'boot_id', '/proc/sys/kernel/random/boot_id')
    try:
        first = boot_original()
        need(first['raw_utf8'].strip() == boot, 'same_actual_boot_before_kernel')
        proc = directory('/proc')
        try:
            os.stat(str(pid), dir_fd=proc, follow_symlinks=False)
        except FileNotFoundError as e:
            need(e.errno == errno.ENOENT, 'positive_original_PID_ENOENT')
        else:
            need(False, 'original_worker_PID_still_exists_unknown')
        parent = directory('/sys/fs/cgroup/system.slice')
        fixed = '/sys/fs/cgroup/system.slice/' + unit
        nodes = []
        try:
            cg = os.open(unit, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError as e:
            need(e.errno == errno.ENOENT, 'positive_fixed_CG_ENOENT')
            state = 'absent'
        else:
            state = 'present-empty'
            fds.append((cg, fixed, meta(os.fstat(cg))))

            def walk(fd, path):
                need(len(nodes) < 128 and time.monotonic() < end, 'bounded_owned_CG_tree')
                before = meta(os.fstat(fd))
                need(before[3] == 0 and stat.S_ISDIR(before[5]) and (not before[5] & 18), 'Root_owned_CG_tree')
                names = sorted(os.listdir(fd))
                leaf = kernel_leaf(fd, 'cgroup.procs', path + '/cgroup.procs')
                need(not leaf['raw_utf8'].strip(), 'owned_CG_nonempty_unknown')
                children = []
                for name in names:
                    z = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(z.st_mode):
                        children.append(name)
                    else:
                        need(not stat.S_ISLNK(z.st_mode), 'owned_CG_symlink_unknown')
                node = {'path': path, 'before_stat': before, 'after_stat': None, 'entries_before': names, 'entries_after': None, 'children': children, 'procs_original': leaf}
                nodes.append(node)
                for name in children:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    fds.append((child, path + '/' + name, meta(os.fstat(child))))
                    walk(child, path + '/' + name)
                node['entries_after'] = sorted(os.listdir(fd))
                node['after_stat'] = meta(os.fstat(fd))
                need(node['entries_before'] == node['entries_after'] and stable_directory(before, node['after_stat']), 'owned_CG_tree_drift')
            walk(cg, fixed)
        second = boot_original()
        need(second['raw_utf8'] == first['raw_utf8'], 'same_actual_boot_after_kernel')
        anchors = []
        for fd, path, before in fds:
            after = meta(os.fstat(fd))
            named = meta(os.stat(path, follow_symlinks=False))
            need(stable_directory(before, after) and stable_directory(before, named), 'kernel_directory_named_identity')
            anchors.append({'path': path, 'before_stat': before, 'after_stat': after, 'named_stat': named})
        need(time.monotonic() < end, 'readonly_phase_absolute_budget')
        return {'schema': 'owned-readonly-poststop-kernel/v1', 'unit': unit, 'original_worker_pid': pid, 'boot_before': first, 'boot_after': second, 'PID_absence': {'path': '/proc/' + str(pid), 'errno': errno.ENOENT}, 'fixed_cgroup': fixed, 'cgroup_state': state, 'cgroup_nodes': nodes, 'directory_anchors': anchors, 'started_at': started, 'finished_at': time.time()}
    finally:
        for fd, _, _ in reversed(fds):
            os.close(fd)
ALLOWED_UNIT = 'dgx-v4-image-segment-c64efe9f2fb5ca21eeb0ee5a107e4e9f.service'

def validate_failed_kernel(k, unit, pid, boot, observed):
    need(type(k) is dict and set(k) == {'schema', 'unit', 'original_worker_pid', 'boot_before', 'boot_after', 'PID_absence', 'fixed_cgroup', 'cgroup_state', 'cgroup_nodes', 'directory_anchors', 'started_at', 'finished_at'} and (k['schema'] == 'owned-readonly-poststop-kernel/v1') and (k['unit'] == unit) and (type(k['original_worker_pid']) is int) and (k['original_worker_pid'] == pid), 'poststop_exact_kernel_identity')
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (k['started_at'], k['finished_at'], observed))) and observed <= k['started_at'] <= k['finished_at'], 'poststop_actual_kernel_time_order')

    def metadata(s, directory=False):
        need(type(s) is list and len(s) == 9 and all((type(x) is int and x >= 0 for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[3] == 0) and (s[6] >= 1) and (not s[5] & 18) and (stat.S_ISDIR(s[5]) if directory else stat.S_ISREG(s[5])), 'poststop_kernel_full_F9_type')

    def original(row, path):
        need(type(row) is dict and set(row) == {'path', 'raw_utf8', 'sha256', 'stat'} and (row['path'] == path) and (type(row['raw_utf8']) is str) and (len(row['raw_utf8'].encode()) <= 65536) and (sha(row['raw_utf8'].encode()) == row['sha256']), 'poststop_kernel_fullraw_SHA')
        metadata(row['stat'])
        return row['raw_utf8']
    bootpath = '/proc/sys/kernel/random/boot_id'
    b = original(k['boot_before'], bootpath)
    need(b == original(k['boot_after'], bootpath) and b.strip() == boot, 'poststop_same_boot_originals')
    need(k['PID_absence'] == {'path': '/proc/' + str(pid), 'errno': 2}, 'poststop_original_PID_positive_ENOENT')
    fixed = '/sys/fs/cgroup/system.slice/' + unit
    need(k['fixed_cgroup'] == fixed and type(k['cgroup_nodes']) is list and (len(k['cgroup_nodes']) <= 128), 'poststop_fixed_CG_bounded')
    nodes = k['cgroup_nodes']
    paths = []
    edges = []
    if k['cgroup_state'] == 'absent':
        need(nodes == [], 'poststop_absent_CG_no_fabricated_tree')
    else:
        need(k['cgroup_state'] == 'present-empty' and nodes, 'poststop_unknown_CG_state')
        for node in nodes:
            need(type(node) is dict and set(node) == {'path', 'before_stat', 'after_stat', 'entries_before', 'entries_after', 'children', 'procs_original'}, 'poststop_complete_CG_node')
            path = node['path']
            need(type(path) is str and (path == fixed or path.startswith(fixed + '/')) and all((x not in ('', '.', '..') for x in path[len(fixed):].split('/')[1:])), 'poststop_only_fixed_CG_tree')
            paths.append(path)
            for key in ('entries_before', 'entries_after', 'children'):
                a = node[key]
                need(type(a) is list and all((type(x) is str and x not in ('', '.', '..') and ('/' not in x) for x in a)) and (a == sorted(set(a))), 'poststop_CG_complete_listing')
            need(node['entries_before'] == node['entries_after'] and set(node['children']) <= set(node['entries_before']) and ('cgroup.procs' in node['entries_before']), 'poststop_CG_no_listing_drift')
            metadata(node['before_stat'], True)
            metadata(node['after_stat'], True)
            need(all((node['before_stat'][i] == node['after_stat'][i] for i in (0, 1, 3, 4, 5))), 'poststop_CG_directory_identity')
            need(not original(node['procs_original'], path + '/cgroup.procs').strip(), 'poststop_CG_full_original_nonempty')
            edges.extend((path + '/' + name for name in node['children']))
        need(paths[0] == fixed and len(paths) == len(set(paths)) and (set(paths) == {fixed} | set(edges)), 'poststop_CG_no_missing_child')
    anchors = k['directory_anchors']
    expected = ['/proc/sys/kernel/random', '/proc', '/sys/fs/cgroup/system.slice'] + paths + ['/proc/sys/kernel/random']
    need(type(anchors) is list and len(anchors) == len(expected) and ([x['path'] for x in anchors] == expected), 'poststop_positive_kernel_anchors')
    for a in anchors:
        need(type(a) is dict and set(a) == {'path', 'before_stat', 'after_stat', 'named_stat'}, 'poststop_kernel_anchor_schema')
        for key in ('before_stat', 'after_stat', 'named_stat'):
            metadata(a[key], True)
        need(all((a['before_stat'][i] == a['after_stat'][i] == a['named_stat'][i] for i in (0, 1, 3, 4, 5))), 'poststop_kernel_anchor_stable_identity')
    return k
