# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def actor_parent(expected_holder):
    path = Path(recovery.ACTOR_ROOT)
    fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    f = lambda z: [getattr(z, k) for k in fields]
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = f(os.fstat(fd))
        names = sorted(os.listdir(fd))
        need(before == f(path.lstat()) and before[3:6] == [999, 989, 16832] and (names == ['b7a518bbefa903b6c43c44b9a2f6f6cf', '69b0a7b8356ae276839c3cc43044096c', 'c64efe9f2fb5ca21eeb0ee5a107e4e9f', '6867e0e5c18d53bc88b7d742da7b86a8']), 'R16_normal_complete_four_actor_set')
        actors = recovery.actors(protected_read, expected_holder)
        children = {n: f(os.stat(n, dir_fd=fd, follow_symlinks=False)) for n in names}
        need(set(actors) == set(names) and f(os.fstat(fd)) == f(path.lstat()) == before and (sorted(os.listdir(fd)) == names), 'R16_normal_actor_held_after_all_history')
        return {'path': str(path), 'F9': before, 'entries': names, 'children': children, 'actor_files': {n: {k: {'sha256': v['sha256'], 'F9': v['F9']} for k, v in a['files'].items()} for n, a in actors.items()}}
    finally:
        os.close(fd)
