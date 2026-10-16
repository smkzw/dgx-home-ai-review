# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Owned subprocess output/deadline bound. No force-kill or retry."""
import os, select, subprocess, time

class Failure(RuntimeError):
    pass

def capture(args, *, env, deadline, cap, check=lambda: None):
    p = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = {p.stdout: bytearray(), p.stderr: bytearray()}
    active = list(out)
    try:
        while active:
            check()
            if time.monotonic() >= deadline:
                raise Failure('owned_process_deadline')
            ready, _, _ = select.select(active, [], [], min(0.25, deadline - time.monotonic()))
            for s in ready:
                b = os.read(s.fileno(), 65536)
                if not b:
                    active.remove(s)
                    continue
                if sum(map(len, out.values())) + len(b) > cap:
                    raise Failure('owned_output_cap')
                out[s].extend(b)
        rc = p.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(args, rc, bytes(out[p.stdout]), bytes(out[p.stderr]))
    except BaseException as e:
        e.partial_stdout = bytes(out[p.stdout])
        e.partial_stderr = bytes(out[p.stderr])
        raise
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise Failure('owned_child_still_alive_no_force')
        for s in out:
            s.close()
