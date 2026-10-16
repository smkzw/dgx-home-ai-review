# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Single aggregate fixed-segment worker. No daemon/import/model execution."""
import os, signal, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan, segment_runtime
from root_io import held, fresh, sha

def execute(c, p, io_factory=None, broker_factory=None):
    from native import Native
    from broker import Broker
    io = (io_factory or Native)(c, time.monotonic() + c['remaining_seconds'])
    end = io.end
    broker = None
    succeeded = False
    result = None
    root = Path(plan.ROOT)
    parent = segment_runtime.payload_parent(c['stage_operation'], create=False)
    plan.need(root == parent / 'range', 'stage_payload_range_fixed_parent')
    plan.need(not root.exists(), 'new_finite_stage_payload_not_retry')
    root.mkdir(mode=448)
    os.chmod(root, 448)
    io.archive()
    intent = {'schema': 'fixed-image-stage-worker-intent/v1', 'operation': plan.OPERATION, 'stage_operation': c['stage_operation'], 'unit': plan.UNIT, 'plan_sha256': c['plan_sha256'], 'source_review_sha256': c['source_release_sha256'], 'worker_pid': os.getpid(), 'worker_start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'invocation_id': os.environ['INVOCATION_ID'], 'boot_id': c['A_boot_id'], 'worker_sha256': sha(Path(__file__).read_bytes()), 'source_index_sha256': sha(held(Path(plan.STAGE) / 'source-index.json')[0]), 'context_sha256': sha(held(Path(plan.STAGE_CONTROL) / 'context.json')[0]), 'original_grant': c['initial_pulse_original'], 'retry': 0, 'observed_at': time.time()}
    fresh(root / 'intent.json', plan.encode(intent))
    try:
        fresh(root / 'initial-kernel-unit.json', plan.encode(io.bootstrap()))
        broker = (broker_factory or Broker)(end, path=plan.SOCKET)
        broker.start()
        child = io.spawn(['/usr/bin/python3', '-I', '-B', plan.STAGE + '/segment_download_worker.py', c['stage_operation']], 'segments', stdin=True)
        broker.worker_pid = child.pid
        child.stdin.write(b'RUN_ONCE\n')
        child.stdin.flush()
        child.stdin.close()
        io.wait(child, max(0.001, end - time.monotonic() - 30))
        raw, st = held(root / 'segments-completed.json')
        result = plan.strict(raw)
        plan.need(result['schema'] == 'fixed-image-selected-segments-returned/v1' and result['stage_operation'] == c['stage_operation'] and (result['image_imported'] is False), 'stage_child_typed_partial_success')
        succeeded = True
    except BaseException as error:
        import diagnostics
        child_original = None
        if (root / 'download-failed.json').exists():
            cr, cs = held(root / 'download-failed.json', mode=384)
            child_original = {'raw_b64': __import__('base64').b64encode(cr).decode(), 'sha256': sha(cr), 'stat': cs}
        fresh(root / 'failed.json', plan.encode(dict(diagnostics.details(error, 'registry.download'), child_failure_original=child_original, schema='fixed-image-stage-failed/v1', stage_operation=c['stage_operation'], automatic_retry=False, partial_preserved=True, observed_at=time.time())))
        raise plan.Refused('fixed_image_stage_failed') from None
    finally:
        first = None
        try:
            if broker is not None:
                broker.close()
        except BaseException as e:
            first = e
        try:
            clean = io.cleanup()
        except BaseException as e:
            if first is None:
                first = e
        if first is not None:
            raise plan.Refused('stage_cleanup_unknown_sticky') from None
        if succeeded:
            fresh(root / 'returned-zero.json', plan.encode({'schema': 'fixed-image-stage-returned-zero/v1', 'operation': plan.OPERATION, 'stage_operation': c['stage_operation'], 'worker_pid': os.getpid(), 'worker_sha256': sha(Path(__file__).read_bytes()), 'boot_id': c['A_boot_id'], 'invocation_id': os.environ['INVOCATION_ID'], 'child_rc': 0, 'stderr_bytes': 0, 'result': result, 'cleanup': clean, 'observed_at': time.time()}))
    return 0

def main():
    stage = sys.argv[1] if len(sys.argv) == 2 else ''
    c, p = segment_runtime.context(stage)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(plan.Refused('stage_owned_TERM_no_retry')))
    return execute(c, p)
if __name__ == '__main__':
    raise SystemExit(main())
