# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Single owned download/containerd/import phase; default inert, no model start."""
import os, signal, time
from pathlib import Path
import sys
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent / 'private'), str(Path(__file__).resolve().parent / 'fetch')]
import plan
from root_io import fresh, held, sha
from broker import Broker
from native import Native

class Worker:

    def __init__(self, context, io_factory=Native, broker_factory=Broker):
        self.phase = 'registry.source_admission'
        self.c = context
        self.end = time.monotonic() + context['remaining_seconds']
        self.io = io_factory(context, self.end)
        self.broker_factory = broker_factory
        self.broker = None

    def pulse(self):
        from broker import request
        from qualification import pulse
        p, left = pulse(request('pulse', {}, self.end, server_pid=os.getpid()), self.c, time.time())
        self.end = min(self.end, time.monotonic() + left)
        self.io.end = self.end
        return p

    def execute(self):
        plan.need(not Path(plan.ROOT).exists(), 'new_owned_registry_namespace_not_replay')
        Path(plan.ROOT).mkdir(mode=448)
        os.chmod(plan.ROOT, 448)
        self.io.archive()
        fresh(Path(plan.ROOT) / 'intent.json', plan.encode({'operation': plan.OPERATION, 'source_review_sha256': self.c['source_release_sha256'], 'remaining_seconds_at_A': self.c['remaining_seconds'], 'original_grant': self.c['initial_pulse_original'], 'observed_at': time.time(), 'retry': 0, 'unit': plan.UNIT, 'worker_pid': os.getpid(), 'worker_start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'invocation_id': os.environ['INVOCATION_ID'], 'boot_id': self.c['A_boot_id'], 'worker_sha256': sha(Path(__file__).read_bytes()), 'source_index_sha256': sha(held(Path(plan.STAGE) / 'source-index.json')[0]), 'context_sha256': sha(held(Path(plan.STAGE) / 'context.json')[0])}))
        succeeded = False
        result = None
        try:
            self.phase = 'registry.kernel_bootstrap'
            actual = self.io.bootstrap()
            fresh(Path(plan.ROOT) / 'initial-kernel-unit.json', plan.encode(actual))
            self.phase = 'registry.download'
            self.broker = self.broker_factory(self.end)
            self.broker.start()
            child = self.io.spawn(['/usr/bin/python3', '-I', '-B', plan.STAGE + '/download_worker.py'], 'download', stdin=True)
            self.broker.worker_pid = child.pid
            child.stdin.write(b'RUN_ONCE\n')
            child.stdin.flush()
            child.stdin.close()
            self.io.wait(child, max(0.001, self.end - 30 - time.monotonic()))
            self.phase = 'registry.download_return'
            raw, st = held(Path(plan.ROOT) / 'download-completed.json')
            download = plan.strict(raw)
            plan.need(download['operation'] == plan.OPERATION and download['manifest_sha256'] == plan.MANIFEST and (download['config_sha256'] == plan.CONFIG) and (download['image_imported'] is False), 'actual_fixed_download_return')
            self.broker.worker_pid = os.getpid()
            self.io.pulse_callback = self.pulse
            self.io.check()
            self.phase = 'registry.config_raw'
            import private_config
            cfg = private_config.config_bytes(plan.ROOT)
            fresh(Path(plan.ROOT) / 'containerd.toml', cfg)
            self.phase = 'registry.config_CLI'
            version = self.io.call([self.io.tool('containerd'), '--version'], 5, 'containerd-version')
            args = [self.io.tool('containerd'), '--config', plan.ROOT + '/containerd.toml']
            dump = self.io.call(args + ['config', 'dump'], 30, 'containerd-dump')
            self.phase = 'registry.config_merged'
            validated = private_config.validate(cfg, dump, plan.ROOT, self.c['tools']['containerd']['sha256'], version)
            plan.need(sha(dump) == self.c['private_config_parse_proof']['dump_sha256'], 'actual_merged_dump_same_reviewed_current_proof')
            fresh(Path(plan.ROOT) / 'private-config-validated.json', plan.encode(validated))
            self.phase = 'registry.daemon_start'
            daemon = self.io.spawn(args, 'containerd')
            socket = self.io.socket(daemon)
            remaining = self.end - time.monotonic() - 30
            plan.need(remaining > 0, 'remaining_import_and_cleanup_window')
            self.phase = 'registry.import'
            importargs = plan.ctr_import(self.c['tools']['ctr'], remaining)
            output = self.io.call(importargs, remaining, 'ctr-import')
            self.phase = 'registry.content_verify'
            import contract
            image = contract.load()
            content = self.io.verify_content(image)
            result = {'schema': 'registry-A-private-import-returned/v1', 'operation': plan.OPERATION, 'source_release_sha256': self.c['source_release_sha256'], 'manifest_sha256': plan.MANIFEST, 'config_sha256': plan.CONFIG, 'download': download, 'download_raw_sha256': sha(raw), 'download_F9': st, 'import': {'argv': importargs, 'rc': 0, 'stderr_bytes': 0, 'stdout_sha256': sha(output), 'namespace': plan.NAMESPACE, 'index_name': plan.INDEX_NAME, 'socket': socket, 'unpack': False, 'local': True, 'imported_content': content}, 'image_imported': True, 'initialized_private_content_registry': True, 'runtime_image_serving_accepted': False, 'ABI_numeric_media_accepted': False, 'models_started': 0, 'hardware_validated': False, 'observed_at': time.time()}
            succeeded = True
        except BaseException as error:
            import diagnostics
            fresh(Path(plan.ROOT) / 'failed.json', plan.encode(dict(diagnostics.details(error, self.phase), schema='registry-R26-A-owned-phase-failed-preserved/v1', reason_code='registry_owned_phase_failed', operation=plan.OPERATION, partial_preserved=True, automatic_retry=False, observed_at=time.time())))
            raise plan.Refused('registry_owned_phase_failed') from None
        finally:
            first = None
            clean = None
            try:
                if self.broker is not None:
                    self.broker.close()
            except BaseException as error:
                first = error
            try:
                clean = self.io.cleanup()
            except BaseException as error:
                if first is None:
                    first = error
            if first is not None:
                import diagnostics
                fresh(Path(plan.ROOT) / 'cleanup-failed.json', plan.encode(dict(diagnostics.details(first, 'registry.cleanup'), operation=plan.OPERATION, reason_code='owned_cleanup_unknown_hold_retained', returned_zero=False, automatic_retry=False, observed_at=time.time())))
                raise plan.Refused('owned_cleanup_unknown_hold_retained') from None
            if succeeded:
                result['registry_original'] = self.io.registry_original()
                returned = {'schema': 'registry-A-worker-returned-zero/v1', 'operation': plan.OPERATION, 'runtime_max_seconds': plan.strict(held(Path(plan.STAGE) / 'runtime-max-original.json')[0])['runtime_max_seconds'], 'worker_pid': os.getpid(), 'worker_sha256': sha(Path(__file__).read_bytes()), 'boot_id': self.c['A_boot_id'], 'invocation_id': os.environ['INVOCATION_ID'], 'result': result, 'cleanup': clean, 'child_rc': 0, 'stderr_bytes': 0, 'loader_returned_zero': True, 'observed_at': time.time()}
                fresh(Path(plan.ROOT) / 'returned-zero.json', plan.encode(returned))
        return 0

def main():
    from root_loader import context, load_source_closure, APPROVED_LITERAL
    if APPROVED_LITERAL is None:
        return 0
    c = context()
    load_source_closure(c)

    def term(*_):
        raise plan.Refused('owned_TERM_no_retry')
    signal.signal(signal.SIGTERM, term)
    return Worker(c).execute()
if __name__ == '__main__':
    raise SystemExit(main())
