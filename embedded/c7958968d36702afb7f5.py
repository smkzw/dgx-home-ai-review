# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Source-bound Root readonly body. Entered only by the held scope loader."""
import base64, os, time
from pathlib import Path
from root_io import held, fresh, sha
from plan import need, strict, encode
import old_failed_kernel as kernel
APPROVED_COLLECT_POLICY = {'stage': 'c64efe9f2fb5ca21eeb0ee5a107e4e9f', 'old_terminal': None, 'old_A_sources': {'EXPECTED_DUMP.json': None, 'OFFICIAL_MERGED_BASELINE.json': None, 'asset_segments.py': None, 'bounded_process.py': None, 'broker.py': None, 'config-original.json': None, 'containerd.candidate.toml': None, 'diagnostics.py': None, 'download_worker.py': None, 'entry_clock.py': None, 'entry_worker.py': None, 'failed_terminal.py': None, 'fetch/config-original.json': None, 'fetch/contract.py': None, 'fetch/entry.py': None, 'fetch/fetch.py': None, 'fetch/manifest-original.json': None, 'fetch/oci.py': None, 'fetch/supervision.py': None, 'fetch/transport.py': None, 'manifest-original.json': None, 'namespace.py': None, 'native.py': None, 'observer.py': None, 'old_failed_kernel.py': None, 'parent_metadata.py': None, 'parent_source.py': None, 'pc_contract.py': None, 'pc_managed_scope.py': None, 'plan.py': None, 'point_clock.py': None, 'private_config.py': None, 'qualification.py': None, 'range_catalog.py': None, 'range_component.py': None, 'range_diagnostic.py': None, 'range_fetch.py': None, 'range_http.py': None, 'range_transport.py': None, 'root_agent.py': None, 'root_io.py': None, 'root_loader.py': None, 'root_worker.py': None, 'segment_agent.py': None, 'segment_download_worker.py': None, 'segment_ready.py': None, 'segment_ready_worker.py': None, 'segment_runtime.py': None, 'segment_terminal_producer.py': None, 'segment_worker.py': None, 'source-index.json': None, 'stage_entry_clock.py': None, 'stage_naming.py': None, 'terminal.py': None, 'topology.py': None}, 'old_worker': {'boot_id': 'redacted-32c02e882269', 'pid': 791840, 'unit': 'dgx-v4-image-segment-c64efe9f2fb5ca21eeb0ee5a107e4e9f.service'}, 'probe_nonce': 'e21f830185b7e1ffbd0ca049a040b4a2'}

def run(request_raw, begin_original):
    p = APPROVED_COLLECT_POLICY
    need(type(p) is dict and set(p) == {'stage', 'old_terminal', 'old_A_sources', 'old_worker', 'probe_nonce'} and (os.getuid() == os.geteuid() == 0), 'R16_owner_readonly_SOURCE_None')
    br = base64.b64decode(begin_original['raw_b64'], validate=True)
    bm = strict(br)
    r = strict(request_raw)
    need(sha(br) == begin_original['sha256'] and begin_original['F9'][2] == len(br) and (begin_original['F9'][3:7] == [0, 989, 33056, 1]) and (bm['schema'] == 'failed-owner-terminal-PC-send/v1') and (bm['request_original']['sha256'] == sha(request_raw)), 'owner_A_PC_BEGIN_not_unclocked_request')
    need(r['schema'] == 'failed-owner-terminal-PC-request/v1' and r['nonce'] == p['probe_nonce'] and (r['stage_operation'] == p['stage']) and (r['old_terminal_sha256'] == p['old_terminal']['sha256']), 'owner_A_actual_fixed_request')
    started = time.time()
    mono = time.monotonic()
    end = mono + 30
    worker = p['old_worker']
    need(kernel.ALLOWED_UNIT == worker['unit'], 'owner_A_private_kernel_exact_old_unit')

    def source():
        out = {}
        for n, ref in p['old_A_sources'].items():
            b, st = held(Path(ref['path']), ref['sha256'], cap=2097152, mode=384)
            need(st == ref['F9'] and sha(b) == ref['sha256'] and (time.monotonic() < end), 'owner_A_actual_old55_complete_source_F9')
            out[n] = ref
        return out
    first = source()
    kb = kernel.kernel_after_stop(worker['unit'], worker['pid'], worker['boot_id'], end)
    last = source()
    ka = kernel.kernel_after_stop(worker['unit'], worker['pid'], worker['boot_id'], end)
    elapsed = time.monotonic() - mono
    need(0 <= elapsed <= 30 and first == last, 'owner_A_original_whole30_no_refresh')
    return {'schema': 'failed-owner-terminal-A-readonly/v1', 'PC_begin_original': begin_original, 'request_raw_b64': base64.b64encode(request_raw).decode(), 'request_sha256': sha(request_raw), 'old_terminal_sha256': p['old_terminal']['sha256'], 'source_before': first, 'source_after': last, 'kernel_before': kb, 'kernel_after': ka, 'started_at': started, 'finished_at': time.time(), 'monotonic_elapsed': elapsed}
