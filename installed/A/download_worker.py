# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Future A-only AS192 child. Source/credentials/data never enter argv or env."""
import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path
import sys
sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent / 'private'), str(Path(__file__).resolve().parent / 'fetch')]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan
from broker import request
from root_io import held, fresh, sha, f9

def execute(context):
    sys.path.insert(0, str(Path(plan.STAGE) / 'fetch'))
    import contract, fetch, oci, transport, supervision
    supervision.limit_address_space()
    plan.need(sys.stdin.buffer.readline(16) == b'RUN_ONCE\n', 'owned_parent_kernel_release')
    budget = contract.Budget(min(1800, context['remaining_seconds']))
    pulse_identity = context['pulse_identity']
    end = budget.deadline

    def pulse():
        answer = request('pulse', {}, end)
        from qualification import pulse as actual_pulse
        p, left = actual_pulse(answer, context, time.time())
        budget.deadline = min(budget.deadline, budget.clock() + left)
        raw = base64.b64decode(answer['original_raw_b64'], validate=True)
        plan.need(sha(raw) == answer['original_sha256'], 'same_actual_PC_pulse_original')
        return raw

    def openssl_tool():
        tool = context['tools']['openssl']
        held(tool['path'], tool['sha256'], cap=128 * 1024 ** 2)
        return tool['path']
    from bounded_process import capture

    def peers(host):
        started = time.time()
        answer = request('dns', {'host': host}, end)
        plan.need(set(answer) == {'host', 'addresses', 'query_nonce', 'requested_nonce', 'source_observed_at', 'source_kind'} and answer['host'] == host and (answer['query_nonce'] == answer['requested_nonce']) and (answer['source_kind'] == 'fresh_existing_VPS_public_DNS') and (time.time() - started <= 30), 'fresh_original_dns_roundtrip_not_historic_IP')
        addresses = answer['addresses']
        plan.need(type(addresses) is list and 0 < len(addresses) <= 64, 'bounded_current_DNS_addresses')
        ip = addresses[0]
        tool = context['tools']['ip']
        held(tool['path'], tool['sha256'], cap=128 * 1024 ** 2)
        r = capture([tool['path'], '-j', 'route', 'get', ip], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=min(end, time.monotonic() + 2), cap=16384)
        plan.need(r.returncode == 0 and r.stderr == b'', 'actual_A_route_command')
        route = plan.strict(r.stdout)
        plan.need(len(route) == 1 and route[0]['dst'] == ip and (route[0].get('dev') == 'enP7s7') and (route[0].get('prefsrc') == '192.0.2.10') and (route[0].get('gateway') == '192.0.2.10'), 'actual_A_direct_peer_route')
        observed = time.time()
        public = {'host': host, 'ip': ip, 'dns_addresses': addresses, 'dns_observed_at': started, 'route_observed_at': observed, 'route_destination': ip, 'route': {'dev': 'enP7s7', 'prefsrc': '192.0.2.10', 'gateway': '192.0.2.10'}, 'application_proxy': False, 'vpn_route_excluded': route[0]['dst'] == ip and route[0].get('dev') == 'enP7s7' and (route[0].get('prefsrc') == '192.0.2.10') and (route[0].get('gateway') == '192.0.2.10')}
        fresh(Path(plan.ROOT) / ('dns-route-' + uuid.uuid4().hex + '.json'), json.dumps({'dns_original': answer, 'A_query_sent_at': started, 'A_received_at': observed, 'route_raw_b64': base64.b64encode(r.stdout).decode()}).encode())
        transport.peer_identity(public, host, observed)
        return public

    def tokens():
        answer = request('anonymous-token', {}, end)
        plan.need(type(answer) is dict and set(answer) == {'token', 'ttl_floor_seconds'}, 'conservative_secret_answer_schema')
        answer = {'token': answer['token'], 'observed_at': time.time(), 'expires_in': answer['ttl_floor_seconds']}
        path = Path(plan.ROOT) / ('anonymous-token-' + uuid.uuid4().hex + '.json')
        fd = None
        try:
            fresh(path, json.dumps(answer, separators=(',', ':')).encode())
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            return transport.token_from_held_fd(fd, budget)
        finally:
            if fd is not None:
                os.close(fd)
            if path.exists():
                path.unlink()
    store = fetch.Store(Path(plan.ROOT) / 'blobs')
    trace = os.open(Path(plan.ROOT) / 'resources.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    try:
        supervisor = supervision.Supervisor(trace, pulse, lambda: supervision.collect_kernel(context['NVMe_IO_major_minor']), pulse_identity, budget, time.time, context['A_boot_id'], os.environ['INVOCATION_ID'], plan.OPERATION, context['source_release_sha256'], pulse_wall=lambda: time.time() - context['A_minus_PC_clock_lower'])
        budget.observer = supervisor.sample
        supervisor.sample(force=True)
        image = contract.load()
        fetch.Fetcher(image, store, transport.DirectHTTP(budget, peers, tool=openssl_tool), tokens, budget).run()
        archive = oci.archive_file(image, store, budget)
        final_files = {}
        for blob in image.unique:
            budget.left()
            with store.verified(blob, budget, verify=False) as (fd, stat_before):
                final_files[blob.digest] = {'bytes': blob.size, 'stat': f9(os.fstat(fd))}
        archive['stat'] = f9(os.stat('image.oci.tar', dir_fd=store.fd, follow_symlinks=False))
        supervisor.sample(force=True)
        result = {'schema': 'registry-fixed-blobs-OCI-returned/v1', 'operation': plan.OPERATION, 'source_release_sha256': context['source_release_sha256'], 'archive': archive, 'manifest_sha256': plan.MANIFEST, 'config_sha256': plan.CONFIG, 'unique_blobs': 63, 'descriptors': 69, 'image_imported': False, 'final_files': final_files, 'models_started': 0, 'hardware_validated': False, 'observed_at': time.time()}
        fresh(Path(plan.ROOT) / 'download-completed.json', json.dumps(result, sort_keys=True).encode())
        return result
    finally:
        os.fsync(trace)
        os.close(trace)
        store.close()

def main():
    from root_loader import context, load_source_closure
    c = context()
    load_source_closure(c)
    try:
        execute(c)
    except BaseException:
        fresh(Path(plan.ROOT) / 'download-failed.json', json.dumps({'reason_code': 'download_child_failed', 'partial_preserved': True, 'automatic_retry': False, 'observed_at': time.time()}).encode())
        raise plan.Refused('download_child_failed') from None
if __name__ == '__main__':
    main()
