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
from root_io import held, fresh, sha, f9

def execute(context):
    from broker import request
    sys.path.insert(0, str(Path(plan.STAGE) / 'fetch'))
    import contract, fetch, oci, transport, supervision
    supervision.UNIT = plan.UNIT
    supervision.CG = plan.CG
    supervision.limit_address_space()
    plan.need(sys.stdin.buffer.readline(16) == b'RUN_ONCE\n', 'owned_parent_kernel_release')
    import range_component
    started = time.monotonic()
    budget = range_component.Deadline(started, started + min(1800, context['remaining_seconds']))
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
    import range_catalog, range_http, range_transport, range_component, asset_segments
    import supervision
    trace = os.open(Path(plan.ROOT) / 'segment-resources.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    supervisor = supervision.Supervisor(trace, pulse, lambda: supervision.collect_kernel(context['NVMe_IO_major_minor']), pulse_identity, budget, time.time, context['A_boot_id'], os.environ['INVOCATION_ID'], plan.OPERATION, context['source_release_sha256'], pulse_wall=lambda: time.time() - context['A_minus_PC_clock_lower'])
    budget.observer = supervisor.sample
    supervisor.sample(force=True)
    range_http.APPROVED_NATIVE_AUTHORITY = authority = object()
    http = range_http.RangeHTTP(budget, peers, authority=authority, tool=openssl_tool)

    def supply(blob, start, count):
        ranged = range_http.RangeHTTP(budget, peers, authority=authority, tool=openssl_tool)
        token = tokens()
        token = range_transport.Token(token.value, token.issued_monotonic, token.lifetime)
        return ranged.chunks(blob, token, start, count)
    root = Path(plan.ROOT) / 'segments'
    root.mkdir(mode=448)
    os.chmod(root, 448)
    raw, st = held(Path(plan.STAGE_CONTROL) / 'plan.json')
    selected = plan.strict(raw)
    ranges = asset_segments.exact_ranges(selected['ranges'])
    values = asset_segments.acquire(root, ranges, budget, supply, binding={'operation_family': plan.OPERATION, 'stage_operation': context['stage_operation'], 'source_review_sha256': context['source_release_sha256'], 'plan_sha256': context['plan_sha256']})
    result = {'schema': 'fixed-image-selected-segments-returned/v1', 'operation_family': plan.OPERATION, 'stage_operation': context['stage_operation'], 'segments': values, 'logical_range_requests': len(ranges), 'retry': 0, 'image_imported': False, 'daemon_started': False, 'models_started': 0, 'observed_at': time.time()}
    supervisor.sample(force=True)
    os.fsync(trace)
    os.close(trace)
    fresh(Path(plan.ROOT) / 'segments-completed.json', plan.encode(result))
    return result

def main():
    from segment_runtime import context
    c, _ = context(sys.argv[1] if len(sys.argv) == 2 else '')
    try:
        execute(c)
    except BaseException as error:
        import diagnostics
        fresh(Path(plan.ROOT) / 'download-failed.json', plan.encode(dict(diagnostics.details(error, 'registry.download'), reason_code='download_child_failed', partial_preserved=True, automatic_retry=False, observed_at=time.time())))
        raise plan.Refused('download_child_failed') from None
if __name__ == '__main__':
    main()
