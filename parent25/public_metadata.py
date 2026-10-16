# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""VPS public-only small metadata supplier. No image bytes or logging secrets."""
import ipaddress, json, socket, time, urllib.request, urllib.parse
APPROVED_PUBLIC = None
HOSTS = {'registry-1.docker.io', 'production.cloudfront.docker.com'}

def strict(raw):

    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise RuntimeError('duplicate_metadata')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('nonfinite_metadata')))

def run(row):
    if APPROVED_PUBLIC is None:
        raise RuntimeError('public_metadata_SOURCE_None')
    if type(row) is not dict or row.get('kind') not in ('dns', 'anonymous-token'):
        raise RuntimeError('public_metadata_kind')
    if row['kind'] == 'dns':
        if set(row) != {'kind', 'host', 'nonce'}:
            raise RuntimeError('fixed_DNS_shape')
        host = row['host']
        if host not in HOSTS:
            raise RuntimeError('fixed_public_DNS_host')
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
        if not addresses or len(addresses) > 64 or (not all((ipaddress.ip_address(x).is_global for x in addresses))):
            raise RuntimeError('public_ipv4')
        return {'host': host, 'addresses': addresses, 'query_nonce': row['nonce'], 'requested_nonce': row['nonce'], 'source_observed_at': time.time(), 'source_kind': 'fresh_existing_VPS_public_DNS'}
    if set(row) != {'kind', 'nonce'}:
        raise RuntimeError('anonymous_repo_only')
    url = 'https://auth.docker.io/token?service=registry.docker.io&scope=repository%3Almsysorg%2Fsglang%3Apull'

    class NoRedirect(urllib.request.HTTPRedirectHandler):

        def redirect_request(self, *a, **k):
            raise RuntimeError('public_metadata_redirect_refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=6) as reply:
        if reply.status != 200:
            raise RuntimeError('public_token_HTTP200')
        raw = reply.read(65537)
    if len(raw) > 65536:
        raise RuntimeError('public_token_cap')
    v = strict(raw)
    value = v.get('token') or v.get('access_token')
    ttl = v['expires_in']
    if type(value) is not str or not value or type(ttl) is not int or (not 45 < ttl <= 300):
        raise RuntimeError('public_anonymous_token_contract')
    return {'token': value, 'expires_in': ttl, 'observed_at': time.time()}

def main():
    import sys
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise RuntimeError('public_metadata_frame_cap')
        v = run(strict(raw))
        sys.stdout.buffer.write((json.dumps(v, separators=(',', ':')) + '\n').encode())
        return 0
    except BaseException:
        sys.stdout.write('{"reason_code":"public_metadata_failed_no_retry"}\n')
        return 1
if __name__ == '__main__':
    raise SystemExit(main())
