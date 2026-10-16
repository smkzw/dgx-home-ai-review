# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One fixed Range exchange over the unchanged direct TLS/route primitives.
No default authority or token supplier. Errors never expose exception text,
Authorization, peer proof, signed URL, request bytes or response headers.
"""
import http.client, math, time
import range_diagnostic
from range_catalog import CHUNK, REGISTRY, CDN, need, Refused
from range_transport import DirectHTTP, Token, peer_identity, redirect, HTTPInput, close_owned
APPROVED_NATIVE_AUTHORITY = None
MAX_RANGE = 64 * 1024 ** 2

def range_headers(response, start, count, total):
    need(type(response.status) is int and response.status == 206, 'range_HTTP206_required')
    need(response.headers.get_all('Content-Range', []) == [f'bytes {start}-{start + count - 1}/{total}'] and response.headers.get_all('Content-Length', []) == [str(count)], 'exact_range_offset_total_length')
    enc = response.headers.get_all('Content-Encoding', [])
    need(not response.headers.get_all('Transfer-Encoding', []) and enc in ([], ['identity']) and (not response.chunked), 'unambiguous_range_identity_framing')
    need(not response.headers.get_all('Location', []) and (not any(('multipart' in v.lower() for v in response.headers.get_all('Content-Type', [])))), 'no_ambiguous_range_redirect_or_multipart')
    response.length = None
    return count

class RangeHTTP(DirectHTTP):

    def __init__(self, budget, peers, *, authority=None, tool=None, wall=time.time, connector=None, hostname_check=None):
        super().__init__(budget, peers, tool=tool, wall=wall, connector=connector, hostname_check=hostname_check)
        self.authority = authority
        self.logical_requests = 0

    def _exchange_range(self, host, path, token, start, count):
        response = tls = None
        phase = ('registry' if host == REGISTRY else 'cdn') + '.peer'
        try:
            need(host in (REGISTRY, CDN) and path.startswith('/') and (len(path) <= 16384) and path.isascii() and all((33 <= ord(c) <= 126 for c in path)), 'fixed_range_target')
            need(host == REGISTRY and type(token) is Token or (host == CDN and token is None), 'range_origin_only_bearer')
            ip = peer_identity(self.peers(host), host, self.wall())
            deadline = min(self.budget.deadline, self.budget.clock() + 30)
            need(deadline > self.budget.clock(), 'range_metadata_deadline')
            if token is not None:
                need(token.issued_monotonic + token.lifetime - self.budget.clock() >= 45, 'range_token_safe_before_send')
            phase = ('registry' if host == REGISTRY else 'cdn') + '.connect'
            tls = self.connector(host, ip, deadline)
            auth = '' if token is None else 'Authorization: Bearer ' + token.value + '\r\n'
            raw = ('GET ' + path + ' HTTP/1.1\r\nHost: ' + host + '\r\n' + auth + 'Range: bytes=' + str(start) + '-' + str(start + count - 1) + '\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode()
            phase = ('registry' if host == REGISTRY else 'cdn') + '.send'
            tls.settimeout(min(8, self.budget.left(), deadline - self.budget.clock()))
            tls.sendall(raw)
            phase = ('registry' if host == REGISTRY else 'cdn') + '.headers'
            incoming = HTTPInput(tls, self.budget, deadline)
            response = http.client.HTTPResponse(incoming)
            response.begin()
            response.deadline_reader = incoming.reader
            need(sum((len(k) + len(v) for k, v in response.getheaders())) <= 65536, 'bounded_range_headers')
            return (response, tls)
        except Exception as error:
            evidence = range_diagnostic.failure(error, phase, getattr(response, 'status', None))
            close_owned(response, tls)
            masked = Refused('range_exchange_failed')
            masked._range_safe_failure = evidence
            raise masked from None

    def chunks(self, blob, token, start, count):
        response = tls = None
        phase = 'range.admission'
        try:
            need(APPROVED_NATIVE_AUTHORITY is not None and self.authority is APPROVED_NATIVE_AUTHORITY, 'range_authority_None')
            need(self.logical_requests == 0, 'one_range_noRetry')
            self.logical_requests = 1
            need(type(start) is int and 0 <= start < blob.size and (type(count) is int) and (0 < count <= MAX_RANGE) and (start + count <= blob.size), 'bounded_exact_range')
            self.budget.left()
            need(type(token) is Token and token.issued_monotonic + token.lifetime - self.budget.clock() >= 45, 'range_safe_token')
            response, tls = self._exchange_range(REGISTRY, '/v2/lmsysorg/sglang/blobs/sha256:' + blob.digest, token, start, count)
            if response.status == 307:
                phase = 'registry.redirect'
                locations = response.headers.get_all('Location', [])
                need(len(locations) == 1, 'one_original_range_redirect')
                path = redirect(locations[0])
                close_owned(response, tls)
                response = tls = None
                response, tls = self._exchange_range(CDN, path, None, start, count)
            phase = 'range.headers'
            range_headers(response, start, count, blob.size)
            response.deadline_reader.deadline = self.budget.deadline
            left = count
            phase = 'body.read'
            while left:
                self.budget.left()
                data = response.read(min(left, CHUNK))
                need(type(data) is bytes and 0 < len(data) <= min(left, CHUNK), 'range_truncation_or_chunk')
                left -= len(data)
                yield data
            phase = 'body.EOF'
            self.budget.left()
            need(response.read(1) == b'', 'range_true_EOF_required')
            self.budget.left()
        except Exception as error:
            masked = Refused('range_failed_noRetry')
            masked._range_safe_failure = range_diagnostic.failure(error, phase, getattr(response, 'status', None))
            raise masked from None
        finally:
            close_owned(response, tls)
