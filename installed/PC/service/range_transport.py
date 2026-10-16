# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One direct IPv4 HTTP exchange; hostname proof precedes every send.

Peer/route and anonymous-token suppliers are trusted future integration seams.
They have no default implementation; no historic IP or expired grant is reused.
"""
import http.client
import io
import ipaddress
import math
import os
import re
import socket
import ssl
import subprocess
import stat
import time
import urllib.parse
from dataclasses import dataclass, field
from range_catalog import Budget, CDN, CHUNK, REGISTRY, SOURCE_IP, Refused, need

def close_owned(*objects):
    failed = False
    for obj in objects:
        if obj is not None:
            try:
                obj.close()
            except Exception:
                failed = True
    if failed:
        raise Refused('owned_HTTP_close_failed') from None

@dataclass(repr=False)
class Token:
    value: str = field(repr=False)
    issued_monotonic: float
    lifetime: float
    scope: str = 'repository:lmsysorg/sglang:pull'

    def __post_init__(self):
        need(type(self.value) is str and re.fullmatch('[A-Za-z0-9._~-]{1,32768}', self.value), 'token_shape')
        need(self.scope == 'repository:lmsysorg/sglang:pull' and type(self.lifetime) in (int, float) and math.isfinite(self.lifetime) and (0 < self.lifetime <= 300) and (type(self.issued_monotonic) in (int, float)) and math.isfinite(self.issued_monotonic), 'token_lifetime_scope')

    def __repr__(self):
        return '<AnonymousScopedToken redacted>'

class TokenPool:

    def __init__(self, supplier, budget):
        self.supplier, self.budget = (supplier, budget)
        self.token, self.supplies, self.active = (None, 0, False)

    def remaining(self):
        return self.token.issued_monotonic + self.token.lifetime - self.budget.clock()

    def acquire(self, request_seconds):
        need(not self.active and 0 < request_seconds <= 120, 'token_request_state')
        self.budget.left()
        if self.token is not None and self.remaining() < request_seconds + 15:
            if self.remaining() > 30:
                self.budget.wait(self.remaining() - 30 + 0.001)
            need(self.remaining() <= 30, 'renewal_threshold')
        if self.token is None or self.remaining() <= 30:
            need(self.supplies < 6, 'token_supply_limit')
            self.supplies += 1
            try:
                token = self.supplier()
            except Exception:
                raise Refused('token_supply_failed') from None
            need(type(token) is Token and 0 <= self.budget.clock() - token.issued_monotonic <= 5, 'fresh_token_supply')
            self.token = token
        need(self.remaining() >= request_seconds + 15 and self.budget.left() > request_seconds, 'token_or_window_too_short')
        self.active = True
        return self.token

    def release(self):
        self.active = False

def token_from_held_fd(fd, budget, wall=time.time):
    """Root's temporary secret FD only; no pathname/env/argv or durable secret receipt."""
    from range_catalog import parse
    from range_fetch import identity
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and (stat.S_IMODE(before.st_mode) == 384) and (before.st_nlink == 1) and (0 < before.st_size <= 65536), 'Root_private_token_FD')
        raw = os.pread(fd, before.st_size + 1, 0)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before), 'held_token_stable')
        row = parse(raw)
        need(set(row) == {'token', 'observed_at', 'expires_in'} and type(row['observed_at']) in (int, float) and math.isfinite(row['observed_at']), 'token_file_schema')
        age = wall() - row['observed_at']
        need(0 <= age <= 5, 'fresh_token_file')
        return Token(row['token'], budget.clock() - age, row['expires_in'])
    except Exception:
        raise Refused('held_secret_refused') from None

def peer_identity(proof, host, now):
    need(type(proof) is dict and set(proof) == {'host', 'ip', 'dns_addresses', 'dns_observed_at', 'route_observed_at', 'route', 'route_destination', 'application_proxy', 'vpn_route_excluded'}, 'peer_proof_schema')
    need(host in (REGISTRY, CDN) and proof['host'] == host, 'original_dns_host')
    need(all((type(proof[k]) in (int, float) and math.isfinite(proof[k]) and (0 <= now - proof[k] <= 30) for k in ('dns_observed_at', 'route_observed_at'))), 'fresh_dns_route')
    need(type(proof['dns_addresses']) is list and 0 < len(proof['dns_addresses']) <= 64 and (proof['ip'] in proof['dns_addresses']), 'peer_in_current_original_dns')
    try:
        need(all((type(s) is str and ipaddress.ip_address(s).version == 4 and ipaddress.ip_address(s).is_global for s in proof['dns_addresses'])), 'public_ipv4_dns')
    except ValueError:
        raise Refused('public_ipv4_dns') from None
    need(proof['route_destination'] == proof['ip'] and proof['route'] == {'dev': 'enP7s7', 'prefsrc': SOURCE_IP, 'gateway': '192.0.2.10'} and (proof['application_proxy'] is False) and (proof['vpn_route_excluded'] is True), 'actual_direct_wired_route')
    return proof['ip']

def redirect(location):
    try:
        u = urllib.parse.urlsplit(location)
        need(u.scheme == 'https' and u.hostname == CDN and (u.port in (None, 443)) and (not u.username) and (not u.password) and (not u.fragment) and (u.netloc in (CDN, CDN + ':443')), 'fixed_cdn_redirect')
        path = u.path + ('?' + u.query if u.query else '')
        need(path.startswith('/') and len(path) <= 16384 and path.isascii() and all((33 <= ord(c) <= 126 for c in path)), 'bounded_redirect_path')
        return path
    except Refused:
        raise
    except Exception:
        raise Refused('fixed_cdn_redirect') from None

class SocketReader(io.RawIOBase):

    def __init__(self, tls, budget, deadline):
        self.tls, self.budget, self.deadline = (tls, budget, deadline)

    def readable(self):
        return True

    def readinto(self, target):
        left = min(self.budget.left(), self.deadline - self.budget.clock())
        need(left > 0, 'request_deadline')
        self.tls.settimeout(min(8, left))
        return self.tls.recv_into(target)

class HTTPInput:

    def __init__(self, tls, budget, deadline):
        self.tls, self.budget, self.deadline = (tls, budget, deadline)
        self.reader = None

    def makefile(self, mode):
        need(mode == 'rb', 'http_reader_mode')
        self.reader = SocketReader(self.tls, self.budget, self.deadline)
        return io.BufferedReader(self.reader, CHUNK)

def openssl_hostname(cert, host, remaining, tool):
    """tool is a future source-qualified existing executable identity, not a path flag."""
    need(tool is not None and callable(tool), 'qualified_openssl_required')
    executable = tool()
    need(executable == '/usr/bin/openssl' and host == REGISTRY and (0 < remaining <= 120) and (type(cert) is bytes) and (0 < len(cert) <= 65536), 'fixed_openssl_path_certificate_deadline')
    try:
        p = subprocess.run([executable, 'x509', '-inform', 'DER', '-noout', '-checkhost', host], input=cert, capture_output=True, timeout=min(3, remaining), check=False)
    except Exception:
        raise Refused('certificate_hostname_command_failed') from None
    need(p.returncode == 0 and p.stderr == b'' and (p.stdout.strip() == ('Hostname ' + host + ' does match certificate').encode()), 'certificate_hostname_refused')

class DirectHTTP:

    def __init__(self, budget, peers, tool=None, wall=time.time, connector=None, hostname_check=None):
        self.budget, self.peers, self.tool, self.wall = (budget, peers, tool, wall)
        self.connector = connector or self._connect
        self.hostname_check = hostname_check or openssl_hostname

    def _connect(self, host, ip, deadline):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls = None
        try:
            raw.settimeout(min(8, deadline - self.budget.clock(), self.budget.left()))
            raw.bind((SOURCE_IP, 0))
            raw.connect((ip, 443))
            ctx = ssl.create_default_context()
            if host == REGISTRY:
                ctx.check_hostname = False
            need(ctx.verify_mode == ssl.CERT_REQUIRED, 'CA_required')
            tls = ctx.wrap_socket(raw, server_hostname=None if host == REGISTRY else host)
            need(tls.getpeername()[0] == ip, 'connected_peer_identity')
            if host == REGISTRY:
                self.hostname_check(tls.getpeercert(binary_form=True), host, min(deadline - self.budget.clock(), self.budget.left()), self.tool)
            return tls
        except Exception:
            close_owned(tls, raw)
            raise Refused('TLS_or_hostname_failed') from None

    def exchange(self, host, path, token, deadline):
        tls = None
        try:
            need(host in (REGISTRY, CDN) and path.startswith('/') and (len(path) <= 16384) and path.isascii() and all((33 <= ord(c) <= 126 for c in path)), 'fixed_http_target')
            need(host == REGISTRY and type(token) is Token or (host == CDN and token is None), 'origin_only_bearer')
            ip = peer_identity(self.peers(host), host, self.wall())
            deadline = min(self.budget.deadline, self.budget.clock() + 30)
            need(deadline > self.budget.clock(), 'request_deadline')
            if token is not None:
                need(token.issued_monotonic + token.lifetime - self.budget.clock() >= 45, 'token_safe_after_bounded_metadata_before_send')
            tls = self.connector(host, ip, deadline)
            auth = '' if token is None else 'Authorization: Bearer ' + token.value + '\r\n'
            request = ('GET ' + path + ' HTTP/1.1\r\nHost: ' + host + '\r\n' + auth + 'Accept: application/octet-stream\r\nConnection: close\r\n\r\n').encode()
            tls.settimeout(min(8, self.budget.left(), deadline - self.budget.clock()))
            tls.sendall(request)
            incoming = HTTPInput(tls, self.budget, deadline)
            response = http.client.HTTPResponse(incoming)
            response.begin()
            response.deadline_reader = incoming.reader
            need(sum((len(k) + len(v) for k, v in response.getheaders())) <= 65536, 'bounded_headers')
            return (response, tls)
        except Exception:
            close_owned(tls)
            raise Refused('direct_exchange_failed') from None

    def chunks(self, blob, token, request_seconds=30):
        need(request_seconds == 30, 'fixed_origin_budget')
        deadline = min(self.budget.deadline, self.budget.clock() + request_seconds)
        response = tls = None
        try:
            need(type(token) is Token and token.issued_monotonic + token.lifetime - self.budget.clock() >= request_seconds + 15, 'token_safe_before_first_send')
            response, tls = self.exchange(REGISTRY, '/v2/lmsysorg/sglang/blobs/sha256:' + blob.digest, token, deadline)
            if response.status == 307:
                locations = response.headers.get_all('Location', [])
                need(len(locations) == 1, 'one_redirect_location')
                path = redirect(locations[0])
                close_owned(response, tls)
                response, tls = self.exchange(CDN, path, None, min(self.budget.deadline, self.budget.clock() + 30))
            need(response.status == 200, 'HTTP_200_required')
            lengths = response.headers.get_all('Content-Length', [])
            need(lengths == [str(blob.size)] and (not response.headers.get_all('Transfer-Encoding')) and (response.getheader('Content-Encoding', 'identity') == 'identity'), 'exact_http_framing')
            response.deadline_reader.deadline = self.budget.deadline
            left = blob.size
            while left:
                self.budget.left()
                need(self.budget.clock() < self.budget.deadline, 'whole_body_deadline')
                data = response.read(min(left, CHUNK))
                need(data != b'', 'truncated_blob')
                left -= len(data)
                yield data
            need(response.read(1) == b'', 'unexpected_http_tail')
            self.budget.left()
        except Exception:
            raise Refused('blob_HTTP_failed') from None
        finally:
            close_owned(response, tls)
