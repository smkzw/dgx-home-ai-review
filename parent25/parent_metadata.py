# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual IO method sequence; finite metadata only, no token in durable records."""
import ipaddress, re, time
import plan
APPROVED_IO_SOURCE_SHA = '13161b573f6b49acdf9a146bc949aa73fe5b47c777aac068c58cac65226ae822'

class Responder:

    def __init__(self, io, end, clock=time.monotonic):
        plan.need(APPROVED_IO_SOURCE_SHA is not None and io.source_sha256 == APPROVED_IO_SOURCE_SHA, 'source_metadata_IO_default_None')
        self.io, self.end, self.clock = (io, end, clock)
        self.seen = set()
        self.failed = False

    def step(self):
        plan.need(not self.failed and self.clock() < self.end, 'metadata_sticky_or_original_window')
        try:
            row = self.io.next_request(plan.OPERATION, min(self.end, self.clock() + 5))
            if row is None:
                return False
            plan.need(set(row) == {'action', 'operation', 'kind', 'nonce', 'payload'} and row['action'] == 'worker-request' and (row['operation'] == plan.OPERATION) and re.fullmatch('[0-9a-f]{32}', row['nonce']) and (row['nonce'] not in self.seen), 'actual_single_inflight_metadata_nonce')
            self.seen.add(row['nonce'])
            k = row['kind']
            d = row['payload']
            if k == 'pulse':
                plan.need(d == {}, 'fixed_pulse_payload')
                a = self.io.new_grant_pulse(plan.OPERATION, row['nonce'], min(self.end, self.clock() + 5))
            elif k == 'dns':
                plan.need(set(d) == {'host'} and d['host'] in ('registry-1.docker.io', 'production.cloudfront.docker.com'), 'fixed_public_DNS_original')
                a = self.io.public_dns(d['host'], row['nonce'], min(self.end, self.clock() + 8))
                plan.need(a['query_nonce'] == a['requested_nonce'] == row['nonce'] and a['host'] == d['host'] and (a['source_kind'] == 'fresh_existing_VPS_public_DNS') and (0 < len(a['addresses']) <= 64) and all((ipaddress.ip_address(x).version == 4 and ipaddress.ip_address(x).is_global for x in a['addresses'])), 'current_DNS_nonce_source_public_IP')
            else:
                plan.need(k == 'anonymous-token' and d == {}, 'only_anonymous_public_repo_token')
                a = self.io.anonymous_repo_token('lmsysorg/sglang', 'pull', row['nonce'], min(self.end, self.clock() + 8))
                plan.need(set(a) == {'token', 'ttl_floor_seconds'} and type(a['ttl_floor_seconds']) is int and (45 < a['ttl_floor_seconds'] <= 300), 'remaining_token_floor_not_body_deadline')
            self.io.answer(plan.OPERATION, row['nonce'], a, min(self.end, self.clock() + 8))
            return True
        except BaseException:
            self.failed = True
            raise plan.Refused('metadata_failed_sticky_no_retry') from None
