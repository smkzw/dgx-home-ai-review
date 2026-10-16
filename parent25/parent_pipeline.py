# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite actual method sequence, SOURCE-inert entry; never blind retry."""
import base64, time
from pathlib import Path
import plan
from root_io import fresh, sha
from observer import positive
import budget_contract, safe_error
APPROVED_PIPELINE = {'entry_worker_sha256': '5b51f3bc679363e2317cad3ef6402fad45744db74664accf8129bd4edff99fb3', 'worker_sha256': 'c31ec3088783e274c8d4a12a5234d702a5058e2a2ff315c4c7d292ebfff9a05c', 'source_review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}

class Pipeline:

    def __init__(self, io, work, context, clock=time.monotonic, sleep=time.sleep):
        plan.need(APPROVED_PIPELINE is not None, 'parent_pipeline_default_None')
        self.io, self.work, self.c, self.clock, self.sleep = (io, Path(work), context, clock, sleep)
        self.end = min(io.end, clock() + min(1800, context['remaining_seconds']))
        self.ordinal = 0

    def archive(self, tag, value):
        fresh(self.work / (tag + '.json'), plan.encode(value))

    def rpc(self, node, action, payload, seconds=8):
        self.io.guard_window()
        plan.need(self.clock() < self.end, 'parent_whole_grant_deadline')
        self.ordinal += 1
        self.archive(str(self.ordinal) + '-' + action + '-intent', {'operation': plan.OPERATION, 'action': action, 'node': node, 'observed_at': time.time(), 'automatic_retry': False})
        v = self.io.rpc(node, action, payload, min(self.end, self.clock() + seconds))
        if action not in ('fetch-answer', 'fetch-next'):
            self.archive(str(self.ordinal) + '-' + action + '-original', v)
        return v

    def entry(self):
        limit = min(self.end, self.clock() + 90)
        begun = self.rpc('pc', 'begin-entry-clock', {}, 90)
        self.rpc('a', 'entry-clock-start', {'request_raw_b64': begun['request_raw_b64'], 'request_sha256': begun['request_sha256']}, min(10, limit - self.clock()))
        while self.clock() < limit:
            v = self.rpc('a', 'entry-observe', {}, min(8, limit - self.clock()))
            if v.get('pending') is True:
                self.sleep(0.2)
                continue
            positive(v, plan.ENTRY_UNIT, APPROVED_PIPELINE['entry_worker_sha256'], True)
            break
        else:
            raise plan.Refused('new_entry_scope_terminal_timeout_no_retry')
        result = self.rpc('a', 'entry-finalize-stop', {}, min(40, limit - self.clock()))
        self.rpc('pc', 'publish-entry-clock', result, min(90, limit - self.clock()))
        return result

    def require_activated_source(self):
        original = self.rpc('pc', 'status-registry-source', {})
        raw = base64.b64decode(original['original_reply_raw_b64'], validate=True)
        plan.need(sha(raw) == original['original_reply_sha256'], 'current_status_full_original_SHA')
        reply = plan.strict(raw)
        value = reply['result']
        plan.need(reply['ok'] is True and value['schema'] == 'registry-R26-source-current-status/v1' and (value['operation'] == plan.OPERATION) and (value['source118'] == self.c['current_PC_source118']) and (value['manager_pid'] == self.c['manager_identity']['pid']), 'actual_same_new_epoch_status')
        proof = value['current']
        plan.need(proof['scheduler']['operator_maintenance'] is False and all((p['state'] == 'STOPPED' and p['owner'] is None for p in proof['Core_profiles'].values())), 'ordinary_API_already_activated_not_replayed')
        plan.need(original['PC_sent_at'] <= value['observed_at'] <= original['PC_received_at'] and 0 <= original['PC_monotonic_elapsed'] <= 90, 'actual_status_clock_no_refresh')
        return original

    def run(self):
        plan.need(not self.work.exists(), 'new_parent_once_NAMESPACE')
        self.work.mkdir(mode=448)
        self.archive('once', {'operation': plan.OPERATION, 'source_review_sha256': APPROVED_PIPELINE['source_review_sha256'], 'observed_at': time.time(), 'old_bf84_replayed': False})
        try:
            entry = self.io.bind_entry(self.c, min(self.end, self.clock() + 12))
            self.archive('entry-context-origin', entry)
            self.require_activated_source()
            self.entry()
            duration = budget_contract.reserve_budget(self.end - self.clock())
            self.rpc('pc', 'reserve-registry-directfetch', {'duration_seconds': duration}, 90)
            initial = self.rpc('pc', 'pulse-registry-directfetch', {})
            bound = self.io.bind_context(self.c, initial, self.end)
            self.archive('A-context-bound-origin', bound)
            self.rpc('a', 'fetch-start', {}, 10)
            while self.clock() < self.end:
                terminal = self.rpc('a', 'fetch-observe', {})
                if terminal.get('pending') is not True:
                    positive(terminal, plan.UNIT, APPROVED_PIPELINE['worker_sha256'])
                    break
                self.io.metadata_step(min(self.end, self.clock() + 8))
                self.sleep(0.1)
            else:
                raise plan.Refused('actual_owned_fetch_whole_deadline_unknown_no_retry')
            qualified = self.rpc('a', 'fetch-finalize-stop', {}, 40)
            self.rpc('pc', 'publish-terminal', qualified)
            final = self.rpc('pc', 'finish-registry-directfetch', {})
            self.archive('technical-barrier-completed', {'operation': plan.OPERATION, 'terminal_qualified_original': qualified, 'same_Runtime_finish_original': final, 'image_content_import_only': True, 'hardware_validated': False, 'model_ready': False, 'observed_at': time.time()})
            return final
        except BaseException as e:
            try:
                q = self.io.cleanup_rpc('a', 'fetch-failed-qualify', {}, self.clock() + 30)
                self.archive('failed-terminal-original', q)
                self.io.cleanup_rpc('pc', 'publish-failed-terminal', q, self.clock() + 30)
                released = self.io.cleanup_rpc('pc', 'finish-failed-registry', {}, self.clock() + 30)
                self.archive('failed-quiescent-release-original', released)
            except BaseException as cleanup_error:
                self.archive('failed-terminal-unresolved', safe_error.original_safe_error('finish-failed-registry', cleanup_error))
            self.archive('failed', {'operation': plan.OPERATION, 'reason_code': 'parent_registry_chain_failed', 'source_reason_code': str(e) if type(e).__name__ == 'Refused' and str(e) in safe_error.CODES else 'parent_registry_chain_failed', 'error_type': type(e).__name__, 'partial_preserved': True, 'automatic_retry': False, 'PC_hold_release_not_inferred': True, 'observed_at': time.time()})
            raise plan.Refused('parent_registry_chain_failed') from None

def main():
    raise plan.Refused('native_parent_context_None_no_autostart')
if __name__ == '__main__':
    main()
