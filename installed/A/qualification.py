# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Strict new grant/source/clock producer ABI; no boolean authority."""
import base64, math, re
import plan
import point_clock
from root_io import sha
PULSE_KEYS = {'schema', 'operation', 'source_release_sha256', 'config_sha256', 'ordinal', 'request_nonce', 'manager_epoch_sha256', 'budget', 'remaining_seconds', 'manager_source', 'clear_reservation_original', 'clear_reservation_sha256', 'observed_at'}

def pulse(frame, c, now):
    raw = base64.b64decode(frame['original_raw_b64'], validate=True)
    plan.need(sha(raw) == frame['original_sha256'], 'original_PC_pulse_raw_SHA')
    p = plan.strict(raw)
    plan.need(set(p) == PULSE_KEYS and p['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and (p['operation'] == plan.OPERATION) and (p['source_release_sha256'] == c['source_release_sha256']), 'original_new1800_grant_not_bf84')
    plan.need(p['config_sha256'] == c['PC_config_sha256'] and p['manager_epoch_sha256'] == sha(plan.encode(c['current_PC_source118'])), 'pulse_current_source_config_cross_binding')
    expected = c['pulse_identity']
    plan.need(all((p[k] == expected[k] for k in ('config_sha256', 'manager_epoch_sha256', 'manager_source', 'clear_reservation_original', 'clear_reservation_sha256'))), 'same_current_qualified_sole_owner_lease_source')
    plan.need(set(p['budget']) == {'CPU', 'memory_bytes', 'swap_bytes', 'tasks', 'io_read_bytes_per_second', 'io_write_bytes_per_second', 'runtime_seconds'} and {k: v for k, v in p['budget'].items() if k != 'runtime_seconds'} == {'CPU': 1, 'memory_bytes': 4294967296, 'swap_bytes': 0, 'tasks': 256, 'io_read_bytes_per_second': 62914560, 'io_write_bytes_per_second': 62914560} and (type(p['budget']['runtime_seconds']) is int) and (0 < p['budget']['runtime_seconds'] <= 1800), 'bounded_parent_window_grant_budget')
    plan.need(frame['operation'] == plan.OPERATION and frame['PC_sent_at'] <= p['observed_at'] <= frame['PC_received_at'] and (0 <= frame['PC_monotonic_elapsed'] <= 5), 'true_PC_clock_original_not_restamped')
    plan.need(frame['A_received_at'] <= now <= frame['A_received_at'] + 5 and type(p['remaining_seconds']) in (int, float) and math.isfinite(p['remaining_seconds']) and (0 < p['remaining_seconds'] <= 1800), 'fresh_A_receipt_of_original_pulse')
    plan.need(0 <= now - c['A_minus_PC_clock_lower'] - p['observed_at'] <= 10, 'actual_conservative_PC_pulse_age')
    remaining = p['remaining_seconds'] - frame['PC_monotonic_elapsed'] - 12
    plan.need(remaining > 0, 'transport_decremented_grant_remainder')
    return (p, remaining)

def parent_preflight(v, c):
    plan.need(v['schema'] == 'registry-R26-A-fresh-source-and-grant/v1' and v['operation'] == plan.OPERATION and (v['source_release_sha256'] == c['source_release_sha256']), 'actual_current_parent_proof_typed')
    plan.need(v['manager_identity'] == c['manager_identity'] and v['current_PC_source118'] == c['current_PC_source118'] and (len(v['current_PC_source118']) == 118) and (v['PC_config_sha256'] == c['PC_config_sha256']), 'new_source_epoch_not_old_negative')
    plan.need(v['current_epoch_raw_sha256'] == c['current_epoch_raw_sha256'] and v['historical_ancestor_sha256'] == c['historical_ancestor_sha256'], 'full_independent_current_and_historical_qualifications')
    plan.context_nvme(c)
    plan.need(v['NVMe_identity'] == c['NVMe_identity'], 'same_original_dual_NVMe_identity_grant_context')
    clock = v['clock_original']
    if type(clock) is dict and clock.get('schema') == point_clock.SCHEMA:
        lower, upper = point_clock.consume(clock, c)
        plan.need(point_clock.strict(point_clock.raw(clock['A_before_original']))['nonce'] == v['request_nonce'], 'point_clock_parent_original_request_nonce')
    else:
        clock = v['clock_original']
        plan.need(set(clock) == {'A_sent_at', 'A_received_at', 'PC_sent_at', 'PC_received_at', 'elapsed_monotonic', 'nonce'} and clock['nonce'] == v['request_nonce'] and (0 <= clock['elapsed_monotonic'] <= 5) and (clock['A_received_at'] - clock['A_sent_at'] <= 5) and (clock['PC_received_at'] >= clock['PC_sent_at']), 'true_bounded_A_PC_clock_exchange')
        lower = clock['A_sent_at'] - clock['PC_received_at']
        upper = clock['A_received_at'] - clock['PC_sent_at']
        plan.need(lower <= upper and upper - lower <= 5 and (c['A_minus_PC_clock_lower'] == lower) and (c['A_minus_PC_clock_upper'] == upper), 'actual_clock_interval_not_self_boolean')
    plan.need(lower <= upper and upper - lower <= 5 and (c['A_minus_PC_clock_lower'] == lower) and (c['A_minus_PC_clock_upper'] == upper), 'actual_clock_interval_not_self_boolean')
    p, left = pulse(c['initial_pulse_original'], c, c['initial_pulse_original']['A_received_at'])
    plan.need(0 < c['remaining_seconds'] <= left and c['whole_seconds'] == 1800, 'original_grant_not_reset_after_transport')
    plan.need(v['fresh_wholeidle_original_sha256'] == p['clear_reservation_sha256'] and v['A_route'] == {'source': '192.0.2.10', 'interface': 'enP7s7', 'gateway': '192.0.2.10', 'application_proxy': False} and (v['A_boot_id'] == c['A_boot_id']), 'actual_PC_reservation_and_A_direct_route')
    plan.need(v['scope_namespace_absent'] is True and v['NVMe_free_bytes'] >= plan.WORKSPACE + plan.RESERVE and (v['MemAvailable_bytes'] >= 8 * 1024 ** 3) and (c['initial_free_bytes'] == v['NVMe_free_bytes']), 'actual_A_resources_no_fake_GPUclaim')
    plan.need(v['observed_at'] == c['parent_proof_observed_at'], 'keep_real_parent_timestamp')
    return v
