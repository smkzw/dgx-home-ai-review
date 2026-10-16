# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Approved experimental first-trial policy, not measured calibration.

Standard-library pure checks shared by the source candidate's sole Manager and
root guard. Positive checks supply policy eligibility, never service readiness.
"""
import math
import re
NODES = ('spark-a', 'spark-b')
PROFILES = ('deepseek-cacheprep-ab', 'deepseek-zig-ab')
OWNER = 'dgx-hx-service'
GIB = 1 << 30
PINS = {'python': '90b68e063a0b8bba59aaf13340ef16619e751195', 'engine': '4e80f05ecba89a4e90d16375ade2eddbdc0a10c4', 'recipe': '5e90ec9302149049e8f019ea035827cb24c206f8', 'kit': '789625a7081e91643cb61ceafd15f588850c511a', 'mia': '64ba41b6c916a587db06eae2e19b7845f7be6e6b', 'engram': '2cba9e42aa026125f3ed06c6d98c1db82f7ca027', 'image': 'sha256:9b00719301e859f7b790b5c4d80ab1e49ef64bef63d3e7af2f3829cfc32cfee1'}
DISK_FREE_GUARD_BYTES = 117978000140
POLICY_ID = 'g7-first-trial-experimental-policy-r1'

class Refusal(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise Refusal(code)

def number(value, positive=False):
    need(type(value) in (int, float) and math.isfinite(value), 'finite_number_required')
    need(value > 0 if positive else value >= 0, 'positive_or_nonnegative_required')
    return value

def policy(total_bytes, cpu_count):
    """Explicit trial policy derived from source precedents, never calibration.

    OS reserve: native cuda_memory.zig max(4GiB, MemTotal/10). Initial
    admission110 and sustained14.5 come from legacy G4/G5 trial plans.
    Warning adds their current guard's 1.5GiB separation; sustained reserves
    an additional2GiB above the OS floor. Parent approved these experimental protections; peak memory remains unmeasured.
    """
    need(type(total_bytes) is int and total_bytes > 0, 'actual_MemTotal_bytes_required')
    need(type(cpu_count) is int and cpu_count >= 3, 'actual_CPU_budget_required')
    reserve = max(4 * GIB, total_bytes // 10)
    floor = max(14.5 * GIB, reserve + 2 * GIB)
    warning = floor + 1.5 * GIB
    need(total_bytes > 110 * GIB and warning < 110 * GIB, 'trial_host_capacity_insufficient')
    return {'policy_id': POLICY_ID, 'measured_calibration': False, 'initial_available_gib': 110.0, 'warning_gib': warning / GIB, 'sustained_floor_gib': floor / GIB, 'emergency_gib': reserve / GIB, 'sustained_count': 1, 'sample_interval_s': 2.0, 'max_age_s': 10.0, 'startup_grace_seconds': 600.0, 'whole_trial_deadline_s': 1800.0, 'container_cpu_limit': cpu_count - 2, 'cpu_limit_is_policy': True, 'GPU_memory_hard_cap_proven': False}

def memory_gate(samples, host_facts, now):
    """Three ordered fresh samples on both nodes; no hardware_validated mutation."""
    number(now)
    need(type(samples) is dict and set(samples) == set(NODES), 'exact_AB_samples')
    need(type(host_facts) is dict and set(host_facts) == set(NODES), 'exact_AB_host_facts')
    policies = {}
    for node in NODES:
        facts = host_facts[node]
        need(type(facts) is dict and set(facts) == {'total_bytes', 'cpu_count'}, 'fixed_host_fields')
        p = policy(**facts)
        seq = samples[node]
        need(type(seq) is list and len(seq) == 3, 'exact_three_samples')
        previous = -1
        for sample in seq:
            need(type(sample) is dict and set(sample) == {'timestamp', 'available_gib', 'reachable'}, 'fixed_sample_fields')
            stamp = number(sample['timestamp'])
            free = number(sample['available_gib'])
            need(sample['reachable'] is True and previous < stamp <= now and (now - stamp <= p['max_age_s']), 'fresh_ordered_reachable_required')
            need(free * GIB <= facts['total_bytes'], 'available_exceeds_total')
            need(free >= p['initial_available_gib'], 'trial_memory_policy_refused')
            previous = stamp
        policies[node] = p
    return policies

def request(body, trusted_run):
    """Client requests have no profile/path/threshold/permission fields."""
    need(type(body) is dict and set(body) == {'action', 'run_id', 'key'}, 'exact_request_fields')
    need(type(body['action']) is str and body['action'] in ('start_qualification', 'status', 'stop'), 'fixed_actions')
    for field in ('run_id', 'key'):
        need(type(body[field]) is str and re.fullmatch('[0-9a-f]{32}', body[field]), 'fixed_run_or_key')
    need(body['run_id'] == trusted_run, 'trusted_run_mismatch')
    return dict(body)

def held(identity, current):
    """CAS prerequisite; future Store must repeat inside its transaction."""
    need(type(identity) is dict and set(identity) == {'profile', 'owner', 'generation'}, 'fixed_identity')
    need(identity['profile'] in PROFILES and identity['owner'] == OWNER, 'fixed_profile_and_owner')
    need(type(identity['generation']) is int and identity['generation'] > 0, 'positive_integer_generation')
    need(type(current) is dict and set(current) == {'profile', 'owner', 'generation', 'holds'}, 'fixed_current_fields')
    need(all((current[k] == v and type(current[k]) is type(v) for k, v in identity.items())), 'stale_or_foreign_identity')
    holds = current['holds']
    need(type(holds) is dict and set(holds) == set(NODES), 'exact_AB_holds')
    for h in holds.values():
        need(type(h) is dict and set(h) == set(identity), 'fixed_node_hold_fields')
        need(all((h[k] == v and type(h[k]) is type(v) for k, v in identity.items())), 'node_hold_changed')
    return True

def watchdog(sample, p, *, elapsed, startup_elapsed, gpu_processes_empty):
    """Evaluate memory even during ARMING; never assumes no GPU PID means safe.

    Caller/root guard must first prove exact container identity and fresh complete
    evidence using existing node fence + inspect/top checks. No action runs here.
    """
    number(elapsed)
    number(startup_elapsed)
    need(type(gpu_processes_empty) is bool, 'actual_gpu_enumeration_required')
    free = number(sample['available_gib'])
    if sample.get('fresh_identity_proven') is not True:
        return 'QUARANTINE_HOLD_RETAINED'
    if elapsed >= p['whole_trial_deadline_s']:
        return 'FENCED_STOP_TRIAL_DEADLINE'
    if free < p['emergency_gib']:
        return 'FENCED_STOP_EMERGENCY'
    if free < p['sustained_floor_gib']:
        return 'FENCED_STOP_LOW_MEMORY'
    if gpu_processes_empty and startup_elapsed >= p['startup_grace_seconds']:
        return 'FENCED_STOP_STARTUP_DEADLINE'
    return 'WARNING_HOLD_RETAINED' if free < p['warning_gib'] else 'OBSERVE_HOLD_RETAINED'

def public_trial_status(phase):
    need(phase in {'PENDING', 'STARTING', 'RUNNING', 'FAILED', 'STOPPED_HELD', 'RELEASED'}, 'explicit_trial_phase')
    return {'qualification': 'qualification_pending', 'trial_phase': phase, 'hardware_validated': False, 'serving_enabled': False, 'ready': False, 'calibration_published': False, 'GPU_lifecycle_permission': False}
