# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Use the existing single service Manager/lease; never create a second owner.

Methods are parent-maintenance integration seams, absent from public gateway/MCP.
No automatic retries, SQL READY, direct Docker or release on failure.
"""
import os
from pathlib import Path
from control_plane.manager import Manager
from hx_service.service import MaintenanceLease, MAINTENANCE_LOCK_PATH, ServiceRuntime
from .adapter import IntegrationNodeAdapter
from .compiler import PREP, NODES

class Refusal(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise Refusal(why)

class CachePreparation:

    def __init__(self, runtime, lease, binding):
        self.runtime = runtime
        self.lease = lease
        self.binding = binding
        self.generation = None
        self.attempted = False
        self._guard()

    def _guard(self):
        b = self.binding
        need(isinstance(self.runtime, ServiceRuntime) and isinstance(self.runtime.manager, Manager), 'existing_single_service_Manager_required')
        need(isinstance(self.runtime.adapter, IntegrationNodeAdapter) and self.runtime.manager.adapter is self.runtime.adapter, 'exact_integrated_adapter_required')
        need(isinstance(self.lease, MaintenanceLease) and self.lease.held and (self.lease.path == MAINTENANCE_LOCK_PATH), 'original_held_MaintenanceLease_required')
        need(b.get('parent_accepted') is True and type(b.get('manager_pid')) is int and (b['manager_pid'] == os.getpid()), 'parent_actual_manager_binding_required')
        f = os.fstat(self.lease._fd)
        s = Path(self.lease.path).stat()
        need((f.st_dev, f.st_ino) == (s.st_dev, s.st_ino) == tuple(b.get('lock_dev_inode', ())), 'same_physical_lease_required')
        for k in ('source_inputs_verified', 'immutable_environment_license_verified', 'fresh_RDMA_GID3_verified', 'fresh_disk_budget_verified', 'prep_memory_calibrated', 'validated_RO_token_map_verified'):
            need(b.get(k) is True, 'pending_' + k)
        need(b.get('owner') == 'dgx-hx-service', 'same_service_owner_required')

    def start(self, *, samples, now):
        self._guard()
        need(not self.attempted, 'no_blind_replay')
        self.attempted = True
        reply = self.runtime.manager.start_profile(PREP, owner=self.binding['owner'], operation='maintenance', samples=samples, now=now)
        if 'generation' in reply and (reply.get('started') or reply.get('pending') or (not reply.get('queued'))):
            self.generation = reply['generation']
        return {'lifecycle': reply, 'cache_accepted': False}

    def _current_generation(self):
        need(type(self.generation) is int and self.generation > 0, 'recorded_generation_required')
        v = self.runtime.manager.store.profile_view(PREP)
        need(v['owner'] == self.binding['owner'] and v['generation'] == self.generation and self.runtime.manager.store.still_owned(PREP, owner=self.binding['owner'], generation=self.generation), 'current_exact_owner_generation_holds_required')

    def poll(self):
        self._guard()
        self._current_generation()
        return {'lifecycle': self.runtime.manager.complete_readiness(PREP, owner=self.binding['owner'], from_states={'STARTING'}, expected_model_id='DeepSeek-V4.1-Flash-TF-CachePrep', enforce_pending_deadline=True), 'cache_accepted': False}

    def stop(self):
        self._guard()
        self._current_generation()
        return self.runtime.manager.stop_profile(PREP, owner=self.binding['owner'], expected_generation=self.generation)

    def release(self):
        self._guard()
        self._current_generation()
        return self.runtime.manager.release_profile(PREP, owner=self.binding['owner'], generation=self.generation)

def attach_preparation(runtime, lease, binding):
    """Explicit in-process seam on the already constructed sole service runtime.

    Returns a coordinator without executing anything or exposing a gateway/admin
    route. A future reviewed composition hook supplies its existing lease;
    out-of-process users cannot create a second Manager or acquire this lease.
    """
    return CachePreparation(runtime, lease, binding)
