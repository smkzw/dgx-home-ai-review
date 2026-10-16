# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same runtime; sampler must terminate before original watchdog/store teardown."""
from G7_INTEGRATION_CANDIDATE_R3.runtime import QualificationRuntime

class TelemetryRuntime(QualificationRuntime):

    def close(self):
        if self._closed:
            return
        sampler = getattr(self, 'telemetry', None)
        if sampler is not None:
            sampler.close()
        super().close()
