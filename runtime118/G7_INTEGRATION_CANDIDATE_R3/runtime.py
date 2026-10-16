# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Same original runtime with watchdog shutdown before store/lease teardown."""
from hx_service.service import ServiceRuntime

class QualificationRuntime(ServiceRuntime):

    def close(self):
        if self._closed:
            return
        self.manager.shutdown_qualification()
        super().close()
