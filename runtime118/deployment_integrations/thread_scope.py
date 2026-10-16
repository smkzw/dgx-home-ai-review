# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Close core SQLite handles on the thread that used them, after the full call."""

class RequestScopedFacade:

    def __init__(self, facade, control_store):
        self._facade = facade
        self._store = control_store

    @property
    def service_owner(self):
        return self._facade.service_owner

    @property
    def profiles(self):
        return self._facade.profiles

    def _call(self, name, **kwargs):
        try:
            return getattr(self._facade, name)(**kwargs)
        finally:
            self._store.close_thread_connection()

    def ensure_ready(self, **kwargs):
        return self._call('ensure_ready', **kwargs)

    def get_generation(self, **kwargs):
        return self._call('get_generation', **kwargs)

    def health(self, **kwargs):
        return self._call('health', **kwargs)

    def safe_drain_and_stop(self, **kwargs):
        return self._call('safe_drain_and_stop', **kwargs)

class RequestScopedReadiness:

    def __init__(self, binding, control_store):
        self._binding = binding
        self._store = control_store

    def __call__(self, profile):
        try:
            return self._binding(profile)
        finally:
            self._store.close_thread_connection()
