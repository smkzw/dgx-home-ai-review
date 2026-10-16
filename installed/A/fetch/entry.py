# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Source candidate only. No grant/daemon/credential integration is installed."""
from contract import Refused
CONTEXT = None

def run(context=CONTEXT):
    raise Refused('native_context_unimplemented_harddeny')
if __name__ == '__main__':
    run()
