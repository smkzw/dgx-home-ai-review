# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One indexed naming source shared by PC request and A runtime configuration."""
import re
FAMILY = 'role-context-r14'
PREFIX = 'dgx-v4-mimo-registry-a-entry-' + FAMILY + '-'

def unit(nonce):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('stage_readiness_nonce_exact')
    return PREFIX + nonce + '.service'
