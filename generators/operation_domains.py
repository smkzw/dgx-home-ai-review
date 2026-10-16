# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit R15 epoch vs same-family asset slots, no global rename."""
from source_io import need, sha

def one(text, old, new, code):
    need(text.count(old) == 1, code)
    return text.replace(old, new, 1)

def recovery(raw):
    s = raw.decode()
    s = one(s, 'from contract import *\n', 'from contract import *\n# Source activation is per epoch; business asset lineage stays OPERATION.\nOPERATION=EPOCH_OPERATION\n', 'R15_one_recovery_epoch_import')
    return s.encode()

def grant(raw):
    s = raw.decode()
    s = one(s, 'from contract import OPERATION,PC_ROOT', 'from contract import OPERATION,EPOCH_OPERATION,PC_ROOT', 'R15_one_grant_domain_import')
    s = one(s, "and body['action'] in ACTIONS and body['operation'] == OPERATION", "and body['action'] in ACTIONS and body['operation'] == (EPOCH_OPERATION if body['action']=='activate-registry-source' else OPERATION)", 'R15_one_private_activation_epoch_domain')
    return s.encode()

def late_context(raw):
    s = raw.decode()
    s = one(s, 'from contract import PC_ROOT,OPERATION,APPROVED_REVIEW', 'from contract import PC_ROOT,OPERATION,EPOCH_OPERATION,APPROVED_REVIEW', 'R15_one_late_domain_import')
    s = one(s, "a['source_epoch']==OPERATION", "a['source_epoch']==EPOCH_OPERATION", 'R15_A_origin_epoch_not_assetfamily')
    need(s.count("p['operation']==OPERATION") == 2, 'R15_two_packet_epoch_references')
    s = s.replace("p['operation']==OPERATION", "p['operation']==EPOCH_OPERATION and p['grant_operation']==OPERATION")
    return s.encode()

def rpc(raw):
    s = raw.decode()
    s = one(s, "body={'action':action,'operation':plan.OPERATION,'request_nonce':nonce}", "body={'action':action,'operation':(plan.EPOCH_OPERATION if action=='activate-registry-source' else plan.OPERATION),'request_nonce':nonce}", 'R15_one_Rootpeer_activation_epoch_body')
    s = one(s, "p['operation']==plan.OPERATION and p['action'] in ACTIONS", "p['operation']==(plan.EPOCH_OPERATION if p['action']=='activate-registry-source' else plan.OPERATION) and p['action'] in ACTIONS", 'R15_one_Root_envelope_activation_epoch')
    return s.encode()

def audit(before, after):
    import ast

    def defs(raw):
        return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(raw).body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    a, b = (defs(before), defs(after))
    need(set(a) == set(b), 'R15_domain_definitions_preserved')
    return {'preimage_sha256': sha(before), 'sha256': sha(after), 'changed_definitions': [n for n in a if a[n] != b[n]]}
