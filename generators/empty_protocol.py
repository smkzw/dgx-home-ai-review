# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One explicit failed-empty variant of the existing protected scope/PC clock.
No historical bytes or old protocol schemas are changed. All transforms are
restricted to known complete source definitions or exact literal slots.
"""
from source_io import base, sha, need, HERE
MODE = 'failed-empty-range-repair'

def seal(raw):
    s = one(raw.decode(), "parent.name in('zero-readonly','current-prebind-readonly')", "parent.name in('zero-readonly','current-prebind-readonly','asset-empty-repairs')")
    s = one(s, "ctx.spec['mode']=='current-stage-prebind' and packed is None", "ctx.spec['mode']in('current-stage-prebind','failed-empty-range-repair') and packed is None")
    compile(s, 'R13_closed_readonly_sealer', 'exec')
    return s.encode()

def one(text, old, new):
    need(text.count(old) == 1, 'empty_repair_source_slot_once:' + old[:65])
    return text.replace(old, new, 1)

def templates():
    out = {'current_negative': (HERE.parent / 'empty_repair_negative.py').read_bytes()}
    for n in ('current_clock', 'current_scope', 'current_qualified'):
        s = base('CURRENT/' + n + '.py').decode()
        for old, new in (('stage-not-launched-PC-BEGIN/v1', 'failed-empty-range-PC-BEGIN/v1'), ('stage-not-launched-PC-finish/v1', 'failed-empty-range-PC-finish/v1'), ('stage-not-launched-PC-qualified/v1', 'failed-empty-range-PC-qualified/v1'), ('current-zero-launch-readonly-scope/v1', 'failed-empty-range-readonly-scope/v1')):
            s = s.replace(repr(old), repr(new))
        out[n] = s.encode()
        compile(out[n], 'R13_' + n, 'exec')
    return out

def renderer(raw):
    s = raw.decode()
    s = one(s, "APPROVED_MODE in('historical-fixed','current-stage-prebind')", "APPROVED_MODE in('historical-fixed','current-stage-prebind','failed-empty-range-repair')")
    s = s.replace("APPROVED_MODE=='current-stage-prebind'", "APPROVED_MODE in('current-stage-prebind','failed-empty-range-repair')")
    s = one(s, "label='asset-zero-readonly'if historical else'asset-current-prebind-readonly'", "label='asset-zero-readonly'if historical else'asset-empty-repair-readonly'if APPROVED_MODE=='failed-empty-range-repair'else'asset-current-prebind-readonly'")
    old = "PC_ROOT+('/zero-readonly/'+nonce if historical else'/current-prebind-readonly/'+strict(APPROVED_ACTOR_RAW)['stage_operation'])"
    new = "PC_ROOT+('/zero-readonly/'+nonce if historical else('/asset-empty-repairs/'if APPROVED_MODE=='failed-empty-range-repair'else'/current-prebind-readonly/')+strict(APPROVED_ACTOR_RAW)['stage_operation'])"
    s = one(s, old, new)
    s = one(s, "'schema':'current-stage-prebind-request/v1'", "'schema':'failed-empty-range-repair-request/v1'if APPROVED_MODE=='failed-empty-range-repair'else'current-stage-prebind-request/v1'")
    s = one(s, "'ROOT':root,'OPERATION':APPROVED_OPERATION}", "'ROOT':A if APPROVED_MODE=='failed-empty-range-repair'else root,'OPERATION':APPROVED_OPERATION}")
    compile(s, 'R13_one_shared_scope_renderer', 'exec')
    return s.encode()

def runtime(raw):
    s = raw.decode()
    s = one(s, "'current-stage-prebind':('current_negative','current_scope','current_clock','current_qualified')", "'current-stage-prebind':('current_negative','current_scope','current_clock','current_qualified'),'failed-empty-range-repair':('current_negative','current_scope','current_clock','current_qualified')")
    s = one(s, "ctx.spec['mode']=='current-stage-prebind'", "ctx.spec['mode']in('current-stage-prebind','failed-empty-range-repair')")
    s = one(s, "a['schema']=='stage-not-launched-PC-BEGIN/v1'", "a['schema']==('failed-empty-range-PC-BEGIN/v1'if ctx.spec['mode']=='failed-empty-range-repair'else'stage-not-launched-PC-BEGIN/v1')")
    s = one(s, "'schema':'stage-not-launched-PC-qualified/v1'", "'schema':'failed-empty-range-PC-qualified/v1'if ctx.spec['mode']=='failed-empty-range-repair'else'stage-not-launched-PC-qualified/v1'")
    s = one(s, "ctx.root/'not-launched-qualified.json'", "ctx.root/('qualified.json'if ctx.spec['mode']=='failed-empty-range-repair'else'not-launched-qualified.json')")
    compile(s, 'R13_shared_readonly_runtime', 'exec')
    return s.encode()

def loader(raw):
    s = one(raw.decode(), "spec['mode']in('historical-fixed','current-stage-prebind')", "spec['mode']in('historical-fixed','current-stage-prebind','failed-empty-range-repair')")
    compile(s, 'R13_closed_readonly_loader', 'exec')
    return s.encode()
