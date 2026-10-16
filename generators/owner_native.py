# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One existing readonly Rootpeer status; no new action, work, or permission."""
import ast
from source_io import need
METHOD = None

def owner_native(s):
    tree = ast.parse(s)
    c = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'RootNative'))
    need(not any((isinstance(n, ast.FunctionDef) and n.name == 'current_failed_owner_status' for n in c.body)), 'R16_new_readonly_method_once')
    lines = s.splitlines(True)
    lines[c.end_lineno:c.end_lineno] = ['\n' + METHOD + '\n']
    out = ''.join(lines)
    compile(out, 'R16_RootNative', 'exec')
    return out
