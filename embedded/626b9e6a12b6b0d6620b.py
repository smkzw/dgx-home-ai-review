# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def payload(p, path, approved):
    d = checked(p, approved)
    name = str(path)
    need(name == str(CONFIG) or name in {x['path'] for x in d['sources']}, 'exact_approved_payload_target')
    return p['new_config_raw_utf8'].encode() if name == str(CONFIG) else p['changed_source_raw_utf8'][name].encode()

def targets(p, approved):
    d = checked(p, approved)
    return [(Path(x['path']), payload(p, x['path'], approved), x) for x in d['sources'] + [d['config']]]
