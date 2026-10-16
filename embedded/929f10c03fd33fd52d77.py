# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
def targets(p, approved):
    d = checked(p, approved)
    return [(Path(x['path']), p['changed_source_raw_utf8'][x['path']].encode(), x) for x in d['sources']] + [(CONFIG, p['new_config_raw_utf8'].encode(), d['config'])]
