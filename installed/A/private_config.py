# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact 2.2.5 merged-dump validation; no effects or runtime boolean waiver."""
import base64, copy, hashlib, json, math, tomllib
from pathlib import Path
ROOT = '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14'
COMMIT = 'e53c7c1516c3b2bff98eb76f1f4117477e6f4e66'
BINARY_SHA = '95619dc645d8bf6c9b26ad881d62bbe17ed03004588a095bac0aba232e3555ce'
VERSION_RAW = b'containerd containerd.io v2.2.5 ' + COMMIT.encode() + b'\n'
IMPORT_DISPLAY = ['/etc/containerd/conf.d/*.toml']
SOURCE_CONFIG_SHA = '4f8b0b01667882c7b5086340c1b7112cad29fa5d763978adf9a7cc3e9d1dd5e7'
DECODERS = ('io.containerd.ocicrypt.decoder.v1.tar', 'io.containerd.ocicrypt.decoder.v1.tar.gzip')
DISABLED = ('io.containerd.grpc.v1.cri', 'io.containerd.cri.v1.images', 'io.containerd.cri.v1.runtime', 'io.containerd.snapshotter.v1.btrfs', 'io.containerd.snapshotter.v1.devmapper', 'io.containerd.snapshotter.v1.zfs', 'io.containerd.nri.v1.nri', 'io.containerd.image-verifier.v1.bindir', 'io.containerd.differ.v1.erofs', 'io.containerd.mount-handler.v1.erofs', 'io.containerd.snapshotter.v1.blockfile', 'io.containerd.snapshotter.v1.erofs', 'io.containerd.snapshotter.v1.native', 'io.containerd.monitor.container.v1.restart', 'io.containerd.internal.v1.tracing', 'io.containerd.tracing.processor.v1.otlp', 'io.containerd.transfer.v1.local')

class Refused(ValueError):
    pass

def need(v, why):
    if not v:
        raise Refused(why)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def config_bytes(root):
    need(root == ROOT, 'fixed_private_root_only')
    q = json.dumps
    s = 'version = 3\nroot = ' + q(root + '/containerd-data') + '\nstate = ' + q(root + '/containerd-exec') + '\ntemp = ' + q(root + '/tmp') + '\nimports = []\ndisabled_plugins = ' + json.dumps(list(DISABLED)) + '\nrequired_plugins = []\n'
    s += '[grpc]\naddress = ' + q(root + '/containerd.sock') + '\nuid = 0\ngid = 0\ntcp_address = ""\n[ttrpc]\naddress = ' + q(root + '/containerd.sock.ttrpc') + '\nuid = 0\ngid = 0\n[debug]\naddress = ""\n[metrics]\naddress = ""\n'
    s += '[plugins."io.containerd.internal.v1.opt"]\npath = ' + q(root + '/private-opt') + '\n[plugins."io.containerd.snapshotter.v1.overlayfs"]\nroot_path = ' + q(root + '/private-overlay') + '\n'
    for name in DECODERS:
        s += '[stream_processors.' + q(name) + ']\naccepts = []\nreturns = ""\npath = ""\nargs = []\nenv = []\n'
    return s.encode()

def equal(actual, expected, path='root'):
    need(type(actual) is type(expected), 'type:' + path)
    if isinstance(expected, dict):
        need(set(actual) == set(expected), 'unknown_or_missing_field:' + path)
        for key in expected:
            equal(actual[key], expected[key], path + '.' + key)
    elif isinstance(expected, list):
        need(len(actual) == len(expected), 'list:' + path)
        for i, x in enumerate(expected):
            equal(actual[i], x, path + '.' + str(i))
    else:
        need((not isinstance(actual, float) or math.isfinite(actual)) and actual == expected, 'value:' + path)

def expected():
    import namespace
    need(namespace.ROOT == ROOT, 'same_exact_private_namespace')
    return namespace.expected(Path(__file__).with_name('EXPECTED_DUMP.json').read_bytes(), ROOT)

def validate(raw, dump, root=ROOT, binary_sha=BINARY_SHA, version_raw=VERSION_RAW):
    need(binary_sha == BINARY_SHA and version_raw == VERSION_RAW, 'exact_existing_containerd225_no_substitution')
    need(len(raw) <= 65536 and len(dump) <= 262144, 'bounded_config_dump')
    need(raw == config_bytes(root), 'exact_private_raw_config')
    v = tomllib.loads(raw.decode())
    need(v['imports'] == [], 'no_effective_raw_imports')
    merged = tomllib.loads(dump.decode())
    equal(merged, expected())
    need(merged['imports'] == IMPORT_DISPLAY, 'only_exact_unavoidable_display_item')
    return {'raw_sha256': sha(raw), 'dump_sha256': sha(dump), 'raw_effective_imports': [], 'display_imports': IMPORT_DISPLAY, 'display_is_not_effective_source_config_sha256': SOURCE_CONFIG_SHA, 'disabled_plugins': list(DISABLED), 'merged_config_plugin_URIs': sorted(merged['plugins']), 'ocicrypt_handlers': 'two whole-entry inert tombstones; accepts/path/args/env empty', 'actual_daemon_or_syscall_effect_accepted': False}

def environment(env):
    need(env.get('CONTAINERD_DISABLE_PIGZ') == 'true' and env.get('CONTAINERD_DISABLE_IGZIP') == 'true', 'disable_upstream_external_gzip_helpers')
    allowed = {'PATH', 'LANG', 'HOME', 'DOCKER_CONFIG', 'DOCKER_TMPDIR', 'MOBY_DISABLE_PIGZ', 'CONTAINERD_DISABLE_PIGZ', 'CONTAINERD_DISABLE_IGZIP'}
    need(set(env) <= allowed, 'no_inherited_plugin_decoder_loader_env')
    need(env.get('PATH') == '/usr/bin:/usr/sbin:/bin' and env.get('HOME') == ROOT + '/home', 'fixed_clean_command_environment')
    return {'upstream_supported_gzip_disable_env': True, 'inherited_host_env': False}

def parent_proof(v, now):
    need(set(v) == {'raw_b64', 'dump_b64', 'raw_sha256', 'dump_sha256', 'binary_sha256', 'version_stdout_b64', 'observed_at'}, 'complete_actual_config_parse_proof')
    need(0 <= now - v['observed_at'] <= 300, 'fresh_actual_config_parse_stamp')
    raw = base64.b64decode(v['raw_b64'], validate=True)
    dump = base64.b64decode(v['dump_b64'], validate=True)
    version = base64.b64decode(v['version_stdout_b64'], validate=True)
    need(sha(raw) == v['raw_sha256'] and sha(dump) == v['dump_sha256'], 'actual_raw_and_dump_SHA')
    return validate(raw, dump, binary_sha=v['binary_sha256'], version_raw=version)
if __name__ == '__main__':
    print(json.dumps({'status': 'SOURCE_INERT', 'native': 0, 'actual_effect': False}))
