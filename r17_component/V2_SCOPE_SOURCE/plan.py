# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed new namespace; no grant or native operation is created by these vectors."""
import re
import json
from pathlib import Path
OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
UNIT = 'dgx-v4-prelaunch-release-e3f0db75d5b0c39cbddfd4f05130b622.service'
CG = '/system.slice/' + UNIT
ROOT = '/var/lib/dgx-v4/mimo-registry-native-r26-asset-protocol-r12'
STAGE = '/opt/dgx-v4/mimo-registry-native-r26-asset-protocol-r12'
PC_STAGE = '/opt/dgx-v4/hx/mimo-registry-native-r26-asset-protocol-r12'
SOCKET = '/var/lib/dgx-v4/mimo-registry-native-r26-asset-protocol-r12/parent-metadata.sock'
NAMESPACE = 'mimo-registry-asset-protocol-r12-owned'
INDEX_NAME = 'dgx-v4-mimo-registry-asset-protocol-r12-index'
CTR_SHA = '46c6f62a0a29fb4c0c11bd78a04f40f1a7299a5a2cf2fef4dc077a37b0cd1fca'
MANIFEST = '2e4bcc8bf4b5811670197334201ea4668001a81325749be1d1d1febffe215514'
CONFIG = '3e17fc3d95b489c35f8c4be0d7d0d1292853c68f0dea3d046851c4e1bc12d1f9'
RESERVE = 100 * 1024 ** 3
WORKSPACE = 80 * 1024 ** 3
MEMORY = 4 * 1024 ** 3
RUNTIME = 1800
APPROVED_CONTEXT = None
NVME_ANCHOR = {'sysfs': {'259:0': {'dev': '259:0\n', 'parent_dev': '235:0\n', 'partition_exists': False, 'queue_exists': True, 'realpath': '/sys/devices/pci0004:00/0004:00:00.0/0004:01:00.0/nvme/nvme0/nvme0n1'}, '259:2': {'dev': '259:2\n', 'parent_dev': '259:0\n', 'partition': '2\n', 'partition_exists': True, 'queue_exists': False, 'realpath': '/sys/devices/pci0004:00/0004:00:00.0/0004:01:00.0/nvme/nvme0/nvme0n1/nvme0n1p2'}}, 'filesystem': {'path': '/dev/nvme0n1p2', 'stat': [7, 227, 0, 0, 6, 25008, 1, 1791712401913318136, 1791712401913318136], 'major_minor': '259:2', 'rdev': 66306}, 'originating_io': {'path': '/dev/nvme0n1', 'stat': [7, 224, 0, 0, 6, 25008, 1, 1791712401901297875, 1791712401901297875], 'major_minor': '259:0', 'rdev': 66304}}
CTR_IMPORT_ARGV = None

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def strict(raw):

    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate_source_or_proof_key')
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite_source_or_proof')))
    except Exception:
        raise Refused('strict_source_or_proof_refused') from None

def scope_argv(device, remaining):
    need(device == '/dev/nvme0n1', 'actual_whole_NVMe_IO_device_required')
    need(type(remaining) in (int, float) and __import__('math').isfinite(remaining) and (30 < remaining <= 1800), 'actual_clamped_runtime_seconds')
    runtime = int(remaining)
    return ['/usr/bin/systemd-run', '--quiet', '--unit=' + UNIT, '--service-type=exec', '-p', 'UMask=0077', '-p', 'User=root', '-p', 'Group=root', '-p', 'CPUQuota=100%', '-p', 'MemoryMax=4G', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=256', '-p', 'Nice=10', '-p', 'IOSchedulingClass=idle', '-p', 'IOReadBandwidthMax=' + device + ' 62914560', '-p', 'IOWriteBandwidthMax=' + device + ' 62914560', '-p', 'Delegate=cpu io memory pids', '-p', 'PrivateMounts=yes', '-p', 'PrivateDevices=yes', '-p', 'KillMode=control-group', '-p', 'SendSIGKILL=no', '-p', 'TimeoutStopSec=60', '-p', 'RuntimeMaxSec=' + str(runtime), '-p', 'Restart=no', '-p', 'RemainAfterExit=yes', '/usr/bin/python3', '-I', '-B', STAGE + '/root_worker.py']

def kernel(row, container=False):
    q = row['cpu.max'].split()
    need(len(q) == 2 and q[0].isdigit() and q[1].isdigit() and (0 < int(q[0]) <= int(q[1])), 'actual_CPU1_aggregate')
    need(row['memory.max'].isdigit() and 0 < int(row['memory.max']) <= MEMORY and (row['memory.swap.max'] == '0') and row['pids.max'].isdigit() and (0 < int(row['pids.max']) <= 256), 'actual_memory_swap_tasks')
    need(row['cgroup'] == CG if not container else row['cgroup'].startswith(CG + '/'), 'actual_owned_cgroup')

def ctr_import(tool, remaining):
    need(tool['path'] == '/usr/bin/ctr' and tool['sha256'] == CTR_SHA and (0 < remaining <= 1800), 'fixed_ctr225_identity_and_deadline')
    seconds = max(1, int(remaining))
    return [tool['path'], '--address', ROOT + '/containerd.sock', '--namespace', NAMESPACE, '--timeout', str(seconds) + 's', '--connect-timeout', str(min(8, seconds)) + 's', 'images', 'import', '--local', '--no-unpack', '--platform', 'linux/arm64', '--digests', '--index-name', INDEX_NAME, ROOT + '/blobs/image.oci.tar']
ENTRY_UNIT = 'dgx-v4-prelaunch-release-e3f0db75d5b0c39cbddfd4f05130b622.service'
ENTRY_STATE = '/opt/dgx-v4/mimo-registry-native-r26-asset-protocol-r12/entry-state'
AGENT = '/opt/dgx-v4/mimo-registry-native-r26-asset-protocol-r12/root_agent.py'

def entry_argv():
    return ['/usr/bin/systemd-run', '--quiet', '--unit=' + ENTRY_UNIT, '--service-type=exec', '-p', 'User=root', '-p', 'Group=root', '-p', 'CPUQuota=100%', '-p', 'MemoryMax=192M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=32', '-p', 'Nice=10', '-p', 'IOSchedulingClass=idle', '-p', 'UMask=0077', '-p', 'Restart=no', '-p', 'RemainAfterExit=yes', '-p', 'SendSIGKILL=no', '-p', 'KillMode=control-group', '-p', 'TimeoutStopSec=30', '-p', 'RuntimeMaxSec=90', '/usr/bin/python3', '-I', '-B', STAGE + '/entry_worker.py']

def oci_index_bytes(manifest_raw):
    """Exact archive index bytes. e53c OCI ImportIndex stores these unchanged."""
    need(__import__('hashlib').sha256(manifest_raw).hexdigest() == MANIFEST, 'fixed_manifest_for_exact_index')
    return json.dumps({'schemaVersion': 2, 'manifests': [{'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': 'sha256:' + MANIFEST, 'size': len(manifest_raw), 'platform': {'architecture': 'arm64', 'os': 'linux'}}]}, sort_keys=True, separators=(',', ':')).encode()

def imported_content_sizes(image):
    index = oci_index_bytes(image.manifest_raw)
    result = {MANIFEST: len(image.manifest_raw), CONFIG: len(image.config_raw), **{x.digest: x.size for x in image.unique}, __import__('hashlib').sha256(index).hexdigest(): len(index)}
    need(len(result) == 66, '63_layer_manifest_config_index_exact_content_set')
    return result

def validate_nvme_identity(v):
    need(NVME_ANCHOR is not None, 'actual_NVMe_dual_identity_SOURCE_pending')
    need(type(v) is dict and set(v) == {'schema', 'filesystem', 'originating_io', 'sysfs_original', 'payload_parent_device', 'stage_device'}, 'typed_partition_and_originating_IO_identity')
    need(v['schema'] == 'registry-R26-NVMe-filesystem-originating-IO-identity/v1' and v['filesystem'] == NVME_ANCHOR['filesystem'] and (v['originating_io'] == NVME_ANCHOR['originating_io']) and (v['sysfs_original'] == NVME_ANCHOR['sysfs']), 'exact_dual_block_fullF9_rdev_sysfs_provenance')
    need(v['filesystem']['path'] == '/dev/nvme0n1p2' and v['filesystem']['major_minor'] == '259:2' and (v['filesystem']['rdev'] == v['payload_parent_device'] == v['stage_device'] == 66306) and (v['originating_io']['path'] == '/dev/nvme0n1') and (v['originating_io']['major_minor'] == '259:0') and (v['originating_io']['rdev'] == 66304), 'filesystem_partition_not_IO_device')
    return v

def context_nvme(c):
    v = validate_nvme_identity(c['NVMe_identity'])
    need((c['NVMe_device'], c['NVMe_major_minor']) == (v['filesystem']['path'], v['filesystem']['major_minor']) and (c['NVMe_IO_device'], c['NVMe_IO_major_minor']) == (v['originating_io']['path'], v['originating_io']['major_minor']), 'context_FS_and_IO_fields_derived_from_qualified_dual_producer')
    return v
