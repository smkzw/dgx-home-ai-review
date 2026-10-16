# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Immutable public OCI inputs; no native authorization is supplied here."""
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
HERE = Path(__file__).resolve().parent
MANIFEST = '2e4bcc8bf4b5811670197334201ea4668001a81325749be1d1d1febffe215514'
CONFIG = '3e17fc3d95b489c35f8c4be0d7d0d1292853c68f0dea3d046851c4e1bc12d1f9'
REGISTRY = 'registry-1.docker.io'
CDN = 'production.cloudfront.docker.com'
SOURCE_IP = '192.0.2.10'
RATE = 60 * 1024 ** 2
CHUNK = 64 * 1024
RESERVE = 100 * 1024 ** 3

class Refused(RuntimeError):
    """Only a fixed code crosses the logging boundary."""

def need(ok, code):
    if not ok:
        raise Refused(code)

def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result

def parse(raw):
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite_json')))
    except Refused:
        raise
    except Exception:
        raise Refused('invalid_json') from None

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

@dataclass(frozen=True)
class Blob:
    digest: str
    size: int

    def __post_init__(self):
        need(type(self.digest) is str and re.fullmatch('[0-9a-f]{64}', self.digest), 'blob_digest')
        need(type(self.size) is int and self.size > 0, 'blob_size')

@dataclass(frozen=True)
class Image:
    manifest_raw: bytes
    config_raw: bytes
    layers: tuple
    unique: tuple
    diff_ids: tuple

    @property
    def unique_bytes(self):
        return sum((b.size for b in self.unique))

def load():
    mr = (HERE / 'manifest-original.json').read_bytes()
    cr = (HERE / 'config-original.json').read_bytes()
    need(len(mr) == 13484 and sha(mr) == MANIFEST, 'fixed_manifest_identity')
    need(len(cr) == 61956 and sha(cr) == CONFIG, 'fixed_config_identity')
    m, c = (parse(mr), parse(cr))
    need(m['schemaVersion'] == 2 and m['mediaType'] == 'application/vnd.oci.image.manifest.v1+json', 'oci_manifest')
    need(m['config'] == {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': 'sha256:' + CONFIG, 'size': len(cr)}, 'oci_config_descriptor')
    need(c['architecture'] == 'arm64' and c['os'] == 'linux' and (c['rootfs']['type'] == 'layers'), 'arm64_linux_config')
    need(len(m['layers']) == len(c['rootfs']['diff_ids']) == 69, 'all_69_layers')
    layers, unique = ([], {})
    for row in m['layers']:
        need(set(row) == {'mediaType', 'digest', 'size'} and row['mediaType'] == 'application/vnd.oci.image.layer.v1.tar+gzip', 'layer_descriptor')
        need(row['digest'].startswith('sha256:'), 'layer_algorithm')
        b = Blob(row['digest'][7:], row['size'])
        need(b.digest not in unique or unique[b.digest] == b, 'duplicate_size_conflict')
        layers.append(b)
        unique[b.digest] = b
    diff = tuple(c['rootfs']['diff_ids'])
    need(all((re.fullmatch('sha256:[0-9a-f]{64}', d) for d in diff)), 'diff_id_format')
    need(len(unique) == 63 and sum((b.size for b in layers)) == 15540014752, 'fixed_descriptor_totals')
    return Image(mr, cr, tuple(layers), tuple(unique.values()), diff)

class Budget:

    def __init__(self, seconds=1800, clock=time.monotonic, sleep=time.sleep):
        need(type(seconds) in (int, float) and 0 < seconds <= 1800, 'bounded_window')
        self.clock, self.sleep = (clock, sleep)
        self.started = clock()
        self.deadline = self.started + seconds
        self.observer = None

    def left(self):
        need(self.deadline > self.clock(), 'whole_deadline')
        if self.observer is not None:
            self.observer()
        value = self.deadline - self.clock()
        need(value > 0, 'whole_deadline')
        return value

    def wait(self, seconds):
        need(0 <= seconds < self.left(), 'insufficient_whole_window')
        target = self.clock() + seconds
        while self.clock() < target:
            self.left()
            self.sleep(min(1, target - self.clock()))
        self.left()
