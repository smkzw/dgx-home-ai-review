# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Complete private-import terminal producer + service-readable consumer."""
from pathlib import Path
import time
import plan
from root_io import held, sha, fresh
from observer import positive
APPROVED_WORKER_SHA = None
APPROVED_FINAL_INDEX_SHA = None
APPROVED_PRODUCER_SHA = None
APPROVED_ENTRY_WORKER_SHA = None
APPROVED_FETCH_PRODUCER_SHA = None
APPROVED_ENTRY_PRODUCER_SHA = None
ENTRY = Path(plan.PC_STAGE) / 'native-entry-qualified.json'
TERMINAL = Path(plan.PC_STAGE) / 'fetch-qualified.json'

def produce(read, scope, c, now):
    plan.need(APPROVED_WORKER_SHA is not None and APPROVED_FINAL_INDEX_SHA is not None, 'terminal_producer_source_None')
    r = positive(scope, plan.UNIT, APPROVED_WORKER_SHA)
    v = r['result']
    d = v['download']
    plan.need(v['schema'] == 'registry-A-private-import-returned/v1' and v['operation'] == plan.OPERATION and (v['source_release_sha256'] == c['source_release_sha256']) and (v['manifest_sha256'] == plan.MANIFEST) and (v['config_sha256'] == plan.CONFIG) and (v['image_imported'] is True) and (v['initialized_private_content_registry'] is True) and (v['models_started'] == 0) and (v['hardware_validated'] is False) and (v['ABI_numeric_media_accepted'] is False), 'actual_imported_content_not_model_or_ABI')
    idx, ix = read(plan.STAGE + '/source-index.json')
    plan.need(sha(idx) == APPROVED_FINAL_INDEX_SHA, 'final_source_index_identity')
    for name, pin in plan.strict(idx)['files'].items():
        code, st = read(plan.STAGE + '/' + name, cap=2097152)
        plan.need(sha(code) == pin, 'all_final_materialized_sources')
    original, os9 = read(plan.ROOT + '/returned-zero.json')
    plan.need(original == scope['returned_original']['raw_utf8'].encode() and os9 == scope['returned_original']['stat'], 'actual_after_return_held_original_raw_F9')
    manifest, _ = read(plan.STAGE + '/fetch/manifest-original.json')
    config, _ = read(plan.STAGE + '/fetch/config-original.json')
    plan.need(sha(manifest) == plan.MANIFEST and sha(config) == plan.CONFIG, 'fixed_actual_metadata')
    layers = plan.strict(manifest)['layers']
    unique = {x['digest'][7:]: x['size'] for x in layers}
    index_bytes = plan.oci_index_bytes(manifest)
    wanted = dict(unique, **{plan.MANIFEST: len(manifest), plan.CONFIG: len(config), sha(index_bytes): len(index_bytes)})
    plan.need(len(wanted) == 66, 'exact_fixed_import_index_content_set')
    plan.need(len(layers) == 69 and len(unique) == 63 and (d['unique_blobs'] == 63) and (d['descriptors'] == 69) and (set(d['final_files']) == set(unique)), 'fixed_descriptors_unique_all_files')
    imp = v['import']
    plan.need(imp['argv'] == plan.ctr_import(c['tools']['ctr'], int(imp['argv'][6][:-1])) and imp['rc'] == 0 and (imp['stderr_bytes'] == 0) and (imp['unpack'] is False) and (imp['local'] is True) and (imp['namespace'] == plan.NAMESPACE) and (imp['index_name'] == plan.INDEX_NAME) and (set(imp['imported_content']) == set(wanted)), 'exact_ctr225_private_local_no_unpack_vector')
    for digest, size in unique.items():
        proof, st = read(plan.ROOT + '/blobs/verified-' + digest + '.json')
        plan.need(plan.strict(proof) == {'digest': digest, 'bytes': size, 'fullSHA': True}, 'original_full_download_SHA_receipt')
        _, current = read(plan.ROOT + '/blobs/' + digest, stat_only=True)
        plan.need(current == d['final_files'][digest]['stat'] and current[2] == size, 'final_download_F9_not_countonly')
    for digest, size in wanted.items():
        item = imp['imported_content'][digest]
        path = plan.ROOT + '/containerd-data/io.containerd.content.v1.content/blobs/sha256/' + digest
        plan.need(item['path'] == path and item['bytes'] == size and (item['fullSHA'] is True), 'actual_full_imported_content_digest')
        _, st = read(path, stat_only=True)
        plan.need(st == item['stat'] and st[2] == size and (st[3:5] == [0, 0]) and (st[6] == 1), 'actual_import_content_F9_after_return')
    a = d['archive']
    _, st = read(plan.ROOT + '/blobs/image.oci.tar', stat_only=True)
    plan.need(a['stat'] == st and a['archive_bytes'] == st[2] and (a['compressed_SHA'] is True) and (a['descriptors_preserved'] == 69) and (a['unique_layer_blobs'] == 63) and (a['uncompressed_diff_ids_verified'] is False) and (a['ARM_ABI_numeric_media_accepted'] is False), 'actual_OCI_footer_not_uncompressed_numeric_acceptance')
    db = v['registry_original']
    path = plan.ROOT + '/containerd-data/io.containerd.metadata.v1.bolt/meta.db'
    archive = plan.ROOT + '/initialized-registry.raw'
    plan.need(db['path'] == path and db['archive_path'] == archive and (db['after_owned_daemon_exit'] is True) and (db['Bolt_interpretation_performed'] is False), 'initialized_registry_original_not_unvalidated_database_claim')
    source, st = read(path, cap=16 * 1024 ** 2)
    mirror, ms = read(archive, cap=16 * 1024 ** 2)
    plan.need(source == mirror and 0 < len(source) <= 16 * 1024 ** 2 and (sha(source) == db['sha256'] == db['archive_sha256']) and (st == db['stat']) and (ms == db['archive_stat']), 'actual_after_owned_daemon_exit_registry_raw_fullSHA_F9')
    plan.need(r['cleanup']['all_owned_children_exited'] is True and r['cleanup']['force_kill'] == r['cleanup']['global_signals'] == 0, 'actual_owned_only_clean_return')
    plan.need(0 <= now - r['observed_at'] <= 30, 'fresh_actual_terminal_no_time_refresh')
    return {'schema': 'registry-R26-private-import-qualified/v1', 'operation': plan.OPERATION, 'producer_sha256': sha(Path(__file__).read_bytes()), 'source_release_sha256': c['source_release_sha256'], 'manager_identity': c['manager_identity'], 'current_PC_source118': c['current_PC_source118'], 'config_sha256': c['PC_config_sha256'], 'actual_owned_scope': scope, 'Root_worker_sha256': APPROVED_WORKER_SHA, 'source_index_sha256': sha(idx), 'source_index_F9': ix, 'manifest_sha256': plan.MANIFEST, 'config_blob_sha256': plan.CONFIG, 'unique_blobs': 63, 'descriptors': 69, 'image_imported': True, 'initialized_private_content_registry': True, 'runtime_image_serving_accepted': False, 'hardware_validated': False, 'models_started': 0, 'observed_at': now}

def consume(read, path, config, identity, now, *, historical=False):
    pin = APPROVED_FETCH_PRODUCER_SHA or APPROVED_PRODUCER_SHA
    plan.need(pin is not None and Path(path) == TERMINAL, 'fixed_terminal_source_None_or_path')
    raw, s = read(path, limit=4194304)
    v = plan.strict(raw)
    plan.need(s[2] == len(raw) and s[3:7] == [0, 989, 33056, 1], 'actual_Service_readable_Root_origin')
    plan.need(v['schema'] == 'registry-R26-private-import-qualified/v1' and v['producer_sha256'] == pin and (v['operation'] == plan.OPERATION) and (v['current_PC_source118'] == config['PC_source_pins']) and (v['config_sha256'] == config['_config_sha256']) and (historical or v['manager_identity'] == identity), 'actual_newsource_current_owner_not_ancestor')
    positive(v['actual_owned_scope'], plan.UNIT, v['Root_worker_sha256'])
    plan.need(v['image_imported'] is True and v['initialized_private_content_registry'] is True and (v['runtime_image_serving_accepted'] is False) and (v['models_started'] == 0) and (v['hardware_validated'] is False) and (v['manifest_sha256'] == plan.MANIFEST) and (v['config_blob_sha256'] == plan.CONFIG) and (v['unique_blobs'] == 63) and (v['descriptors'] == 69) and (v['observed_at'] <= now), 'technical_import_barrier_not_deployment')
    return dict(v, actual_retained_EXIT0=True)

def consume_terminal(read, path, config, identity, now, *, historical):
    return consume(read, path, config, identity, now, historical=historical)

def consume_entry_ready(read, config, identity, now):
    plan.need(APPROVED_ENTRY_PRODUCER_SHA is not None, 'actual_entry_producer_None')
    raw, st = read(ENTRY, limit=4194304)
    v = plan.strict(raw)
    plan.need(st[2] == len(raw) and st[3:7] == [0, 989, 33056, 1] and (v['schema'] == 'registry-R26-A-entry-qualified/v1') and (v['operation'] == plan.OPERATION) and (v['producer_sha256'] == APPROVED_ENTRY_PRODUCER_SHA), 'actual_entry_Root_origin_and_source')
    plan.need(v['manager_identity'] == identity and v['current_PC_source118'] == config['PC_source_pins'] and (v['PC_config_sha256'] == config['_config_sha256']) and (v['models_started'] == 0) and (0 <= now - v['observed_at'] <= 300), 'same_current_entry_fresh_not_historical_NEGATIVE')
    positive(v['actual_readonly_scope'], plan.ENTRY_UNIT, v['readonly_worker_sha256'], True)
    result = v['result']
    plan.validate_nvme_identity(result['NVMe_identity'])
    plan.need(result['payload_namespace_absent'] is True and result['daemon_started'] is False and (result['models_started'] == 0) and (result['MemAvailable_bytes'] >= 8 * 1024 ** 3) and (result['NVMe_free_bytes'] >= plan.WORKSPACE + plan.RESERVE), 'actual_readonly_resource_source_ready_not_GPU')
    return v
