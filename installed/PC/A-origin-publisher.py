# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed new A source-origin receipt. No source installation or asset launch."""
import base64, os, stat
from pathlib import Path
from root_io import held, sha, f9, fresh
from plan import need, strict, encode
APPROVED = {'operation': '2b9e9b631cebc13ae6b1550ee59c13ed', 'review': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9', 'source_pins': {'EXPECTED_DUMP.json': '4f9711763a29cedefae3497b09e4aa8de95e5d3f2dfa2ebc55c2f51c8cc49d02', 'OFFICIAL_MERGED_BASELINE.json': '6bb755798fafa04c6a66bc7dca67688f6a3102b8f39c370d4461db6737f35676', 'asset_segments.py': '17bcf8e3fa714b2ce8ccfa6e387c48eab3938aa0e3043b8f17cf00df0331ef2e', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'broker.py': '518b902faf0519b71baa3a2215618e2f534fbb64f8868ed5e78326ba97226ab5', 'config-original.json': '3e17fc3d95b489c35f8c4be0d7d0d1292853c68f0dea3d046851c4e1bc12d1f9', 'containerd.candidate.toml': 'c51a01c993ecc3b1a995b3423709adc4df634b0be886fbdf9ba7caf961422544', 'diagnostics.py': 'ac104840f0299457b93e1390905131e5fb92cef962695d26075699d9362908dd', 'download_worker.py': '7aeb81186d2d856e6759632fedf3e044187968bc85c817b1a6082105ea757a0e', 'entry_clock.py': 'c94f22300a5fbea23f655914d38dce3586646aa08957f3c4ee3f64c0f3e4dbc3', 'entry_worker.py': '5b51f3bc679363e2317cad3ef6402fad45744db74664accf8129bd4edff99fb3', 'failed_terminal.py': '5cf4d64d0d9b6e83f461c76babe84faa9128d4972f78d34f16eb8c3d7921eaf8', 'fetch/config-original.json': '3e17fc3d95b489c35f8c4be0d7d0d1292853c68f0dea3d046851c4e1bc12d1f9', 'fetch/contract.py': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde', 'fetch/entry.py': '74555b3a46f63530eeb785da2eb3ae93bd51e9ee7a3e099f1f583449ae55e8d8', 'fetch/fetch.py': '3733df9272e6f9552930f8b6889093a4484724bbcae687b561e378ed8a153aed', 'fetch/manifest-original.json': '2e4bcc8bf4b5811670197334201ea4668001a81325749be1d1d1febffe215514', 'fetch/oci.py': '13b9ef60b443a18f0757f4602ba7e3738c5c0d99b768e91edeeb9ac6697d4ff1', 'fetch/supervision.py': '0b4b24b13250bafb38d41e5ef6fe079b725665bf7fbe8f9ca2d96ad2ab5fbbdf', 'fetch/transport.py': 'f604a7e6a2eaf04dfe8202049dbe277238fef02cf5110a861fc04b370a5228f1', 'manifest-original.json': '2e4bcc8bf4b5811670197334201ea4668001a81325749be1d1d1febffe215514', 'namespace.py': '70c3d3fcc9421f1136d1df706a544bc938e220bcf1d2376f0e2bee59c65c8fff', 'native.py': '14a42d31490502225de1e9cab6858ad7e78164f900b652ac7539a442c29e312b', 'observer.py': '5bbe537a7d145bddeca96dcdf665d5fc286356cd3bf89c8242db432b06f70b71', 'old_failed_kernel.py': '4a22ee3a3e10ff91e8b0118ce810324ab205b2832b64932ab5ce786583b39ee9', 'parent_metadata.py': 'fca2f690c5532b6e119b33271df702cccbca62b0f983713f7635e8ce19520bf3', 'parent_source.py': '7b7fc54021b9d2f0b0a0dae1e01f8cc12ff2228569b441caf8d616245df8613a', 'pc_contract.py': '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8', 'pc_managed_scope.py': '0fb463b06fc6da5ee9f933080dc768ff99d8909aa687d35f916e88f8b807180f', 'plan.py': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f', 'point_clock.py': 'e2f13cb881c4ce33716f4dfb377e6304101296d4382144f2d02c64b20a6edeae', 'private_config.py': '2654bf922b0b9c4ce772f948f621cd3d3a7fc7f72e14b191a3852cfc9bfa72f8', 'qualification.py': 'dfb10d2fc04dc63f95e45968d5e0d358a79ae7862b303cde4e95fe2c5e522718', 'range_catalog.py': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde', 'range_component.py': '46ea4378229ada599beecb4e4c1b78d4d9be0ef77bb9d43ba32bec8e3c5233ad', 'range_diagnostic.py': '85cb26cc3bf8c542b38cbd753337f6c047a8607373326f5ee353adc3b54db9ac', 'range_fetch.py': '4ab3dca44b7db63471f873f82f5da282580dfc6189950f0e34bb513aebc2b8a0', 'range_http.py': '4b3cc3e764ffc1c80db69800cc0060546a4891543705f18c7e353fe77540f626', 'range_transport.py': 'ae0e06e60226dc4759a95df8281115fbcaf84f4a2147de19be109b7d9f85433c', 'root_agent.py': 'c5fa8dcb08f08462a40c672eb74cf546f67e4ba2ef48d9d408c3d8f8cef0e7f7', 'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'root_loader.py': '0f37ee0dc291ed2cd99ca0b19e8cfe5311519271d909f98bdca6686b05f29362', 'root_worker.py': 'c31ec3088783e274c8d4a12a5234d702a5058e2a2ff315c4c7d292ebfff9a05c', 'segment_agent.py': '0e16aa00ba7d192711a590303266361e17ec8854857479f8c2e93c17e08bcf42', 'segment_download_worker.py': '452d0e1e07e63218b8b12f843b3e1545e17c9e9fb8fa3f438aa11f242bdd0411', 'segment_ready.py': 'fc79a15b64a04a63e38ebcda8395be64f19b563d291e49665186c91b3c43371a', 'segment_ready_worker.py': 'b7b66f6114bd035a98713adfe1cea67b0e96bf70b4f026f15e503b91aae15ccd', 'segment_runtime.py': '356294b8ce09d3eee16948b89009a03ee21388d484ff539f41acbb952dbb4eb6', 'segment_terminal_producer.py': '58b4538613e4c19278f50fa9cfdcce66ce59dcfef76ea1aaa86c9b406fb0c508', 'segment_worker.py': 'e976ddc881c539de2984319cf96abc0e6410108e8d37a28c925e4b6526ae8b49', 'source-index.json': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'stage_entry_clock.py': 'c94f22300a5fbea23f655914d38dce3586646aa08957f3c4ee3f64c0f3e4dbc3', 'stage_naming.py': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d', 'terminal.py': 'd5276461483778757687896daecfe68f113cbdc2c970e5d4bcba1911eb2c4aca', 'topology.py': '411036bf0b9b5fe3e419ff4a3ca6663151f086beb06f37962e3fc1c29aaadaac'}, 'source_sizes': {'EXPECTED_DUMP.json': 2876, 'OFFICIAL_MERGED_BASELINE.json': 3559, 'asset_segments.py': 11853, 'bounded_process.py': 1175, 'broker.py': 7481, 'config-original.json': 61956, 'containerd.candidate.toml': 1661, 'diagnostics.py': 26972, 'download_worker.py': 7444, 'entry_clock.py': 16892, 'entry_worker.py': 10639, 'failed_terminal.py': 11667, 'fetch/config-original.json': 61956, 'fetch/contract.py': 4134, 'fetch/entry.py': 334, 'fetch/fetch.py': 9193, 'fetch/manifest-original.json': 13484, 'fetch/oci.py': 3903, 'fetch/supervision.py': 9841, 'fetch/transport.py': 13491, 'manifest-original.json': 13484, 'namespace.py': 1766, 'native.py': 8961, 'observer.py': 4089, 'old_failed_kernel.py': 8271, 'parent_metadata.py': 2202, 'parent_source.py': 2635, 'pc_contract.py': 53300, 'pc_managed_scope.py': 3117, 'plan.py': 7381, 'point_clock.py': 4556, 'private_config.py': 5240, 'qualification.py': 5167, 'range_catalog.py': 4134, 'range_component.py': 4760, 'range_fetch.py': 218, 'range_http.py': 5193, 'range_transport.py': 13507, 'root_agent.py': 16479, 'root_io.py': 3020, 'root_loader.py': 3475, 'root_worker.py': 6907, 'segment_agent.py': 9224, 'segment_download_worker.py': 7746, 'segment_ready.py': 2489, 'segment_ready_worker.py': 10772, 'segment_runtime.py': 6496, 'segment_terminal_producer.py': 3695, 'segment_worker.py': 3759, 'source-index.json': 4446, 'stage_entry_clock.py': 16892, 'stage_naming.py': 341, 'terminal.py': 8004, 'topology.py': 9467, 'range_diagnostic.py': 4800}}
ROOT = '/opt/dgx-v4/mimo-registry-r16'
PC_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'

def validate(raw):
    need(type(APPROVED) is dict and ROOT is not None and (PC_ROOT is not None), 'A_origin_SOURCE_None')
    v = strict(raw)
    need(set(v) == {'schema', 'source_root', 'source_epoch', 'review_sha256', 'files', 'boot_original'} and v['schema'] == 'R12-A-source-held-original/v1' and (v['source_root'] == ROOT) and (v['source_epoch'] == APPROVED['operation']) and (v['review_sha256'] == APPROVED['review']) and (set(v['files']) == set(APPROVED['source_pins'])), 'A_origin_exact_source_domain')
    for name, row in v['files'].items():
        s = row['F9']
        need(set(row) == {'sha256', 'F9'} and row['sha256'] == APPROVED['source_pins'][name] and (type(s) is list) and (len(s) == 9) and all((type(x) is int and x >= 0 for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[2] == APPROVED['source_sizes'][name]) and (s[3:7] == [0, 0, 33152, 1]), 'A_origin_full_source_SHA_F9')
    b = v['boot_original']
    r = base64.b64decode(b['raw_b64'], validate=True)
    s = b['F9']
    need(set(b) == {'raw_b64', 'sha256', 'F9'} and sha(r) == b['sha256'] and (len(r) == 37) and (s[3] == 0) and (s[2] == 0) and (s[6] == 1) and (r.decode().strip().count('-') == 4), 'A_origin_kernel_boot_actual_proc_zero_size')
    return v

def collect():
    need(os.getuid() == os.geteuid() == 0 and type(APPROVED) is dict, 'A_origin_Root_fixed_source')
    files = {}
    for name, pin in APPROVED['source_pins'].items():
        raw, s = held(Path(ROOT) / name, pin, cap=2097152, mode=384)
        need(len(raw) == APPROVED['source_sizes'][name], 'A_origin_source_size')
        files[name] = {'sha256': sha(raw), 'F9': s}
    p = Path('/proc/sys/kernel/random/boot_id')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = f9(os.fstat(fd))
        raw = os.read(fd, 128)
        need(before == f9(os.fstat(fd)) == f9(p.lstat()) and len(raw) == 37, 'A_origin_boot_full_F9')
        boot = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': before}
    finally:
        os.close(fd)
    v = {'schema': 'R12-A-source-held-original/v1', 'source_root': ROOT, 'source_epoch': APPROVED['operation'], 'review_sha256': APPROVED['review'], 'files': files, 'boot_original': boot}
    validate(encode(v))
    for name, row in files.items():
        need(held(Path(ROOT) / name, row['sha256'], mode=384)[1] == row['F9'], 'A_origin_source_after_collection')
    out = Path(ROOT) / 'source-origin.json'
    fresh(out, encode(v), mode=384)
    raw, s = held(out, sha(encode(v)), mode=384)
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}

def publish(original, current):
    need(os.getuid() == os.geteuid() == 0, 'A_origin_PC_Root_publisher')
    need(type(original) is dict and set(original) == {'raw_b64', 'sha256', 'F9'}, 'A_origin_exact_Root_original')
    raw = base64.b64decode(original['raw_b64'], validate=True)
    s = original['F9']
    need(sha(raw) == original['sha256'] and s[2] == len(raw) <= 2097152 and (s[3:7] == [0, 0, 33152, 1]), 'A_origin_actual_remote_Root_raw_F9')
    v = validate(raw)
    need(current['review_sha256'] == APPROVED['review'] and len(current['source118']) == 118, 'A_origin_new_qualified_current_binding')
    body = encode({'schema': 'R12-PC-held-A-source-origin/v1', 'current': current, 'A_original': original})
    out = Path(PC_ROOT) / 'A-source-origin.json'
    fresh(out, body, mode=288)
    os.chown(out, 0, 989)
    os.chmod(out, 288)
    held(out, sha(body), mode=288)
    return {'path': str(out), 'sha256': sha(body), 'source_files': len(v['files'])}
