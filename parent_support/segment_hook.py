# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One exact hook in frozen H5's Mac parent, never a service replacement.
Ordinary successful/started-worker terminal phases retain the original path.
"""
import ast
import re
import types
from emission import need
import prebind_failure

def derive(raw):
    text = raw.decode()
    marker = "  if reserved and not attempted.intersection({'begin-asset-terminal-clock','asset-finalize','publish-asset-terminal','finish-asset-stage'}):\n"
    need(text.count(marker) == 1, 'one_exact_H5_failed_terminal_hook')
    prefix = "  if reserved and 'asset-start' not in attempted and not attempted.intersection({'begin-asset-terminal-clock','asset-finalize','publish-asset-terminal','finish-asset-stage','finish-failed-asset-stage','prepare-not-launched-asset-stage','finish-not-launched-asset-stage'}):\n   try:\n    cleanup_end=time.monotonic()+90;io.close_not_launched(stage,attempted,cleanup_end)\n   except BaseException as cleanup_error:\n    fresh(root/'cleanup-failed.json',encode(original_safe_error('finish-failed-asset-stage',cleanup_error)))\n  elif reserved and not attempted.intersection({'begin-asset-terminal-clock','asset-finalize','publish-asset-terminal','finish-asset-stage'}):\n"
    text = text.replace(marker, prefix, 1)
    record = "'attempted':sorted(attempted.intersection({'begin-asset-terminal-clock','asset-finalize','publish-asset-terminal','finish-asset-stage','finish-failed-asset-stage'}))"
    need(text.count(record) == 1, 'one_exact_original_attempted_phase_record')
    text = text.replace(record, record.replace("'finish-failed-asset-stage'", "'finish-failed-asset-stage','prepare-not-launched-asset-stage','finish-not-launched-asset-stage'"), 1)
    tree = ast.parse(text)
    assignment = next((n for n in tree.body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'APPROVED_STAGE' for t in n.targets))))
    lines = text.splitlines(True)
    lines[assignment.lineno - 1:assignment.end_lineno] = ['APPROVED_STAGE=None\n']
    result = ''.join(lines).encode()
    compile(result, 'one_R12_parent_prebind_failure_hook', 'exec')
    return result

def bind_stage(module, contract):
    need(set(contract) == {'stage_operation', 'ranges', 'maximum_seconds'} and re.fullmatch('[0-9a-f]{32}', contract['stage_operation']) is not None and (contract['stage_operation'] != 'd8d0f06cc54a807f320d03813daf3b4b') and (type(contract['maximum_seconds']) is int) and (1 <= contract['maximum_seconds'] <= 1800), 'new_finite_stage_not_replay_or_extension')
    MAX_SEGMENT = 64 * 1024 ** 2
    MAX_BATCH = 256 * 1024 ** 2

    def load():
        return types.SimpleNamespace(unique=[types.SimpleNamespace(digest=k, size=v) for k, v in {'76fd055477b6edf8004a5a962edad02a820d4c8b2f02682410edfbe376b418c5': 28874075, '2ed23d91404d4701b704d1bde211c59a2a564a31c315f05871a6e9403bc19945': 6754305, 'b69841cb303ccedcf38d7b88ef5624621de9afac92f991bd9493046493af0459': 376792, 'f96e895ae7545ec872855c3f2adf4d95fa731dd2e8545b054f7aa1afc3d979f9': 99450625, '4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1': 32, '4efc2d488f5acb1bcdef886876870bffe7f6435015718596101285c66bfd9fea': 187, '730c8029606bf4b4533d7a7159458cf5e3f348ea956ccfb10ce5da3e20adac8f': 6886, '1b32cf91a1bf3f3f7ae37872a438565ab17ba9b8d07603039885d8a0bc0bf99b': 1634601671, '639485f1f45f8c40371c8ef81ac16128b3009825e58436becb1fc4b8a6a6a1ec': 59963, '063065dd5a0bcec95324d9aa1f46e7311ea2b41b099949a82cb6cb82a0384622': 1685, '1868124c7d5b7d7ef6579a7d2729713f71b31752baf0d7e2d0cad49ebfb5e128': 1524, '9c6b8f5a26d7663808df6235190a9e4cbf214a8337c0737c66b0beb7a0637d38': 2159025177, '17071d079121f2639f05774fea4bc3b899298e87602eae4c41154c28a14fe75a': 90147, '801ff5d640da07c7b698f949f0976a8b29394fad3d0e0470331287aa7de52a37': 416534374, 'd84688a77e45fac979672951cfcc1319b685dee97286db3526b9694aeac7fd1b': 18701743, '532774ecde391b613eed107ed03ca1c3f05555eb6529d148631bc9914581af5b': 31018813, 'fa0a74323e2e40cd5c2e8546a8900aac83975b2b7bf3a0d5de46fe9b773a5a51': 398087458, 'd5ab7237901ade16cdc139d17a1fb5d54417882d52dc3566d49cf366ffa49358': 1442615, '30efa5d6f3bcd3fa0228236a8f0b2d795712383d6292438f39bf738b9f8c9a89': 186, 'fad336e0a45ff330a4d33a822e18ee713783e685fc934fc4b58c4ec5cf69f6c4': 866621, '010884a829ecaf5a88125f246864b21ba5a0c40915423e667d2fbf4621c00654': 103, '3442ea1fcd4b89ba47862820a5a33e97182fe17e78b7bcc354d3e4ca4be31a29': 187516462, 'e6ee4e24d8162921c291358c41371a7366c2fec1ea3d75f33a3233e10670bbe1': 26699033, 'a8c7a6a22a8ae835f1745dc7e8c494a29737ef3316da4bd4af08d6b48ea33a22': 3253, '1a08ccfa0883c4002dd1e0c667e9113e1182cd7d0f85145125266d1e1c73a294': 23953, 'c08bfe43ce0dfcf45e4d050f289cdc22e3c81c2a8553f22f89dc725fed90b35c': 45889, 'ca23cdacd297503b77364db298ce3dfd4176d2b8fd4742a9e0ac37f369bc58ca': 36345, 'af270579779973f5f98d2e3d213cdc0c78ec57d581ada2d50c75ee4ed214049b': 4225959836, 'ddfa71d57a019985d4265f3320d8e6b833e329de5e0121d24c66bff82698cc2d': 224304715, '952c54ee9114d6d4d21ccf4b2569305c07a5db2bb61a85615aa93e6f5f8602b3': 141, 'dd83a627576a2a2275efc47be3fa86aa8f14190155f598d0193281cbb571960f': 154, '2bfe1971642b84ddeae6d486637d3cbba35274c81d256264c73c344a52180637': 3057390290, 'dfcc0e1eb08de6a3777e240c30582c73d48beb271bd22bf6d5befb8709b1cc7b': 13441, 'b9c0757ebb35bc4ddf92652f455ac2d81f4d2abb107433ba383c0d5a46e9a22f': 1787299, '2d384f28253879e2e1df7924b1024464f59b39c2cdfb8c0d8ed9668e69b9f014': 84928123, '7b0d39cbbe8c05e152dd9aecf5fdca99e3e212a7632ee88bea367931f3b7f191': 980266, '25c1ba674fd234968dbd35206c22c285e32f7fdff37245f42d6890420a90156e': 7683623, 'fc6e694d69a0b6d54c798995abcf7804667b624f885e4b7d397db5e043626601': 8347498, '615acf13fb5188964596d4b0708e9a724d8c53746783d2797371db32912d1d67': 7878307, '18c57db03619afa3ef8e3c2477eb3da4ee9d3d677dd02734971c1371d67321d9': 2021768, '45e72d0a367274a510faeafad60fd5f9530fb80a97a9e4a971ca46ba4060b766': 1846650, '76fbcc4f86f822b8cd473bc35dddd4bbb5cbb67112dc276e3bad9cfb5b88a044': 7934228, '098813dde205ae424680ad80829fac0e072ba29eae0b568e420795820d28a8a5': 74487850, '0cc6fcb63c7fa41816a87b93c0bdc78d4f8bff0df6763ce5dec977eb16aaf627': 208381868, 'a7cfc8773bb4468a76811a11bf827c761b3df9b4677b73150f4046ca781ce1be': 76585279, 'f192a3344e51feb961c49ff91ffa3438402b2f22a28499d69c201f24bfb11f20': 177643981, 'c059a32706e0f8db19f2d876db7b0999a899a793a9250f6fd6966a02ed568d80': 303790988, '506af951d9f86ca3c316069f7f33052534b64d626a3b4e2fcbe4dd3acb46c7a2': 216250791, 'b6181cba382a97b150df265da032ba4fb02bf9566dc5a700745589e08b4191c5': 57008479, 'eda4ace6950706447dfa268109d947cedab4955f40f141185ea3522a020e8677': 344258069, 'c3888ccf237e2e1de77b8f4dab409aea4c93e6ab8902f351df83f12e73f6f205': 445, '7e3a0247bce83bfe23b1f4bf5a90d313a373d4edccbce9c190524fc20e080a91': 724, '55805617fadd9dcbdbb72da5904d1817211c2d3ec6c2a2f0183228ec662b58ca': 508, 'e5d7b232cb4fd7564ac3902455a1c61d7025aa6a61ee97a116ca4871a2d2f922': 521, '55650df6994619533e07b77c7b722acf42e57e476eec5a24950e015d466c7503': 391, '94dd311d03c6efd7b30b7af5c24fc3b5c6231ae29f57423a2e2f721b44288b6c': 6457174, '21baecf931724bc48a798facc44922eae89e378e61263aa907bdad549208aa1e': 3946591, 'e7ac6d2ee44d842f424b4e15a2c4896ad7d3470c727d586555cf055a8e020246': 189180343, '89f0aee0df29dfa0f679fd9cfd77844b1dd4ed61b3e83091e6516e9ef619235f': 189179321, '4a3cc43c7b0369ea764f0fcbb082b09afd458c3c8495dd3a9478b26f9548a760': 990261637, 'a6575e07e766fc9f59a266ee0551a64f1ecfcee827129abdf929d3b665c4f335': 18308203, '155aa5f03b563858a99669aad2f3500eacc78bbf7ec621d18d9fc1938dbde62d': 18170590, '0d31f5b429cdd302151a4b5812ca1d37651c38c65e0fe80922aae6cfb50482fd': 24804551}.items()])

    def exact_ranges(rows):
        catalog = {b.digest: b for b in load().unique}
        need(type(rows) is list and 1 <= len(rows) <= 8, 'bounded_fixed_ranges')
        seen = []
        for r in rows:
            need(type(r) is dict and set(r) == {'digest', 'start', 'count'} and (r['digest'] in catalog), 'fixed63_range_descriptor')
            a, n = (r['start'], r['count'])
            need(type(a) is int and type(n) is int and (0 <= a < catalog[r['digest']].size) and (0 < n <= MAX_SEGMENT) and (a + n <= catalog[r['digest']].size), 'bounded_fixed_interval')
            need(not any((d == r['digest'] and max(a, s) < min(a + n, e) for d, s, e in seen)), 'no_duplicate_or_overlapping_ranges')
            seen.append((r['digest'], a, a + n))
        need(sum((r['count'] for r in rows)) <= MAX_BATCH, 'bounded_stage_bytes')
        return rows
    exact_ranges(contract['ranges'])
    need(module.APPROVED_STAGE is None, 'new_parent_stage_binding_once')
    module.APPROVED_STAGE = contract

def attach(io, once, emitted, RPC_original, A_original, *, tag):
    """Mac parent private IO only; no live service globals or caller admin hooks."""
    need(not hasattr(io, 'close_not_launched'), 'parent_IO_once_prebind_binding')

    def close(self, stage, attempted, cleanup_end):
        return prebind_failure.close(once, emitted, RPC_original, A_original, stage, attempted, deadline=cleanup_end, tag=tag + '-' + stage)
    io.close_not_launched = types.MethodType(close, io)
    return io
