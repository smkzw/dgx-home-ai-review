# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual accepted five bodies / old118 map; future final wire/config are CPU source fixtures."""
import copy, hashlib, json, pathlib, runpy, sys, unittest
H = pathlib.Path(__file__).resolve().parent
R = H.parent
b = runpy.run_path(str(H / 'binder.py'))
BASE = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
packet = json.loads((BASE / 'FINAL_GRAPH/PC/epoch-packet.json').read_bytes())
q = json.loads((BASE / 'CPU/OWNER_EIGHTH/PC/current-source-qualified.json').read_bytes())
old = packet['new_config_raw_utf8'].encode()
oldcfg = json.loads(old)
assert oldcfg['PC_source_pins'] == q['current']['current_source118']
paths = {'/opt/dgx-v4/hx/runtime/llm_gateway/scheduler.py': R / 'R17_GATEWAY_DURABLE_TERMINAL_SOURCE_R1/SOURCE/llm_gateway/scheduler.py', '/opt/dgx-v4/hx/runtime/llm_gateway/server.py': R / 'R17_GATEWAY_DURABLE_TERMINAL_SOURCE_R2/SOURCE/llm_gateway/server.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/shared_scheduler.py': R / 'R17_GATEWAY_DURABLE_TERMINAL_SOURCE_R1/SOURCE/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/shared_scheduler.py', '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/gateway.py': R / 'R17_GATEWAY_DURABLE_TERMINAL_SOURCE_R1/SOURCE/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/gateway.py', '/opt/dgx-v4/hx/runtime/llm_gateway/validation.py': R / 'R17_FINITE_JSON_GATEWAY_SOURCE_R1/src/llm_gateway/validation.py'}
five = {p: f.read_bytes() for p, f in paths.items()}
ctx = {'APPROVED_REVIEW': 'c' * 64, 'APPROVED_PREDECESSOR_IDENTITY': q['current']['manager_identity'], 'APPROVED_PREDECESSOR_CONFIG_SHA': b['sha'](old), 'OPERATION': packet['grant_operation'], 'EPOCH_OPERATION': packet['operation'], 'ENTRY_PHASE': packet['entry_phase'], 'SCOPE_UNIT': 'CPU-only-not-launched.service', 'PC_ROOT': '/opt/dgx-v4/hx/CPU-only-dag-fixture', 'PARENT_SOURCE_BUNDLE': '/home/REDACTED_USER/CPU-only-never-staged.json'}
refs = {str(p): {'sha256': b['sha'](p.read_bytes()), 'bytes': p.stat().st_size} for p in [BASE / 'FINAL_GRAPH/PC/epoch-packet.json', BASE / 'CPU/OWNER_EIGHTH/PC/current-source-qualified.json', *paths.values()]}
(H / 'CPU_INPUT_REFS.json').write_text(json.dumps(refs, sort_keys=True, indent=2) + '\n')

def domain():
    return b['service_domain'](old_config_raw=old, old_source_files=q['current']['source_files'], old_config_stat=q['current']['config_stat'], runtime_five=five, contract_values=ctx)

def finish(d, suffix=''):
    wire = ('# CPU-only final wire; never launched\nHELPER_PINS=' + repr({k: b['sha'](v) for k, v in {'contract': d.contract, 'source_delta': d.delta_source, 'policy': d.policy_source}.items()}) + '\n' + suffix).encode()
    newmap = dict(oldcfg['PC_source_pins'], **{p: b['sha'](raw) for p, raw in five.items()}, **{b['WIRE']: b['sha'](wire)})
    cfg = b['encode'](dict(oldcfg, PC_source_pins=newmap, review_sha256=ctx['APPROVED_REVIEW']))
    src = b['inputs']()
    tools = b['source_tools'](src['recipe__source_io.py'])
    worker = tools['bind'](src['R16__worker.py'], {'ROLE': 'epoch', 'APPROVED_REVIEW': ctx['APPROVED_REVIEW']})
    qual = tools['bind'](src['delta__qualifier.py'], {'APPROVED_REVIEW': ctx['APPROVED_REVIEW'], 'APPROVED_WORKER_SHA': b['sha'](worker)})
    native = {'APPROVED_INPUT_PINS': {}, 'APPROVED_OLD_CONFIG_SHA': b['sha'](old), 'APPROVED_NEW_CONFIG_SHA': b['sha'](cfg), 'APPROVED_STOPPED_LIVE_IDLE_SHA': None, 'APPROVED_PRESTART_PROBE_SHA': None}
    fields = {k: packet[k] for k in ('entry_phase', 'operation', 'grant_operation', 'old_identity', 'helpers', 'input_pins', 'historical_ancestor_sha256', 'historical_oldmap', 'old_grant_operation')}
    fields['old_identity'] = q['current']['manager_identity']
    return (b['bind_root'](d, final_wire=wire, final_config=cfg, qualifier=qual, worker=worker, native_values=native, packet_fields=fields), cfg)

class Tests(unittest.TestCase):

    @classmethod
    def setUpClass(c):
        c.d = domain()
        c.g, c.cfg = finish(c.d)

    def test_seven_CAS_exact_old_map_complement_and_no_duplicate_wire(self):
        g = self.g
        p = g['packet']
        self.assertEqual(len(p['source_delta']['sources']), 6)
        self.assertEqual(g['unchanged_count'], 112)
        self.assertEqual(len(p['changed_source_raw_utf8']), 6)
        self.assertNotIn('wire_raw_utf8', p)
        m = b['private_load']({k: (raw, b['sha'](raw)) for k, raw in {'contract': g['Root']['contract.py'], 'source_delta': g['Root']['pc/source_delta.py']}.items()}, ('contract', 'source_delta'))
        self.assertEqual(len(m['source_delta'].targets(p, m['contract'].APPROVED_SOURCE_DELTA)), 7)

    def test_DAG_no_service_wire_config_or_qualifier_cycle(self):
        g2, cfg2 = finish(self.d, '# different CPU final wire\n')
        self.assertEqual(self.g['service'], g2['service'])
        self.assertNotEqual(self.g['Root']['contract.py'], g2['Root']['contract.py'])
        self.assertEqual(self.g['Root']['pc/qualifier.py'], g2['Root']['pc/qualifier.py'])
        self.assertEqual(self.g['Root']['epoch-scope/worker.py'], g2['Root']['epoch-scope/worker.py'])
        for source in self.g['service'].values():
            self.assertNotIn(b['sha'](self.cfg).encode(), source)
            self.assertNotIn(self.g['packet']['newmap'][b['WIRE']].encode(), source)
        self.assertEqual(self.g['phase_contract_ref']['sha256'], b['sha'](self.d.contract))
        self.assertNotEqual(self.d.contract, self.g['Root']['contract.py'])

    def test_service_derives_only_internal_config_and_static_five(self):
        table = {'contract': self.d.contract, 'source_delta': self.d.delta_source, 'service_delta_policy': self.d.policy_source}
        m = b['private_load']({k: (v, b['sha'](v)) for k, v in table.items()}, ('contract', 'source_delta', 'service_delta_policy'))
        config = json.loads(self.cfg)
        config['_config_sha256'] = b['sha'](self.cfg)
        d = m['service_delta_policy'].approved_from_internal_config(config)
        self.assertEqual(d, self.g['source_delta'])
        wrong = copy.deepcopy(config)
        wrong['PC_source_pins'][next(iter(five))] = 'f' * 64
        with self.assertRaises(RuntimeError):
            m['service_delta_policy'].approved_from_internal_config(wrong)
        other = next((p for p in oldcfg['PC_source_pins'] if p not in d['sources'] and p not in five and (p != b['WIRE'])))
        wrong = copy.deepcopy(config)
        wrong['PC_source_pins'][other] = 'f' * 64
        with self.assertRaises(RuntimeError):
            m['service_delta_policy'].approved_from_internal_config(wrong)
        with self.assertRaises(RuntimeError):
            m['service_delta_policy'].approved_from_internal_config(json.loads(self.cfg))

    def test_private_source_order_SHA_and_unknown_import(self):
        table = {'contract': (self.d.contract, b['sha'](self.d.contract)), 'source_delta': (self.d.delta_source, b['sha'](self.d.delta_source))}
        with self.assertRaises(ValueError):
            b['private_load'](table, ('source_delta', 'contract'))
        wrong = dict(table)
        wrong['contract'] = (self.d.contract + b'\n', '0' * 64)
        with self.assertRaises(ValueError):
            b['private_load'](wrong, ('contract', 'source_delta'))
        raw = b'import unknown_external\n'
        with self.assertRaises(ValueError):
            b['private_load']({'x': (raw, b['sha'](raw))}, ('x',))

    def test_exact_payload_F9_and_v1_record_refused(self):
        g = self.g
        m = b['private_load']({k: (raw, b['sha'](raw)) for k, raw in {'contract': g['Root']['contract.py'], 'source_delta': g['Root']['pc/source_delta.py']}.items()}, ('contract', 'source_delta'))
        p = copy.deepcopy(g['packet'])
        p['changed_source_raw_utf8'][b['WIRE']] += 'x'
        with self.assertRaises(RuntimeError):
            m['contract'].fixed_packet(p)
        p = copy.deepcopy(g['packet'])
        p['source_delta']['sources'][0]['old_stat'][1] += 1
        with self.assertRaises(RuntimeError):
            m['contract'].fixed_packet(p)
        with self.assertRaises(RuntimeError):
            m['source_delta'].verify_installed({'schema': 'registry-R26-PC-installed-unqualified/v1'}, g['source_delta'])

    def test_complement_same_bytes_new_inode_before_any_CAS_refused(self):
        g = self.g
        m = b['private_load']({k: (raw, b['sha'](raw)) for k, raw in {'contract': g['Root']['contract.py'], 'source_delta': g['Root']['pc/source_delta.py']}.items()}, ('contract', 'source_delta'))
        before = copy.deepcopy(q['current'])
        name = next((p for p in oldcfg['PC_source_pins'] if p not in five and p != b['WIRE']))
        before['source_files'][name]['stat'][1] += 1
        with self.assertRaises(RuntimeError):
            m['source_delta'].before_matches(before, g['source_delta'])

    def test_cross_domain_record_and_receipt_self_config_refusal(self):
        g = self.g
        d = g['source_delta']
        after = copy.deepcopy(q['current'])
        after['current_source118'] = g['packet']['newmap']
        after['config_sha256'] = b['sha'](self.cfg)
        for i, row in enumerate(d['sources'] + [d['config']], 1):
            meta = list(row['old_stat'])
            meta[1] += 100000 + i
            meta[2] = len(self.cfg) if row['path'] == b['CONFIG'] else len(g['packet']['changed_source_raw_utf8'][row['path']].encode())
            meta[8] += 1
            if row['path'] == b['CONFIG']:
                after['config_stat'] = meta
            else:
                after['source_files'][row['path']] = {'sha256': row['new_sha256'], 'stat': meta}
        originals = [dict(row, new_stat=after['config_stat'] if row['path'] == b['CONFIG'] else after['source_files'][row['path']]['stat']) for row in d['sources'] + [d['config']]]
        inst = {'schema': 'registry-R26-PC-installed-unqualified/v2', 'source_delta': d, 'before': q['current'], 'current': after, 'CAS_calls': 7, 'cas_originals': originals, 'unchanged_source_count': 112, 'normal_stop_calls': 1, 'normal_start_calls': 1, 'socket_unlink_calls': 0, 'models_started': 0}
        table = {'contract': self.d.contract, 'source_delta': self.d.delta_source, 'service_delta_policy': self.d.policy_source}
        m = b['private_load']({k: (v, b['sha'](v)) for k, v in table.items()}, ('contract', 'source_delta', 'service_delta_policy'))
        cfg = json.loads(self.cfg)
        cfg['_config_sha256'] = b['sha'](self.cfg)
        self.assertEqual(m['service_delta_policy'].verify_installed(inst, cfg), 112)
        forged = copy.deepcopy(inst)
        forged['source_delta']['config']['new_sha256'] = 'f' * 64
        with self.assertRaises(RuntimeError):
            m['service_delta_policy'].verify_installed(forged, cfg)

    def test_single_pinned_payload_getter_all_seven_and_unknown_refusal(self):
        g = self.g
        m = b['private_load']({k: (raw, b['sha'](raw)) for k, raw in {'contract': g['Root']['contract.py'], 'source_delta': g['Root']['pc/source_delta.py']}.items()}, ('contract', 'source_delta'))
        d = g['source_delta']
        p = g['packet']
        helper = m['source_delta']
        self.assertEqual(len(helper.targets(p, d)), 7)
        self.assertEqual(helper.payload(p, b['WIRE'], d), p['changed_source_raw_utf8'][b['WIRE']].encode())
        self.assertEqual(helper.payload(p, b['CONFIG'], d), self.cfg)
        with self.assertRaises(RuntimeError):
            helper.payload(p, '/unknown', d)

    def test_accepted_source_bytes_and_full_F9_required(self):
        wrong = dict(five)
        key = next(iter(wrong))
        wrong[key] += b'\n'
        with self.assertRaises(ValueError):
            b['service_domain'](old_config_raw=old, old_source_files=q['current']['source_files'], old_config_stat=q['current']['config_stat'], runtime_five=wrong, contract_values=ctx)
        wrong = copy.deepcopy(q['current']['source_files'])
        wrong.pop(next(iter(wrong)))
        with self.assertRaises(ValueError):
            b['service_domain'](old_config_raw=old, old_source_files=wrong, old_config_stat=q['current']['config_stat'], runtime_five=five, contract_values=ctx)

    def test_original_serialized_encoding_metadata_and_limits(self):
        files = dict(self.g['Root'])
        files['epoch-index.json'] = b['encode']({'review_sha256': ctx['APPROVED_REVIEW'], 'files': {n: b['sha'](raw) for n, raw in files.items()}})
        v = b['measure'](files)
        self.assertTrue(v['metadata_counted'])
        self.assertGreater(v['serialized_PC_source_bundle_bytes'], v['all_source_bytes'])
        self.assertEqual(v['physical128_acceptance'], 'PENDING_MAIN_DEDUP_FULL_GRAPH')
        wrong = dict(files)
        wrong['oversize.py'] = b'x' * (2097152 + 1)
        with self.assertRaises(ValueError):
            b['measure'](wrong)
        wrong = dict(files)
        wrong['large-a.py'] = b'x' * 1800000
        wrong['large-b.py'] = b'x' * 1800000
        with self.assertRaises(ValueError):
            b['measure'](wrong)
        (H / 'MEASURE_CPU_FRAGMENT.json').write_text(json.dumps(v, sort_keys=True, indent=2) + '\n')
if __name__ == '__main__':
    unittest.main(verbosity=2)
