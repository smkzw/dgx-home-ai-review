# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Trusted internal late scope derivation. No caller-selected source or permission.
A fresh private renderer/held closure per call; service globals are never rebound.
"""
import base64, builtins, os, re, sys, types
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, sha, encode, protected_read
from contract import PC_ROOT, OPERATION, EPOCH_OPERATION, APPROVED_REVIEW
APPROVED_RENDERER = {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-renderer.py', 'sha256': 'da6899595a2e3af7e78f947f5435b066abd812f56104619ebb9d169b34f8e7b8'}
APPROVED_LOADER = {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-held-loader.py', 'sha256': '67cbc03712da35aeaa2e76b98bb5cbc89ddf989e6a736d3821f0c127546d7e66'}
APPROVED_TEMPLATES = {'historical-fixed': {'B_OWNER_RECOVERY_R25_WIRING.common': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'B_OWNER_RECOVERY_R25_WIRING.common', 'sha256': 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'}, 'bounded_process': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'bounded_process', 'sha256': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f'}, 'history_publication': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_publication', 'sha256': '70fb096fb1baae20dd2dbecfcad593b8f770b5d46b2f0fbaf0b90954c41d02d8'}, 'history_reader_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_a', 'sha256': 'b0d1c785cdc0ba27cacd07ab62582a1ecbbd18e5053ae88d7fef7fe172a09049'}, 'history_reader_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_pc', 'sha256': 'd7434d7f7815fea509ae187a4b699f879e31d13eb9e337349b0a8e76281faaa7'}, 'not_launched_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'not_launched_history', 'sha256': 'a98667ccaf33b707f0dbac291bee08a64cb61555363d184dbe28094c1caee0fb'}, 'observer': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'observer', 'sha256': '5bbe537a7d145bddeca96dcdf665d5fc286356cd3bf89c8242db432b06f70b71'}, 'old_failed_kernel': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'old_failed_kernel', 'sha256': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd'}, 'plan': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'plan', 'sha256': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f'}, 'proc_lifetime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'proc_lifetime', 'sha256': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d'}, 'publication_fs_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_a', 'sha256': '9eb4e5afd13ce9681c186ca5cc1aa3b7d43101df8851e46a350dc0ccbf7fbd61'}, 'publication_fs_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_pc', 'sha256': '56ac434b84f1e3a92e53014c9a1d2a0d393a07921fd003ae8e17bd5bc597a95e'}, 'ready_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'ready_history', 'sha256': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5'}, 'receipt_codec': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'receipt_codec', 'sha256': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312'}, 'root_io': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'root_io', 'sha256': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e'}, 'zero_negative': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_negative', 'sha256': '4909b66fab499e174e1a948b4b430b0ecf38e6da7712345d826dc528f2faf465'}, 'zero_pc_clock': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_pc_clock', 'sha256': '75d3bb7060cd64287bc7b061fc4f00ce511355ec5e2de7c83e3d7bbdc8da18ff'}, 'zero_qualified': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_qualified', 'sha256': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86'}, 'zero_scope': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_scope', 'sha256': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16'}, 'zero_runtime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_runtime', 'sha256': 'bab1c94680e97e9d3087538721a2202cb1935561dfb4236fd9da34f216c1d7a6'}}, 'current-stage-prebind': {'B_OWNER_RECOVERY_R25_WIRING.common': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'B_OWNER_RECOVERY_R25_WIRING.common', 'sha256': 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'}, 'bounded_process': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'bounded_process', 'sha256': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f'}, 'history_publication': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_publication', 'sha256': '70fb096fb1baae20dd2dbecfcad593b8f770b5d46b2f0fbaf0b90954c41d02d8'}, 'history_reader_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_a', 'sha256': 'b0d1c785cdc0ba27cacd07ab62582a1ecbbd18e5053ae88d7fef7fe172a09049'}, 'history_reader_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_pc', 'sha256': 'd7434d7f7815fea509ae187a4b699f879e31d13eb9e337349b0a8e76281faaa7'}, 'not_launched_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'not_launched_history', 'sha256': 'a98667ccaf33b707f0dbac291bee08a64cb61555363d184dbe28094c1caee0fb'}, 'observer': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'observer', 'sha256': '5bbe537a7d145bddeca96dcdf665d5fc286356cd3bf89c8242db432b06f70b71'}, 'old_failed_kernel': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'old_failed_kernel', 'sha256': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd'}, 'plan': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'plan', 'sha256': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f'}, 'proc_lifetime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'proc_lifetime', 'sha256': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d'}, 'publication_fs_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_a', 'sha256': '9eb4e5afd13ce9681c186ca5cc1aa3b7d43101df8851e46a350dc0ccbf7fbd61'}, 'publication_fs_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_pc', 'sha256': '56ac434b84f1e3a92e53014c9a1d2a0d393a07921fd003ae8e17bd5bc597a95e'}, 'ready_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'ready_history', 'sha256': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5'}, 'receipt_codec': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'receipt_codec', 'sha256': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312'}, 'root_io': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'root_io', 'sha256': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e'}, 'zero_negative': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_negative', 'sha256': '4909b66fab499e174e1a948b4b430b0ecf38e6da7712345d826dc528f2faf465'}, 'zero_pc_clock': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_pc_clock', 'sha256': '75d3bb7060cd64287bc7b061fc4f00ce511355ec5e2de7c83e3d7bbdc8da18ff'}, 'zero_qualified': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_qualified', 'sha256': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86'}, 'zero_scope': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_scope', 'sha256': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16'}, 'zero_runtime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_runtime', 'sha256': 'bab1c94680e97e9d3087538721a2202cb1935561dfb4236fd9da34f216c1d7a6'}, 'current_clock': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'current_clock', 'sha256': '587ac7ed8d956fe6c0b3ffc368fa64292257a55425fa301bc066707b3bdea875'}, 'current_negative': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'current_negative', 'sha256': '5187857874f57fc384934a40b8a06357ab735f95d6733239e16f4cf93fb872fc'}, 'current_scope': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'current_scope', 'sha256': '7822ffbb9297807d656dab73702bbc411c84a506ad2923148813b73ff2e816b9'}, 'current_qualified': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'current_qualified', 'sha256': '06867ed09d2c5529a00f16a487d02e15639acf2f8961d1ddaa7c74df5cf71424'}, 'known_prior_assets': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'known_prior_assets', 'sha256': '02bdd4e05e83c50d60cbb42804271d6b5ec5f4bae9b4a11ef7638ce404e16797'}, 'stage_naming': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'stage_naming', 'sha256': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d'}}, 'failed-empty-range-repair': {'B_OWNER_RECOVERY_R25_WIRING.common': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'B_OWNER_RECOVERY_R25_WIRING.common', 'sha256': 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'}, 'bounded_process': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'bounded_process', 'sha256': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f'}, 'history_publication': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_publication', 'sha256': '70fb096fb1baae20dd2dbecfcad593b8f770b5d46b2f0fbaf0b90954c41d02d8'}, 'history_reader_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_a', 'sha256': 'b0d1c785cdc0ba27cacd07ab62582a1ecbbd18e5053ae88d7fef7fe172a09049'}, 'history_reader_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'history_reader_pc', 'sha256': 'd7434d7f7815fea509ae187a4b699f879e31d13eb9e337349b0a8e76281faaa7'}, 'not_launched_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'not_launched_history', 'sha256': 'a98667ccaf33b707f0dbac291bee08a64cb61555363d184dbe28094c1caee0fb'}, 'observer': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'observer', 'sha256': '5bbe537a7d145bddeca96dcdf665d5fc286356cd3bf89c8242db432b06f70b71'}, 'old_failed_kernel': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'old_failed_kernel', 'sha256': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd'}, 'plan': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'plan', 'sha256': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f'}, 'proc_lifetime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'proc_lifetime', 'sha256': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d'}, 'publication_fs_a': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_a', 'sha256': '9eb4e5afd13ce9681c186ca5cc1aa3b7d43101df8851e46a350dc0ccbf7fbd61'}, 'publication_fs_pc': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'publication_fs_pc', 'sha256': '56ac434b84f1e3a92e53014c9a1d2a0d393a07921fd003ae8e17bd5bc597a95e'}, 'ready_history': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'ready_history', 'sha256': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5'}, 'receipt_codec': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'receipt_codec', 'sha256': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312'}, 'root_io': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'root_io', 'sha256': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e'}, 'zero_negative': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_negative', 'sha256': '4909b66fab499e174e1a948b4b430b0ecf38e6da7712345d826dc528f2faf465'}, 'zero_pc_clock': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_pc_clock', 'sha256': '75d3bb7060cd64287bc7b061fc4f00ce511355ec5e2de7c83e3d7bbdc8da18ff'}, 'zero_qualified': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_qualified', 'sha256': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86'}, 'zero_scope': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_scope', 'sha256': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16'}, 'zero_runtime': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'zero_runtime', 'sha256': 'bab1c94680e97e9d3087538721a2202cb1935561dfb4236fd9da34f216c1d7a6'}, 'current_clock': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'failed-empty-range-repair:current_clock', 'sha256': '0b5870efab8f7b760c108bbf583a451c0a3a7f97d531dca2ff196c473bfa06da'}, 'current_negative': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'failed-empty-range-repair:current_negative', 'sha256': '5a5c4656867578f40566959e2d73d78b5329cf08cd8c34e8437d12e3d122aa09'}, 'current_scope': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'failed-empty-range-repair:current_scope', 'sha256': '2af2e7ba8cc6b976e0c61b1676fe4f15d471b31b949b8686b5da33e705c319ec'}, 'current_qualified': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'failed-empty-range-repair:current_qualified', 'sha256': 'b92b68e64ed8a7dd067354c49be7095047b1e4edf829aa505ab7fff2e549bf26'}, 'stage_naming': {'path': '/opt/dgx-v4/hx/mimo-registry-r16/readonly-template-source.json', 'bundle_sha256': 'da18c0a1f6ec6196612fe028c8e68eeed746948abe5dbe7d95beffdfa60c6197', 'bundle_key': 'stage_naming', 'sha256': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d'}}}
APPROVED_STATIC = {'historical-fixed': {'policy': None, 'packed_pins': {'pc': {'packed_sha256': '0b0ca235f283257ee2376b2fafb273b0671f4a4a765f2e4e003869164a135d4d', 'raw_sha256': 'b926d4cd5109e64ce4ed018a19130db71f7b37ee61e124fbbe69c2a8e4362039'}, 'a': {'packed_sha256': 'd87052e5937711927ef3a1e2b1a1614294b9446279a852b2a117b168a6b0ba2c', 'raw_sha256': 'f7b27ba689057403411d3ad20e8eba4ce6b678a4724b8ee827824b338e5e7992'}, 'sources': {'packed_sha256': '087774e024094969e1d76c9f85a98fbe5406c9c5d020196b3345b10e752b0f00', 'raw_sha256': 'ecce14f7542063b278a9d32f9c7addb343d5cc5bd824cafed5c9fd7215786433'}}, 'publication_operation': '2b9e9b631cebc13ae6b1550ee59c13ed'}, 'current-stage-prebind': {'policy': None, 'packed_pins': None, 'publication_operation': None}, 'failed-empty-range-repair': {'policy': None, 'packed_pins': None, 'publication_operation': None}}
APPROVED_CURRENT_READER_SHA = '4d9331fa6e3f7de1f4fef7beee2f3ad9007b3f68bf1a25f19f660f8c89250eab'
APPROVED_A_ORIGIN = None

def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def _pure(raw, path, name):

    def imports(module, globals=None, locals=None, fromlist=(), level=0):
        need(not level and module.split('.')[0] in sys.stdlib_module_names, 'late_scope_only_pinned_source_or_stdlib')
        return builtins.__import__(module, globals, locals, fromlist, level)
    m = types.ModuleType(name)
    m.__file__ = str(path)
    m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m

def current_policy(g=None):
    """Held Root-origin source data, not a caller permission or mutable global."""
    need(type(APPROVED_A_ORIGIN) is dict, 'late_scope_A_origin_SOURCE_None')
    raw, st = protected_read(PC_ROOT / 'A-source-origin.json', limit=2097152)
    v = strict(raw)
    need(st[3:7] == [0, 989, 33056, 1] and set(v) == {'schema', 'current', 'A_original'} and (v['schema'] == 'R12-PC-held-A-source-origin/v1'), 'late_scope_A_origin_PC_original')
    if g is not None:
        need(v['current']['config_sha256'] == g.config['_config_sha256'] and v['current']['source118'] == g.config['PC_source_pins'] and (v['current']['review_sha256'] == APPROVED_REVIEW), 'late_scope_A_origin_same_static_source')
    row = v['A_original']
    b = base64.b64decode(row['raw_b64'], validate=True)
    need(set(row) == {'raw_b64', 'sha256', 'F9'} and sha(b) == row['sha256'] and (row['F9'][2] == len(b)) and (row['F9'][3:7] == [0, 0, 33152, 1]), 'late_scope_original_A_raw_F9')
    a = strict(b)
    fixed = APPROVED_A_ORIGIN
    need(set(a) == {'schema', 'source_root', 'source_epoch', 'review_sha256', 'files', 'boot_original'} and a['schema'] == 'R12-A-source-held-original/v1' and (a['source_root'] == fixed['source_root']) and (a['source_epoch'] == EPOCH_OPERATION) and (a['review_sha256'] == APPROVED_REVIEW) and (set(a['files']) == set(fixed['source_pins'])), 'late_scope_A_origin_exact_complete_source')
    for n, r in a['files'].items():
        f = r['F9']
        need(set(r) == {'sha256', 'F9'} and r['sha256'] == fixed['source_pins'][n] and (type(f) is list) and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[0] > 0) and (f[1] > 0) and (f[2] == fixed['source_sizes'][n]) and (f[3:7] == [0, 0, 33152, 1]), 'late_scope_A_origin_every_full_source_F9')
    boot = a['boot_original']
    br = base64.b64decode(boot['raw_b64'], validate=True)
    need(set(boot) == {'raw_b64', 'sha256', 'F9'} and sha(br) == boot['sha256'] and (len(br) == 37) and (boot['F9'][2] == 0) and (boot['F9'][3] == 0) and (boot['F9'][6] == 1) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\n', br.decode()), 'late_scope_A_origin_actual_boot')
    need(protected_read(PC_ROOT / 'A-source-origin.json', limit=2097152) == (raw, st), 'late_scope_A_origin_held_after')
    return {'source_root': fixed['source_root'], 'data_root': fixed['data_root'], 'sources': a['files'], 'index_sha256': fixed['index_sha256'], 'ready_worker_sha256': fixed['ready_worker_sha256'], 'boot_id': br.decode().strip()}

def actor_validator(g):
    """One internal private module; no service/global approval rebinding."""
    policy = current_policy(g)
    packet, ps = protected_read(PC_ROOT / 'epoch-packet.json', limit=2097152)
    p = strict(packet)
    path = PC_ROOT / 'service/current_negative.py'
    raw, st = protected_read(path, limit=2097152)
    need(p['operation'] == EPOCH_OPERATION and p['grant_operation'] == OPERATION and (p['newmap'] == g.config['PC_source_pins']) and (sha(p['new_config_raw_utf8'].encode()) == g.config['_config_sha256']) and (sha(raw) == p['helpers']['current_negative.py']) and (st[3:7] == [0, 989, 33056, 1]), 'late_scope_actor_actual_held_validator')
    m = types.ModuleType('private_current_actor_validator')
    m.__file__ = str(path)
    m.__dict__['__builtins__'] = __builtins__
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    m.APPROVED_POLICY = policy
    m.APPROVED_REVIEW = APPROVED_REVIEW
    m.ROOT = PC_ROOT / 'current-prebind-readonly'
    m.OPERATION = OPERATION
    need(protected_read(path, limit=2097152) == (raw, st) and protected_read(PC_ROOT / 'epoch-packet.json', limit=2097152) == (packet, ps), 'late_scope_actor_source_F9_after')
    return m

def _consume(mode, g, qualified_raw, qualified_F9, actor_raw, now, *, historical):
    need(mode in ('historical-fixed', 'current-stage-prebind', 'failed-empty-range-repair') and type(APPROVED_STATIC) is dict and (mode in APPROVED_STATIC) and (type(APPROVED_TEMPLATES) is dict) and (mode in APPROVED_TEMPLATES) and (APPROVED_RENDERER is not None) and (APPROVED_LOADER is not None) and (APPROVED_CURRENT_READER_SHA is not None), 'late_scope_SOURCE_None_harddeny')
    need(historical or g.lock.locked(), 'late_scope_same_private_grant_lock')
    g.same()

    def source_context():
        if historical and mode == 'failed-empty-range-repair':
            from current_epoch import consume_installation
            value = consume_installation(protected_read, g.config, now)
            need(value['historical_only'] is True, 'empty_repair_original_installation_history_only')
            return value
        return g.current_epoch()
    source_context()
    need(g.config['review_sha256'] == APPROVED_REVIEW, 'late_scope_internal_new_source_review')
    v = strict(qualified_raw)
    c = v['current'] if historical else {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'manager_identity': identity(), 'source118': g.config['PC_source_pins']}
    need(c['review_sha256'] == APPROVED_REVIEW and c['config_sha256'] == g.config['_config_sha256'] and (c['source118'] == g.config['PC_source_pins']), 'late_scope_history_same_source_not_new_PID_authority')
    need(v['current'] == c and v['review_sha256'] == APPROVED_REVIEW and (qualified_F9[2] == len(qualified_raw)) and (qualified_F9[3:7] == [0, 989, 33056, 1]), 'late_scope_actual_internal_current_Root_receipt')
    held = {}

    def read(path, pin=None):
        path = Path(path)
        raw, f9 = held[path] if path in held else protected_read(path, limit=2097152)
        need(pin is None or sha(raw) == pin, 'late_scope_exact_source_pin')
        held[path] = (raw, f9)
        return (raw, f9)
    br = base64.b64decode(v['begin']['raw_b64'], validate=True)
    need(sha(br) == v['begin']['sha256'], 'late_scope_full_BEGIN_original')
    nonce = strict(br)['request_nonce']
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'late_scope_actual_request_nonce')
    if mode == 'historical-fixed':
        need(actor_raw is None and (historical or g.asset_stages.zero_pending is not None), 'late_scope_fixed_history_no_caller_actor')
        target = PC_ROOT / 'zero-readonly' / nonce
    else:
        need(type(actor_raw) is bytes, 'late_scope_owned_current_actor_only')
        actor = strict(actor_raw)
        need(actor['current'] == c and nonce == actor['stage_operation'], 'late_scope_actor_current_context_and_owned_nonce')
        if not historical:
            active = g.asset_stages.active
            if mode == 'failed-empty-range-repair':
                from empty_range_repair import actor as original_actor
                original, _, _ = original_actor(g.asset_stages, actor['stage_operation'])
                need(active is None and original == actor_raw, 'late_scope_empty_repair_internal_original_no_active_work')
            else:
                need(active is not None and actor['stage_operation'] == active['stage_operation'] and (actor['plan_original']['sha256'] == active['plan_ref']['sha256']) and (actor['ordinal'] == active['ordinal']), 'late_scope_actor_not_body_selected')
        target = PC_ROOT / ('asset-empty-repairs' if mode == 'failed-empty-range-repair' else 'current-prebind-readonly') / actor['stage_operation']
    qraw, qf = read(target / ('qualified.json' if mode == 'failed-empty-range-repair' else 'not-launched-qualified.json'))
    need(qraw == qualified_raw, 'late_scope_original_qualified_not_restamped_copy')
    packet_raw, _ = read(PC_ROOT / 'epoch-packet.json')
    p = strict(packet_raw)
    cfg = p['new_config_raw_utf8'].encode()
    need(sha(cfg) == c['config_sha256'] and strict(cfg)['PC_source_pins'] == c['source118'] and (p['operation'] == EPOCH_OPERATION) and (p['grant_operation'] == OPERATION) and (p['newmap'] == c['source118']), 'late_scope_new_packet_config_current118')
    reader, _ = read(PC_ROOT / 'pc/current_reader.py', APPROVED_CURRENT_READER_SHA)
    renderer_raw, _ = read(APPROVED_RENDERER['path'], APPROVED_RENDERER['sha256'])
    loader_raw, _ = read(APPROVED_LOADER['path'], APPROVED_LOADER['sha256'])
    renderer = _pure(renderer_raw, APPROVED_RENDERER['path'], 'private_late_renderer')
    templates = {}
    for n, row in APPROVED_TEMPLATES[mode].items():
        if 'bundle_key' in row:
            bundle = strict(read(row['path'], row['bundle_sha256'])[0])
            need(set(bundle) == {'schema', 'files'} and bundle['schema'] == 'R12-readonly-template-source/v1' and (row['bundle_key'] in (n, mode + ':' + n)), 'late_scope_fixed_template_bundle')
            item = bundle['files'][row['bundle_key']]
            raw = base64.b64decode(item['source_bytes_base64'], validate=True)
            need(sha(raw) == item['sha256'] == row['sha256'] and len(raw) == item['source_bytes'], 'late_scope_template_original_fullbytes')
        else:
            raw = read(row['path'], row['sha256'])[0]
        templates[n] = raw
    static = APPROVED_STATIC[mode]
    scope_policy = current_policy(g) if mode in ('current-stage-prebind', 'failed-empty-range-repair') else static['policy']
    approved = {'mode': mode, 'review': APPROVED_REVIEW, 'policy': scope_policy, 'operation': OPERATION, 'current_reader_sha256': sha(reader), 'current_reader_input_pins': p['input_pins'], 'packed_pins': static['packed_pins'], 'publication_operation': static['publication_operation']}
    plan = renderer.render_plan(c, nonce, actor_raw, approved=approved, templates=templates, loader=loader_raw)
    need(plan['PC']['root'] == str(target), 'late_scope_derived_fixed_namespace')
    for name, raw in plan['PC']['files'].items():
        need(read(target / name)[0] == raw, 'late_scope_rederived_complete_PC_source_bytes')
    ack_raw, _ = read(target / 'prestage-ack.json')
    ack = strict(ack_raw)
    need(ack['schema'] == 'zero-readonly-prestage-ack/v1' and ack['root'] == plan['A']['root'] and (ack['nonce'] == nonce) and (ack['request_sha256'] == sha(plan['A']['files']['request.json'])) and (ack['clock_started'] is False) and (set(ack['files']) == set(plan['A']['files'])), 'late_scope_full_A_prepublication_source_set')
    for name, raw in plan['A']['files'].items():
        row = ack['files'][name]
        f = row['F9']
        need(row['sha256'] == sha(raw) and type(f) is list and (len(f) == 9) and all((type(x) is int and x >= 0 for x in f)) and (f[2] == len(raw)) and (f[3:7] == [0, 0, 33152, 1]), 'late_scope_actual_A_fullsource_SHA_F9')
    loader = _pure(loader_raw, APPROVED_LOADER['path'], 'private_late_scope_loader')
    context = loader.load(target, sha(plan['PC']['files']['spec.json']))
    consumer = context.module('zero_qualified' if mode == 'historical-fixed' else 'current_qualified')
    outer = strict(context.module('receipt_codec').unpack(v['A_proof']))
    context.module('zero_runtime').clock_causality(context, outer, br)
    consume_at = now if historical else g.runtime.manager._now()
    if mode == 'historical-fixed':
        pcraw, araw, _ = context.module('not_launched_history').histories()
        result = consumer.consume(qualified_raw, qf, araw, pcraw, c, consume_at)
    else:
        result = consumer.consume(qualified_raw, qf, actor_raw, actor_raw, c, consume_at)
    need(all((protected_read(path, limit=2097152) == row for path, row in held.items())), 'late_scope_held_source_F9_after_full_consumer')
    g.same()
    source_context()
    if not historical:
        final_now = g.runtime.manager._now()
        begin = strict(br)
        need(0 <= final_now - begin['PC_sent_at'] <= 30, 'late_scope_final_real_now_original_BEGIN_whole30')
    return result

def consume(mode, g, qualified_raw, qualified_F9, actor_raw, now):
    return _consume(mode, g, qualified_raw, qualified_F9, actor_raw, now, historical=False)

def consume_history(mode, g, qualified_raw, qualified_F9, actor_raw, event_time):
    """Only complete immutable completion-chain callers; no writes or release.
 The caller must first verify intent/completed/fence and bind event_time to its
 original completion. This does not accept a current work request or clear hold.
 """
    return _consume(mode, g, qualified_raw, qualified_F9, actor_raw, event_time, historical=True)
