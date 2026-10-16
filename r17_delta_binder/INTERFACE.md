# Finite offline late binder

SOURCE only; no CLI action, Runtime, installed source or actual epoch is produced. ACTUAL_CONTEXT=None and every result has native_eligible=false/actual_slots=None. Mode execution: the bounded two-domain source compiler and narrow pure CPU checks resolve the known hash-DAG cut without touching the main graph.

## Two stages and exact inputs

`service_domain(*, old_config_raw, old_source_files, old_config_stat, runtime_five, contract_values) -> ServiceDomain`

- old_config_raw: complete original config bytes (PC_source_pins exactly118).
- old_source_files: exactly118 `{path:{sha256,stat:full9}}` rows; old_config_stat full9. These are main-supplied original facts, never inferred from a future installed record. Future native freshness/Root origin remains main admission.
- runtime_five: exact native-path → bytes for the five parent cc70e536 accepted source deltas; no added/missing path/unknown bytes.
- contract_values: exactly APPROVED_REVIEW, APPROVED_PREDECESSOR_IDENTITY, APPROVED_PREDECESSOR_CONFIG_SHA, OPERATION, EPOCH_OPERATION, ENTRY_PHASE, SCOPE_UNIT, PC_ROOT, PARENT_SOURCE_BUNDLE. They come from main's final source contract; this function generates no identifier/window/permission. Paths are bound using the original source_io.expression. Other literals use its original bind function.

This pre-wire stage emits a service contract with APPROVED_SOURCE_DELTA=None and one static APPROVED_OLD_SOURCE_FILES table (full118 SHA/F9), plus APPROVED_DELTA_POLICY. Policy includes the complete old config/old118 SHA map, exact changed6 sorted paths and their old SHA/F9, five fixed new SHAs and old config identity. It contains no final new wire/config SHA, no Root fulltable or Root source hash. Full118 F9 is NOT repeated in policy/packet; service policy references the corresponding private contract table.

`bind_root(domain, *, final_wire, final_config, qualifier, worker, native_values, packet_fields) -> logical tables/packet/pins/order`

- final_wire/config are complete main-final bytes, config differs only in PC_source_pins and review. Source diff is exactly the accepted5 + fixed WIRE; config is target7.
- qualifier must equal frozen 6fcd qualifier bound only to review+workerSHA. Worker must equal original R16 generic worker bound only to review/ROLE=epoch. Neither body contains the late fulltable. This strict input contract is deliberate; a different template needs explicit source review rather than silent acceptance.
- native_values: exactly APPROVED_INPUT_PINS, APPROVED_OLD_CONFIG_SHA, APPROVED_NEW_CONFIG_SHA, APPROVED_STOPPED_LIVE_IDLE_SHA, APPROVED_PRESTART_PROBE_SHA; main supplies final closure. This component does not fabricate missing dependency pins.
- packet_fields: exactly entry_phase, operation, grant_operation, old_identity, helpers, input_pins, historical_ancestor_sha256, historical_oldmap, old_grant_operation. No field can override derived maps/delta/raw payload.

The Root domain gets full APPROVED_SOURCE_DELTA late and the same complete old118 F9 table, with service-only policy removed. The service contract and Root contract MUST NOT be forced byte equal or deduplicated together.

## Logical source table / imports

Root contribution: `contract.py`, `pc/source_delta.py`, `pc/current_reader.py`, `pc/native.py`, `pc/epoch_transaction.py`, `pc/qualifier.py`, `epoch-scope/worker.py`, `epoch-packet.json`.

Service contribution: `service/contract.py`, `service/source_delta.py`, `service/service_delta_policy.py`.

Root_private_order derives exact frozen R16 final_graph.ROOT_ORDER and inserts pc/source_delta.py immediately after contract.py. Root_external_logical_sources lists the remaining original Root modules which main MUST supply/pin; this fragment is not a complete loader. Root_component_order/pins name this component's six execution bodies. Service component order is contract.py → source_delta.py → service_delta_policy.py, before current_epoch calls it. Main must merge actual final helper/private-order/Root index/UID999 bootstrap/source pins, never supply these from ambient sys.modules. `private_load` tests use fresh private module dictionaries/exactSHA/closed stdlib imports; they do not install aliases globally.

**Critical phase contract edge:** returned `phase_contract_ref` is `service/contract.py` + exact SHA. The copied phase gate must read that path for its historical private contract. If it instead embeds late Root contract SHA and service current_epoch embeds that gate SHA, it recreates the cycle Rootfulldelta→gate→service→wire→Rootfulldelta. Main/g7 owns that bounded gate path change. Root native loader alone uses Root fulltable contract.

## Payload, records and internal service config

Packet contains changed_source_raw_utf8 exactly six paths, once. No wire_raw_utf8 duplicate remains. Copied helper adds `payload(packet,path,approved)`; targets calls that getter for all7 targets, and the unchanged copied transaction uses targets. Exact scan of frozen pc/epoch-scope consumers found old wire_raw_utf8 only in the original transaction; 6fcd already replaces that callsite. Existing prestart/reader/renewal defs use config/maps/helpers, not that removed field. New main-parent callers must use final_wire they own or this pinned payload getter, not an obsolete packet key. No historical raw is newly embedded by this binder.

The helper additionally imports APPROVED_OLD_SOURCE_FILES and checks complete before.source_files exact equality in before_matches, shared by Root backup / qualifier / service verification. This refuses an old complement leaf whose bytes match but inode/F9 changed before any CAS.

`service_delta_policy.approved_from_internal_config(internal_config)` derives only wire's new SHA and actual loaded config SHA from the existing internal `g.config` supplied by original Root config loader. It fixes exact changed6, all old118, five accepted new SHAs, config field scope and new review. `verify_installed(installed, internal_config)` then checks current config binding and invokes the full shared v2 verifier. There is no RPC/receipt config adapter. `_config_sha256` is not evidence by itself: main caller MUST retain original Root loader plus current actual config raw SHA/F9 checks. A JSON object taken from an installed/qualified receipt is not this input.

Old v1 R16 history/phase records keep their original source namespace. This binder does not rewrite them v2 or decide owner authorization.

## Exact size API and pending graph

`measure(full_logical_sources)` uses the actual AST serialized expression from frozen R16 recipes/builder.py materialize, and original encode: role + packet review + base64 of every provided leaf + full parsed epoch-index. Thus packet/index and any metadata leaves count fully. Enforces leaf2MiB, all source4MiB, actual serialized4MiB. No compression shortcut, cap increase or guessed encoding. It deliberately does not invent a new index-set rule: R16 adds four final wrappers after original index creation.

MEASURE_FINAL_CPU_FRAGMENT.json measures only this declared CPU Root fragment + its index: 415214 raw bytes, 554745 serialized bytes, 9 logical leaves. It is NOT the full main graph or 128 physical-leaf acceptance. Actual full graph size/index/source closure/dedup/schema consumers/owner/F3/C remain main/g7 obligations. All7 O_EXCL CAS temp paths must also be confirmed unused before a future stop; no native admission occurs here.
