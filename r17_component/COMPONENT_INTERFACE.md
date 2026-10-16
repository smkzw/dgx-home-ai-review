# F1–F4 bounded component / SOURCE only

This checkpoint freezes the selected historical cut and finite owner decision slice, **not an installable R17 graph**. No new actual nonce, source epoch, C31, installer, budget or permission exists. `owner_DECISION_POLICY=None` and all actual slots remain None.

- `history_prepare.prepare_bridge` / `PreparedBridge`: selected two immutable FAILED old actors only; immutable semantic and actual compiler flags/optimize are prepared before BEGIN. Protected dependencies are re-read with full SHA/F9. It does not cache current PID/lease/actor observations.
- `phase_prepare.prepare` / `PreparedInstallation`: original initial-installation and phase event consumers, 43 held dependencies. `installation` rechecks them; `current_owner` retains actual internal identity, actual actor/lease consumer and fresh source reads. New PID enters original renewal before current owner checks. Complete valid renewal receipt remains an integration gate.
- New clock functions are generated as v2; old v1 event functions stay unchanged. `owner_final_clock_v2` compares original PC send monotonic against actual sameboot `g.clock`; wall is audit/drift. Limits30/120 remain unchanged.
- `owner_decision.Journal`: one fixed operation under an already protected private parent FD. PREPARED, decision, post-physical-finish witness, expiry/abort, and one projection descriptor are closed records. Physical finish + its post-mono check must be inside30. A newly opened complete witness is FINISH_WITNESS_PRESENT/held; exact SHA/F9-bound leaf+opdir+parent durability confirmation under the original owned scheduler RLock is required for cold COMMITTED. Failed same-process instances cannot confirm themselves. No additional seal chain, old finish replay or resource authority.
- `owner_projection.render(recipe, terminal_raw, verified_finish_clock)`: exact bytes for three actor and three source metadata leaves. Completion/fence and intent.release_commit_clock use the validated witness finish clock; intent.observed_at uses recipe.recorded_at. No new clock/stamp/fallback. `project` creates missing canonical leaves O_EXCL only; existing bytes and all nine metadata fields must match the sealed refs. It never overwrites or deletes.
- `owner_state.owner_restore_decision_cold(recovery, stages)`: fixed source policy/operation, original private HeldParent base plus NOFOLLOW child-dirFD algorithm, actual Journal barrier, full v2 historical eligibility/old pending consumer, exact projection refs and live `g.same`. Called by `Recovery.owner_decision_cold` from the original Stages cold hook under scheduler lock.
- `owner_state.owner_committed_history_v2`: full sealed past-event consumer for service/Root historical calls; no barrier/write/finish/resource permission. Root Journal access is read-only. Existing v1 history has its separate unchanged body.

## Cold state meanings

A complete old owner transaction recovers completed/used (`failed_owner_pending=None`, no closed cause from that old actor). It **does not clear the distinct new PID/source fence**: original negative.pending remains true, Recovery.released remains false, scheduler maintenance remains true; new source activation/current qualification/renewal are still required.

Unknown/broken/expired/uncommitted evidence remains held. A correct missing canonical projection can be completed only for an already valid finish witness. Existing partial/wrongraw projections are preserved and are not auto-repaired. If a cold projection write itself partially fails, the original before/after actor snapshot gate can reject constructor completion; this is a retained safe startup limitation. No fresh snapshot is substituted for the failed observation.

## Required integration, deliberately not claimed here

1. Full private-loader co-location/order and new fixed policy/Root refs; final physical counts/caps are not established by this component. No ambient import fallback is allowed.
2. Actual producer binding prepare→fresh recheck→Root BEGIN→new activation to the same prepared closure, and replacing the old v1 owner_activate path with Journal commit under the actual grant/lifecycle/scheduler locks. The component cold join replays one saved v2 CPU event; it is not current resource authorization.
3. Full Grant/Runtime/cold factory/source activation/valid new-PID renewal; current source fence must be released through the existing independent source protocol, never by an old owner witness.
4. Service v2 explicit-delta consumer plus final two-contract graph. Backend binder phase_contract_ref must change the historical gate to actual `PC_ROOT/service/contract.py` path **and** SHA. Root full7 table is late-bound after wire/config; never embedded back into service. Full final source/table/bundle measure before any native preparation.
5. Target read-only real cost, final byte graph, independent review and any future finite authorization belong to the parent. Local CPU timing is not native5/30 qualification.

## Explicit verifier

Absolute Python3.11 `-I -B verify_component.py` checks all frozen static/input refs and compiles own Python. `--cold UNIQUE_LABEL` performs only the new saved-v2 Journal→Recovery/Stages and historical roles slice; it does not rerun the A scope, normal epoch, C29/C30, Manager or Runtime. Original existing read-only R16 catalogue/capsule paths must remain available. This is a local explicit-input clone, not a portable standalone deployment.

Earlier `tests/verify_cold.py`, early PROJECTION_RESULT and failed FIRST/SECOND/DIAGNOSTIC outputs are historical development evidence. They are not final integration entry points.
