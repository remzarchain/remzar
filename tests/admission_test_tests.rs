//! admission_test_tests.rs

use std::fs;
use std::path::{Path, PathBuf};

const S03_PATH_CANDIDATES: &[&str] = &[
    "src/commandline/s_03_start_node.rs",
    "src/commandline/s_03_startnode.rs",
];

const ENGINE_PATH_CANDIDATES: &[&str] = &["src/blockchain/blockchain_003_orchestration_engine.rs"];

const TX_REGISTER_PATH_CANDIDATES: &[&str] = &["src/blockchain/transaction_002_tx_register.rs"];

fn resolve_source_path(candidates: &[&str], label: &str) -> PathBuf {
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.exists() {
            return path.to_path_buf();
        }
    }

    panic!(
        "could not find {label}. Tried these paths:\n{}",
        candidates.join("\n")
    );
}

fn read_source(candidates: &[&str], label: &str) -> String {
    let path = resolve_source_path(candidates, label);
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read {} at {}: {e}", label, path.display());
    })
}

fn normalize(src: &str) -> String {
    src.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_normalized(src: &str, needle: &str) -> bool {
    normalize(src).contains(&normalize(needle))
}

fn assert_contains(src: &str, needle: &str, label: &str) {
    assert!(
        src.contains(needle),
        "missing required code for {label}\nneedle:\n{needle}"
    );
}

fn assert_not_contains(src: &str, needle: &str, label: &str) {
    assert!(
        !src.contains(needle),
        "forbidden old/buggy code still exists for {label}\nneedle:\n{needle}"
    );
}

fn assert_contains_any(src: &str, needles: &[&str], label: &str) {
    assert!(
        needles.iter().any(|needle| src.contains(needle)),
        "missing required code for {label}\ntried needles:\n{needles:#?}"
    );
}

fn assert_normalized_contains(src: &str, needle: &str, label: &str) {
    assert!(
        contains_normalized(src, needle),
        "missing required normalized code for {label}\nneedle:\n{needle}"
    );
}

fn assert_normalized_contains_any(src: &str, needles: &[&str], label: &str) {
    assert!(
        needles
            .iter()
            .any(|needle| contains_normalized(src, needle)),
        "missing required normalized code for {label}\ntried needles:\n{needles:#?}"
    );
}

fn assert_normalized_not_contains(src: &str, needle: &str, label: &str) {
    assert!(
        !contains_normalized(src, needle),
        "forbidden old/buggy normalized code still exists for {label}\nneedle:\n{needle}"
    );
}

#[test]
fn admission_01_required_source_files_exist() {
    let s03_path = resolve_source_path(S03_PATH_CANDIDATES, "S03 start node source");
    let engine_path = resolve_source_path(ENGINE_PATH_CANDIDATES, "orchestration engine source");
    let tx_register_path =
        resolve_source_path(TX_REGISTER_PATH_CANDIDATES, "RegisterNodeTx source");

    assert!(
        s03_path.exists(),
        "resolved S03 source path must exist: {}",
        s03_path.display()
    );

    assert!(
        engine_path.exists(),
        "resolved engine source path must exist: {}",
        engine_path.display()
    );

    assert!(
        tx_register_path.exists(),
        "resolved RegisterNodeTx source path must exist: {}",
        tx_register_path.display()
    );
}

#[test]
fn admission_02_s03_imports_validator_state_for_canonical_bootstrap() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains_any(
        &src,
        &[
            "use crate::blockchain::validatorstate::ValidatorState;",
            "validatorstate::ValidatorState",
        ],
        "S03 ValidatorState import",
    );
}

#[test]
fn admission_03_s03_has_canonical_founder_bootstrap_helpers() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(
        &src,
        "fn ensure_canonical_founder_bootstrap",
        "S03 canonical founder bootstrap helper",
    );

    assert_contains(
        &src,
        "fn verify_canonical_founder_bootstrap",
        "S03 canonical founder verification helper",
    );

    assert_contains(
        &src,
        "fn reconcile_and_verify_canonical_founder_bootstrap",
        "S03 canonical founder reconcile helper",
    );
}

#[test]
fn admission_04_s03_seeds_genesis_founder_into_validator_state() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(&src, "seed_genesis_founder", "S03 genesis founder seeding");

    assert_contains(
        &src,
        "block0.metadata.timestamp",
        "S03 founder lifecycle timestamp comes from canonical block0 metadata",
    );
}

#[test]
fn admission_05_s03_checks_founder_canonical_membership() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(
        &src,
        "is_canonically_known",
        "S03 canonical founder membership check",
    );

    assert_contains(
        &src,
        "meta_for(&founder_wallet)",
        "S03 founder metadata check",
    );
}

#[test]
fn admission_06_s03_reconciles_founder_when_resuming_existing_chain() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(
        &src,
        "reconcile_and_verify_canonical_founder_bootstrap(&mgr)",
        "S03 existing-chain canonical founder reconciliation",
    );

    assert_contains(
        &src,
        "reconcile_and_verify_canonical_founder_bootstrap(&tmp_mgr)",
        "S03 startup canonical founder reconciliation",
    );
}

#[test]
fn admission_07_s03_keeps_node_ephemeral_as_runtime_liveness_registry() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(&src, "NodeEphemeral", "S03 runtime ephemeral registry type");

    assert_contains(
        &src,
        "register_wallet_strict",
        "S03 runtime ephemeral wallet registration",
    );

    assert_contains(
        &src,
        "set_join_height",
        "S03 runtime ephemeral join-height tracking",
    );
}

#[test]
fn admission_08_s03_has_a_recognizable_initial_mining_gate() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_normalized_contains_any(
        &src,
        &[
            "let initial_miner_allowed = mining_intent && wallet_registered_now;",
            "let initial_miner_allowed = mining_intent && canonical_registered_now;",
        ],
        "S03 initial mining gate",
    );
}

#[test]
fn admission_09_s03_does_not_use_malformed_send_register_admission_shortcuts() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_not_contains(
        &src,
        "NetCmd::SendRegister(reg_kind)",
        "forbidden SendRegister(reg_kind) admission shortcut",
    );

    assert_not_contains(
        &src,
        "NetCmd::SendRegister(reg_tx)",
        "forbidden SendRegister(reg_tx) admission shortcut",
    );
}

#[test]
fn admission_10_register_node_tx_exists_and_canonicalizes_wallets() {
    let src = read_source(TX_REGISTER_PATH_CANDIDATES, "RegisterNodeTx source");

    assert_contains(&src, "pub struct RegisterNodeTx", "RegisterNodeTx struct");

    assert_contains(
        &src,
        "canon_wallet_id_checked",
        "RegisterNodeTx wallet canonicalization",
    );

    assert_contains(
        &src,
        "pub wallet_address: [u8; WALLET_LEN]",
        "RegisterNodeTx fixed canonical wallet storage",
    );
}

#[test]
fn admission_11_register_node_tx_separates_replay_safe_and_mempool_validation() {
    let src = read_source(TX_REGISTER_PATH_CANDIDATES, "RegisterNodeTx source");

    assert_contains(
        &src,
        "validate_structural",
        "RegisterNodeTx replay-safe structural validation",
    );

    assert_contains(
        &src,
        "validate_for_mempool",
        "RegisterNodeTx runtime mempool validation",
    );

    assert_contains(
        &src,
        "deserialize_for_mempool",
        "RegisterNodeTx runtime mempool deserialization",
    );
}

#[test]
fn admission_12_register_node_tx_deserialize_is_replay_safe() {
    let src = read_source(TX_REGISTER_PATH_CANDIDATES, "RegisterNodeTx source");

    assert_contains(
        &src,
        "pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorDetection>",
        "RegisterNodeTx replay-safe deserialize function",
    );

    assert_contains(
        &src,
        "tx.validate_structural()",
        "RegisterNodeTx deserialize uses structural validation",
    );

    assert_normalized_contains(
        &src,
        "let tx = Self::deserialize(bytes)?; tx.validate_for_mempool()?;",
        "RegisterNodeTx mempool deserialize layers runtime freshness on top",
    );
}

#[test]
fn admission_13_engine_send_txkind_stages_to_mempool_and_gossips_txkind() {
    let src = read_source(ENGINE_PATH_CANDIDATES, "orchestration engine source");

    assert_contains(
        &src,
        "Some(NetCmd::SendTxKind(kind))",
        "engine SendTxKind branch",
    );

    assert_contains(
        &src,
        "self.mempool.add_tx_kind(&kind)",
        "engine SendTxKind mempool staging",
    );

    assert_contains(
        &src,
        "send_tx_kind(&kind)",
        "engine SendTxKind canonical gossip",
    );
}

#[test]
fn admission_14_engine_send_register_also_stages_canonical_txkind() {
    let src = read_source(ENGINE_PATH_CANDIDATES, "orchestration engine source");

    assert_contains(
        &src,
        "Some(NetCmd::SendRegister(r))",
        "engine SendRegister branch",
    );

    assert_normalized_contains(
        &src,
        "let kind = TxKind::RegisterNode(r.clone())",
        "engine SendRegister wraps RegisterNode as canonical TxKind",
    );

    assert_contains(
        &src,
        "self.mempool.add_tx_kind(&kind)",
        "engine SendRegister stages canonical TxKind",
    );

    assert_contains(
        &src,
        "send_tx_kind(&kind)",
        "engine SendRegister gossips canonical TxKind",
    );
}

#[test]
fn admission_15_engine_keeps_runtime_register_gossip_separate() {
    let src = read_source(ENGINE_PATH_CANDIDATES, "orchestration engine source");

    assert_contains(
        &src,
        "send_register_node(&r)",
        "engine runtime/ephemeral register gossip path",
    );

    assert_contains(
        &src,
        "Keep the old runtime/ephemeral register gossip path",
        "engine explicit comment separating runtime register gossip",
    );
}

#[test]
fn admission_16_engine_has_empty_wallet_guard_before_mining_admission() {
    let src = read_source(ENGINE_PATH_CANDIDATES, "orchestration engine source");

    assert_contains(
        &src,
        "self.local_wallet.trim().is_empty()",
        "engine empty-wallet guard",
    );

    assert_contains(
        &src,
        "return false;",
        "engine false return for invalid local wallet admission",
    );
}

#[test]
#[ignore = "enable after S03 is patched to stage RegisterNodeTx as TxKind and gate mining on canonical ValidatorState"]
fn strict_future_01_s03_stages_admission_as_canonical_txkind() {
    let src = read_source(S03_PATH_CANDIDATES, "S03 start node source");

    assert_contains(
        &src,
        "transaction_002_tx_register::RegisterNodeTx",
        "S03 RegisterNodeTx import",
    );

    assert_contains(&src, "transaction_004_tx_kind::TxKind", "S03 TxKind import");

    assert_contains(
        &src,
        "let canonical_registered_now",
        "S03 canonical registration variable",
    );

    assert_contains(
        &src,
        "vs.is_canonically_known(&local_wallet)",
        "S03 canonical local wallet check",
    );

    assert_contains(
        &src,
        "RegisterNodeTx::new(local_wallet.clone())",
        "S03 RegisterNodeTx construction",
    );

    assert_contains(
        &src,
        "TxKind::RegisterNode",
        "S03 RegisterNodeTx wrapped as TxKind",
    );

    assert_contains(
        &src,
        "mempool.add_tx_kind(&reg_kind)",
        "S03 admission TxKind staged in mempool",
    );

    assert_contains(
        &src,
        "NetCmd::SendTxKind(reg_kind)",
        "S03 admission TxKind broadcast",
    );

    assert_normalized_contains(
        &src,
        "let initial_miner_allowed = mining_intent && canonical_registered_now;",
        "S03 initial miner gate uses canonical validator state",
    );

    assert_normalized_not_contains(
        &src,
        "let initial_miner_allowed = mining_intent && wallet_registered_now;",
        "S03 old ephemeral-only mining gate is absent",
    );
}

#[test]
#[ignore = "enable after engine is patched to gate miner startup/tick on canonical ValidatorState membership"]
fn strict_future_02_engine_rejects_ephemeral_only_mining() {
    let src = read_source(ENGINE_PATH_CANDIDATES, "orchestration engine source");

    assert_contains_any(
        &src,
        &[
            "validatorstate::ValidatorState",
            "use crate::blockchain::validatorstate::ValidatorState",
        ],
        "engine ValidatorState import",
    );

    assert_contains(
        &src,
        "local_wallet_canonical_in_validator_state",
        "engine canonical validator helper",
    );

    assert_contains(
        &src,
        "ValidatorState::load_or_new",
        "engine helper loads ValidatorState",
    );

    assert_contains(
        &src,
        "is_canonically_known(&self.local_wallet)",
        "engine helper checks canonical membership",
    );

    assert_normalized_contains(
        &src,
        "if !present || !self.local_wallet_canonical_in_validator_state()",
        "engine initialize_miner rejects ephemeral-only wallet",
    );

    assert_normalized_contains(
        &src,
        "if present && self.local_wallet_canonical_in_validator_state()",
        "engine registry tick enables miner only with canonical membership",
    );

    assert_normalized_not_contains(
        &src,
        "if present { match BlockchainBuilder::new",
        "engine old ephemeral-only enable pattern is absent",
    );
}
