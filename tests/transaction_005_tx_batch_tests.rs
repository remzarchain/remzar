use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::tokens::nft_001::{NftMintTx, NftTransferTx};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::helper::REMZAR_WALLET_LEN;

use std::collections::BTreeSet;

type TestResult = Result<(), String>;

const UNIX_2000: u64 = 946_684_800;

fn require(condition: bool, context: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(context.to_owned())
    }
}

fn require_equal<T>(left: &T, right: &T, context: &str) -> TestResult
where
    T: PartialEq + core::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(format!("{context}: left={left:?}, right={right:?}"))
    }
}

fn require_not_equal<T>(left: &T, right: &T, context: &str) -> TestResult
where
    T: PartialEq + core::fmt::Debug,
{
    if left != right {
        Ok(())
    } else {
        Err(format!("{context}: both values were {left:?}"))
    }
}

fn map_err_debug<T>(result: Result<T, ErrorDetection>, context: &str) -> Result<T, String> {
    result.map_err(|error| format!("{context}: {error:?}"))
}

fn wallet_with_repeated_hex(ch: char) -> String {
    let body = ch.to_string().repeat(128);
    format!("r{body}")
}

fn wallet_body_from_seed(seed: u64) -> String {
    let digest = blake3::hash(&seed.to_le_bytes()).to_hex().to_string();
    let mut body = String::with_capacity(128);
    body.push_str(&digest);
    body.push_str(&digest);
    body
}

fn wallet_from_seed(seed: u64) -> String {
    let body = wallet_body_from_seed(seed);
    format!("r{body}")
}

fn wallet_array(address: &str) -> Result<[u8; REMZAR_WALLET_LEN], String> {
    if address.len() != REMZAR_WALLET_LEN {
        return Err(format!(
            "wallet_array requires {REMZAR_WALLET_LEN} bytes, got {}",
            address.len()
        ));
    }

    let mut out = [0_u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(address.as_bytes());
    Ok(out)
}

fn hash_from_seed(seed: u64) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&seed.to_le_bytes());

    let mut out = [0_u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

fn bytes_from_seed(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0_u64;

    while out.len() < len {
        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&seed.to_le_bytes());
        input.extend_from_slice(&counter.to_le_bytes());

        let digest = blake3::hash(&input);
        for byte in digest.as_bytes() {
            if out.len() == len {
                break;
            }
            out.push(*byte);
        }

        counter = counter.wrapping_add(1);
    }

    out
}

fn transfer_kind(seed: u64) -> Result<TxKind, String> {
    Ok(TxKind::Transfer(Transaction {
        sender: wallet_array(&wallet_from_seed(seed))?,
        receiver: wallet_array(&wallet_from_seed(seed.saturating_add(10_000)))?,
        amount: seed
            .checked_add(1)
            .ok_or_else(|| "transfer amount overflowed".to_owned())?,
        timestamp: UNIX_2000,
    }))
}

fn register_kind(seed: u64) -> Result<TxKind, String> {
    Ok(TxKind::RegisterNode(RegisterNodeTx {
        wallet_address: wallet_array(&wallet_from_seed(seed.saturating_add(20_000)))?,
        timestamp: UNIX_2000,
    }))
}

fn reward_kind(seed: u64) -> Result<TxKind, String> {
    Ok(TxKind::Reward(RewardTx {
        receiver: wallet_array(&wallet_from_seed(seed.saturating_add(30_000)))?,
        amount: 1,
        block_height: seed
            .checked_add(1)
            .ok_or_else(|| "reward block height overflowed".to_owned())?,
        timestamp: UNIX_2000,
    }))
}

fn nft_mint_kind(seed: u64) -> TxKind {
    TxKind::NftMint(NftMintTx {
        nft_id: hash_from_seed(seed.saturating_add(40_000)),
        content_hash: hash_from_seed(seed.saturating_add(50_000)),
        title: format!("NFT #{seed}"),
        description: format!("NFT description #{seed}"),
    })
}

fn nft_transfer_kind(seed: u64) -> TxKind {
    TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(seed.saturating_add(60_000)),
        new_owner_wallet: wallet_from_seed(seed.saturating_add(70_000)),
    })
}

fn all_variant_kinds(seed: u64) -> Result<Vec<TxKind>, String> {
    Ok(vec![
        transfer_kind(seed)?,
        register_kind(seed)?,
        reward_kind(seed)?,
        nft_mint_kind(seed),
        nft_transfer_kind(seed),
    ])
}

fn valid_batch() -> Result<TransactionBatch, String> {
    map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(1)?),
        "valid batch should create",
    )
}

fn serialized_tx_kind_payload_len(kind: &TxKind) -> Result<usize, String> {
    match kind {
        TxKind::Transfer(tx) => {
            map_err_debug(tx.serialize(), "transfer should serialize").map(|v| v.len())
        }
        TxKind::RegisterNode(tx) => {
            map_err_debug(tx.serialize(), "register should serialize").map(|v| v.len())
        }
        TxKind::Reward(tx) => {
            map_err_debug(tx.serialize(), "reward should serialize").map(|v| v.len())
        }
        TxKind::NftMint(tx) => postcard::to_allocvec(tx)
            .map(|v| v.len())
            .map_err(|error| format!("NFT mint should serialize: {error}")),
        TxKind::NftTransfer(tx) => postcard::to_allocvec(tx)
            .map(|v| v.len())
            .map_err(|error| format!("NFT transfer should serialize: {error}")),
    }
}

fn require_any_error<T>(result: Result<T, ErrorDetection>, context: &str) -> TestResult
where
    T: core::fmt::Debug,
{
    match result {
        Err(_) => Ok(()),
        Ok(value) => Err(format!("{context}: expected error, got {value:?}")),
    }
}

fn require_validation_error_contains<T>(
    result: Result<T, ErrorDetection>,
    needle: &str,
    context: &str,
) -> TestResult
where
    T: core::fmt::Debug,
{
    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => require(
            message.contains(needle),
            &format!("{context}: message was {message:?}"),
        ),
        Err(other) => Err(format!(
            "{context}: expected ValidationError, got {other:?}"
        )),
        Ok(value) => Err(format!("{context}: expected error, got {value:?}")),
    }
}

#[test]
fn tx_batch_01_new_empty_batch_sets_fields() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(7, UNIX_2000, Vec::new()),
        "empty batch should create",
    )?;

    require_equal(&batch.index, &7_u64, "index should be stored")?;
    require_equal(&batch.timestamp, &UNIX_2000, "timestamp should be stored")?;
    require(
        batch.transactions.is_empty(),
        "transactions should be empty",
    )?;
    require_equal(
        &batch.guardian_signature,
        &None,
        "new batch should not have guardian signature",
    )?;

    Ok(())
}

#[test]
fn tx_batch_02_new_with_all_variants_sets_transaction_count() -> TestResult {
    let batch = valid_batch()?;

    require_equal(
        &batch.transactions.len(),
        &5_usize,
        "batch should contain all five TxKind variants",
    )?;
    require_equal(&batch.index, &1_u64, "index should match")?;
    require_equal(&batch.timestamp, &UNIX_2000, "timestamp should match")?;

    Ok(())
}

#[test]
fn tx_batch_03_default_is_empty_zeroed_batch() -> TestResult {
    let batch = TransactionBatch::default();

    require_equal(&batch.index, &0_u64, "default index should be zero")?;
    require_equal(&batch.timestamp, &0_u64, "default timestamp should be zero")?;
    require(
        batch.transactions.is_empty(),
        "default transactions should be empty",
    )?;
    require_equal(
        &batch.guardian_signature,
        &None,
        "default guardian signature should be none",
    )?;

    Ok(())
}

#[test]
fn tx_batch_04_total_size_empty_is_zero() -> TestResult {
    let batch = TransactionBatch::default();
    let total = map_err_debug(batch.total_size(), "empty total_size should succeed")?;

    require_equal(&total, &0_usize, "empty total_size should be zero")
}

#[test]
fn tx_batch_05_total_size_matches_sum_of_inner_payload_serializations() -> TestResult {
    let batch = valid_batch()?;
    let expected = batch
        .transactions
        .iter()
        .map(serialized_tx_kind_payload_len)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .try_fold(0_usize, |acc, len| {
            acc.checked_add(*len)
                .ok_or_else(|| "expected total size overflowed".to_owned())
        })?;

    let actual = map_err_debug(batch.total_size(), "total_size should succeed")?;

    require_equal(
        &actual,
        &expected,
        "total_size should equal sum of inner variant payload sizes",
    )
}

#[test]
fn tx_batch_06_serialized_len_matches_serialize_len() -> TestResult {
    let batch = valid_batch()?;
    let serialized = map_err_debug(batch.serialize(), "batch should serialize")?;
    let serialized_len = map_err_debug(batch.serialized_len(), "serialized_len should succeed")?;

    require_equal(
        &serialized_len,
        &serialized.len(),
        "serialized_len should equal serialize().len()",
    )
}

#[test]
fn tx_batch_07_serialize_for_storage_matches_serialize_under_cap() -> TestResult {
    let batch = valid_batch()?;

    let normal = map_err_debug(batch.serialize(), "batch should serialize")?;
    let storage = map_err_debug(
        batch.serialize_for_storage(),
        "batch should serialize for storage",
    )?;

    require_equal(
        &storage,
        &normal,
        "serialize_for_storage should match serialize for under-cap batch",
    )
}

#[test]
fn tx_batch_08_serialize_deserialize_roundtrip_empty_batch() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(0, 0, Vec::new()),
        "empty batch should create",
    )?;

    let bytes = map_err_debug(batch.serialize(), "empty batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "empty batch should deserialize",
    )?;

    require_equal(&decoded, &batch, "empty batch should roundtrip")
}

#[test]
fn tx_batch_09_serialize_deserialize_roundtrip_all_variants() -> TestResult {
    let batch = valid_batch()?;
    let bytes = map_err_debug(batch.serialize(), "batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch should deserialize",
    )?;

    require_equal(&decoded, &batch, "all-variant batch should roundtrip")
}

#[test]
fn tx_batch_10_serialize_is_deterministic_for_fixed_batch() -> TestResult {
    let batch = valid_batch()?;

    let first = map_err_debug(batch.serialize(), "first serialization should succeed")?;
    let second = map_err_debug(batch.serialize(), "second serialization should succeed")?;

    require_equal(
        &first,
        &second,
        "fixed batch serialization should be deterministic",
    )
}

#[test]
fn tx_batch_11_deserialize_rejects_empty_wire() -> TestResult {
    require_any_error(
        TransactionBatch::deserialize(&[]),
        "empty wire should reject",
    )
}

#[test]
fn tx_batch_12_deserialize_rejects_truncated_wire() -> TestResult {
    let batch = valid_batch()?;
    let mut bytes = map_err_debug(batch.serialize(), "batch should serialize")?;
    let half = bytes
        .len()
        .checked_div(2)
        .ok_or_else(|| "serialized length division failed".to_owned())?;
    bytes.truncate(half);

    require_any_error(
        TransactionBatch::deserialize(&bytes),
        "truncated wire should reject",
    )
}

#[test]
fn tx_batch_13_deserialize_rejects_trailing_bytes_current_contract() -> TestResult {
    let batch = valid_batch()?;
    let mut bytes = map_err_debug(batch.serialize(), "batch should serialize")?;
    bytes.extend_from_slice(&[0_u8, 1_u8, 2_u8, 3_u8]);

    require_any_error(
        TransactionBatch::deserialize(&bytes),
        "deserialize should reject trailing bytes after valid batch payload",
    )
}

#[test]
fn tx_batch_14_from_reward_only_wraps_one_reward() -> TestResult {
    let reward = RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    let batch = map_err_debug(
        TransactionBatch::from_reward_only(9, UNIX_2000, reward.clone()),
        "reward-only batch should create",
    )?;

    require_equal(&batch.index, &9_u64, "reward-only index should match")?;
    require_equal(
        &batch.transactions.len(),
        &1_usize,
        "reward-only batch should contain one transaction",
    )?;
    require_equal(
        &batch.transactions,
        &vec![TxKind::Reward(reward)],
        "reward-only batch should wrap reward TxKind",
    )?;

    Ok(())
}

#[test]
fn tx_batch_15_compute_merkle_root_empty_returns_64_bytes() -> TestResult {
    let batch = TransactionBatch::default();
    let root = map_err_debug(
        batch.compute_merkle_root(),
        "empty batch merkle root should compute",
    )?;

    require_equal(&root.len(), &64_usize, "merkle root should be 64 bytes")
}

#[test]
fn tx_batch_16_compute_merkle_root_single_transfer_returns_64_bytes() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "single transfer batch should create",
    )?;

    let root = map_err_debug(
        batch.compute_merkle_root(),
        "single transfer merkle root should compute",
    )?;

    require_equal(&root.len(), &64_usize, "merkle root should be 64 bytes")
}

#[test]
fn tx_batch_17_compute_merkle_root_changes_when_transaction_changes() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(2)?]),
        "second batch should create",
    )?;

    let first_root = map_err_debug(first.compute_merkle_root(), "first root should compute")?;
    let second_root = map_err_debug(second.compute_merkle_root(), "second root should compute")?;

    require_not_equal(
        &first_root,
        &second_root,
        "changing transaction should change merkle root",
    )
}

#[test]
fn tx_batch_18_compute_merkle_root_is_stable_for_same_batch() -> TestResult {
    let batch = valid_batch()?;

    let first = map_err_debug(batch.compute_merkle_root(), "first root should compute")?;
    let second = map_err_debug(batch.compute_merkle_root(), "second root should compute")?;

    require_equal(&first, &second, "same batch merkle root should be stable")
}

#[test]
fn tx_batch_19_compute_merkle_root_order_sensitive() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?, reward_kind(1)?]),
        "first ordered batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![reward_kind(1)?, transfer_kind(1)?]),
        "second ordered batch should create",
    )?;

    let first_root = map_err_debug(first.compute_merkle_root(), "first root should compute")?;
    let second_root = map_err_debug(second.compute_merkle_root(), "second root should compute")?;

    require_not_equal(
        &first_root,
        &second_root,
        "merkle root should change when transaction order changes",
    )
}

#[test]
fn tx_batch_20_inclusion_proof_empty_batch_rejects_index_zero() -> TestResult {
    let batch = TransactionBatch::default();

    require_any_error(
        batch.inclusion_proof(0),
        "empty batch inclusion proof should reject index zero",
    )
}

#[test]
fn tx_batch_21_inclusion_proof_single_leaf_is_empty() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "single-leaf batch should create",
    )?;

    let proof = map_err_debug(
        batch.inclusion_proof(0),
        "single-leaf inclusion proof should compute",
    )?;

    require(
        proof.is_empty(),
        "single-leaf merkle proof should have no siblings",
    )
}

#[test]
fn tx_batch_22_inclusion_proof_two_leaves_has_one_sibling() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?, reward_kind(1)?]),
        "two-leaf batch should create",
    )?;

    let proof_zero = map_err_debug(
        batch.inclusion_proof(0),
        "leaf zero inclusion proof should compute",
    )?;
    let proof_one = map_err_debug(
        batch.inclusion_proof(1),
        "leaf one inclusion proof should compute",
    )?;

    require_equal(
        &proof_zero.len(),
        &1_usize,
        "leaf zero proof should have one sibling",
    )?;
    require_equal(
        &proof_one.len(),
        &1_usize,
        "leaf one proof should have one sibling",
    )?;

    Ok(())
}

#[test]
fn tx_batch_23_inclusion_proof_rejects_out_of_bounds() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "single-leaf batch should create",
    )?;

    require_any_error(
        batch.inclusion_proof(1),
        "out-of-bounds inclusion proof should reject",
    )
}

#[test]
fn tx_batch_24_guardian_signature_none_survives_roundtrip() -> TestResult {
    let batch = valid_batch()?;
    let bytes = map_err_debug(batch.serialize(), "batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch should deserialize",
    )?;

    require_equal(
        &decoded.guardian_signature,
        &None,
        "guardian_signature None should survive roundtrip",
    )
}

#[test]
fn tx_batch_25_guardian_signature_some_survives_roundtrip() -> TestResult {
    let mut batch = valid_batch()?;
    batch.guardian_signature = Some(vec![0xAB; 16]);

    let bytes = map_err_debug(batch.serialize(), "signed-like batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "signed-like batch should deserialize",
    )?;

    require_equal(
        &decoded.guardian_signature,
        &Some(vec![0xAB; 16]),
        "guardian signature bytes should survive roundtrip",
    )
}

#[test]
fn tx_batch_26_total_size_does_not_include_guardian_signature() -> TestResult {
    let batch = valid_batch()?;
    let mut with_sig = batch.clone();
    with_sig.guardian_signature = Some(vec![0xAB; 1024]);

    let base_total = map_err_debug(batch.total_size(), "base total_size should succeed")?;
    let signed_total = map_err_debug(with_sig.total_size(), "signed total_size should succeed")?;

    require_equal(
        &signed_total,
        &base_total,
        "total_size sums transactions only and should not include guardian_signature",
    )
}

#[test]
fn tx_batch_27_serialized_len_increases_when_guardian_signature_added() -> TestResult {
    let batch = valid_batch()?;
    let mut with_sig = batch.clone();
    with_sig.guardian_signature = Some(vec![0xAB; 1024]);

    let base_len = map_err_debug(batch.serialized_len(), "base serialized_len should succeed")?;
    let signed_len = map_err_debug(
        with_sig.serialized_len(),
        "signed serialized_len should succeed",
    )?;

    require(
        signed_len > base_len,
        "serialized_len should include guardian_signature bytes",
    )
}

#[test]
fn tx_batch_28_serialize_for_storage_rejects_oversized_guardian_signature() -> TestResult {
    let mut batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, Vec::new()),
        "empty batch should create",
    )?;

    let max_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|error| format!("MAX_BLOCK_SIZE conversion failed: {error}"))?;
    let sig_len = max_size
        .checked_add(1024)
        .ok_or_else(|| "oversized signature length overflowed".to_owned())?;
    batch.guardian_signature = Some(vec![0xAB; sig_len]);

    require_validation_error_contains(
        batch.serialize_for_storage(),
        "TransactionBatch exceeds MAX_BLOCK_SIZE",
        "oversized guardian signature should fail storage serialization",
    )
}

#[test]
fn tx_batch_29_serialize_for_storage_rejects_oversized_nft_metadata() -> TestResult {
    let max_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|error| format!("MAX_BLOCK_SIZE conversion failed: {error}"))?;

    let huge_title_len = max_size
        .checked_add(1024)
        .ok_or_else(|| "huge title length overflowed".to_owned())?;

    let huge_nft = TxKind::NftMint(NftMintTx {
        nft_id: hash_from_seed(1),
        content_hash: hash_from_seed(2),
        title: "T".repeat(huge_title_len),
        description: String::new(),
    });

    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![huge_nft]),
        "oversized NFT batch should create before storage cap check",
    )?;

    require_validation_error_contains(
        batch.serialize_for_storage(),
        "TransactionBatch exceeds MAX_BLOCK_SIZE",
        "oversized NFT metadata batch should fail storage serialization",
    )
}

#[test]
fn tx_batch_30_clone_equality_and_mutation() -> TestResult {
    let batch = valid_batch()?;
    let mut cloned = batch.clone();

    require_equal(&cloned, &batch, "clone should equal original")?;

    cloned.index = cloned
        .index
        .checked_add(1)
        .ok_or_else(|| "index mutation overflowed".to_owned())?;

    require_not_equal(
        &cloned,
        &batch,
        "mutating cloned index should change equality",
    )
}

#[test]
fn tx_batch_31_mutating_timestamp_changes_serialized_bytes() -> TestResult {
    let batch = valid_batch()?;
    let mut mutated = batch.clone();

    mutated.timestamp = mutated
        .timestamp
        .checked_add(1)
        .ok_or_else(|| "timestamp mutation overflowed".to_owned())?;

    let original_bytes = map_err_debug(batch.serialize(), "original should serialize")?;
    let mutated_bytes = map_err_debug(mutated.serialize(), "mutated should serialize")?;

    require_not_equal(
        &mutated_bytes,
        &original_bytes,
        "changing timestamp should change serialized bytes",
    )
}

#[test]
fn tx_batch_32_mutating_transactions_changes_merkle_root() -> TestResult {
    let batch = valid_batch()?;
    let mut mutated = batch.clone();
    mutated.transactions.push(transfer_kind(999)?);

    let original_root = map_err_debug(batch.compute_merkle_root(), "original root should compute")?;
    let mutated_root = map_err_debug(mutated.compute_merkle_root(), "mutated root should compute")?;

    require_not_equal(
        &mutated_root,
        &original_root,
        "adding a transaction should change merkle root",
    )
}

#[test]
fn tx_batch_33_vector_single_variant_batches_roundtrip() -> TestResult {
    let variants = all_variant_kinds(1)?;

    for kind in variants {
        let batch = map_err_debug(
            TransactionBatch::new(1, UNIX_2000, vec![kind]),
            "single-variant batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "single-variant batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "single-variant batch should deserialize",
        )?;

        require_equal(&decoded, &batch, "single-variant batch should roundtrip")?;
    }

    Ok(())
}

#[test]
fn tx_batch_34_vector_single_variant_batches_merkle_root_64_bytes() -> TestResult {
    let variants = all_variant_kinds(2)?;

    for kind in variants {
        let batch = map_err_debug(
            TransactionBatch::new(1, UNIX_2000, vec![kind]),
            "single-variant batch should create",
        )?;

        let root = map_err_debug(
            batch.compute_merkle_root(),
            "single-variant merkle root should compute",
        )?;

        require_equal(&root.len(), &64_usize, "root should be 64 bytes")?;
    }

    Ok(())
}

#[test]
fn tx_batch_35_property_generated_transfer_batches_roundtrip() -> TestResult {
    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![transfer_kind(seed)?]),
            "generated transfer batch should create",
        )?;
        let bytes = map_err_debug(
            batch.serialize(),
            "generated transfer batch should serialize",
        )?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "generated transfer batch should deserialize",
        )?;

        require_equal(
            &decoded,
            &batch,
            "generated transfer batch should roundtrip",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_36_property_generated_reward_batches_roundtrip() -> TestResult {
    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![reward_kind(seed)?]),
            "generated reward batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "generated reward batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "generated reward batch should deserialize",
        )?;

        require_equal(&decoded, &batch, "generated reward batch should roundtrip")?;
    }

    Ok(())
}

#[test]
fn tx_batch_37_property_generated_nft_batches_roundtrip() -> TestResult {
    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(
                seed,
                UNIX_2000,
                vec![nft_mint_kind(seed), nft_transfer_kind(seed)],
            ),
            "generated NFT batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "generated NFT batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "generated NFT batch should deserialize",
        )?;

        require_equal(&decoded, &batch, "generated NFT batch should roundtrip")?;
    }

    Ok(())
}

#[test]
fn tx_batch_38_property_generated_mixed_batches_have_stable_merkle_roots() -> TestResult {
    for seed in 0_u64..32_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "generated mixed batch should create",
        )?;

        let first = map_err_debug(batch.compute_merkle_root(), "first root should compute")?;
        let second = map_err_debug(batch.compute_merkle_root(), "second root should compute")?;

        require_equal(
            &first,
            &second,
            "generated mixed batch root should be stable",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_39_property_generated_mixed_batches_have_unique_serialized_bytes() -> TestResult {
    let mut seen = BTreeSet::new();

    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "generated mixed batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "generated mixed batch should serialize")?;

        require(
            seen.insert(bytes),
            "generated mixed batch serialized bytes should be unique",
        )?;
    }

    require_equal(&seen.len(), &64_usize, "should collect 64 unique batches")?;

    Ok(())
}

#[test]
fn tx_batch_40_fuzz_arbitrary_payloads_do_not_deserialize_to_valid_nonempty_batch() -> TestResult {
    for len in 0_usize..256_usize {
        let seed = u64::try_from(len).map_err(|error| format!("len conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed, len);

        if let Ok(batch) = TransactionBatch::deserialize(&bytes) {
            require(
                batch.transactions.is_empty(),
                "arbitrary decoded batch should not contain valid transaction list",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_41_fuzz_all_truncated_prefixes_reject() -> TestResult {
    let batch = valid_batch()?;
    let bytes = map_err_debug(batch.serialize(), "batch should serialize")?;

    for cut in 0_usize..bytes.len() {
        let prefix = bytes
            .get(..cut)
            .ok_or_else(|| format!("failed to get prefix at cut {cut}"))?;

        require_any_error(
            TransactionBatch::deserialize(prefix),
            "truncated batch prefix should reject",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_42_fuzz_bitflips_reject_or_decode_to_different_batch() -> TestResult {
    let original = valid_batch()?;
    let original_bytes = map_err_debug(original.serialize(), "original batch should serialize")?;

    for byte_index in 0_usize..original_bytes.len().min(64) {
        let mut mutated = original_bytes.clone();

        if let Some(byte) = mutated.get_mut(byte_index) {
            *byte ^= 0x01;
        } else {
            return Err(format!("failed to mutate byte index {byte_index}"));
        }

        if let Ok(decoded) = TransactionBatch::deserialize(&mutated) {
            require_not_equal(
                &decoded,
                &original,
                "accepted bitflip mutation should not decode to original batch",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_43_load_many_small_batches_serialize_deserialize() -> TestResult {
    let mut accepted = 0_usize;

    for seed in 0_u64..256_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![transfer_kind(seed)?]),
            "load small batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "load small batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "load small batch should deserialize",
        )?;

        require_equal(&decoded, &batch, "load small batch should roundtrip")?;

        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| "accepted counter overflowed".to_owned())?;
    }

    require_equal(
        &accepted,
        &256_usize,
        "all load small batches should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_44_load_large_batch_under_cap_serializes_for_storage() -> TestResult {
    let mut txs = Vec::new();

    for seed in 0_u64..512_u64 {
        txs.push(transfer_kind(seed)?);
    }

    let batch = map_err_debug(
        TransactionBatch::new(44, UNIX_2000, txs),
        "large under-cap batch should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize_for_storage(),
        "large under-cap batch should serialize for storage",
    )?;

    let max_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|error| format!("MAX_BLOCK_SIZE conversion failed: {error}"))?;

    require(
        bytes.len() <= max_size,
        "large under-cap batch storage bytes should be <= MAX_BLOCK_SIZE",
    )?;

    Ok(())
}

#[test]
fn tx_batch_45_adversarial_duplicate_batch_wires_detected_by_serialized_set() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..32_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![transfer_kind(seed)?]),
            "duplicate batch should create",
        )?;
        let wire = map_err_debug(batch.serialize(), "duplicate batch should serialize")?;

        wires.push(wire.clone());
        wires.push(wire.clone());
        wires.push(wire);
    }

    let mut unique = 0_usize;
    let mut duplicate = 0_usize;
    let mut seen = BTreeSet::new();

    for wire in wires {
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&wire),
            "duplicate batch wire should deserialize",
        )?;
        let key = map_err_debug(
            decoded.serialize(),
            "decoded duplicate key should serialize",
        )?;

        if seen.insert(key) {
            unique = unique
                .checked_add(1)
                .ok_or_else(|| "unique counter overflowed".to_owned())?;
        } else {
            duplicate = duplicate
                .checked_add(1)
                .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
        }
    }

    require_equal(&unique, &32_usize, "should detect 32 unique batch wires")?;
    require_equal(
        &duplicate,
        &64_usize,
        "should detect 64 duplicate batch wires",
    )?;

    Ok(())
}

#[test]
fn tx_batch_46_adversarial_mixed_batch_wires_count_decode_success_and_failure() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..40_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "valid mixed adversarial batch should create",
        )?;
        let valid_wire = map_err_debug(batch.serialize(), "valid mixed batch should serialize")?;
        wires.push(valid_wire.clone());

        if seed < 10 {
            wires.push(valid_wire.clone());
        }

        let mut truncated = valid_wire.clone();
        let half = truncated
            .len()
            .checked_div(2)
            .ok_or_else(|| "truncated length division failed".to_owned())?;
        truncated.truncate(half);
        wires.push(truncated);

        wires.push(bytes_from_seed(seed, 24));
    }

    let mut decoded = 0_usize;
    let mut rejected = 0_usize;
    let mut duplicate = 0_usize;
    let mut seen = BTreeSet::new();

    for wire in wires {
        match TransactionBatch::deserialize(&wire) {
            Ok(batch) => {
                let key = map_err_debug(batch.serialize(), "decoded batch key should serialize")?;
                if seen.insert(key) {
                    decoded = decoded
                        .checked_add(1)
                        .ok_or_else(|| "decoded counter overflowed".to_owned())?;
                } else {
                    duplicate = duplicate
                        .checked_add(1)
                        .ok_or_else(|| "duplicate counter overflowed".to_owned())?;
                }
            }
            Err(_) => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or_else(|| "rejected counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(&decoded, &40_usize, "should decode 40 unique valid batches")?;
    require_equal(
        &duplicate,
        &10_usize,
        "should detect 10 duplicate valid batches",
    )?;
    require_equal(
        &rejected,
        &80_usize,
        "should reject truncated and arbitrary wires",
    )?;

    Ok(())
}

#[test]
fn tx_batch_47_vector_serialized_len_non_decreasing_with_more_transactions() -> TestResult {
    let empty = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, Vec::new()),
        "empty batch should create",
    )?;
    let one = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "one tx batch should create",
    )?;
    let two = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?, transfer_kind(2)?]),
        "two tx batch should create",
    )?;

    let empty_len = map_err_debug(
        empty.serialized_len(),
        "empty serialized_len should succeed",
    )?;
    let one_len = map_err_debug(one.serialized_len(), "one serialized_len should succeed")?;
    let two_len = map_err_debug(two.serialized_len(), "two serialized_len should succeed")?;

    require(
        one_len > empty_len,
        "one tx batch should serialize larger than empty batch",
    )?;
    require(
        two_len > one_len,
        "two tx batch should serialize larger than one tx batch",
    )?;

    Ok(())
}

#[test]
fn tx_batch_48_vector_total_size_non_decreasing_with_more_transactions() -> TestResult {
    let empty = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, Vec::new()),
        "empty batch should create",
    )?;
    let one = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?]),
        "one tx batch should create",
    )?;
    let two = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![transfer_kind(1)?, transfer_kind(2)?]),
        "two tx batch should create",
    )?;

    let empty_size = map_err_debug(empty.total_size(), "empty total_size should succeed")?;
    let one_size = map_err_debug(one.total_size(), "one total_size should succeed")?;
    let two_size = map_err_debug(two.total_size(), "two total_size should succeed")?;

    require_equal(&empty_size, &0_usize, "empty total_size should be zero")?;
    require(
        one_size > empty_size,
        "one tx total_size should be larger than empty",
    )?;
    require(
        two_size > one_size,
        "two tx total_size should be larger than one tx",
    )?;

    Ok(())
}

#[test]
fn tx_batch_49_merkle_roots_unique_for_generated_single_transfer_batches() -> TestResult {
    let mut roots = BTreeSet::<Vec<u8>>::new();

    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![transfer_kind(seed)?]),
            "generated single transfer batch should create",
        )?;
        let root: Hash = map_err_debug(batch.compute_merkle_root(), "root should compute")?;

        require(
            roots.insert(root.to_vec()),
            "generated single-transfer roots should be unique",
        )?;
    }

    require_equal(&roots.len(), &64_usize, "should collect 64 unique roots")?;

    Ok(())
}

#[test]
fn tx_batch_50_storage_serialization_roundtrip_for_generated_batches() -> TestResult {
    for seed in 0_u64..64_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "generated storage batch should create",
        )?;

        let storage_bytes = map_err_debug(
            batch.serialize_for_storage(),
            "generated batch should serialize for storage",
        )?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&storage_bytes),
            "generated storage bytes should deserialize",
        )?;

        require_equal(
            &decoded,
            &batch,
            "storage serialization bytes should roundtrip through deserialize",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_51_merkle_root_does_not_change_when_index_changes() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(51)?),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(2, UNIX_2000, all_variant_kinds(51)?),
        "second batch should create",
    )?;

    let first_root = map_err_debug(first.compute_merkle_root(), "first root should compute")?;
    let second_root = map_err_debug(second.compute_merkle_root(), "second root should compute")?;

    require_equal(
        &second_root,
        &first_root,
        "merkle root should depend on transactions, not batch index",
    )
}

#[test]
fn tx_batch_52_merkle_root_does_not_change_when_timestamp_changes() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(52)?),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(1, UNIX_2000.saturating_add(1), all_variant_kinds(52)?),
        "second batch should create",
    )?;

    let first_root = map_err_debug(first.compute_merkle_root(), "first root should compute")?;
    let second_root = map_err_debug(second.compute_merkle_root(), "second root should compute")?;

    require_equal(
        &second_root,
        &first_root,
        "merkle root should depend on transactions, not batch timestamp",
    )
}

#[test]
fn tx_batch_53_merkle_root_does_not_change_when_guardian_signature_changes() -> TestResult {
    let first = valid_batch()?;
    let mut second = first.clone();
    second.guardian_signature = Some(vec![0xAB; 64]);

    let first_root = map_err_debug(first.compute_merkle_root(), "first root should compute")?;
    let second_root = map_err_debug(second.compute_merkle_root(), "second root should compute")?;

    require_equal(
        &second_root,
        &first_root,
        "merkle root should depend on transactions, not guardian signature",
    )
}

#[test]
fn tx_batch_54_serialized_bytes_change_when_index_changes() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(54)?),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(2, UNIX_2000, all_variant_kinds(54)?),
        "second batch should create",
    )?;

    let first_bytes = map_err_debug(first.serialize(), "first batch should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second batch should serialize")?;

    require_not_equal(
        &second_bytes,
        &first_bytes,
        "serialized bytes should include batch index",
    )
}

#[test]
fn tx_batch_55_serialized_bytes_change_when_timestamp_changes() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(55)?),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(1, UNIX_2000.saturating_add(1), all_variant_kinds(55)?),
        "second batch should create",
    )?;

    let first_bytes = map_err_debug(first.serialize(), "first batch should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second batch should serialize")?;

    require_not_equal(
        &second_bytes,
        &first_bytes,
        "serialized bytes should include batch timestamp",
    )
}

#[test]
fn tx_batch_56_serialized_bytes_change_when_guardian_signature_changes() -> TestResult {
    let first = valid_batch()?;
    let mut second = first.clone();
    second.guardian_signature = Some(vec![0xCD; 64]);

    let first_bytes = map_err_debug(first.serialize(), "first batch should serialize")?;
    let second_bytes = map_err_debug(second.serialize(), "second batch should serialize")?;

    require_not_equal(
        &second_bytes,
        &first_bytes,
        "serialized bytes should include guardian signature",
    )
}

#[test]
fn tx_batch_57_total_size_same_when_batch_index_and_timestamp_change() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, all_variant_kinds(57)?),
        "first batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(999, UNIX_2000.saturating_add(999), all_variant_kinds(57)?),
        "second batch should create",
    )?;

    let first_size = map_err_debug(first.total_size(), "first total_size should succeed")?;
    let second_size = map_err_debug(second.total_size(), "second total_size should succeed")?;

    require_equal(
        &second_size,
        &first_size,
        "total_size should depend only on transaction payloads",
    )
}

#[test]
fn tx_batch_58_total_size_same_when_guardian_signature_changes() -> TestResult {
    let first = valid_batch()?;
    let mut second = first.clone();
    second.guardian_signature = Some(vec![0xEF; 2048]);

    let first_size = map_err_debug(first.total_size(), "first total_size should succeed")?;
    let second_size = map_err_debug(second.total_size(), "second total_size should succeed")?;

    require_equal(
        &second_size,
        &first_size,
        "total_size should not include guardian signature",
    )
}

#[test]
fn tx_batch_59_serialized_len_is_at_least_total_size_for_nonempty_batch() -> TestResult {
    let batch = valid_batch()?;

    let total_size = map_err_debug(batch.total_size(), "total_size should succeed")?;
    let serialized_len = map_err_debug(batch.serialized_len(), "serialized_len should succeed")?;

    require(
        serialized_len >= total_size,
        "full batch serialized_len should include wrapper fields and be >= total_size",
    )
}

#[test]
fn tx_batch_60_serialized_len_empty_batch_is_nonzero() -> TestResult {
    let batch = TransactionBatch::default();

    let serialized_len = map_err_debug(
        batch.serialized_len(),
        "empty serialized_len should succeed",
    )?;

    require(
        serialized_len > 0,
        "empty batch still has serialized wrapper bytes",
    )
}

#[test]
fn tx_batch_61_inclusion_proof_three_leaves_all_valid_indices_return_proofs() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(
            1,
            UNIX_2000,
            vec![transfer_kind(1)?, reward_kind(1)?, nft_transfer_kind(1)],
        ),
        "three-leaf batch should create",
    )?;

    for index in 0_usize..3_usize {
        let proof = map_err_debug(
            batch.inclusion_proof(index),
            "three-leaf inclusion proof should compute",
        )?;

        require(
            !proof.is_empty(),
            "three-leaf inclusion proof should contain at least one sibling",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_62_inclusion_proof_three_leaves_rejects_index_three() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(
            1,
            UNIX_2000,
            vec![transfer_kind(1)?, reward_kind(1)?, nft_transfer_kind(1)],
        ),
        "three-leaf batch should create",
    )?;

    require_any_error(
        batch.inclusion_proof(3),
        "three-leaf inclusion proof should reject index 3",
    )
}

#[test]
fn tx_batch_63_inclusion_proof_four_leaves_all_indices_return_nonempty_proofs() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(
            1,
            UNIX_2000,
            vec![
                transfer_kind(1)?,
                reward_kind(1)?,
                register_kind(1)?,
                nft_transfer_kind(1),
            ],
        ),
        "four-leaf batch should create",
    )?;

    for index in 0_usize..4_usize {
        let proof = map_err_debug(
            batch.inclusion_proof(index),
            "four-leaf inclusion proof should compute",
        )?;

        require(
            !proof.is_empty(),
            "four-leaf inclusion proof should contain siblings",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_64_inclusion_proof_rejects_usize_max_index() -> TestResult {
    let batch = valid_batch()?;

    require_any_error(
        batch.inclusion_proof(usize::MAX),
        "usize::MAX inclusion proof index should reject",
    )
}

#[test]
fn tx_batch_65_compute_merkle_root_empty_is_deterministic_across_empty_batches() -> TestResult {
    let first = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, Vec::new()),
        "first empty batch should create",
    )?;
    let second = map_err_debug(
        TransactionBatch::new(999, UNIX_2000.saturating_add(999), Vec::new()),
        "second empty batch should create",
    )?;

    let first_root = map_err_debug(
        first.compute_merkle_root(),
        "first empty root should compute",
    )?;
    let second_root = map_err_debug(
        second.compute_merkle_root(),
        "second empty root should compute",
    )?;

    require_equal(
        &second_root,
        &first_root,
        "empty merkle root should be deterministic independent of batch metadata",
    )
}

#[test]
fn tx_batch_66_compute_merkle_root_duplicate_transactions_is_stable() -> TestResult {
    let tx = transfer_kind(66)?;
    let batch = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![tx.clone(), tx]),
        "duplicate transaction batch should create",
    )?;

    let first = map_err_debug(
        batch.compute_merkle_root(),
        "first duplicate root should compute",
    )?;
    let second = map_err_debug(
        batch.compute_merkle_root(),
        "second duplicate root should compute",
    )?;

    require_equal(
        &second,
        &first,
        "duplicate transaction root should be stable",
    )
}

#[test]
fn tx_batch_67_compute_merkle_root_duplicate_vs_single_transaction_differs() -> TestResult {
    let tx = transfer_kind(67)?;
    let single = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![tx.clone()]),
        "single transaction batch should create",
    )?;
    let duplicate = map_err_debug(
        TransactionBatch::new(1, UNIX_2000, vec![tx.clone(), tx]),
        "duplicate transaction batch should create",
    )?;

    let single_root = map_err_debug(single.compute_merkle_root(), "single root should compute")?;
    let duplicate_root = map_err_debug(
        duplicate.compute_merkle_root(),
        "duplicate root should compute",
    )?;

    require_not_equal(
        &duplicate_root,
        &single_root,
        "duplicating a transaction should change the merkle root",
    )
}

#[test]
fn tx_batch_68_from_reward_only_roundtrip_and_merkle_root() -> TestResult {
    let reward = RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    let batch = map_err_debug(
        TransactionBatch::from_reward_only(68, UNIX_2000, reward),
        "reward-only batch should create",
    )?;
    let root = map_err_debug(
        batch.compute_merkle_root(),
        "reward-only root should compute",
    )?;
    let bytes = map_err_debug(batch.serialize(), "reward-only batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "reward-only batch should deserialize",
    )?;

    require_equal(
        &root.len(),
        &64_usize,
        "reward-only root should be 64 bytes",
    )?;
    require_equal(&decoded, &batch, "reward-only batch should roundtrip")?;

    Ok(())
}

#[test]
fn tx_batch_69_from_reward_only_wraps_invalid_reward_without_batch_validation() -> TestResult {
    let reward = RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
        amount: 0,
        block_height: 1,
        timestamp: UNIX_2000,
    };

    let batch = map_err_debug(
        TransactionBatch::from_reward_only(69, UNIX_2000, reward),
        "from_reward_only should wrap the reward without validating inner reward",
    )?;

    require_equal(
        &batch.transactions.len(),
        &1_usize,
        "invalid reward is still wrapped as one transaction",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "batch with invalid inner reward should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with invalid inner reward should deserialize",
    )?;

    require_equal(
        &decoded,
        &batch,
        "batch with invalid inner reward should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_70_batch_can_contain_invalid_inner_transfer_and_still_serialize() -> TestResult {
    let invalid = TxKind::Transfer(Transaction {
        sender: wallet_array(&wallet_with_repeated_hex('a'))?,
        receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
        amount: 0,
        timestamp: UNIX_2000,
    });

    let batch = map_err_debug(
        TransactionBatch::new(70, UNIX_2000, vec![invalid]),
        "batch with invalid inner transfer should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "batch with invalid inner transfer should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with invalid inner transfer should deserialize",
    )?;

    require_equal(
        &decoded,
        &batch,
        "invalid-inner transfer batch should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_71_batch_can_contain_invalid_inner_register_and_still_serialize() -> TestResult {
    let invalid = TxKind::RegisterNode(RegisterNodeTx {
        wallet_address: wallet_array(&wallet_with_repeated_hex('a'))?,
        timestamp: UNIX_2000.saturating_sub(1),
    });

    let batch = map_err_debug(
        TransactionBatch::new(71, UNIX_2000, vec![invalid]),
        "batch with invalid inner register should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "batch with invalid inner register should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with invalid inner register should deserialize",
    )?;

    require_equal(
        &decoded,
        &batch,
        "invalid-inner register batch should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_72_batch_can_contain_invalid_inner_reward_and_still_serialize() -> TestResult {
    let invalid = TxKind::Reward(RewardTx {
        receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
        amount: 1,
        block_height: 0,
        timestamp: UNIX_2000,
    });

    let batch = map_err_debug(
        TransactionBatch::new(72, UNIX_2000, vec![invalid]),
        "batch with invalid inner reward should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "batch with invalid inner reward should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with invalid inner reward should deserialize",
    )?;

    require_equal(
        &decoded,
        &batch,
        "invalid-inner reward batch should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_73_batch_can_contain_invalid_inner_nft_transfer_and_still_serialize() -> TestResult {
    let invalid = TxKind::NftTransfer(NftTransferTx {
        nft_id: hash_from_seed(73),
        new_owner_wallet: format!("x{}", wallet_body_from_seed(73)),
    });

    let batch = map_err_debug(
        TransactionBatch::new(73, UNIX_2000, vec![invalid]),
        "batch with invalid inner NFT transfer should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "batch with invalid inner NFT transfer should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with invalid inner NFT transfer should deserialize",
    )?;

    require_equal(
        &decoded,
        &batch,
        "invalid-inner NFT transfer batch should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_74_deserialized_invalid_inner_transactions_can_be_detected_by_txkind_validate()
-> TestResult {
    let invalids = vec![
        TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_with_repeated_hex('a'))?,
            receiver: wallet_array(&wallet_with_repeated_hex('b'))?,
            amount: 0,
            timestamp: UNIX_2000,
        }),
        TxKind::RegisterNode(RegisterNodeTx {
            wallet_address: wallet_array(&wallet_with_repeated_hex('a'))?,
            timestamp: UNIX_2000.saturating_sub(1),
        }),
        TxKind::Reward(RewardTx {
            receiver: wallet_array(&wallet_with_repeated_hex('a'))?,
            amount: 1,
            block_height: 0,
            timestamp: UNIX_2000,
        }),
        TxKind::NftTransfer(NftTransferTx {
            nft_id: hash_from_seed(74),
            new_owner_wallet: format!("x{}", wallet_body_from_seed(74)),
        }),
    ];

    let batch = map_err_debug(
        TransactionBatch::new(74, UNIX_2000, invalids),
        "invalid-inner batch should create",
    )?;
    let bytes = map_err_debug(batch.serialize(), "invalid-inner batch should serialize")?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "invalid-inner batch should deserialize",
    )?;

    let rejected = decoded
        .transactions
        .iter()
        .filter(|tx| tx.validate().is_err())
        .count();

    require_equal(
        &rejected,
        &4_usize,
        "all four invalid inner TxKinds should be detectable by TxKind::validate",
    )
}

#[test]
fn tx_batch_75_txkind_validate_accepts_all_inner_transactions_from_valid_batch() -> TestResult {
    let batch = valid_batch()?;

    for tx in &batch.transactions {
        map_err_debug(
            tx.validate(),
            "inner TxKind from valid batch should validate",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_76_touched_addresses_union_for_transfer_and_reward_batch() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(76, UNIX_2000, vec![transfer_kind(1)?, reward_kind(1)?]),
        "transfer and reward batch should create",
    )?;

    let mut touched = BTreeSet::new();

    for tx in &batch.transactions {
        for address in tx.touched_addresses() {
            touched.insert(address);
        }
    }

    require_equal(
        &touched.len(),
        &3_usize,
        "transfer touches sender and receiver, reward touches receiver",
    )?;

    Ok(())
}

#[test]
fn tx_batch_77_touched_addresses_union_deduplicates_repeated_wallets() -> TestResult {
    let wallet = wallet_array(&wallet_with_repeated_hex('a'))?;
    let transfer = TxKind::Transfer(Transaction {
        sender: wallet,
        receiver: wallet,
        amount: 1,
        timestamp: UNIX_2000,
    });
    let reward = TxKind::Reward(RewardTx {
        receiver: wallet,
        amount: 1,
        block_height: 1,
        timestamp: UNIX_2000,
    });

    let batch = map_err_debug(
        TransactionBatch::new(77, UNIX_2000, vec![transfer, reward]),
        "dedupe touched batch should create",
    )?;

    let mut touched = BTreeSet::new();

    for tx in &batch.transactions {
        for address in tx.touched_addresses() {
            touched.insert(address);
        }
    }

    require_equal(
        &touched,
        &BTreeSet::from([wallet_with_repeated_hex('a')]),
        "union of touched addresses should deduplicate same wallet",
    )
}

#[test]
fn tx_batch_78_serialize_for_storage_with_empty_signature_vector_roundtrips() -> TestResult {
    let mut batch = valid_batch()?;
    batch.guardian_signature = Some(Vec::new());

    let bytes = map_err_debug(
        batch.serialize_for_storage(),
        "batch with empty signature vec should serialize for storage",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "batch with empty signature vec should deserialize",
    )?;

    require_equal(
        &decoded.guardian_signature,
        &Some(Vec::new()),
        "empty signature vector should roundtrip distinctly from None",
    )?;

    Ok(())
}

#[test]
fn tx_batch_79_none_and_empty_signature_are_distinct() -> TestResult {
    let none_batch = valid_batch()?;
    let mut empty_batch = none_batch.clone();
    empty_batch.guardian_signature = Some(Vec::new());

    require_not_equal(
        &empty_batch,
        &none_batch,
        "None signature and Some(empty vec) should be distinct batches",
    )?;

    let none_bytes = map_err_debug(none_batch.serialize(), "none batch should serialize")?;
    let empty_bytes = map_err_debug(
        empty_batch.serialize(),
        "empty signature batch should serialize",
    )?;

    require_not_equal(
        &empty_bytes,
        &none_bytes,
        "None signature and Some(empty vec) should serialize differently",
    )
}

#[test]
fn tx_batch_80_vector_guardian_signature_lengths_roundtrip() -> TestResult {
    for len in [0_usize, 1_usize, 16_usize, 64_usize, 128_usize, 1024_usize] {
        let mut batch = valid_batch()?;
        batch.guardian_signature = Some(vec![0xAB; len]);

        let bytes = map_err_debug(
            batch.serialize(),
            "signature length vector should serialize",
        )?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "signature length vector should deserialize",
        )?;

        require_equal(
            &decoded.guardian_signature,
            &Some(vec![0xAB; len]),
            "guardian signature length vector should roundtrip",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_81_vector_indices_roundtrip() -> TestResult {
    for index in [
        0_u64,
        1_u64,
        9_u64,
        10_u64,
        999_u64,
        1_000_000_u64,
        u64::MAX,
    ] {
        let batch = map_err_debug(
            TransactionBatch::new(index, UNIX_2000, vec![transfer_kind(81)?]),
            "index vector batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "index vector batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "index vector batch should deserialize",
        )?;

        require_equal(&decoded.index, &index, "batch index should roundtrip")?;
    }

    Ok(())
}

#[test]
fn tx_batch_82_vector_timestamps_roundtrip() -> TestResult {
    for timestamp in [0_u64, 1_u64, UNIX_2000, UNIX_2000 + 1, u64::MAX] {
        let batch = map_err_debug(
            TransactionBatch::new(82, timestamp, vec![transfer_kind(82)?]),
            "timestamp vector batch should create",
        )?;
        let bytes = map_err_debug(batch.serialize(), "timestamp vector batch should serialize")?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "timestamp vector batch should deserialize",
        )?;

        require_equal(
            &decoded.timestamp,
            &timestamp,
            "batch timestamp should roundtrip",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_83_vector_transaction_counts_roundtrip() -> TestResult {
    for count in [0_usize, 1_usize, 2_usize, 5_usize, 10_usize, 32_usize] {
        let mut txs = Vec::new();

        for seed in 0_u64
            ..u64::try_from(count).map_err(|error| format!("count conversion failed: {error}"))?
        {
            txs.push(transfer_kind(seed)?);
        }

        let batch = map_err_debug(
            TransactionBatch::new(83, UNIX_2000, txs),
            "transaction count vector batch should create",
        )?;
        let bytes = map_err_debug(
            batch.serialize(),
            "transaction count vector batch should serialize",
        )?;
        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "transaction count vector batch should deserialize",
        )?;

        require_equal(
            &decoded.transactions.len(),
            &count,
            "transaction count should roundtrip",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_84_vector_total_size_matches_manual_for_transaction_counts() -> TestResult {
    for count in [1_usize, 2_usize, 4_usize, 8_usize, 16_usize] {
        let mut txs = Vec::new();

        for seed in 0_u64
            ..u64::try_from(count).map_err(|error| format!("count conversion failed: {error}"))?
        {
            txs.push(transfer_kind(seed)?);
        }

        let batch = map_err_debug(
            TransactionBatch::new(84, UNIX_2000, txs),
            "total size vector batch should create",
        )?;

        let expected = batch
            .transactions
            .iter()
            .map(serialized_tx_kind_payload_len)
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .try_fold(0_usize, |acc, len| {
                acc.checked_add(*len)
                    .ok_or_else(|| "manual total size overflowed".to_owned())
            })?;

        let actual = map_err_debug(batch.total_size(), "total_size should succeed")?;

        require_equal(&actual, &expected, "manual and API total_size should match")?;
    }

    Ok(())
}

#[test]
fn tx_batch_85_vector_storage_serialization_is_within_cap_for_small_counts() -> TestResult {
    let max_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE)
        .map_err(|error| format!("MAX_BLOCK_SIZE conversion failed: {error}"))?;

    for count in [0_usize, 1_usize, 2_usize, 8_usize, 32_usize] {
        let mut txs = Vec::new();

        for seed in 0_u64
            ..u64::try_from(count).map_err(|error| format!("count conversion failed: {error}"))?
        {
            txs.push(transfer_kind(seed)?);
        }

        let batch = map_err_debug(
            TransactionBatch::new(85, UNIX_2000, txs),
            "storage cap vector batch should create",
        )?;
        let bytes = map_err_debug(
            batch.serialize_for_storage(),
            "small count batch should serialize for storage",
        )?;

        require(
            bytes.len() <= max_size,
            "small count storage bytes should be within MAX_BLOCK_SIZE",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_86_fuzz_random_short_payloads_reject_or_decode_empty_only() -> TestResult {
    for len in 0_usize..128_usize {
        let seed =
            u64::try_from(len).map_err(|error| format!("length conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed.saturating_add(86), len);

        if let Ok(batch) = TransactionBatch::deserialize(&bytes) {
            require(
                batch.transactions.is_empty(),
                "random short decoded batch should not contain transactions",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_87_fuzz_random_medium_payloads_reject_or_decode_empty_only() -> TestResult {
    for len in 128_usize..384_usize {
        let seed =
            u64::try_from(len).map_err(|error| format!("length conversion failed: {error}"))?;
        let bytes = bytes_from_seed(seed.saturating_add(87), len);

        if let Ok(batch) = TransactionBatch::deserialize(&bytes) {
            require(
                batch.transactions.is_empty(),
                "random medium decoded batch should not contain transactions",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_88_fuzz_reversed_valid_bytes_reject_or_decode_different_batch() -> TestResult {
    let batch = valid_batch()?;
    let mut bytes = map_err_debug(batch.serialize(), "valid batch should serialize")?;
    bytes.reverse();

    match TransactionBatch::deserialize(&bytes) {
        Ok(decoded) => require_not_equal(
            &decoded,
            &batch,
            "reversed bytes must not decode to original batch",
        ),
        Err(_) => Ok(()),
    }
}

#[test]
fn tx_batch_89_fuzz_zeroed_payloads_reject_or_decode_empty_only() -> TestResult {
    for len in [
        1_usize, 2_usize, 4_usize, 8_usize, 16_usize, 32_usize, 64_usize,
    ] {
        let bytes = vec![0_u8; len];

        if let Ok(batch) = TransactionBatch::deserialize(&bytes) {
            require(
                batch.transactions.is_empty(),
                "zeroed decoded batch should not contain transactions",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_90_load_merkle_roots_unique_for_generated_mixed_batches() -> TestResult {
    let mut roots = BTreeSet::<Vec<u8>>::new();

    for seed in 0_u64..128_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "generated mixed batch should create",
        )?;
        let root = map_err_debug(
            batch.compute_merkle_root(),
            "generated mixed root should compute",
        )?;

        require(
            roots.insert(root.to_vec()),
            "generated mixed batch merkle root should be unique",
        )?;
    }

    require_equal(
        &roots.len(),
        &128_usize,
        "should collect 128 unique merkle roots",
    )?;

    Ok(())
}

#[test]
fn tx_batch_91_load_serialized_storage_bytes_unique_for_generated_batches() -> TestResult {
    let mut seen = BTreeSet::new();

    for seed in 0_u64..128_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "generated storage batch should create",
        )?;
        let bytes = map_err_debug(
            batch.serialize_for_storage(),
            "generated storage batch should serialize",
        )?;

        require(
            seen.insert(bytes),
            "generated storage batch bytes should be unique",
        )?;
    }

    require_equal(
        &seen.len(),
        &128_usize,
        "should collect 128 unique storage byte blobs",
    )?;

    Ok(())
}

#[test]
fn tx_batch_92_load_total_size_many_batches_nonzero() -> TestResult {
    let mut checked = 0_usize;

    for seed in 0_u64..256_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, vec![transfer_kind(seed)?]),
            "generated total-size batch should create",
        )?;
        let total_size = map_err_debug(batch.total_size(), "generated total_size should succeed")?;

        require(
            total_size > 0,
            "single transfer batch total_size should be nonzero",
        )?;

        checked = checked
            .checked_add(1)
            .ok_or_else(|| "checked counter overflowed".to_owned())?;
    }

    require_equal(&checked, &256_usize, "should check 256 generated batches")?;

    Ok(())
}

#[test]
fn tx_batch_93_load_inclusion_proofs_for_many_two_leaf_batches() -> TestResult {
    let mut checked = 0_usize;

    for seed in 0_u64..128_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(
                seed,
                UNIX_2000,
                vec![transfer_kind(seed)?, reward_kind(seed)?],
            ),
            "two-leaf generated batch should create",
        )?;

        let proof_zero = map_err_debug(batch.inclusion_proof(0), "proof zero should compute")?;
        let proof_one = map_err_debug(batch.inclusion_proof(1), "proof one should compute")?;

        require_equal(
            &proof_zero.len(),
            &1_usize,
            "two-leaf proof zero should have one sibling",
        )?;
        require_equal(
            &proof_one.len(),
            &1_usize,
            "two-leaf proof one should have one sibling",
        )?;

        checked = checked
            .checked_add(1)
            .ok_or_else(|| "checked counter overflowed".to_owned())?;
    }

    require_equal(&checked, &128_usize, "should check 128 two-leaf batches")?;

    Ok(())
}

#[test]
fn tx_batch_94_adversarial_batch_with_many_duplicate_transactions_roundtrips() -> TestResult {
    let tx = transfer_kind(94)?;
    let txs = vec![tx; 64];

    let batch = map_err_debug(
        TransactionBatch::new(94, UNIX_2000, txs),
        "duplicate transaction batch should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize(),
        "duplicate transaction batch should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "duplicate transaction batch should deserialize",
    )?;

    require_equal(
        &decoded.transactions.len(),
        &64_usize,
        "duplicate transaction batch should preserve count",
    )?;
    require_equal(
        &decoded,
        &batch,
        "duplicate transaction batch should roundtrip",
    )?;

    Ok(())
}

#[test]
fn tx_batch_95_adversarial_large_signature_increases_storage_bytes_without_changing_total_size()
-> TestResult {
    let batch = valid_batch()?;
    let mut signed = batch.clone();
    signed.guardian_signature = Some(vec![0x42; 4096]);

    let batch_total = map_err_debug(batch.total_size(), "base total_size should succeed")?;
    let signed_total = map_err_debug(signed.total_size(), "signed total_size should succeed")?;
    let batch_len = map_err_debug(batch.serialized_len(), "base serialized_len should succeed")?;
    let signed_len = map_err_debug(
        signed.serialized_len(),
        "signed serialized_len should succeed",
    )?;

    require_equal(
        &signed_total,
        &batch_total,
        "large signature should not change transaction-only total_size",
    )?;
    require(
        signed_len > batch_len,
        "large signature should increase serialized_len",
    )?;

    Ok(())
}

#[test]
fn tx_batch_96_adversarial_many_invalid_inner_transactions_roundtrip_and_reject_by_inner_validation()
-> TestResult {
    let mut txs = Vec::new();

    for seed in 0_u64..64_u64 {
        txs.push(TxKind::Transfer(Transaction {
            sender: wallet_array(&wallet_from_seed(seed))?,
            receiver: wallet_array(&wallet_from_seed(seed.saturating_add(1_000)))?,
            amount: 0,
            timestamp: UNIX_2000,
        }));
    }

    let batch = map_err_debug(
        TransactionBatch::new(96, UNIX_2000, txs),
        "many invalid inner transfers batch should create",
    )?;
    let bytes = map_err_debug(
        batch.serialize(),
        "many invalid inner transfers should serialize",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "many invalid inner transfers should deserialize",
    )?;

    let rejected = decoded
        .transactions
        .iter()
        .filter(|tx| tx.validate().is_err())
        .count();

    require_equal(
        &rejected,
        &64_usize,
        "all invalid inner transfers should reject by TxKind validation",
    )?;

    Ok(())
}

#[test]
fn tx_batch_97_adversarial_mixed_valid_invalid_duplicate_wires_counts_expected() -> TestResult {
    let mut wires = Vec::new();

    for seed in 0_u64..32_u64 {
        let valid = map_err_debug(
            TransactionBatch::new(seed, UNIX_2000, all_variant_kinds(seed)?),
            "valid adversarial batch should create",
        )?;
        let valid_wire = map_err_debug(
            valid.serialize(),
            "valid adversarial batch should serialize",
        )?;
        wires.push(valid_wire.clone());

        if seed < 8 {
            wires.push(valid_wire.clone());
        }

        let invalid_inner = map_err_debug(
            TransactionBatch::new(
                seed.saturating_add(10_000),
                UNIX_2000,
                vec![TxKind::Transfer(Transaction {
                    sender: wallet_array(&wallet_from_seed(seed.saturating_add(20_000)))?,
                    receiver: wallet_array(&wallet_from_seed(seed.saturating_add(30_000)))?,
                    amount: 0,
                    timestamp: UNIX_2000,
                })],
            ),
            "invalid-inner adversarial batch should create",
        )?;
        wires.push(map_err_debug(
            invalid_inner.serialize(),
            "invalid-inner adversarial batch should serialize",
        )?);

        let mut truncated = valid_wire;
        let half = truncated
            .len()
            .checked_div(2)
            .ok_or_else(|| "truncated length division failed".to_owned())?;
        truncated.truncate(half);
        wires.push(truncated);
    }

    let mut unique_valid = 0_usize;
    let mut duplicate_valid = 0_usize;
    let mut invalid_inner = 0_usize;
    let mut rejected_wire = 0_usize;
    let mut seen = BTreeSet::new();

    for wire in wires {
        match TransactionBatch::deserialize(&wire) {
            Ok(batch) => {
                let all_inner_valid = batch.transactions.iter().all(|tx| tx.validate().is_ok());

                if all_inner_valid {
                    let key = map_err_debug(batch.serialize(), "valid batch key should serialize")?;
                    if seen.insert(key) {
                        unique_valid = unique_valid
                            .checked_add(1)
                            .ok_or_else(|| "unique valid counter overflowed".to_owned())?;
                    } else {
                        duplicate_valid = duplicate_valid
                            .checked_add(1)
                            .ok_or_else(|| "duplicate valid counter overflowed".to_owned())?;
                    }
                } else {
                    invalid_inner = invalid_inner
                        .checked_add(1)
                        .ok_or_else(|| "invalid inner counter overflowed".to_owned())?;
                }
            }
            Err(_) => {
                rejected_wire = rejected_wire
                    .checked_add(1)
                    .ok_or_else(|| "rejected wire counter overflowed".to_owned())?;
            }
        }
    }

    require_equal(
        &unique_valid,
        &32_usize,
        "should decode 32 unique valid batches",
    )?;
    require_equal(
        &duplicate_valid,
        &8_usize,
        "should detect 8 duplicate valid batches",
    )?;
    require_equal(
        &invalid_inner,
        &32_usize,
        "should decode 32 batches with invalid inner txs",
    )?;
    require_equal(
        &rejected_wire,
        &32_usize,
        "should reject 32 truncated wires",
    )?;

    Ok(())
}

#[test]
fn tx_batch_98_storage_serialization_matches_canonical_db_fetch_bytes_contract() -> TestResult {
    let batch = valid_batch()?;
    let storage_bytes = map_err_debug(
        batch.serialize_for_storage(),
        "batch should serialize for storage",
    )?;

    let decoded = map_err_debug(
        TransactionBatch::deserialize(&storage_bytes),
        "canonical storage bytes should deserialize",
    )?;
    let decoded_storage_bytes = map_err_debug(
        decoded.serialize_for_storage(),
        "decoded batch should serialize for storage",
    )?;

    require_equal(
        &decoded_storage_bytes,
        &storage_bytes,
        "bytes fetched from canonical tx_batch_{index:010} storage should be stable after decode/re-encode",
    )
}

#[test]
fn tx_batch_99_vector_canonical_batch_key_strings_match_rocksdb_reference_format() -> TestResult {
    let cases = [
        (0_u64, "tx_batch_0000000000"),
        (1_u64, "tx_batch_0000000001"),
        (42_u64, "tx_batch_0000000042"),
        (999_999_999_u64, "tx_batch_0999999999"),
        (1_000_000_000_u64, "tx_batch_1000000000"),
    ];

    for (index, expected) in cases {
        let key = format!("tx_batch_{index:010}");

        require_equal(
            &key,
            &expected.to_owned(),
            "canonical RocksDB batch key format should match tx_batch_{:010}",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_100_load_storage_roundtrip_many_mixed_batches_and_key_vectors() -> TestResult {
    let mut seen_keys = BTreeSet::new();
    let mut seen_bytes = BTreeSet::new();

    for index in 0_u64..128_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(index, UNIX_2000, all_variant_kinds(index)?),
            "load storage batch should create",
        )?;

        let key = format!("tx_batch_{index:010}");
        require(
            seen_keys.insert(key),
            "canonical storage key should be unique for each index",
        )?;

        let bytes = map_err_debug(
            batch.serialize_for_storage(),
            "load storage batch should serialize",
        )?;
        require(
            seen_bytes.insert(bytes.clone()),
            "canonical storage bytes should be unique for each generated mixed batch",
        )?;

        let decoded = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "load storage batch should deserialize",
        )?;

        require_equal(
            &decoded,
            &batch,
            "load storage batch should roundtrip exactly",
        )?;
    }

    require_equal(
        &seen_keys.len(),
        &128_usize,
        "should produce 128 unique canonical keys",
    )?;
    require_equal(
        &seen_bytes.len(),
        &128_usize,
        "should produce 128 unique storage payloads",
    )?;

    Ok(())
}

#[test]
fn tx_batch_101_vector_storage_key_format_for_large_indices() -> TestResult {
    let cases = [
        (1_000_000_001_u64, "tx_batch_1000000001"),
        (4_294_967_295_u64, "tx_batch_4294967295"),
        (10_000_000_000_u64, "tx_batch_10000000000"),
        (u64::MAX, "tx_batch_18446744073709551615"),
    ];

    for (index, expected) in cases {
        let key = format!("tx_batch_{index:010}");

        require_equal(
            &key,
            &expected.to_owned(),
            "canonical tx batch key should use minimum width 10 and expand for large indices",
        )?;
    }

    Ok(())
}

#[test]
fn tx_batch_102_nodeopts_default_values_match_runtime_contract() -> TestResult {
    let opts = remzar::runtime::p2p_006_sync_runtime::NodeOpts::default();

    require_equal(
        &opts.identity_file,
        &"identity.key".to_owned(),
        "default identity file should match runtime default",
    )?;
    require_equal(
        &opts.listen,
        &"/ip4/0.0.0.0/tcp/36213".to_owned(),
        "default listen address should match runtime default",
    )?;
    require(
        opts.bootstrap.is_empty(),
        "default bootstrap list should be empty",
    )?;
    require_equal(
        &opts.log,
        &"info".to_owned(),
        "default log level should be info",
    )?;
    require_equal(
        &opts.data_dir,
        &"data".to_owned(),
        "default data dir should be data",
    )?;
    require_equal(
        &opts.wallet_address,
        &String::new(),
        "default wallet address should be empty",
    )?;
    require_equal(
        &opts.founder,
        &false,
        "default founder flag should be false",
    )?;

    Ok(())
}

#[test]
fn tx_batch_103_empty_batch_storage_roundtrip_preserves_zero_index_and_timestamp() -> TestResult {
    let batch = map_err_debug(
        TransactionBatch::new(0, 0, Vec::new()),
        "empty zero batch should create",
    )?;

    let bytes = map_err_debug(
        batch.serialize_for_storage(),
        "empty zero batch should serialize for storage",
    )?;
    let decoded = map_err_debug(
        TransactionBatch::deserialize(&bytes),
        "empty zero storage bytes should deserialize",
    )?;

    require_equal(&decoded.index, &0_u64, "zero index should roundtrip")?;
    require_equal(
        &decoded.timestamp,
        &0_u64,
        "zero timestamp should roundtrip",
    )?;
    require(
        decoded.transactions.is_empty(),
        "transactions should remain empty",
    )?;
    require_equal(
        &decoded.guardian_signature,
        &None,
        "guardian signature should remain None",
    )?;

    Ok(())
}

#[test]
fn tx_batch_104_storage_bytes_are_stable_after_multiple_decode_encode_cycles() -> TestResult {
    let batch = valid_batch()?;
    let original_bytes = map_err_debug(
        batch.serialize_for_storage(),
        "original storage serialization should succeed",
    )?;

    let mut current = batch;

    for _ in 0_usize..10_usize {
        let bytes = map_err_debug(
            current.serialize_for_storage(),
            "cycle storage serialization should succeed",
        )?;
        current = map_err_debug(
            TransactionBatch::deserialize(&bytes),
            "cycle storage bytes should deserialize",
        )?;
    }

    let final_bytes = map_err_debug(
        current.serialize_for_storage(),
        "final storage serialization should succeed",
    )?;

    require_equal(
        &final_bytes,
        &original_bytes,
        "storage bytes should remain stable across repeated decode/encode cycles",
    )?;

    Ok(())
}

#[test]
fn tx_batch_105_inclusion_proofs_for_power_of_two_batches_are_deterministic() -> TestResult {
    for count in [2_usize, 4_usize, 8_usize] {
        let mut txs = Vec::new();

        for seed in 0_u64
            ..u64::try_from(count).map_err(|error| format!("count conversion failed: {error}"))?
        {
            txs.push(transfer_kind(seed)?);
        }

        let batch = map_err_debug(
            TransactionBatch::new(
                u64::try_from(count)
                    .map_err(|error| format!("index conversion failed: {error}"))?,
                UNIX_2000,
                txs,
            ),
            "power-of-two batch should create",
        )?;

        for index in 0_usize..count {
            let first = map_err_debug(
                batch.inclusion_proof(index),
                "first power-of-two inclusion proof should compute",
            )?;
            let second = map_err_debug(
                batch.inclusion_proof(index),
                "second power-of-two inclusion proof should compute",
            )?;

            require(
                !first.is_empty(),
                "power-of-two inclusion proof should contain at least one sibling",
            )?;

            let first_bytes: Vec<Vec<u8>> =
                first.iter().map(|node| node.as_bytes().to_vec()).collect();

            let second_bytes: Vec<Vec<u8>> =
                second.iter().map(|node| node.as_bytes().to_vec()).collect();

            require_equal(
                &first_bytes,
                &second_bytes,
                "power-of-two inclusion proof bytes should be deterministic for the same index",
            )?;

            for node_bytes in &first_bytes {
                require_equal(
                    &node_bytes.len(),
                    &64_usize,
                    "each inclusion proof node should expose 64 hash bytes",
                )?;
            }
        }
    }

    Ok(())
}

#[test]
fn tx_batch_106_inclusion_proof_lengths_for_non_power_of_two_batches_are_nonzero() -> TestResult {
    for count in [3_usize, 5_usize, 7_usize, 9_usize] {
        let mut txs = Vec::new();

        for seed in 0_u64
            ..u64::try_from(count).map_err(|error| format!("count conversion failed: {error}"))?
        {
            txs.push(transfer_kind(seed)?);
        }

        let batch = map_err_debug(
            TransactionBatch::new(
                u64::try_from(count)
                    .map_err(|error| format!("index conversion failed: {error}"))?,
                UNIX_2000,
                txs,
            ),
            "non-power-of-two batch should create",
        )?;

        for index in 0_usize..count {
            let proof = map_err_debug(
                batch.inclusion_proof(index),
                "non-power-of-two inclusion proof should compute",
            )?;

            require(
                !proof.is_empty(),
                "non-power-of-two inclusion proof should contain siblings",
            )?;
        }
    }

    Ok(())
}

#[test]
fn tx_batch_107_merkle_root_changes_when_duplicate_count_changes() -> TestResult {
    let tx = transfer_kind(107)?;

    let one = map_err_debug(
        TransactionBatch::new(107, UNIX_2000, vec![tx.clone()]),
        "one duplicate-count batch should create",
    )?;
    let two = map_err_debug(
        TransactionBatch::new(107, UNIX_2000, vec![tx.clone(), tx.clone()]),
        "two duplicate-count batch should create",
    )?;
    let three = map_err_debug(
        TransactionBatch::new(107, UNIX_2000, vec![tx.clone(), tx.clone(), tx]),
        "three duplicate-count batch should create",
    )?;

    let one_root = map_err_debug(one.compute_merkle_root(), "one root should compute")?;
    let two_root = map_err_debug(two.compute_merkle_root(), "two root should compute")?;
    let three_root = map_err_debug(three.compute_merkle_root(), "three root should compute")?;

    require_not_equal(
        &one_root,
        &two_root,
        "one and two duplicate roots should differ",
    )?;
    require_not_equal(
        &two_root,
        &three_root,
        "two and three duplicate roots should differ",
    )?;
    require_not_equal(
        &one_root,
        &three_root,
        "one and three duplicate roots should differ",
    )?;

    Ok(())
}

#[test]
fn tx_batch_108_total_size_matches_inner_payloads_for_all_variant_repetition() -> TestResult {
    let mut txs = Vec::new();

    for seed in 0_u64..10_u64 {
        txs.extend(all_variant_kinds(seed)?);
    }

    let batch = map_err_debug(
        TransactionBatch::new(108, UNIX_2000, txs),
        "repeated all-variant batch should create",
    )?;

    let expected = batch
        .transactions
        .iter()
        .map(serialized_tx_kind_payload_len)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .try_fold(0_usize, |acc, len| {
            acc.checked_add(*len)
                .ok_or_else(|| "manual total size overflowed".to_owned())
        })?;

    let actual = map_err_debug(
        batch.total_size(),
        "repeated all-variant total_size should succeed",
    )?;

    require_equal(
        &actual,
        &expected,
        "total_size should match manual sum for repeated all-variant batch",
    )?;

    Ok(())
}

#[test]
fn tx_batch_109_adversarial_trailing_bytes_rejected_before_storage_canonicalization() -> TestResult
{
    let batch = valid_batch()?;
    let original_storage = map_err_debug(
        batch.serialize_for_storage(),
        "original storage serialization should succeed",
    )?;

    let mut poisoned = original_storage;
    poisoned.extend_from_slice(&bytes_from_seed(109, 128));

    require_any_error(
        TransactionBatch::deserialize(&poisoned),
        "poisoned storage bytes with trailing data should be rejected, not decoded/recanonicalized",
    )
}

#[test]
fn tx_batch_110_load_storage_key_and_payload_vectors_remain_aligned() -> TestResult {
    let mut keys = BTreeSet::new();
    let mut payloads = BTreeSet::new();

    for index in 500_u64..600_u64 {
        let batch = map_err_debug(
            TransactionBatch::new(index, UNIX_2000, all_variant_kinds(index)?),
            "aligned load batch should create",
        )?;

        let key = format!("tx_batch_{index:010}");
        let payload = map_err_debug(
            batch.serialize_for_storage(),
            "aligned load batch should serialize for storage",
        )?;

        require(keys.insert(key), "canonical storage key should be unique")?;
        require(payloads.insert(payload), "storage payload should be unique")?;
    }

    require_equal(
        &keys.len(),
        &100_usize,
        "should produce 100 unique storage keys",
    )?;
    require_equal(
        &payloads.len(),
        &100_usize,
        "should produce 100 unique storage payloads",
    )?;

    Ok(())
}
