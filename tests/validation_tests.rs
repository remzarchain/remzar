// tests/blockchain_001_validation_tests.rs

#![allow(clippy::too_many_lines)]

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::blockchain::halving_schedule::RewardHalving;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_003_tx_reward::RewardTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::blockchain::validation::{BlockchainValidation, FullBlockValidationContext};
use remzar::blockchain::validatorstate::ValidatorState;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::consensus::por_006_committee_eligibility::CommitteeEligibility;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use remzar::utility::helper::REMZAR_WALLET_LEN;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;

use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::{PorPuzzleEngine, PorPuzzleSolution};
use std::time::Duration;

type TestResult = Result<(), Box<dyn Error>>;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDb {
    manager: Option<RockDBManager>,
    root: PathBuf,
}

impl TestDb {
    fn manager(&self) -> Result<&RockDBManager, Box<dyn Error>> {
        self.manager
            .as_ref()
            .ok_or_else(|| boxed_error("test database manager is not available"))
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        drop(self.manager.take());

        if std::fs::remove_dir_all(&self.root).is_err() {
            // Best-effort cleanup only.
        }
    }
}

fn boxed_error(message: &str) -> Box<dyn Error> {
    Box::new(std::io::Error::other(message.to_owned()))
}

fn unique_root(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("remzar_validation_{label}_{pid}_{id}"))
}

fn path_to_string(path: &Path) -> Result<String, Box<dyn Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| boxed_error("test path is not valid UTF-8"))
}

fn fib_for_test(n: u32) -> u128 {
    let mut a = 0u128;
    let mut b = 1u128;

    for _ in 0..n {
        let next = a.saturating_add(b);
        a = b;
        b = next;
    }

    a
}

fn test_por_engine() -> PorPuzzleEngine {
    PorPuzzleEngine::new(PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1_000,
    })
}

fn puzzle_output_for_engine(
    engine: &PorPuzzleEngine,
    height: u64,
    validator: &str,
    previous_hash: Hash,
) -> Result<u128, Box<dyn Error>> {
    let header = engine.derive_puzzle(height, validator, previous_hash);

    match header.kind {
        PorPuzzleKind::FibonacciDelayDev => Ok(fib_for_test(header.param)),
        PorPuzzleKind::FactorizationDelayDev => Err(boxed_error(
            "test helper expects mandatory Fibonacci puzzle kind",
        )),
    }
}

fn valid_block_puzzle_proof(
    height: u64,
    validator: &str,
    previous_hash: Hash,
) -> Result<BlockPuzzleProof, Box<dyn Error>> {
    let engine = PorPuzzleEngine::from_globals();
    let output = puzzle_output_for_engine(&engine, height, validator, previous_hash)?;
    Ok(BlockPuzzleProof::new(
        height,
        validator.to_owned(),
        previous_hash,
        output,
    )?)
}

fn metadata_with_proof(
    index: u64,
    previous_hash: Hash,
    proof: Option<BlockPuzzleProof>,
) -> Result<BlockMetadata, Box<dyn Error>> {
    let mut metadata = valid_metadata(index, previous_hash)?;
    metadata.puzzle_proof = proof;
    Ok(metadata)
}

fn context_with_founder(
    label: &str,
    miner: &str,
) -> Result<
    (
        TestDb,
        ValidatorState,
        CommitteeEligibility,
        DetectionSystem,
        TimeManager,
        ml_dsa_65::PublicKey,
    ),
    Box<dyn Error>,
> {
    let (db, mut validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts(label)?;
    validator_state.seed_genesis_founder(miner, now_ts()?)?;
    Ok((
        db,
        validator_state,
        committee_eligibility,
        detection,
        tm,
        pk,
    ))
}

fn full_block_candidate(
    height: u64,
    miner: &str,
    previous_timestamp: u64,
    previous_hash: Hash,
    reward: u64,
    proof: Option<BlockPuzzleProof>,
) -> Result<Block, Box<dyn Error>> {
    let mut metadata = metadata_with_proof(height, previous_hash, proof)?;
    metadata.timestamp =
        previous_timestamp.saturating_add(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1));

    Ok(block_from_metadata(metadata, miner.to_owned(), reward))
}

fn wallet(seed: u64) -> String {
    format!("r{seed:0128x}")
}

fn wallet_arr(seed: u64) -> Result<[u8; REMZAR_WALLET_LEN], Box<dyn Error>> {
    let value = wallet(seed);
    let bytes = value.as_bytes();

    if bytes.len() != REMZAR_WALLET_LEN {
        return Err(boxed_error("generated wallet has invalid length"));
    }

    let mut out = [0u8; REMZAR_WALLET_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn node_opts(root: &Path) -> Result<NodeOpts, Box<dyn Error>> {
    Ok(NodeOpts {
        identity_file: path_to_string(&root.join("identity.key"))?,
        listen: "/ip4/127.0.0.1/tcp/0".to_owned(),
        bootstrap: Vec::new(),
        log: "error".to_owned(),
        data_dir: path_to_string(root)?,
        wallet_address: wallet(1),
        founder: false,
    })
}

fn new_blockchain_db(label: &str) -> Result<TestDb, Box<dyn Error>> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let opts = node_opts(&root)?;
    let blockchain_path = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_string = path_to_string(&blockchain_path)?;
    let manager = RockDBManager::new_blockchain(&opts, &blockchain_path_string)?;

    Ok(TestDb {
        manager: Some(manager),
        root,
    })
}

fn now_ts() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn fixed_hash(seed: u8) -> Hash {
    [seed; 64]
}

fn nonzero_guardian_signature(seed: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    [seed; ml_dsa_65::SIG_LEN]
}

fn valid_metadata(index: u64, previous_hash: Hash) -> Result<BlockMetadata, Box<dyn Error>> {
    Ok(BlockMetadata::new(
        index,
        now_ts()?,
        previous_hash,
        fixed_hash(77),
        nonzero_guardian_signature(9),
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    ))
}

fn valid_genesis() -> Result<GenesisBlock, ErrorDetection> {
    GenesisBlock::new_with_timestamp("validation genesis", 1_700_000_000)
}

fn direct_genesis(prev_hash: Hash, merkle_root: Hash) -> GenesisBlock {
    GenesisBlock {
        genesis_hash: fixed_hash(10),
        merkle_root,
        prev_hash,
        timestamp: 1_700_000_000,
        data: "direct genesis".to_owned(),
        founder_wallet: None,
    }
}

fn manual_tx(sender: u64, receiver: u64, amount: u64) -> Result<Transaction, Box<dyn Error>> {
    Ok(Transaction {
        sender: wallet_arr(sender)?,
        receiver: wallet_arr(receiver)?,
        amount,
        timestamp: now_ts()?,
    })
}

fn tx_batch(index: u64, transactions: Vec<TxKind>) -> Result<TransactionBatch, ErrorDetection> {
    TransactionBatch::new(index, 1_700_000_000u64.saturating_add(index), transactions)
}

fn signing_key() -> Result<ml_dsa_65::PrivateKey, Box<dyn Error>> {
    let (_pk, sk) = ml_dsa_65::try_keygen()
        .map_err(|err| boxed_error(&format!("ml_dsa_65 keygen failed: {err:?}")))?;
    Ok(sk)
}

fn verifying_key_pair() -> Result<(ml_dsa_65::PublicKey, ml_dsa_65::PrivateKey), Box<dyn Error>> {
    ml_dsa_65::try_keygen().map_err(|err| boxed_error(&format!("ml_dsa_65 keygen failed: {err:?}")))
}

fn validation_context_parts(
    label: &str,
) -> Result<
    (
        TestDb,
        ValidatorState,
        CommitteeEligibility,
        DetectionSystem,
        TimeManager,
        ml_dsa_65::PublicKey,
        ml_dsa_65::PrivateKey,
    ),
    Box<dyn Error>,
> {
    let db = new_blockchain_db(label)?;
    let validator_state = ValidatorState::with_manager(db.manager()?.clone());
    let committee_eligibility = CommitteeEligibility::with_default_config();
    let detection = DetectionSystem::new();
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(now_ts()?));
    let (pk, sk) = verifying_key_pair()?;

    Ok((
        db,
        validator_state,
        committee_eligibility,
        detection,
        tm,
        pk,
        sk,
    ))
}

fn block_from_metadata(metadata: BlockMetadata, miner: String, reward: u64) -> Block {
    Block {
        metadata,
        batch_key: Some("tx_batch_test".to_owned()),
        miner,
        block_hash: fixed_hash(88),
        reward,
    }
}

#[test]
fn test_001_validate_genesis_block_accepts_valid_genesis() -> TestResult {
    let genesis = valid_genesis()?;

    BlockchainValidation::validate_genesis_block(&genesis)?;

    Ok(())
}

#[test]
fn test_002_validate_genesis_block_rejects_nonzero_prev_hash() -> TestResult {
    let genesis = direct_genesis(fixed_hash(1), fixed_hash(2));

    let result = BlockchainValidation::validate_genesis_block(&genesis);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_003_validate_genesis_block_rejects_zero_merkle_root() -> TestResult {
    let genesis = direct_genesis([0u8; 64], [0u8; 64]);

    let result = BlockchainValidation::validate_genesis_block(&genesis);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_004_validate_genesis_block_rejects_ff_merkle_root() -> TestResult {
    let genesis = direct_genesis([0u8; 64], [0xFFu8; 64]);

    let result = BlockchainValidation::validate_genesis_block(&genesis);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_005_validate_transaction_accepts_valid_transfer() -> TestResult {
    let tx = Transaction::new(wallet(5), wallet(6), 1)?;

    BlockchainValidation::validate_transaction(&tx)?;

    Ok(())
}

#[test]
fn test_006_validate_transaction_rejects_zero_amount() -> TestResult {
    let tx = manual_tx(7, 8, 0)?;

    let result = BlockchainValidation::validate_transaction(&tx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_007_validate_transaction_rejects_same_sender_receiver() -> TestResult {
    let tx = manual_tx(9, 9, 1)?;

    let result = BlockchainValidation::validate_transaction(&tx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_008_validate_transaction_rejects_above_max_amount() -> TestResult {
    let tx = manual_tx(10, 11, GlobalConfiguration::MAX_TX_AMOUNT.saturating_add(1))?;

    let result = BlockchainValidation::validate_transaction(&tx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_009_validate_reward_transaction_accepts_valid_reward() -> TestResult {
    let reward = RewardTx::new(wallet(12), 1, 1)?;

    BlockchainValidation::validate_reward_transaction(&reward)?;

    Ok(())
}

#[test]
fn test_010_validate_reward_transaction_rejects_zero_amount_raw_reward() -> TestResult {
    let reward = RewardTx::new(wallet(13), 0, 1);

    assert!(reward.is_err());
    Ok(())
}

#[test]
fn test_011_validate_reward_transaction_rejects_height_zero_constructor() -> TestResult {
    let reward = RewardTx::new(wallet(14), 1, 0);

    assert!(reward.is_err());
    Ok(())
}

#[test]
fn test_012_validate_reward_transaction_rejects_above_max_reward_constructor() -> TestResult {
    let reward = RewardTx::new(
        wallet(15),
        GlobalConfiguration::MAX_BLOCK_REWARD.saturating_add(1),
        1,
    );

    assert!(reward.is_err());
    Ok(())
}

#[test]
fn test_013_validate_block_metadata_accepts_valid_non_genesis_metadata() -> TestResult {
    let detection = DetectionSystem::new();
    let metadata = valid_metadata(1, fixed_hash(1))?;

    BlockchainValidation::validate_block_metadata(&metadata, &detection)?;

    Ok(())
}

#[test]
fn test_014_validate_block_metadata_accepts_genesis_with_nonzero_signature() -> TestResult {
    let detection = DetectionSystem::new();
    let metadata = valid_metadata(0, [0u8; 64])?;

    BlockchainValidation::validate_block_metadata(&metadata, &detection)?;

    Ok(())
}

#[test]
fn test_015_validate_block_metadata_rejects_genesis_nonzero_previous_hash() -> TestResult {
    let detection = DetectionSystem::new();
    let metadata = valid_metadata(0, fixed_hash(2))?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_016_validate_block_metadata_rejects_non_genesis_zero_previous_hash() -> TestResult {
    let detection = DetectionSystem::new();
    let metadata = valid_metadata(1, [0u8; 64])?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_017_validate_block_metadata_rejects_zero_merkle_root() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(3))?;
    metadata.merkle_root = [0u8; 64];

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_018_validate_block_metadata_rejects_ff_merkle_root() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(4))?;
    metadata.merkle_root = [0xFFu8; 64];

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_019_validate_block_metadata_rejects_ff_previous_hash() -> TestResult {
    let detection = DetectionSystem::new();
    let metadata = valid_metadata(1, [0xFFu8; 64])?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_020_validate_block_metadata_rejects_zero_guardian_signature() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(5))?;
    metadata.guardian_signature = [0u8; ml_dsa_65::SIG_LEN];

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_021_validate_block_metadata_rejects_ff_guardian_signature() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(6))?;
    metadata.guardian_signature = [0xFFu8; ml_dsa_65::SIG_LEN];

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_022_validate_block_metadata_rejects_too_small_size() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(7))?;
    metadata.size = 63;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_023_validate_block_metadata_rejects_too_large_size() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(8))?;
    metadata.size = GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1);

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_024_validate_block_metadata_rejects_merkle_equal_previous_hash() -> TestResult {
    let detection = DetectionSystem::new();
    let same = fixed_hash(9);
    let mut metadata = valid_metadata(1, same)?;
    metadata.merkle_root = same;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_025_validate_block_metadata_rejects_old_timestamp() -> TestResult {
    let detection = DetectionSystem::new();
    let mut metadata = valid_metadata(1, fixed_hash(10))?;
    metadata.timestamp = 946_684_799;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_026_validate_transaction_batch_accepts_empty_batch_and_finalizes_metadata() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let mut batch = tx_batch(26, Vec::new())?;

    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(26),
        &detection,
    )?;

    assert_eq!(metadata.index, 26);
    assert_eq!(metadata.previous_hash, fixed_hash(26));
    Ok(())
}

#[test]
fn test_027_validate_transaction_batch_accepts_single_transfer() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let tx = Transaction::new(wallet(27), wallet(28), 10)?;
    let mut batch = tx_batch(27, vec![TxKind::Transfer(tx)])?;

    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(27),
        &detection,
    )?;

    assert_eq!(metadata.index, 27);
    assert_eq!(metadata.previous_hash, fixed_hash(27));
    Ok(())
}

#[test]
fn test_028_validate_transaction_batch_rejects_invalid_transfer() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let tx = manual_tx(29, 30, 0)?;
    let mut batch = tx_batch(28, vec![TxKind::Transfer(tx)])?;

    let result = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(28),
        &detection,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_029_validate_transaction_batch_rejects_duplicate_transfer_id_in_batch() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let tx = Transaction::new(wallet(31), wallet(32), 10)?;
    let mut batch = tx_batch(29, vec![TxKind::Transfer(tx.clone()), TxKind::Transfer(tx)])?;

    let result = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(29),
        &detection,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_030_validate_transaction_batch_accepts_reward_only_batch() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let reward = RewardTx::new(wallet(33), 1, 30)?;
    let mut batch = tx_batch(30, vec![TxKind::Reward(reward)])?;

    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(30),
        &detection,
    )?;

    assert_eq!(metadata.index, 30);
    Ok(())
}

#[test]
fn test_031_validate_full_block_rejects_invalid_metadata_before_context_heavy_checks() -> TestResult
{
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_invalid_metadata")?;

    let mut metadata = valid_metadata(1, fixed_hash(31))?;
    metadata.merkle_root = [0u8; 64];

    let block = block_from_metadata(metadata, wallet(31), 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(now_ts()?),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_032_validate_full_block_rejects_missing_previous_timestamp_for_non_genesis() -> TestResult {
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_missing_prev_ts")?;

    let metadata = valid_metadata(1, fixed_hash(32))?;
    let block = block_from_metadata(metadata, wallet(32), 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: None,
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_033_validate_full_block_rejects_timestamp_before_parent_interval() -> TestResult {
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_timewarp")?;

    let mut metadata = valid_metadata(1, fixed_hash(33))?;
    let previous_timestamp = now_ts()?.saturating_add(100);
    metadata.timestamp = previous_timestamp;

    let block = block_from_metadata(metadata, wallet(33), 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_034_validate_full_block_rejects_invalid_miner_wallet_after_timestamp_gate() -> TestResult {
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_invalid_miner")?;

    let interval = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
    let previous_timestamp = now_ts()?;
    let mut metadata = valid_metadata(1, fixed_hash(34))?;
    metadata.timestamp = previous_timestamp.saturating_add(interval);

    let block = block_from_metadata(metadata, "not-a-wallet".to_owned(), 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_035_validate_full_block_rejects_empty_canonical_validator_set() -> TestResult {
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_empty_committee")?;

    let interval = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
    let previous_timestamp = now_ts()?;
    let mut metadata = valid_metadata(1, fixed_hash(35))?;
    metadata.timestamp = previous_timestamp.saturating_add(interval);

    let block = block_from_metadata(metadata, wallet(35), 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_036_validate_block_metadata_vector_rejects_bad_sizes() -> TestResult {
    let detection = DetectionSystem::new();
    let bad_sizes = [
        0,
        1,
        63,
        GlobalConfiguration::MAX_BLOCK_SIZE.saturating_add(1),
    ];

    for size in bad_sizes {
        let mut metadata = valid_metadata(1, fixed_hash(36))?;
        metadata.size = size;

        let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);
        assert!(result.is_err());
    }

    Ok(())
}

#[test]
fn test_037_validate_block_metadata_vector_rejects_bad_hash_patterns() -> TestResult {
    let detection = DetectionSystem::new();

    let mut zero_merkle = valid_metadata(1, fixed_hash(37))?;
    zero_merkle.merkle_root = [0u8; 64];
    assert!(BlockchainValidation::validate_block_metadata(&zero_merkle, &detection).is_err());

    let mut ff_merkle = valid_metadata(1, fixed_hash(38))?;
    ff_merkle.merkle_root = [0xFFu8; 64];
    assert!(BlockchainValidation::validate_block_metadata(&ff_merkle, &detection).is_err());

    let ff_previous = valid_metadata(1, [0xFFu8; 64])?;
    assert!(BlockchainValidation::validate_block_metadata(&ff_previous, &detection).is_err());

    Ok(())
}

#[test]
fn test_038_validate_transaction_vector_valid_amounts() -> TestResult {
    let amounts = [1, 2, 10, GlobalConfiguration::MAX_TX_AMOUNT];

    for amount in amounts {
        let tx = Transaction::new(wallet(amount), wallet(amount.saturating_add(1)), amount)?;
        BlockchainValidation::validate_transaction(&tx)?;
    }

    Ok(())
}

#[test]
fn test_039_validate_reward_transaction_vector_valid_amounts() -> TestResult {
    let amounts = [1, 2, 10, GlobalConfiguration::MAX_BLOCK_REWARD];

    for amount in amounts {
        let reward = RewardTx::new(wallet(amount.saturating_add(100)), amount, 1)?;
        BlockchainValidation::validate_reward_transaction(&reward)?;
    }

    Ok(())
}

#[test]
fn test_040_load_style_many_metadata_validations_remain_deterministic() -> TestResult {
    let detection = DetectionSystem::new();

    for index in 1u64..=100u64 {
        let mut previous_seed = u8::try_from(index.rem_euclid(200))
            .map_err(|_| boxed_error("index conversion failed"))?
            .saturating_add(1);

        if previous_seed == 77 {
            previous_seed = 78;
        }

        let previous_hash = fixed_hash(previous_seed);
        let metadata = valid_metadata(index, previous_hash)?;

        BlockchainValidation::validate_block_metadata(&metadata, &detection)?;
    }

    Ok(())
}

#[test]
fn test_041_block_puzzle_proof_new_accepts_valid_proof() -> TestResult {
    let validator = wallet(41);
    let previous_hash = fixed_hash(41);
    let proof = valid_block_puzzle_proof(41, &validator, previous_hash)?;

    assert_eq!(proof.height, 41);
    assert_eq!(proof.validator, validator);
    assert_eq!(proof.prev_block_hash, previous_hash);
    assert!(proof.output > 0);
    Ok(())
}

#[test]
fn test_042_block_puzzle_proof_rejects_invalid_validator() -> TestResult {
    let result = BlockPuzzleProof::new(42, "not-a-wallet".to_owned(), fixed_hash(42), 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_043_block_puzzle_proof_rejects_oversized_validator() -> TestResult {
    let oversized = format!("r{}", "a".repeat(300));
    let result = BlockPuzzleProof::new(43, oversized, fixed_hash(43), 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_044_block_puzzle_proof_rejects_zero_previous_hash() -> TestResult {
    let result = BlockPuzzleProof::new(44, wallet(44), [0u8; 64], 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_045_block_puzzle_proof_rejects_ff_previous_hash() -> TestResult {
    let result = BlockPuzzleProof::new(45, wallet(45), [0xFFu8; 64], 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_046_block_puzzle_proof_rejects_zero_output() -> TestResult {
    let result = BlockPuzzleProof::new(46, wallet(46), fixed_hash(46), 0);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_047_block_puzzle_proof_rejects_height_above_reasonable_bound() -> TestResult {
    let result = BlockPuzzleProof::new(10_000_001, wallet(47), fixed_hash(47), 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_048_block_puzzle_proof_commitment_is_64_bytes_and_stable() -> TestResult {
    let proof = valid_block_puzzle_proof(48, &wallet(48), fixed_hash(48))?;

    let first = proof.commitment_bytes()?;
    let second = proof.commitment_bytes()?;

    assert_eq!(first.len(), 64);
    assert_eq!(first, second);
    assert_eq!(proof.commitment_hex()?.len(), 128);
    Ok(())
}

#[test]
fn test_049_block_puzzle_proof_to_gossip_round_trip_keeps_fields() -> TestResult {
    let proof = valid_block_puzzle_proof(49, &wallet(49), fixed_hash(49))?;
    let gossip = proof.to_gossip();

    assert_eq!(gossip.height, proof.height);
    assert_eq!(gossip.validator, proof.validator);
    assert_eq!(gossip.prev_block_hash, proof.prev_block_hash);
    assert_eq!(gossip.output, proof.output);
    Ok(())
}

#[test]
fn test_050_block_puzzle_proof_verify_with_engine_accepts_correct_output() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(50);
    let previous_hash = fixed_hash(50);
    let output = puzzle_output_for_engine(&engine, 50, &validator, previous_hash)?;
    let proof = BlockPuzzleProof::new(50, validator, previous_hash, output)?;

    assert!(proof.verify_with_engine_checked(&engine)?);
    assert!(proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_051_block_puzzle_proof_verify_with_engine_rejects_wrong_output() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(51);
    let previous_hash = fixed_hash(51);
    let output = puzzle_output_for_engine(&engine, 51, &validator, previous_hash)?;
    let proof = BlockPuzzleProof::new(51, validator, previous_hash, output.saturating_add(1))?;

    assert!(!proof.verify_with_engine_checked(&engine)?);
    assert!(!proof.verify_with_engine(&engine));
    Ok(())
}

#[test]
fn test_052_validate_block_metadata_accepts_matching_puzzle_proof() -> TestResult {
    let detection = DetectionSystem::new();
    let previous_hash = fixed_hash(52);
    let proof = valid_block_puzzle_proof(52, &wallet(52), previous_hash)?;
    let metadata = metadata_with_proof(52, previous_hash, Some(proof))?;

    BlockchainValidation::validate_block_metadata(&metadata, &detection)?;

    Ok(())
}

#[test]
fn test_053_validate_block_metadata_rejects_genesis_with_puzzle_proof() -> TestResult {
    let detection = DetectionSystem::new();
    let previous_hash = fixed_hash(53);
    let proof = valid_block_puzzle_proof(1, &wallet(53), previous_hash)?;
    let mut metadata = metadata_with_proof(0, [0u8; 64], Some(proof))?;

    metadata.guardian_signature = nonzero_guardian_signature(3);

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_054_validate_block_metadata_rejects_puzzle_proof_height_mismatch() -> TestResult {
    let detection = DetectionSystem::new();
    let previous_hash = fixed_hash(54);
    let proof = valid_block_puzzle_proof(55, &wallet(54), previous_hash)?;
    let metadata = metadata_with_proof(54, previous_hash, Some(proof))?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_055_validate_block_metadata_rejects_puzzle_proof_prev_hash_mismatch() -> TestResult {
    let detection = DetectionSystem::new();
    let proof = valid_block_puzzle_proof(55, &wallet(55), fixed_hash(56))?;
    let metadata = metadata_with_proof(55, fixed_hash(55), Some(proof))?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_056_validate_block_metadata_rejects_structurally_invalid_puzzle_proof() -> TestResult {
    let detection = DetectionSystem::new();
    let previous_hash = fixed_hash(56);
    let proof = BlockPuzzleProof {
        height: 56,
        validator: wallet(56),
        prev_block_hash: previous_hash,
        output: 0,
    };
    let metadata = metadata_with_proof(56, previous_hash, Some(proof))?;

    let result = BlockchainValidation::validate_block_metadata(&metadata, &detection);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_057_por_consensus_config_from_globals_is_valid() -> TestResult {
    let cfg = PorConsensusConfig::from_globals();

    cfg.validate()?;
    assert!(cfg.target_block_time.as_secs() >= 1);
    assert!(cfg.max_local_puzzle_ms >= 1_000);
    assert_eq!(cfg.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
    Ok(())
}

#[test]
fn test_058_por_consensus_config_rejects_zero_target_time() -> TestResult {
    let cfg = PorConsensusConfig {
        target_block_time: Duration::from_secs(0),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 1_000,
    };

    assert!(cfg.validate().is_err());
    Ok(())
}

#[test]
fn test_059_por_consensus_config_rejects_zero_soft_cap() -> TestResult {
    let cfg = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FibonacciDelayDev,
        max_local_puzzle_ms: 0,
    };

    assert!(cfg.validate().is_err());
    Ok(())
}

#[test]
fn test_060_por_consensus_config_rejects_non_mandatory_factorization_puzzle_kind() -> TestResult {
    let cfg = PorConsensusConfig {
        target_block_time: Duration::from_secs(1),
        puzzle_kind: PorPuzzleKind::FactorizationDelayDev,
        max_local_puzzle_ms: 1_000,
    };

    let result = cfg.validate();

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_061_por_engine_derive_puzzle_is_deterministic() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(61);
    let previous_hash = fixed_hash(61);

    let first = engine.derive_puzzle(61, &validator, previous_hash);
    let second = engine.derive_puzzle(61, &validator, previous_hash);

    assert_eq!(first.height, second.height);
    assert_eq!(first.validator, second.validator);
    assert_eq!(first.prev_block_hash, second.prev_block_hash);
    assert_eq!(first.kind, second.kind);
    assert_eq!(first.param, second.param);
    Ok(())
}

#[test]
fn test_062_por_engine_verify_checked_accepts_manual_fibonacci_solution() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(62);
    let previous_hash = fixed_hash(62);
    let header = engine.derive_puzzle(62, &validator, previous_hash);
    let output = fib_for_test(header.param);
    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    engine.verify_checked(&solution, 62, &validator, previous_hash)?;

    Ok(())
}

#[test]
fn test_063_por_engine_verify_checked_rejects_wrong_height() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(63);
    let previous_hash = fixed_hash(63);
    let header = engine.derive_puzzle(63, &validator, previous_hash);
    let output = fib_for_test(header.param);
    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    let result = engine.verify_checked(&solution, 64, &validator, previous_hash);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_064_por_engine_verify_checked_rejects_wrong_validator() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(64);
    let previous_hash = fixed_hash(64);
    let header = engine.derive_puzzle(64, &validator, previous_hash);
    let output = fib_for_test(header.param);
    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    let result = engine.verify_checked(&solution, 64, &wallet(65), previous_hash);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_065_por_engine_verify_checked_rejects_wrong_previous_hash() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(65);
    let previous_hash = fixed_hash(65);
    let header = engine.derive_puzzle(65, &validator, previous_hash);
    let output = fib_for_test(header.param);
    let solution = PorPuzzleSolution {
        header,
        output,
        solved_in_ms: 0,
    };

    let result = engine.verify_checked(&solution, 65, &validator, fixed_hash(66));

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_066_genesis_block_with_founder_is_accepted_by_header_validation() -> TestResult {
    let genesis =
        GenesisBlock::new_with_timestamp_and_miner("founder genesis", 1_700_000_000, &wallet(66))?;

    BlockchainValidation::validate_genesis_block(&genesis)?;
    assert_eq!(genesis.founder_wallet(), Some(wallet(66).as_str()));
    assert_eq!(genesis.miner_for_genesis_block(), wallet(66));
    Ok(())
}

#[test]
fn test_067_genesis_block_rejects_empty_data_constructor() -> TestResult {
    let result = GenesisBlock::new_with_timestamp("", 1_700_000_000);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_068_genesis_block_rejects_oversized_data_constructor() -> TestResult {
    let data = "x".repeat(1_025);
    let result = GenesisBlock::new_with_timestamp(&data, 1_700_000_000);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_069_genesis_block_rejects_invalid_founder_wallet() -> TestResult {
    let result =
        GenesisBlock::new_with_timestamp_and_miner("bad founder", 1_700_000_000, "bad-wallet");

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_070_genesis_block_json_round_trip_stays_valid() -> TestResult {
    let genesis =
        GenesisBlock::new_with_timestamp_and_miner("json genesis", 1_700_000_000, &wallet(70))?;

    let json = genesis.to_json()?;
    let decoded = GenesisBlock::from_json(&json)?;

    assert_eq!(decoded, genesis);
    BlockchainValidation::validate_genesis_block(&decoded)?;
    Ok(())
}

#[test]
fn test_071_genesis_block_storage_round_trip_stays_valid() -> TestResult {
    let genesis =
        GenesisBlock::new_with_timestamp_and_miner("storage genesis", 1_700_000_000, &wallet(71))?;

    let bytes = genesis.serialize_for_storage()?;
    let decoded = GenesisBlock::deserialize(&bytes)?;

    assert_eq!(decoded, genesis);
    BlockchainValidation::validate_genesis_block(&decoded)?;
    Ok(())
}

#[test]
fn test_072_genesis_block_deserialize_accepts_legacy_trailing_padding() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp("padded genesis", 1_700_000_000)?;
    let mut bytes = genesis.serialize()?;
    bytes.extend_from_slice(&[0u8; 32]);

    let decoded = GenesisBlock::deserialize(&bytes)?;

    assert_eq!(decoded, genesis);
    Ok(())
}

#[test]
fn test_073_genesis_block_validate_against_now_rejects_far_future() -> TestResult {
    let genesis = GenesisBlock::new_with_timestamp("future genesis", 1_700_000_000)?;

    let result = genesis.validate_against_now(1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_074_validate_transaction_batch_accepts_register_node_only_batch() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let register = RegisterNodeTx::new(wallet(74))?;
    let mut batch = tx_batch(74, vec![TxKind::RegisterNode(register)])?;

    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(74),
        &detection,
    )?;

    assert_eq!(metadata.index, 74);
    assert_eq!(metadata.previous_hash, fixed_hash(74));
    Ok(())
}

#[test]
fn test_075_validate_transaction_batch_rejects_invalid_register_node() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let register = RegisterNodeTx {
        wallet_address: [b'!'; REMZAR_WALLET_LEN],
        timestamp: now_ts()?,
    };
    let mut batch = tx_batch(75, vec![TxKind::RegisterNode(register)])?;

    let result = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(75),
        &detection,
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_076_validate_transaction_batch_vector_empty_batches_finalize() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;

    for index in 76u64..86u64 {
        let mut batch = tx_batch(index, Vec::new())?;
        let metadata = BlockchainValidation::validate_transaction_batch(
            &mut batch,
            &sk,
            fixed_hash(76),
            &detection,
        )?;

        assert_eq!(metadata.index, index);
    }

    Ok(())
}

#[test]
fn test_077_validate_transaction_batch_vector_transfer_batches_finalize() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;

    for index in 87u64..97u64 {
        let tx = Transaction::new(wallet(index), wallet(index.saturating_add(10)), 1)?;
        let mut batch = tx_batch(index, vec![TxKind::Transfer(tx)])?;
        let metadata = BlockchainValidation::validate_transaction_batch(
            &mut batch,
            &sk,
            fixed_hash(77),
            &detection,
        )?;

        assert_eq!(metadata.index, index);
    }

    Ok(())
}

#[test]
fn test_078_full_block_reaches_missing_puzzle_proof_gate_for_active_miner() -> TestResult {
    let miner = wallet(78);
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_missing_proof", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, fixed_hash(78), 0, None)?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_079_full_block_rejects_puzzle_proof_validator_mismatch() -> TestResult {
    let miner = wallet(79);
    let other = wallet(80);
    let previous_hash = fixed_hash(79);
    let proof = valid_block_puzzle_proof(1, &other, previous_hash)?;
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_proof_validator_mismatch", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, previous_hash, 0, Some(proof))?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_080_full_block_rejects_puzzle_proof_bad_output() -> TestResult {
    let miner = wallet(80);
    let previous_hash = fixed_hash(80);
    let engine = PorPuzzleEngine::from_globals();
    let output = puzzle_output_for_engine(&engine, 1, &miner, previous_hash)?.saturating_add(1);
    let proof = BlockPuzzleProof::new(1, miner.clone(), previous_hash, output)?;
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_proof_bad_output", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, previous_hash, 0, Some(proof))?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_081_full_block_rejects_pre_reward_delay_nonzero_block_reward() -> TestResult {
    let miner = wallet(81);
    let previous_hash = fixed_hash(81);
    let proof = valid_block_puzzle_proof(1, &miner, previous_hash)?;
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_pre_delay_reward", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, previous_hash, 1, Some(proof))?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_082_full_block_rejects_pre_reward_delay_reward_tx() -> TestResult {
    let miner = wallet(82);
    let previous_hash = fixed_hash(82);
    let proof = valid_block_puzzle_proof(1, &miner, previous_hash)?;
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_pre_delay_reward_tx", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, previous_hash, 0, Some(proof))?;
    let reward = RewardTx::new(miner.clone(), 1, 1)?;
    let batch = tx_batch(1, vec![TxKind::Reward(reward)])?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_083_full_block_rejects_block_reward_mismatch_at_reward_height() -> TestResult {
    let miner = wallet(83);
    let height = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
    let previous_hash = fixed_hash(83);
    let proof = valid_block_puzzle_proof(height, &miner, previous_hash)?;
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_reward_mismatch", &miner)?;
    let previous_timestamp = now_ts()?;
    let wrong_reward = RewardHalving::get_block_reward(height).saturating_add(1);
    let block = full_block_candidate(
        height,
        &miner,
        previous_timestamp,
        previous_hash,
        wrong_reward,
        Some(proof),
    )?;
    let batch = tx_batch(height, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_084_full_block_rejects_reward_sum_mismatch_at_reward_height() -> TestResult {
    let miner = wallet(84);
    let height = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
    let previous_hash = fixed_hash(84);
    let proof = valid_block_puzzle_proof(height, &miner, previous_hash)?;
    let expected_reward = RewardHalving::get_block_reward(height);
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_reward_sum_mismatch", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(
        height,
        &miner,
        previous_timestamp,
        previous_hash,
        expected_reward,
        Some(proof),
    )?;
    let batch = tx_batch(height, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_085_full_block_rejects_invalid_transaction_after_reward_checks() -> TestResult {
    let miner = wallet(85);
    let height = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
    let previous_hash = fixed_hash(85);
    let proof = valid_block_puzzle_proof(height, &miner, previous_hash)?;
    let expected_reward = RewardHalving::get_block_reward(height);
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_invalid_tx_after_reward", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(
        height,
        &miner,
        previous_timestamp,
        previous_hash,
        expected_reward,
        Some(proof),
    )?;
    let reward = RewardTx::new(miner.clone(), expected_reward, height)?;
    let invalid_tx = manual_tx(85, 86, 0)?;
    let batch = tx_batch(
        height,
        vec![TxKind::Reward(reward), TxKind::Transfer(invalid_tx)],
    )?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_086_full_block_rejects_rogue_miner_not_in_validator_state() -> TestResult {
    let miner = wallet(86);
    let (_db, validator_state, committee_eligibility, detection, tm, pk, _sk) =
        validation_context_parts("full_rogue_miner")?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, fixed_hash(86), 0, None)?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_087_full_block_rejects_height_zero_canonical_committee_path() -> TestResult {
    let miner = wallet(87);
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_height_zero", &miner)?;
    let metadata = valid_metadata(0, [0u8; 64])?;
    let block = block_from_metadata(metadata, miner, 0);
    let batch = tx_batch(0, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: None,
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_088_full_block_rejects_timestamp_gate_with_too_early_schedule_time() -> TestResult {
    let miner = wallet(88);
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_schedule_timewarp", &miner)?;
    let previous_timestamp = now_ts()?;
    let mut metadata = metadata_with_proof(1, fixed_hash(88), None)?;
    metadata.timestamp = previous_timestamp;
    let block = block_from_metadata(metadata, miner, 0);
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_089_full_block_runtime_committee_liveness_does_not_remove_canonical_single_validator()
-> TestResult {
    let miner = wallet(89);
    let (_db, validator_state, mut committee_eligibility, detection, tm, pk) =
        context_with_founder("full_runtime_ignored", &miner)?;
    committee_eligibility.mark_wallet_live(&miner, false)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(1, &miner, previous_timestamp, fixed_hash(89), 0, None)?;
    let batch = tx_batch(1, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_090_validate_block_metadata_load_vector_valid_proofs() -> TestResult {
    let detection = DetectionSystem::new();

    for height in 90u64..110u64 {
        let previous_hash = fixed_hash(
            u8::try_from(height.rem_euclid(150))
                .map_err(|_| boxed_error("height conversion failed"))?
                .saturating_add(1),
        );
        let proof = valid_block_puzzle_proof(height, &wallet(height), previous_hash)?;
        let metadata = metadata_with_proof(height, previous_hash, Some(proof))?;

        BlockchainValidation::validate_block_metadata(&metadata, &detection)?;
    }

    Ok(())
}

#[test]
fn test_091_block_puzzle_proof_load_vector_commitments_are_not_zero() -> TestResult {
    for height in 111u64..131u64 {
        let previous_hash = fixed_hash(
            u8::try_from(height.rem_euclid(150))
                .map_err(|_| boxed_error("height conversion failed"))?
                .saturating_add(2),
        );
        let proof = valid_block_puzzle_proof(height, &wallet(height), previous_hash)?;
        let commitment = proof.commitment_bytes()?;

        assert_ne!(commitment, [0u8; 64]);
        assert_ne!(commitment, [0xFFu8; 64]);
    }

    Ok(())
}

#[test]
fn test_092_puzzle_output_property_matches_engine_for_many_heights() -> TestResult {
    let engine = test_por_engine();
    let validator = wallet(92);

    for height in 1u64..=25u64 {
        let previous_hash =
            fixed_hash(u8::try_from(height).map_err(|_| boxed_error("height conversion failed"))?);
        let output = puzzle_output_for_engine(&engine, height, &validator, previous_hash)?;
        let proof = BlockPuzzleProof::new(height, validator.clone(), previous_hash, output)?;

        assert!(proof.verify_with_engine_checked(&engine)?);
    }

    Ok(())
}

#[test]
fn test_093_genesis_validation_vector_valid_founders() -> TestResult {
    for seed in 930u64..940u64 {
        let genesis = GenesisBlock::new_with_timestamp_and_miner(
            "founder vector genesis",
            1_700_000_000,
            &wallet(seed),
        )?;

        BlockchainValidation::validate_genesis_block(&genesis)?;
        assert_eq!(genesis.founder_wallet(), Some(wallet(seed).as_str()));
    }

    Ok(())
}

#[test]
fn test_094_genesis_from_json_rejects_bad_hash_hex_length() -> TestResult {
    let json = r#"{
        "genesis_hash": "00",
        "merkle_root": "00",
        "prev_hash": "00",
        "timestamp": 1700000000,
        "data": "bad json"
    }"#;

    let result = GenesisBlock::from_json(json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_095_genesis_from_json_rejects_noncanonical_founder_wallet() -> TestResult {
    let mut json = GenesisBlock::new_with_timestamp("json base", 1_700_000_000)?.to_json()?;
    json = json.replace(
        "\"data\": \"json base\"",
        "\"data\": \"json base\",\n  \"founder_wallet\": \"not-a-wallet\"",
    );

    let result = GenesisBlock::from_json(&json);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_096_validate_transaction_batch_load_test_registers_finalize() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let mut txs = Vec::with_capacity(50);

    for seed in 960u64..1_010u64 {
        txs.push(TxKind::RegisterNode(RegisterNodeTx::new(wallet(seed))?));
    }

    let mut batch = tx_batch(96, txs)?;
    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(96),
        &detection,
    )?;

    assert_eq!(metadata.index, 96);
    assert_eq!(batch.transactions.len(), 50);
    Ok(())
}

#[test]
fn test_097_validate_transaction_batch_load_test_transfers_finalize() -> TestResult {
    let detection = DetectionSystem::new();
    let sk = signing_key()?;
    let mut txs = Vec::with_capacity(50);

    for seed in 970u64..1_020u64 {
        txs.push(TxKind::Transfer(Transaction::new(
            wallet(seed),
            wallet(seed.saturating_add(10_000)),
            1,
        )?));
    }

    let mut batch = tx_batch(97, txs)?;
    let metadata = BlockchainValidation::validate_transaction_batch(
        &mut batch,
        &sk,
        fixed_hash(97),
        &detection,
    )?;

    assert_eq!(metadata.index, 97);
    assert_eq!(batch.transactions.len(), 50);
    Ok(())
}

#[test]
fn test_098_metadata_puzzle_proof_rejects_sentinel_hash_vectors() -> TestResult {
    let detection = DetectionSystem::new();
    let cases = [[0u8; 64], [0xFFu8; 64]];

    for previous_hash in cases {
        let proof = BlockPuzzleProof {
            height: 98,
            validator: wallet(98),
            prev_block_hash: previous_hash,
            output: 1,
        };
        let mut metadata = valid_metadata(98, fixed_hash(98))?;
        metadata.puzzle_proof = Some(proof);

        assert!(BlockchainValidation::validate_block_metadata(&metadata, &detection).is_err());
    }

    Ok(())
}

#[test]
fn test_099_full_block_rejects_structurally_invalid_proof_before_reward_math() -> TestResult {
    let miner = wallet(99);
    let previous_hash = fixed_hash(99);
    let proof = BlockPuzzleProof {
        height: 99,
        validator: miner.clone(),
        prev_block_hash: previous_hash,
        output: 0,
    };
    let (_db, validator_state, committee_eligibility, detection, tm, pk) =
        context_with_founder("full_structurally_invalid_proof", &miner)?;
    let previous_timestamp = now_ts()?;
    let block = full_block_candidate(
        99,
        &miner,
        previous_timestamp,
        previous_hash,
        0,
        Some(proof),
    )?;
    let batch = tx_batch(99, Vec::new())?;

    let ctx = FullBlockValidationContext {
        verifying_key: &pk,
        previous_timestamp: Some(previous_timestamp),
        detection: &detection,
        validator_state: &validator_state,
        committee_eligibility: &committee_eligibility,
        tm: &tm,
    };

    let result = BlockchainValidation::validate_full_block(&block, &batch, &ctx);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_100_puzzle_proof_commitment_changes_when_output_changes() -> TestResult {
    let validator = wallet(100);
    let previous_hash = fixed_hash(100);
    let engine = test_por_engine();
    let output = puzzle_output_for_engine(&engine, 100, &validator, previous_hash)?;

    let first = BlockPuzzleProof::new(100, validator.clone(), previous_hash, output)?;
    let second = BlockPuzzleProof::new(100, validator, previous_hash, output.saturating_add(1))?;

    assert_ne!(first.commitment_bytes()?, second.commitment_bytes()?);
    Ok(())
}
