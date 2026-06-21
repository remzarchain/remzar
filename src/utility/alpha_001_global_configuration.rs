// ─────────────────────────────────────────────────────────────────────────────
// Global Configuration for the "remzar" Blockchain Project
// ─────────────────────────────────────────────────────────────────────────────

use crate::utility::helper::UNIT_DIVISOR;
use fips204::ml_dsa_65;

pub struct GlobalConfiguration;

impl GlobalConfiguration {
    // ─────────────────────────────────────────────────────────────────────────────
    // --- Versioning
    // ─────────────────────────────────────────────────────────────────────────────
    /// The current version of the blockchain.
    pub const VERSION: u64 = 1;

    // ─────────────────────────────────────────────────────────────────────────────
    // Database Path Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// The name of the dedicated wallets directory.
    pub const WALLETS_DIR: &str = "000.wallets";
    /// The name of the main RocksDB database directory (CLI operations).
    pub const DATABASE_DIR_NAME: &str = "001.database_db";
    /// The name of the dedicated blockchain RocksDB directory.
    pub const BLOCKCHAIN_DATABASE_DIR: &str = "002.blockchain_db";
    /// The name of the registry database directory.
    pub const REGISTRY_DIR_NAME: &str = "003.registry_db";
    /// The name of the dedicated logging directory (all error and related files).
    pub const LOG_DATABASE_DIR: &str = "004.log_db";
    /// The name of the dedicated audit reports directory.
    pub const AUDIT_REPORTS_DIR: &str = "005.audit_reports";
    /// The name of the dedicated account model tree RocksDB directory.
    pub const ACCOUNTMODEL_DATABASE_DIR: &str = "006.accountmodel_db";
    /// The name of the dedicated peer list directory.
    pub const PEER_LIST_DIR: &str = "007.peerlist";
    /// The name of the dedicated side chain RocksDB directory.
    pub const SIDECHAIN_DATABASE_DIR: &str = "008.sidechain_db";

    /// Update the total:
    pub const TOTAL_DB_DIRS: usize = 9;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Genesis File Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    pub const GENESIS_JSON_PATH: &str = "blockchain/genesis.json";

    /// Default genesis timestamp for new user blockchains.
    /// DEV-NET  1780277303
    /// MAIN-NET 1782432000
    /// 2026-06-26 00:00:00 UTC
    /// 2026-06-25 8:00 PM North American Eastern time during June.
    pub const DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP: u64 = 1782432000;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Genesis Founder Key Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    ///   GENESIS_FOUNDER_KEY_EXPECTED_HASH.
    pub const GENESIS_FOUNDER_KEY_PATH: &'static str = "founder.key";

    pub const GENESIS_FOUNDER_KEY_HEX_LEN: usize = 128;
    pub const GENESIS_FOUNDER_KEY_HASH_HEX_LEN: usize = 128;

    /// Huge file is rejected before read_to_string.
    pub const GENESIS_FOUNDER_KEY_MAX_FILE_BYTES: u64 = 256;

    /// Domain separator for founder-key verification.
    pub const GENESIS_FOUNDER_KEY_HASH_DOMAIN: &'static [u8] = b"REMZAR_FOUNDER_KEY_HASH_V1\0";

    /// Genesis keygen.
    pub const GENESIS_FOUNDER_KEY_EXPECTED_HASH: &'static str = "8a952fdd39da65821dbe85b7d8ff5929f748df3378874d80987163423ef0ee1a91536e335bea083e77b0385df361cb7dfb99783bcbf35819b06d43751254dcbc";

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Genesis Block Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// The all-zero “previous” hash of the genesis block, as raw bytes for crypto.
    pub const GENESIS_PREV_HASH_BYTES: [u8; 64] = [0u8; 64];

    /// Hex form only for display/logging of the genesis prev-hash.
    /// MUST be 64 bytes = 128 hex chars.
    pub const GENESIS_PREV_HASH_HEX: &'static str = "0000000000000000000000000000000000000000000000000000000000000000\
                                                     0000000000000000000000000000000000000000000000000000000000000000";

    /// Hex form of the genesis merkle root.
    /// MUST be 64 bytes = 128 hex chars (NO 32-byte legacy).
    /// That is acceptable as long as EVERY node uses the exact same value.
    pub const GENESIS_MERKLE_ROOT_HEX: &'static str = "29f984fad3389b577d75f22c4c849b1a848fb2ae9e458778ea36bd1765a79dab\
    29f984fad3389b577d75f22c4c849b1a848fb2ae9e458778ea36bd1765a79dab";

    /// Canonical 64-byte genesis block hash (RemzarHash over the deterministic genesis preimage).
    /// MUST be 64 bytes = 128 hex chars.
    /// This MUST match `GenesisBlock::new_with_timestamp_and_miner(...).genesis_hash`
    /// when using the configured GENESIS_PREV_HASH_HEX + GENESIS_MERKLE_ROOT_HEX + constants.
    ///
    /// Value taken from passing test output:
    pub const GENESIS_HASH_HEX: &'static str = "48ca1f065debb4f4291f1423c3e9da446635e6fbc39e169c2c7b4dfb25b310c95143bc31ab6afb7e63a861abb4807dfc50611765337aa459e3470f682d210e66";

    /// The nonce value for the Genesis block.
    pub const GENESIS_NONCE: u64 = 299_792_458;

    /// The address of the Genesis validator.
    /// MUST be canonical wallet format: "r" + 128 lowercase hex chars (total len = 129).
    pub const GENESIS_VALIDATOR: &str = "r0000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000";

    /// No reward is distributed for the Genesis block.
    pub const GENESIS_REWARD: u64 = 0;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Identity Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// Name of the blockchain's native coin.
    pub const COIN_NAME: &'static str = "remzar";
    /// Symbol for the blockchain's currency.
    pub const SYMBOL: &'static str = "remzar";
    /// Official start date of the blockchain.
    pub const START_DATE: &'static str = "2026-06-26";
    /// Default network port used by nodes.
    /// “Open port 36213 for Remzar node communication.” ///
    pub const DEFAULT_PORT: u64 = 36213;

    // ─────────────────────────────────────────────────────────────────────────────
    // Block Size and Weight Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// **Maximum allowable block size in bytes (2MB).**
    ///
    /// - Blocks will always be **batched at exactly 2MB intervals**.
    pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;

    /// Reserved bytes for block overhead (block metadata + signatures, etc).
    /// Must be conservative so we never over-select from mempool.
    pub const BLOCK_OVERHEAD_RESERVE: usize = 16 * 1024;

    /// **Transaction Storage Limit (Mempool-like Buffer)**
    /// - Transactions can now accumulate up to 2MB before batching, acting as a disk-based mempool.
    /// - Transactions will be **batched at 2MB intervals**.
    /// - If full (2MB), new transactions **get rejected**.
    pub const TRANSACTION_BUFFER_LIMIT: u64 = 2 * 1024 * 1024;

    /// **Maximum allowable number of transactions per block.**
    /// - Blocks cannot contain more than this number of transactions.
    /// - Helps prevent “block explosion” from huge numbers of tiny transactions.
    /// - Final block admission is still bounded by MAX_BLOCK_SIZE and BLOCK_OVERHEAD_RESERVE.
    pub const MAX_TXS_PER_BLOCK: u64 = 7_500;

    /// Prevent oversized untrusted batch blobs in `deserialize`.
    /// Keep <= MAX_BLOCK_SIZE plus a little overhead for postcard framing.
    pub const MAX_BATCH_SERIALIZED_OVERHEAD: usize = 2048;

    /// Allowable future skew for timestamps (seconds).
    pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;

    // ────────────────────────────────────────────────
    // ML-DSA-65 secret sizes (4032 bytes, 8064 hex chars)
    // ────────────────────────────────────────────────
    pub const MLDSA65_SECRET_BYTES: usize = ml_dsa_65::SK_LEN;
    pub const MLDSA65_SECRET_HEX_LEN: usize = Self::MLDSA65_SECRET_BYTES * 2;
    pub const MAX_PRIVKEY_HEX_INPUT_LEN: usize = Self::MLDSA65_SECRET_HEX_LEN;

    // ────────────────────────────────────────────────
    // Guardian signature length (ML-DSA-65)
    // ────────────────────────────────────────────────
    pub const GUARDIAN_SIG_LEN: usize = ml_dsa_65::SIG_LEN;

    // ─────────────────────────────────────────────────────────────────────────────
    // Economic Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// Maximum (and total) supply available through mining / validator rewards.
    /// This chain has **no staking supply** and **no gaming supply**.
    /// All issuance comes from the block reward schedule until exhaustion.
    pub const MAX_REWARD_SUPPLY: u64 = 200_000_000 * UNIT_DIVISOR;

    /// Absolute maximum supply of REMZAR.
    /// Since there are no other issuance buckets, MAX_SUPPLY == MAX_REWARD_SUPPLY.
    pub const MAX_SUPPLY: u64 = Self::MAX_REWARD_SUPPLY;

    /// Blocks at the start of chain that never mint rewards.
    /// Set to 1 if only genesis (block 0) is rewardless.
    pub const REWARDLESS_PREFIX_BLOCKS: u64 = 1;

    // ─────────────────────────────────────────────────────────────────────────────
    // Prevent any single transaction from sending more than 100 million REMZAR
    // ─────────────────────────────────────────────────────────────────────────────

    /// Max value allowed in a single transaction (100 million REMZAR, 8 decimals)
    pub const MAX_TX_AMOUNT: u64 = 10_000_000_000_000_000;

    // ─────────────────────────────────────────────────────────────────────────────
    // Timing and Block Delay Management (seconds-first, no magic block counts)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Block creation interval in seconds.
    ///
    /// This is the full slot length for one block height.
    /// Example:
    /// - 30s slot => height h should normally be resolved within 30 seconds
    ///
    /// IMPORTANT:
    /// This remains the OUTER mint cadence for the chain.
    /// Increasing failover slack does NOT change this slot length.
    pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;

    /// Per-node puzzle delay (how long `solve_locally` must take at least).
    ///
    /// This is the minimum puzzle/work time for a proposer attempt.
    /// It intentionally stays small so the chain preserves fast proposer turnover
    /// inside a 30-second slot.
    ///
    /// NOTE:
    /// We keep this at 2s for now because the logs suggest the main pressure is
    /// not the raw puzzle target itself, but the lack of post-puzzle margin for:
    /// - local block assembly/signing
    /// - scheduler jitter on a single host
    /// - gossip / parent visibility
    /// - peer-side processing before the next failover round
    pub const PUZZLE_CREATION_INTERVAL_SECS: u64 = 2;

    /// Minimum warm-up time after a validator registers before it can propose.
    /// Expressed in seconds to avoid “3 blocks” magic numbers.
    pub const ACTIVATION_WARMUP_SECS: u64 = 30;

    /// Number of blocks to skip before rewards are issued (can stay in blocks).
    pub const REWARD_DELAY_BLOCKS: usize = 1;

    /// Ceiling division available in const context.
    pub const fn ceil_div(a: u64, b: u64) -> u64 {
        a.div_ceil(b)
    }

    /// Derived: blocks a newly-registered validator must wait before proposing.
    /// = ceil(ACTIVATION_WARMUP_SECS / BLOCK_CREATION_INTERVAL_SECS)
    pub const VALIDATOR_ACTIVATION_DELAY_BLOCKS: u64 = Self::ceil_div(
        Self::ACTIVATION_WARMUP_SECS,
        Self::BLOCK_CREATION_INTERVAL_SECS,
    );

    /// Number of blocks a (re)joining validator must observe before being eligible to propose.
    /// Used by Peacemaker/JointHeight quarantine gating.
    pub const QUARANTINE_BLOCKS: u64 = 4;

    /// Heights per epoch for scheduling/telemetry; set to 60 for 60-slot epochs.
    /// Set to 1 to effectively disable epoch grouping.
    pub const EPOCH_SLOTS: u64 = 60;

    // ─────────────────────────────────────────────────────────────────────────────
    /// Canonical heartbeat renewal.
    /// This stays slow to avoid network spam.
    ///
    /// Meaning:
    /// - A live validator should renew its on-chain RegisterNode record every 10 blocks.
    /// - With 30s blocks, this is every 5 minutes.
    /// - This does NOT control runtime dead-peer removal.
    pub const CANONICAL_RENEW_INTERVAL_BLOCKS: u64 = 10;

    pub const HEARTBEAT_TX_INTERVAL_SECS: u64 =
        Self::CANONICAL_RENEW_INTERVAL_BLOCKS * Self::BLOCK_CREATION_INTERVAL_SECS;

    /// Canonical validator lease expiry.
    /// This removes validators from the canonical leader committee if they stop
    /// renewing on-chain.
    ///
    /// Meaning:
    /// - Runtime dead peers are removed fast by DEAD_PEER_EVICTION_*.
    /// - Canonical leader eligibility expires after the validator misses its
    ///   expected on-chain renewal window.
    /// - This must be deterministic and based on block height, not local peer disconnects.
    /// - With 30s blocks, 10 blocks = 5 minutes.
    ///
    /// Since renewal also runs every 10 blocks, a delayed/missed renewal can expire
    /// the validator faster. That is acceptable if you want aggressive canonical cleanup.
    pub const CANONICAL_LEASE_BLOCKS: u64 = Self::CANONICAL_RENEW_INTERVAL_BLOCKS;

    /// Runtime dead-peer eviction.
    /// This is NOT the canonical renewal interval.
    /// This removes disconnected/unreachable/dead peers from the live runtime set.
    ///
    /// With 30s blocks:
    /// - 2 blocks = 60 seconds.
    pub const DEAD_PEER_EVICTION_BLOCKS: u64 = 2;

    pub const DEAD_PEER_EVICTION_SECS: u64 =
        Self::DEAD_PEER_EVICTION_BLOCKS * Self::BLOCK_CREATION_INTERVAL_SECS;

    /// No extra grace for known-dead runtime peers.
    pub const HEARTBEAT_GRACE_SECS: u64 = 0;

    // ─────────────────────────────────────────────────────────────────────────────
    // Failover rounds (dead leader protection) — PoR mainchain
    //
    // Model:
    // - One block height gets one full slot: BLOCK_CREATION_INTERVAL_SECS
    // - Inside that slot, we may advance across multiple deterministic rounds
    // - Each round uses the SAME canonical committee snapshot
    // - Only the selected canonical leader for that round may mint
    //
    // IMPORTANT:
    // These constants MUST remain deterministic across all nodes.
    // They define shared consensus timing for round advancement.
    //
    // Current local-dev tuning:
    // - slot = 30s
    // - puzzle = 2s
    // - build slack = 5s
    // - leader grace = 5s
    // => τ (failover window) = 12s
    //
    // With a 6s gossip tail:
    // - proposal deadline = 24s
    // - max rounds = floor(24 / 12) = 2
    //
    // Why this tuning:
    // - keeps the 30-second chain cadence unchanged
    // - keeps the puzzle target unchanged
    // - gives materially more breathing room after the puzzle completes
    // - gives the selected leader more time to publish before deterministic rotation
    // - reduces same-host scheduling / logging / propagation sensitivity
    // - reduces false failover pressure during local multi-node runs
    // ─────────────────────────────────────────────────────────────────────────────

    /// Extra seconds reserved for local block assembly / signing / small execution overhead
    /// after the puzzle completes successfully.
    ///
    /// This exists because solving the puzzle is not the whole proposer path:
    /// a leader still needs to assemble the candidate, sign, commit, and publish.
    ///
    /// Set to 5s to reduce false failover pressure in local multi-node runs.
    pub const FAILOVER_BUILD_SLACK_SECS: u64 = 5;

    /// Extra seconds of grace given to the currently selected leader before the network
    /// deterministically advances to the next failover round.
    ///
    /// Think of this as a small shared leader publication grace period.
    /// This is NOT a local-only fudge factor; it is part of consensus timing and
    /// must match across all nodes.
    ///
    /// Set to 5s to give more room for propagation, parent visibility, and
    /// block advertisement before the network rotates to the next round.
    pub const FAILOVER_LEADER_GRACE_SECS: u64 = 5;

    /// Backward-compatible aggregate slack.
    ///
    /// Kept so existing call sites using `FAILOVER_SLACK_SECS` do not break.
    /// Total extra time beyond the raw puzzle time.
    ///
    /// Current value:
    /// 5 + 5 = 10s
    pub const FAILOVER_SLACK_SECS: u64 =
        Self::FAILOVER_BUILD_SLACK_SECS + Self::FAILOVER_LEADER_GRACE_SECS;

    /// τ (tau): how long a leader gets before we move to the next leader
    /// in the SAME slot / SAME block height.
    ///
    /// Formula:
    /// τ = puzzle_time + build_slack + leader_grace
    ///
    /// Current value:
    /// 2 + 5 + 5 = 12s
    pub const FAILOVER_WINDOW_SECS: u64 =
        Self::PUZZLE_CREATION_INTERVAL_SECS + Self::FAILOVER_SLACK_SECS;

    /// Reserve the tail of the slot for propagation / drift.
    ///
    /// We do not want to start a brand-new proposer attempt too late in the slot,
    /// otherwise a valid block may be produced but arrive too late to be useful.
    pub const SLOT_GOSSIP_BUFFER_SECS: u64 = 6;

    /// Proposal deadline inside the slot (seconds from slot start).
    ///
    /// Leaders must publish before this boundary.
    /// After this point, the remaining slot time is reserved for gossip / settle / drift.
    ///
    /// Current value with a 30s slot and 6s gossip tail:
    pub const FAILOVER_PROPOSAL_DEADLINE_SECS: u64 =
        Self::BLOCK_CREATION_INTERVAL_SECS - Self::SLOT_GOSSIP_BUFFER_SECS;

    /// How many failover rounds fit in the proposal window (>= 1).
    ///
    /// Example with current values:
    /// - proposal deadline = 24s
    /// - τ = 12s
    /// - rounds = floor(24 / 12) = 2
    pub const FAILOVER_MAX_ROUNDS: u64 = {
        let r = Self::FAILOVER_PROPOSAL_DEADLINE_SECS.div_euclid(Self::FAILOVER_WINDOW_SECS);
        if r == 0 { 1 } else { r }
    };

    /// Tight drift bound used ONLY for slot/round gating
    /// separate from MAX_FUTURE_SKEW_SECS).
    ///
    /// This should stay small so nodes agree on the active failover round.
    pub const SLOT_GATE_DRIFT_SECS: u64 = 2;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Computed Constants for Rewards (production)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Initial block reward at launch.
    ///
    /// Economic design:
    /// - Keeps long-term issuance simple with a 1 REMZAR/block stabilized tail.
    pub const INITIAL_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;

    /// Reward reduction sequence.
    ///
    /// Each entry applies for `HALVING_INTERVAL_BLOCKS` blocks before moving to the next.
    ///
    /// Schedule:
    /// - 20 REMZAR/block for 500,000 blocks
    /// - 10 REMZAR/block for 500,000 blocks
    /// - 5 REMZAR/block for 500,000 blocks
    /// - 2 REMZAR/block for 500,000 blocks
    /// - 1 REMZAR/block for 500,000 blocks
    ///
    /// Total ladder weight:
    /// 20 + 10 + 5 + 2 + 1 = 38 REMZAR/block across the full ladder.
    ///
    /// Economic result:
    /// - Ladder issuance = 38 * 500,000 = 19,000,000 REMZAR.
    /// - That is ~9.5% of the 200,000,000 REMZAR max reward supply.
    /// - After the ladder, the chain stabilizes at 1 REMZAR/block until exhaustion.
    pub const REWARD_REDUCTION_SEQUENCE: &'static [u64] = &[
        20 * UNIT_DIVISOR,
        10 * UNIT_DIVISOR,
        5 * UNIT_DIVISOR,
        2 * UNIT_DIVISOR,
        UNIT_DIVISOR,
    ];

    /// Stabilized block reward after the reduction phase.
    ///
    /// Remains at 1 REMZAR/block until `MAX_REWARD_SUPPLY` is exhausted.
    pub const STABILIZED_BLOCK_REWARD: u64 = UNIT_DIVISOR;

    /// Number of blocks between each reward step-down.
    pub const HALVING_INTERVAL_BLOCKS: u64 = 500_000;

    /// Total issued during the reward reduction ladder only.
    ///
    /// Sum(20 + 10 + 5 + 2 + 1) = 38 REMZAR.
    /// Ladder issuance = 38 * 500,000 = 19,000,000 REMZAR.
    pub const CUMULATIVE_REWARD_SEQUENCE: u64 = 38 * Self::HALVING_INTERVAL_BLOCKS * UNIT_DIVISOR;

    /// Nominal issuance that would have happened during the rewardless prefix,
    /// based on the tier-0 reward.
    ///
    /// Current design:
    /// - REWARDLESS_PREFIX_BLOCKS = 1
    /// - Only genesis/block 0 is rewardless.
    pub const REWARDLESS_PREFIX_NOMINAL_ISSUANCE: u64 =
        Self::REWARDLESS_PREFIX_BLOCKS * Self::INITIAL_BLOCK_REWARD;

    /// Effective ladder issuance after accounting for skipped prefix rewards.
    pub const EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE: u64 =
        Self::CUMULATIVE_REWARD_SEQUENCE.saturating_sub(Self::REWARDLESS_PREFIX_NOMINAL_ISSUANCE);

    /// After the ladder, mint 1 REMZAR/block for enough blocks to consume
    /// the remaining reward supply.
    pub const BLOCKS_FOR_STABILIZED_REWARD: u64 = GlobalConfiguration::ceil_div(
        GlobalConfiguration::MAX_REWARD_SUPPLY
            .saturating_sub(GlobalConfiguration::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE),
        GlobalConfiguration::STABILIZED_BLOCK_REWARD,
    );

    /// Total number of block heights covered by the reward schedule.
    /// With the current 20,10,5,2,1 schedule:
    /// - estimated exhaustion is around late year 2200.
    pub const TOTAL_REWARD_BLOCKS: u64 = GlobalConfiguration::REWARDLESS_PREFIX_BLOCKS
        + (GlobalConfiguration::REWARD_REDUCTION_SEQUENCE.len() as u64
            * GlobalConfiguration::HALVING_INTERVAL_BLOCKS)
        + GlobalConfiguration::BLOCKS_FOR_STABILIZED_REWARD;

    /// Maximum single block reward.
    pub const MAX_BLOCK_REWARD: u64 = 20 * UNIT_DIVISOR;

    // ─────────────────────────────────────────────────────────────────────────────
    // RocksDB Column Family Indexes (Mapped Numerically)
    // ─────────────────────────────────────────────────────────────────────────────

    /// **Meta Data (Headers, Blockchain Metadata)**
    pub const META_DATA_COLUMN: u8 = 0;
    /// **Global Configuration Data**
    pub const GLOBAL_COLUMN: u8 = 1;
    /// **Account & Wallet Data**
    pub const ACCOUNT_COLUMN: u8 = 2;
    /// **Network Data (Peer Nodes, Validators, P2P State)**
    pub const NETWORK_COLUMN: u8 = 3;
    /// **Sidechain Data (Layer-2, Atomic Swaps, Bridges, Merkle Trie, Smart Contracts)**
    pub const SIDECHAIN_COLUMN: u8 = 4;
    /// **AccountModelTree Data (balances + blocks)**
    pub const STATE_COLUMN: u8 = 5;
    /// **Transaction Data (Individual Transactions / Mempool)**
    pub const TRANSACTION_COLUMN: u8 = 6;
    /// **Transaction Batch Data (Finalized Transaction Batches)**
    pub const TRANSACTION_BATCH_COLUMN: u8 = 7;
    /// **Reward Data (Individual Reward Transactions / Mempool)**
    pub const REWARD_COLUMN: u8 = 8;
    /// **Reward Batch Data (Finalized Reward Batches)**
    pub const REWARD_BATCH_COLUMN: u8 = 9;
    /// **Blockmint Data (Finalized 1MB Blocks)**
    pub const BLOCKMINT_DATA_COLUMN: u8 = 10;
    /// **Log Data (Events, Debugging, Error Logs)**
    pub const LOGS_COLUMN: u8 = 11;
    /// **Block-by-Hash Data (hash ➔ serialized block)**
    pub const BLOCK_TO_HASH_COLUMN: u8 = 12;
    /// **Tx-by-Hash Data (hash ➔ serialized tx)**
    pub const TX_TO_HASH_COLUMN: u8 = 13;
    /// **Node Identity → Wallet Data (peer_id ➔ wallet_address)**
    pub const IDENTITY_COLUMN: u8 = 14;
    /// **Block Meta-by-Hash Data (hash -> metadata record)**
    pub const BLOCK_META_BY_HASH_COLUMN: u8 = 15;
    /// **Batch-by-Block-Hash Data (block_hash -> serialized tx batch)**
    pub const BATCH_BY_BLOCK_HASH_COLUMN: u8 = 16;
    /// **Canonical Height -> Hash View**
    pub const CANONICAL_HEIGHT_TO_HASH_COLUMN: u8 = 17;
    /// **Canonical Chain View (tip hash / tip height)**
    pub const CANONICAL_CHAIN_VIEW_COLUMN: u8 = 18;

    /// **Total Number of Active Database Storage Columns**
    pub const TOTAL_COLUMNS: usize = 19;

    // ─────────────────────────────────────────────────────────────────────────────
    // RocksDB Column Family Names (Mapped as Strings)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Column family name for meta data (column #0).
    pub const META_DATA_COLUMN_NAME: &str = "meta_data";
    /// Column family name for global configuration data (column #1).
    pub const GLOBAL_COLUMN_NAME: &str = "global_metadata";
    /// Column family name for account & wallet data (column #2).
    pub const ACCOUNT_COLUMN_NAME: &str = "wallet_accounts";
    /// Column family name for network/peer data (column #3).
    pub const NETWORK_COLUMN_NAME: &str = "network_data";
    /// Column family name for sidechain data (column #4).
    pub const SIDECHAIN_COLUMN_NAME: &str = "sidechain_data";
    /// Column family name for AccountModelTree (balances + blocks) (column #5).
    pub const STATE_COLUMN_NAME: &str = "state_data";
    /// Column family name for individual transaction data (mempool) (column #6).
    pub const TRANSACTION_COLUMN_NAME: &str = "transaction_data";
    /// Column family name for transaction batch data (finalized blocks) (column #7).
    pub const TRANSACTION_BATCH_COLUMN_NAME: &str = "transaction_batch_data";
    /// Column family name for individual reward transaction data (mempool) (column #8).
    pub const REWARD_COLUMN_NAME: &str = "reward_data";
    /// Column family name for reward batch data (finalized reward batches) (column #9).
    pub const REWARD_BATCH_COLUMN_NAME: &str = "reward_batch_data";
    /// Column family name for blockmint data (finalized 1MB per blocks) (column #10).
    pub const BLOCKMINT_DATA_COLUMN_NAME: &str = "blockmint_data";
    /// Column family name for log data (events, debugging, error logs) (column #11).
    pub const LOGS_COLUMN_NAME: &str = "logs_data";
    /// Column family name for p2p block to hash (column #12).
    pub const BLOCK_TO_HASH_COLUMN_NAME: &str = "blockhash_data";
    /// Column family name for p2p transaction to hash (column #13).
    pub const TX_TO_HASH_COLUMN_NAME: &str = "txhash_data";
    /// Column family name for node identity mappings (column #14).
    pub const IDENTITY_COLUMN_NAME: &str = "node_identity_data";
    /// Column family name for block metadata by hash (column #15).
    pub const BLOCK_META_BY_HASH_COLUMN_NAME: &str = "block_meta_by_hash";
    /// Column family name for batch-by-block-hash (column #16).
    pub const BATCH_BY_BLOCK_HASH_COLUMN_NAME: &str = "batch_by_block_hash";
    /// Column family name for canonical height -> hash (column #17).
    pub const CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME: &str = "canonical_height_to_hash";
    /// Column family name for canonical chain view (column #18).
    pub const CANONICAL_CHAIN_VIEW_COLUMN_NAME: &str = "canonical_chain_view";

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Security Configuration
    // ─────────────────────────────────────────────────────────────────────────────

    /// Threshold to consider a 51% attack.
    pub const ATTACK_THRESHOLD: u64 = 51;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Transaction Confirmation Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// Number of blocks required to confirm a transaction.
    pub const TRANSACTION_CONFIRMATION_COUNT: u64 = 6;
    /// Minimum reward threshold in micro-units.
    pub const MIN_REWARD_THRESHOLD: u64 = 1_000_000;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Governance Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// Proposal threshold for governance submissions.
    pub const GOVERNANCE_PROPOSAL_THRESHOLD: u64 = 1_000_000;
    /// Majority percentage required to pass governance proposals.
    pub const MAJORITY_THRESHOLD: u64 = 75;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- Base58 Alphabet Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// Base58 alphabet for encoding addresses and keys.
    pub const BASE58_ALPHABET: &'static str =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // ─────────────────────────────────────────────────────────────────────────────
    //--- MULTI-LAYER BLOCKCHAIN CONFIGURATION
    // ─────────────────────────────────────────────────────────────────────────────
    /// **Multi-Chain Mode Toggle**
    pub const ENABLE_MULTI_CHAIN: bool = true;

    // ─────────────────────────────────────────────────────────────────────────────
    //  **Storage & Database Paths for User Chains**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Directory where user-generated blockchain databases are stored.
    pub const USER_CHAIN_DATABASE_DIR: &'static str = "user_chains_db";
    /// Directory for user chain snapshot storage (separate from mainchain snapshots).
    pub const USER_CHAIN_SNAPSHOT_DIR: &'static str = "user_chain_snapshots";

    // ─────────────────────────────────────────────────────────────────────────────
    // **Dynamic Blockchain Creation Settings**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Maximum number of user-generated blockchains allowed in the system.
    pub const MAX_USER_CHAINS: u64 = 1_000;
    /// Default name prefix for user-generated chains.
    pub const DEFAULT_USER_CHAIN_PREFIX: &'static str = "Remzar_Chain_";
    /// Maximum number of concurrent databases (mainchain + user blockchains).
    pub const MAX_CONCURRENT_DATABASES: u64 = 1_000;
    /// Default transaction buffer limit for new chains (in bytes).
    pub const DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT: u64 = 4 * 1024 * 1024;
    /// Maximum block size for user-generated chains (inherits mainchain setting).
    pub const DEFAULT_USER_CHAIN_BLOCK_SIZE: u64 = Self::MAX_BLOCK_SIZE;

    // ─────────────────────────────────────────────────────────────────────────────
    // 💰 **User Blockchain Economic Configuration**
    // ─────────────────────────────────────────────────────────────────────────────
    /// User chains inherit the same economic rules as the mainchain by default.
    pub const USER_CHAIN_MAX_SUPPLY: u64 = Self::MAX_REWARD_SUPPLY;
    pub const USER_CHAIN_ZAR_SUPPLY: u64 = Self::MAX_REWARD_SUPPLY;

    // ─────────────────────────────────────────────────────────────────────────────
    // **Multi-Database Architecture**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Toggle to enable multi-database mode for independent user blockchains.
    pub const ENABLE_MULTI_DATABASE: bool = true;
    /// Maximum concurrent RocksDB instances (mainchain + user blockchains).
    pub const MAX_CONCURRENT_ROCKSDB_INSTANCES: u64 = 10_000;
    /// Toggle to allow user blockchains to inherit mainchain snapshots.
    pub const INHERIT_MAINCHAIN_SNAPSHOTS: bool = true;

    // ─────────────────────────────────────────────────────────────────────────────
    //  **Blockchain Naming & Identity Configuration**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Default coin name format for user chains (e.g., "Remzar_Chain_1").
    pub const DEFAULT_USER_COIN_NAME_FORMAT: &'static str = "Remzar_Chain_{id}";
    /// Default symbol format for user-generated chains.
    pub const DEFAULT_USER_COIN_SYMBOL_FORMAT: &'static str = "REMZAR{id}";
    /// Default network magic bytes for user chains.
    pub const USER_CHAIN_NETWORK_MAGIC_BASE: [u8; 4] = [137, 29, 3, 7];

    // ─────────────────────────────────────────────────────────────────────────────
    // **Governance & Security Thresholds**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Proposal threshold for governance submissions in user chains.
    pub const USER_CHAIN_GOVERNANCE_PROPOSAL_THRESHOLD: u64 = Self::GOVERNANCE_PROPOSAL_THRESHOLD;
    /// Majority percentage required to pass governance proposals (inherits from mainchain).
    pub const USER_CHAIN_MAJORITY_THRESHOLD: u64 = Self::MAJORITY_THRESHOLD;
    /// Attack detection threshold (e.g., 51% attack).
    pub const USER_CHAIN_ATTACK_THRESHOLD: u64 = Self::ATTACK_THRESHOLD;

    // ─────────────────────────────────────────────────────────────────────────────
    // **Block Rewards & Incentives**
    // ─────────────────────────────────────────────────────────────────────────────
    /// Stabilized block reward for user blockchains.
    pub const USER_CHAIN_STABILIZED_BLOCK_REWARD: u64 = Self::STABILIZED_BLOCK_REWARD;

    /// Initial block reward for user-generated blockchains.
    pub const USER_CHAIN_INITIAL_BLOCK_REWARD: u64 = Self::INITIAL_BLOCK_REWARD;

    /// Reward reduction sequence for user chains.
    pub const USER_CHAIN_REWARD_REDUCTION_SEQUENCE: &'static [u64] =
        Self::REWARD_REDUCTION_SEQUENCE;

    /// Number of blocks between reward reductions on user chains.
    pub const USER_CHAIN_BLOCKS_PER_HALVING: u64 = Self::HALVING_INTERVAL_BLOCKS;

    /// Hard bounds for robust decode/anti-DoS. Metadata is small; keep this conservative.
    /// This does NOT affect cryptographic algorithms; it only bounds decompression/allocation.
    pub const MAX_METADATA_DECOMPRESSED_BYTES: usize = 8 * 1024;

    /// Minimum plausible metadata-reported block size.
    /// Keep aligned with existing validation logic (64).
    pub const MIN_BLOCK_SIZE: u64 = 64;

    /// Lower bound for timestamps: 2000-01-01 00:00:00 UTC in seconds.
    pub const MIN_TIMESTAMP_SECS: u64 = 946_684_800;

    /// Max plausible future drift for *policy checks* (NOT used in decoding).
    pub const MAX_FUTURE_DRIFT_SECS: u64 = 3600 * 24 * 365 * 10;

    // ─────────────────────────────────────────────────────────────────────────────
    // Paranoia / future-proof limits (tune for network rules)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Max number of items allowed in a batch.
    /// Prevents unbounded CPU/memory usage from attacker-controlled batches.
    pub const MAX_BATCH_ITEMS: usize = 50_000;

    /// Max bytes per individual batch element.
    /// Prevents a single huge item from dominating memory/CPU.
    pub const MAX_ITEM_BYTES: usize = 4 * 1024 * 1024;

    /// Max total bytes across the entire batch.
    /// Prevents “many medium items” DoS.
    pub const MAX_TOTAL_BATCH_BYTES: usize = 64 * 1024 * 1024;

    /// Optional domain separation (OFF by default to avoid changing preimage).
    /// If you later decide to enable, it reduces cross-protocol hash confusion risk.
    pub const DOMAIN_SEPARATION_ON: bool = false;
    pub const DOMAIN_TAG: &'static [u8] = b"REMZAR_GUARDIAN_BATCH_SHAKE256_V1";

    // ─────────────────────────────────────────────────────────────────────────────
    // Cryption
    // ─────────────────────────────────────────────────────────────────────────────

    /// Adjust these constants as needed.
    pub const NONCE_SIZE: usize = 12;
    pub const AES_KEY_SIZE: usize = 32;
    pub const SALT_SIZE: usize = 16;

    /// Sensible Argon2id defaults (tweak as needed).
    /// memory_cost in KiB (64 MiB), time_cost (iterations), lanes (parallelism).
    pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
    pub const ARGON2_TIME_COST: u32 = 3;
    pub const ARGON2_LANES: u32 = 1;

    /// These do not alter cryptographic algorithms; they only bound allocation / inputs.
    pub const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;
    pub const MAX_ENCRYPTED_BLOB_BYTES: usize = 16 * 1024 * 1024;

    // ─────────────────────────────────────────────────────────────────────────────
    //--- ZAR Consensus Participation Configuration
    // ─────────────────────────────────────────────────────────────────────────────
    /// Maximum participants allowed currently in ZAR consensus.
    pub const MAX_ZAR_PARTICIPANTS: u64 = 10000;
    pub const MAX_VALIDATORS: usize = 10000;
    pub const MAX_IDENTITIES: usize = 20000;
    pub const MAX_VERIFYING_KEYS: usize = 10000;
    pub const MAX_SNAPSHOT_ENTRIES: usize = 50000;

    /// libp2p PeerId base58 strings are typically not huge. Bound it anyway.
    pub const MAX_PEER_ID_B58_LEN: usize = 128;

    // ─────────────────────────────────────────────────────────────────────────────
    // Retry Configuration for Database and Operations
    // ─────────────────────────────────────────────────────────────────────────────

    /// Maximum number of attempts to retry a database operation.
    pub const MAX_ATTEMPTS: u32 = 5;

    /// The delay in seconds between retry attempts.
    pub const RETRY_DELAY_SECS: u64 = 2;

    /// Maximum time (seconds) to wait for the background P2P task to join during shutdown.
    pub const JOIN_TIMEOUT_SECS: u64 = 5;

    pub const MAX_INPUT_BYTES: usize = 256;
    pub const MAX_IDENTITY_KEY_BYTES: u64 = 2 * 1024 * 1024;
    pub const MAX_GENESIS_JSON_BYTES: u64 = 50 * 1024 * 1024;

    // ─────────────────────────────────────────────────────────────────────────────
    // wallet addresses single and batch
    // ─────────────────────────────────────────────────────────────────────────────

    // Lightweight CLI/FS guards
    pub const MAX_YN_INPUT_LEN: usize = 16;
    pub const MAX_PASS_PROMPTS: usize = 5;

    // Batch guards
    pub const MAX_MODE_INPUT_LEN: usize = 16;
    pub const MAX_BATCH_INPUT_LEN: usize = 16;
    pub const MAX_BATCH_WALLETS: usize = 10;

    // ─────────────────────────────────────────────────────────────────────────────
    // Burn wallet addresses (dead wallets)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Burn address for fees and others usecase.
    /// MUST be canonical wallet format: "r" + 128 lowercase hex chars (total len = 129).
    pub const BURN_ADDRESS: &str = "r023de0ef87458573f9cd4031e3ae45e9fa5123e2b7365fb71c97644f90b2609e1747dd03398f5eb06f4c2086d1907d8c852641d5977370e10abcb9f35c88a248";

    // ─────────────────────────────────────────────────────────────────────────────
    // **Final Notes:**
    // - This configuration allows each user-generated blockchain to operate independently while leveraging mainchain features.
    // - RocksDB storage is separated, allowing full autonomy per user chain.
    // - Consensus, governance (future), rewards, and security settings are inherited from the mainchain, but can be customized per user blockchain.
    // ─────────────────────────────────────────────────────────────────────────────
}
