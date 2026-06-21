// fuzz/fuzz_targets/fuzz_alpha_001_global_configuration.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

mod utility {
    pub mod helper {
        pub const UNIT_DIVISOR: u64 = 100_000_000;
    }

    pub mod alpha_001_global_configuration {
        include!("../../src/utility/alpha_001_global_configuration.rs");
    }
}

use utility::alpha_001_global_configuration::GlobalConfiguration as G;

const UNIT_DIVISOR: u64 = utility::helper::UNIT_DIVISOR;

const EXPECTED_TOTAL_DB_DIRS: usize = 9;
const EXPECTED_TOTAL_COLUMNS: usize = 19;
const HEX_64_BYTES_LEN: usize = 128;
const WALLET_TEXT_LEN: usize = 129;

#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take_u8(&mut self) -> u8 {
        if self.pos >= self.data.len() {
            return 0;
        }

        let b = self.data[self.pos];
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }

    fn take_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill(&mut out);
        u64::from_le_bytes(out)
    }

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        usize::try_from(self.take_u64()).unwrap_or(0) % max
    }

    fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut out = String::with_capacity(len);

        for _ in 0..len {
            let b = self.take_u8();
            let ch = char::from(32u8.saturating_add(b % 96));
            out.push(ch);
        }

        out
    }
}

fn is_lower_hex_ascii(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_hex_ascii(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn assert_hex_64(label: &str, s: &str) {
    assert_eq!(
        s.len(),
        HEX_64_BYTES_LEN,
        "{label} must be 64 bytes / 128 hex chars"
    );
    assert!(
        s.as_bytes().iter().copied().all(is_hex_ascii),
        "{label} must be hex"
    );
}

fn assert_canonical_wallet(label: &str, s: &str) {
    assert_eq!(
        s.len(),
        WALLET_TEXT_LEN,
        "{label} must be 'r' + 128 lowercase hex chars"
    );

    assert_eq!(
        s.as_bytes().first().copied(),
        Some(b'r'),
        "{label} must start with lowercase r"
    );

    assert!(
        s.as_bytes()[1..].iter().copied().all(is_lower_hex_ascii),
        "{label} body must be lowercase hex only"
    );
}

fn assert_safe_dir_name(label: &str, s: &str) {
    assert!(!s.is_empty(), "{label} must not be empty");
    assert!(!s.contains('/'), "{label} must be a single path component");
    assert!(!s.contains('\\'), "{label} must be a single path component");
    assert_ne!(s, ".", "{label} must not be '.'");
    assert_ne!(s, "..", "{label} must not be '..'");
}

fn assert_nonempty_name(label: &str, s: &str) {
    assert!(!s.is_empty(), "{label} must not be empty");
    assert!(
        !s.chars().any(char::is_control),
        "{label} must not contain control characters"
    );
}

fn ceil_div_model(a: u64, b: u64) -> u64 {
    assert!(b > 0);
    a.div_ceil(b)
}

fn sum_reward_sequence() -> u128 {
    G::REWARD_REDUCTION_SEQUENCE
        .iter()
        .copied()
        .map(u128::from)
        .sum::<u128>()
}

fn assert_database_directory_invariants() {
    let dirs = [
        G::WALLETS_DIR,
        G::DATABASE_DIR_NAME,
        G::BLOCKCHAIN_DATABASE_DIR,
        G::REGISTRY_DIR_NAME,
        G::LOG_DATABASE_DIR,
        G::AUDIT_REPORTS_DIR,
        G::ACCOUNTMODEL_DATABASE_DIR,
        G::PEER_LIST_DIR,
        G::SIDECHAIN_DATABASE_DIR,
    ];

    assert_eq!(G::TOTAL_DB_DIRS, EXPECTED_TOTAL_DB_DIRS);
    assert_eq!(dirs.len(), G::TOTAL_DB_DIRS);

    for (idx, dir) in dirs.iter().enumerate() {
        assert_safe_dir_name(&format!("database dir #{idx}"), dir);
    }

    for i in 0..dirs.len() {
        for j in (i + 1)..dirs.len() {
            assert_ne!(dirs[i], dirs[j], "database directories must be unique");
        }
    }

    assert_nonempty_name("GENESIS_JSON_PATH", G::GENESIS_JSON_PATH);
}

fn assert_genesis_and_wallet_invariants() {
    assert_eq!(G::GENESIS_PREV_HASH_BYTES.len(), 64);
    assert_eq!(G::GENESIS_PREV_HASH_BYTES, [0u8; 64]);

    assert_hex_64("GENESIS_PREV_HASH_HEX", G::GENESIS_PREV_HASH_HEX);
    assert_hex_64("GENESIS_MERKLE_ROOT_HEX", G::GENESIS_MERKLE_ROOT_HEX);
    assert_hex_64("GENESIS_HASH_HEX", G::GENESIS_HASH_HEX);

    assert!(G::GENESIS_NONCE > 0);
    assert_canonical_wallet("GENESIS_VALIDATOR", G::GENESIS_VALIDATOR);
    assert_canonical_wallet("BURN_ADDRESS", G::BURN_ADDRESS);

    assert_eq!(G::GENESIS_REWARD, 0);
    assert_nonempty_name("COIN_NAME", G::COIN_NAME);
    assert_nonempty_name("SYMBOL", G::SYMBOL);
    assert!(G::DEFAULT_PORT > 0);
    assert!(G::DEFAULT_PORT <= u64::from(u16::MAX));
}

fn assert_block_and_tx_limit_invariants() {
    assert!(G::MAX_BLOCK_SIZE > 0);
    assert!(G::MAX_BLOCK_SIZE <= usize::MAX as u64);
    assert!(G::BLOCK_OVERHEAD_RESERVE > 0);
    assert!(u64::try_from(G::BLOCK_OVERHEAD_RESERVE).unwrap_or(u64::MAX) < G::MAX_BLOCK_SIZE);

    assert!(G::TRANSACTION_BUFFER_LIMIT > 0);
    assert!(G::TRANSACTION_BUFFER_LIMIT <= G::MAX_TOTAL_BATCH_BYTES as u64);
    assert_eq!(G::TRANSACTION_BUFFER_LIMIT, G::MAX_BLOCK_SIZE);

    assert!(G::MAX_TXS_PER_BLOCK > 0);
    assert!(G::MAX_BATCH_SERIALIZED_OVERHEAD > 0);
    assert!(G::MAX_FUTURE_SKEW_SECS > 0);

    assert_eq!(G::MLDSA65_SECRET_HEX_LEN, G::MLDSA65_SECRET_BYTES * 2);
    assert_eq!(G::MAX_PRIVKEY_HEX_INPUT_LEN, G::MLDSA65_SECRET_HEX_LEN);
    assert!(G::GUARDIAN_SIG_LEN > 0);

    assert!(G::MAX_BATCH_ITEMS > 0);
    assert!(G::MAX_ITEM_BYTES > 0);
    assert!(G::MAX_TOTAL_BATCH_BYTES >= G::MAX_ITEM_BYTES);
}

fn assert_reward_economic_invariants() {
    assert!(UNIT_DIVISOR > 0);

    assert_eq!(G::MAX_SUPPLY, G::MAX_REWARD_SUPPLY);
    assert!(G::MAX_REWARD_SUPPLY > 0);

    assert!(G::REWARDLESS_PREFIX_BLOCKS > 0);
    assert!(G::INITIAL_BLOCK_REWARD > 0);
    assert_eq!(G::MAX_BLOCK_REWARD, G::INITIAL_BLOCK_REWARD);

    assert!(!G::REWARD_REDUCTION_SEQUENCE.is_empty());
    assert_eq!(G::REWARD_REDUCTION_SEQUENCE[0], G::INITIAL_BLOCK_REWARD);

    for reward in G::REWARD_REDUCTION_SEQUENCE {
        assert!(*reward > 0);
        assert!(*reward <= G::MAX_BLOCK_REWARD);
    }

    for pair in G::REWARD_REDUCTION_SEQUENCE.windows(2) {
        assert!(pair[1] <= pair[0]);
    }

    assert!(G::STABILIZED_BLOCK_REWARD > 0);
    assert!(G::STABILIZED_BLOCK_REWARD <= G::MAX_BLOCK_REWARD);
    assert!(G::HALVING_INTERVAL_BLOCKS > 0);

    let seq_sum = sum_reward_sequence();
    let expected_cumulative = seq_sum
        .checked_mul(u128::from(G::HALVING_INTERVAL_BLOCKS))
        .expect("reward sequence cumulative multiplication must not overflow");

    assert_eq!(
        u128::from(G::CUMULATIVE_REWARD_SEQUENCE),
        expected_cumulative
    );

    let expected_prefix_offset = u128::from(G::REWARDLESS_PREFIX_BLOCKS)
        .checked_mul(u128::from(G::INITIAL_BLOCK_REWARD))
        .expect("rewardless prefix nominal issuance must not overflow");

    assert_eq!(
        u128::from(G::REWARDLESS_PREFIX_NOMINAL_ISSUANCE),
        expected_prefix_offset
    );

    let expected_effective = u128::from(G::CUMULATIVE_REWARD_SEQUENCE)
        .saturating_sub(u128::from(G::REWARDLESS_PREFIX_NOMINAL_ISSUANCE));

    assert_eq!(
        u128::from(G::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE),
        expected_effective
    );

    assert!(u128::from(G::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE) <= u128::from(G::MAX_REWARD_SUPPLY));

    let remaining_after_ladder = G::MAX_REWARD_SUPPLY
        .saturating_sub(G::EFFECTIVE_CUMULATIVE_REWARD_SEQUENCE);

    let expected_tail_blocks = ceil_div_model(remaining_after_ladder, G::STABILIZED_BLOCK_REWARD);

    assert_eq!(G::BLOCKS_FOR_STABILIZED_REWARD, expected_tail_blocks);

    let seq_len_u64 = u64::try_from(G::REWARD_REDUCTION_SEQUENCE.len()).unwrap_or(u64::MAX);

    let expected_total_reward_blocks = G::REWARDLESS_PREFIX_BLOCKS
        .saturating_add(seq_len_u64.saturating_mul(G::HALVING_INTERVAL_BLOCKS))
        .saturating_add(G::BLOCKS_FOR_STABILIZED_REWARD);

    assert_eq!(G::TOTAL_REWARD_BLOCKS, expected_total_reward_blocks);
    assert!(G::TOTAL_REWARD_BLOCKS >= G::REWARDLESS_PREFIX_BLOCKS);
}

fn assert_timing_and_failover_invariants() {
    assert!(G::BLOCK_CREATION_INTERVAL_SECS > 0);
    assert!(G::PUZZLE_CREATION_INTERVAL_SECS > 0);
    assert!(G::ACTIVATION_WARMUP_SECS > 0);

    assert_eq!(
        G::VALIDATOR_ACTIVATION_DELAY_BLOCKS,
        ceil_div_model(G::ACTIVATION_WARMUP_SECS, G::BLOCK_CREATION_INTERVAL_SECS)
    );

    assert!(G::QUARANTINE_BLOCKS > 0);
    assert!(G::EPOCH_SLOTS > 0);

    assert!(G::CANONICAL_RENEW_INTERVAL_BLOCKS > 0);
    assert_eq!(
        G::HEARTBEAT_TX_INTERVAL_SECS,
        G::CANONICAL_RENEW_INTERVAL_BLOCKS * G::BLOCK_CREATION_INTERVAL_SECS
    );

    assert_eq!(G::CANONICAL_LEASE_BLOCKS, G::CANONICAL_RENEW_INTERVAL_BLOCKS);

    assert!(G::DEAD_PEER_EVICTION_BLOCKS > 0);
    assert_eq!(
        G::DEAD_PEER_EVICTION_SECS,
        G::DEAD_PEER_EVICTION_BLOCKS * G::BLOCK_CREATION_INTERVAL_SECS
    );

    assert_eq!(
        G::FAILOVER_SLACK_SECS,
        G::FAILOVER_BUILD_SLACK_SECS + G::FAILOVER_LEADER_GRACE_SECS
    );

    assert_eq!(
        G::FAILOVER_WINDOW_SECS,
        G::PUZZLE_CREATION_INTERVAL_SECS + G::FAILOVER_SLACK_SECS
    );

    assert!(G::SLOT_GOSSIP_BUFFER_SECS < G::BLOCK_CREATION_INTERVAL_SECS);

    assert_eq!(
        G::FAILOVER_PROPOSAL_DEADLINE_SECS,
        G::BLOCK_CREATION_INTERVAL_SECS - G::SLOT_GOSSIP_BUFFER_SECS
    );

    let raw_rounds = G::FAILOVER_PROPOSAL_DEADLINE_SECS.div_euclid(G::FAILOVER_WINDOW_SECS);
    let expected_rounds = if raw_rounds == 0 { 1 } else { raw_rounds };

    assert_eq!(G::FAILOVER_MAX_ROUNDS, expected_rounds);
    assert!(G::FAILOVER_MAX_ROUNDS >= 1);
    assert!(G::SLOT_GATE_DRIFT_SECS <= G::SLOT_GOSSIP_BUFFER_SECS);
}

fn assert_column_family_invariants() {
    let column_indices = [
        G::META_DATA_COLUMN,
        G::GLOBAL_COLUMN,
        G::ACCOUNT_COLUMN,
        G::NETWORK_COLUMN,
        G::SIDECHAIN_COLUMN,
        G::STATE_COLUMN,
        G::TRANSACTION_COLUMN,
        G::TRANSACTION_BATCH_COLUMN,
        G::REWARD_COLUMN,
        G::REWARD_BATCH_COLUMN,
        G::BLOCKMINT_DATA_COLUMN,
        G::LOGS_COLUMN,
        G::BLOCK_TO_HASH_COLUMN,
        G::TX_TO_HASH_COLUMN,
        G::IDENTITY_COLUMN,
        G::BLOCK_META_BY_HASH_COLUMN,
        G::BATCH_BY_BLOCK_HASH_COLUMN,
        G::CANONICAL_HEIGHT_TO_HASH_COLUMN,
        G::CANONICAL_CHAIN_VIEW_COLUMN,
    ];

    assert_eq!(G::TOTAL_COLUMNS, EXPECTED_TOTAL_COLUMNS);
    assert_eq!(column_indices.len(), G::TOTAL_COLUMNS);

    for expected in 0..G::TOTAL_COLUMNS {
        assert!(
            column_indices.contains(&(expected as u8)),
            "missing column index {expected}"
        );
    }

    for i in 0..column_indices.len() {
        for j in (i + 1)..column_indices.len() {
            assert_ne!(
                column_indices[i],
                column_indices[j],
                "column indices must be unique"
            );
        }
    }

    let column_names = [
        G::META_DATA_COLUMN_NAME,
        G::GLOBAL_COLUMN_NAME,
        G::ACCOUNT_COLUMN_NAME,
        G::NETWORK_COLUMN_NAME,
        G::SIDECHAIN_COLUMN_NAME,
        G::STATE_COLUMN_NAME,
        G::TRANSACTION_COLUMN_NAME,
        G::TRANSACTION_BATCH_COLUMN_NAME,
        G::REWARD_COLUMN_NAME,
        G::REWARD_BATCH_COLUMN_NAME,
        G::BLOCKMINT_DATA_COLUMN_NAME,
        G::LOGS_COLUMN_NAME,
        G::BLOCK_TO_HASH_COLUMN_NAME,
        G::TX_TO_HASH_COLUMN_NAME,
        G::IDENTITY_COLUMN_NAME,
        G::BLOCK_META_BY_HASH_COLUMN_NAME,
        G::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        G::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        G::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ];

    assert_eq!(column_names.len(), G::TOTAL_COLUMNS);

    for (idx, name) in column_names.iter().enumerate() {
        assert_safe_dir_name(&format!("column family name #{idx}"), name);
    }

    for i in 0..column_names.len() {
        for j in (i + 1)..column_names.len() {
            assert_ne!(
                column_names[i],
                column_names[j],
                "column family names must be unique"
            );
        }
    }
}

fn assert_security_and_cli_limit_invariants() {
    assert!(G::ATTACK_THRESHOLD >= 51);
    assert!(G::TRANSACTION_CONFIRMATION_COUNT > 0);
    assert!(G::MIN_REWARD_THRESHOLD > 0);
    assert!(G::GOVERNANCE_PROPOSAL_THRESHOLD > 0);
    assert!(G::MAJORITY_THRESHOLD > 50);
    assert!(G::MAJORITY_THRESHOLD <= 100);

    assert!(!G::BASE58_ALPHABET.is_empty());
    assert!(!G::BASE58_ALPHABET.contains('0'));
    assert!(!G::BASE58_ALPHABET.contains('O'));
    assert!(!G::BASE58_ALPHABET.contains('I'));
    assert!(!G::BASE58_ALPHABET.contains('l'));

    assert_eq!(G::NONCE_SIZE, 12);
    assert_eq!(G::AES_KEY_SIZE, 32);
    assert_eq!(G::SALT_SIZE, 16);

    assert!(G::ARGON2_MEMORY_KIB > 0);
    assert!(G::ARGON2_TIME_COST > 0);
    assert!(G::ARGON2_LANES > 0);

    assert!(G::MAX_PRIVATE_KEY_BYTES >= G::MLDSA65_SECRET_BYTES);
    assert!(G::MAX_ENCRYPTED_BLOB_BYTES >= G::MAX_PRIVATE_KEY_BYTES);

    assert!(G::MAX_ZAR_PARTICIPANTS > 0);
    assert!(G::MAX_VALIDATORS > 0);
    assert!(G::MAX_IDENTITIES >= G::MAX_VALIDATORS);
    assert!(G::MAX_VERIFYING_KEYS >= G::MAX_VALIDATORS);
    assert!(G::MAX_SNAPSHOT_ENTRIES >= G::MAX_VALIDATORS);
    assert!(G::MAX_PEER_ID_B58_LEN >= 32);

    assert!(G::MAX_ATTEMPTS > 0);
    assert!(G::RETRY_DELAY_SECS > 0);
    assert!(G::JOIN_TIMEOUT_SECS > 0);

    assert!(G::MAX_INPUT_BYTES >= G::MAX_YN_INPUT_LEN);
    assert!(G::MAX_INPUT_BYTES >= G::MAX_MODE_INPUT_LEN);
    assert!(G::MAX_INPUT_BYTES >= G::MAX_BATCH_INPUT_LEN);
    assert!(G::MAX_IDENTITY_KEY_BYTES > 0);
    assert!(G::MAX_GENESIS_JSON_BYTES > 0);
    assert!(G::MAX_PASS_PROMPTS > 0);
    assert!(G::MAX_BATCH_WALLETS >= 2);
}

fn assert_multichain_invariants() {
    assert_safe_dir_name("USER_CHAIN_DATABASE_DIR", G::USER_CHAIN_DATABASE_DIR);
    assert_safe_dir_name("USER_CHAIN_SNAPSHOT_DIR", G::USER_CHAIN_SNAPSHOT_DIR);
    assert!(G::MAX_USER_CHAINS > 0);
    assert!(G::MAX_CONCURRENT_DATABASES >= G::MAX_USER_CHAINS);
    assert!(G::MAX_CONCURRENT_ROCKSDB_INSTANCES >= G::MAX_CONCURRENT_DATABASES);

    assert_nonempty_name("DEFAULT_USER_CHAIN_PREFIX", G::DEFAULT_USER_CHAIN_PREFIX);
    assert_nonempty_name("DEFAULT_USER_COIN_NAME_FORMAT", G::DEFAULT_USER_COIN_NAME_FORMAT);
    assert_nonempty_name("DEFAULT_USER_COIN_SYMBOL_FORMAT", G::DEFAULT_USER_COIN_SYMBOL_FORMAT);

    assert!(G::DEFAULT_USER_CHAIN_GENESIS_TIMESTAMP >= G::MIN_TIMESTAMP_SECS);
    assert_eq!(G::USER_CHAIN_NETWORK_MAGIC_BASE.len(), 4);

    assert_eq!(G::USER_CHAIN_MAX_SUPPLY, G::MAX_REWARD_SUPPLY);
    assert_eq!(G::USER_CHAIN_ZAR_SUPPLY, G::MAX_REWARD_SUPPLY);
    assert_eq!(G::USER_CHAIN_GOVERNANCE_PROPOSAL_THRESHOLD, G::GOVERNANCE_PROPOSAL_THRESHOLD);
    assert_eq!(G::USER_CHAIN_MAJORITY_THRESHOLD, G::MAJORITY_THRESHOLD);
    assert_eq!(G::USER_CHAIN_ATTACK_THRESHOLD, G::ATTACK_THRESHOLD);
    assert_eq!(G::USER_CHAIN_STABILIZED_BLOCK_REWARD, G::STABILIZED_BLOCK_REWARD);
    assert_eq!(G::USER_CHAIN_INITIAL_BLOCK_REWARD, G::INITIAL_BLOCK_REWARD);
    assert_eq!(G::USER_CHAIN_REWARD_REDUCTION_SEQUENCE, G::REWARD_REDUCTION_SEQUENCE);
    assert_eq!(G::USER_CHAIN_BLOCKS_PER_HALVING, G::HALVING_INTERVAL_BLOCKS);
    assert_eq!(G::DEFAULT_USER_CHAIN_BLOCK_SIZE, G::MAX_BLOCK_SIZE);
    assert_eq!(G::DEFAULT_USER_CHAIN_TX_BUFFER_LIMIT, 4 * 1024 * 1024);
}

fn run_all_fixed_invariants() {
    assert_database_directory_invariants();
    assert_genesis_and_wallet_invariants();
    assert_block_and_tx_limit_invariants();
    assert_reward_economic_invariants();
    assert_timing_and_failover_invariants();
    assert_column_family_invariants();
    assert_security_and_cli_limit_invariants();
    assert_multichain_invariants();
}

fn fuzz_ceil_div(cursor: &mut Cursor<'_>) {
    let a = cursor.take_u64();

    let b = cursor.take_u64().max(1);

    assert_eq!(G::ceil_div(a, b), ceil_div_model(a, b));
    assert!(G::ceil_div(a, b) >= a / b);
    assert!(G::ceil_div(a, b) <= a.saturating_div(b).saturating_add(1));
}

fn fuzz_wallet_candidate(cursor: &mut Cursor<'_>) {
    let candidate = match cursor.take_u8() % 6 {
        0 => G::GENESIS_VALIDATOR.to_string(),
        1 => G::BURN_ADDRESS.to_string(),
        2 => format!("r{}", "0".repeat(128)),
        3 => format!("R{}", "F".repeat(128)),
        4 => format!("r{}g", "0".repeat(127)),
        _ => cursor.take_ascii_string(160),
    };

    let structurally_valid = {
        let bytes = candidate.as_bytes();
        bytes.len() == WALLET_TEXT_LEN
            && matches!(bytes.first().copied(), Some(b'r') | Some(b'R'))
            && bytes[1..].iter().copied().all(is_hex_ascii)
    };

    if candidate == G::GENESIS_VALIDATOR || candidate == G::BURN_ADDRESS {
        assert!(structurally_valid);
        assert!(candidate.as_bytes()[1..].iter().copied().all(is_lower_hex_ascii));
    }

    if structurally_valid {
        let canon = format!("r{}", candidate[1..].to_ascii_lowercase());
        assert_eq!(canon.len(), WALLET_TEXT_LEN);
        assert!(canon.as_bytes()[1..].iter().copied().all(is_lower_hex_ascii));
    }
}

fn fuzz_selected_constants(cursor: &mut Cursor<'_>) {
    match cursor.take_u8() % 10 {
        0 => assert_database_directory_invariants(),
        1 => assert_genesis_and_wallet_invariants(),
        2 => assert_block_and_tx_limit_invariants(),
        3 => assert_reward_economic_invariants(),
        4 => assert_timing_and_failover_invariants(),
        5 => assert_column_family_invariants(),
        6 => assert_security_and_cli_limit_invariants(),
        7 => assert_multichain_invariants(),
        8 => fuzz_ceil_div(cursor),
        _ => fuzz_wallet_candidate(cursor),
    }
}

fuzz_target!(|data: &[u8]| {
    run_all_fixed_invariants();

    let mut cursor = Cursor::new(data);

    let iterations = 1usize.saturating_add(cursor.take_usize_mod(64));
    for _ in 0..iterations {
        fuzz_selected_constants(&mut cursor);

        if cursor.take_bool() {
            fuzz_ceil_div(&mut cursor);
        }

        if cursor.take_bool() {
            fuzz_wallet_candidate(&mut cursor);
        }
    }
});
