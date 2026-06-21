#![no_main]

extern crate self as libp2p;

use fips204::traits::KeyGen;
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn set_env_var(key: &str, value: &str) {
    // SAFETY:
    // This fuzz target serializes all REMZAR_GENESIS_PATH mutation through ENV_LOCK.
    // The target uses a current-thread Tokio runtime and only mutates this env var
    // inside the locked fuzz iteration before cleaning it up.
    unsafe {
        std::env::set_var(key, value);
    }
}

fn remove_env_var(key: &str) {
    // SAFETY:
    // This fuzz target serializes all REMZAR_GENESIS_PATH mutation through ENV_LOCK.
    // See set_env_var safety note above.
    unsafe {
        std::env::remove_var(key);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal libp2p stand-in
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub fn random() -> Self {
        Self::from_seed(0xA5)
    }

    pub fn from_seed(seed: u8) -> Self {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        Self(out)
    }

    pub fn to_base58(&self) -> String {
        format!("peer_{}", hex::encode(self.0))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiaddr(Vec<u8>);

impl Multiaddr {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

pub mod swarm {
    use super::{Multiaddr, PeerId};

    #[derive(Debug, Clone)]
    pub enum SwarmEvent<T> {
        Behaviour(T),
        ConnectionClosed {
            peer_id: PeerId,
            event: Option<T>,
        },
        Other(T),
    }

    #[derive(Debug, Clone)]
    pub struct Swarm<B> {
        local_peer_id: PeerId,
        behaviour: B,
        connected_peers: Vec<PeerId>,
        listeners: Vec<Multiaddr>,
    }

    impl<B> Swarm<B> {
        pub fn new_for_fuzz(
            local_peer_id: PeerId,
            behaviour: B,
            connected_peers: Vec<PeerId>,
            listeners: Vec<Multiaddr>,
        ) -> Self {
            Self {
                local_peer_id,
                behaviour,
                connected_peers,
                listeners,
            }
        }

        pub fn local_peer_id(&self) -> &PeerId {
            &self.local_peer_id
        }

        pub fn behaviour(&self) -> &B {
            &self.behaviour
        }

        pub fn behaviour_mut(&mut self) -> &mut B {
            &mut self.behaviour
        }

        pub fn connected_peers(&self) -> impl Iterator<Item = &PeerId> {
            self.connected_peers.iter()
        }

        pub fn listeners(&self) -> impl Iterator<Item = &Multiaddr> {
            self.listeners.iter()
        }
    }
}

pub use swarm::Swarm;

// ─────────────────────────────────────────────────────────────────────────────
// commandline stubs
// ─────────────────────────────────────────────────────────────────────────────

mod commandline {
    pub mod s_04_view_blockchain_console {
        #[derive(Debug, Clone, Default)]
        pub struct ConsoleBus;

        impl ConsoleBus {
            pub fn new() -> Self {
                Self
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// utility stubs
// ─────────────────────────────────────────────────────────────────────────────

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const STATE_COLUMN_NAME: &'static str = "state_data";
            pub const MAX_BLOCK_SIZE: u64 = 7_500;
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;
            pub const FAILOVER_WINDOW_SECS: u64 = 7;
            pub const FAILOVER_PROPOSAL_DEADLINE_SECS: u64 = 24;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            StorageError {
                message: String,
            },
            DatabaseError {
                details: String,
            },
            NotFound {
                resource: String,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod alpha_003_detection_system {
        #[derive(Debug, Clone, Default)]
        pub struct DetectionSystem;

        impl DetectionSystem {
            pub fn new() -> Self {
                Self
            }
        }
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            if !b[1..]
                .iter()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".into(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// consensus stubs
// ─────────────────────────────────────────────────────────────────────────────

mod consensus {
    pub mod por_000_ephemeral_registration {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        pub struct RegistryData {
            pub wallets: BTreeSet<String>,
            peer_to_wallet: BTreeMap<String, String>,
        }

        impl RegistryData {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn sorted_wallets(&self) -> Vec<String> {
                self.wallets.iter().cloned().collect()
            }

            pub fn is_registered(&self, wallet: &str) -> bool {
                canon_wallet_id_checked(wallet)
                    .ok()
                    .is_some_and(|w| self.wallets.contains(&w))
            }

            pub fn wallet_for_peer(&self, peer: &str) -> Option<String> {
                self.peer_to_wallet.get(peer).cloned()
            }

            pub fn register_wallet_strict(
                &mut self,
                wallet: &str,
                _join_height: u64,
            ) -> Result<String, ErrorDetection> {
                let wallet = canon_wallet_id_checked(wallet)?;
                self.wallets.insert(wallet.clone());
                Ok(wallet)
            }

            pub fn register_peer_for_wallet(
                &mut self,
                peer: &str,
                wallet: &str,
            ) -> Result<(), ErrorDetection> {
                let wallet = canon_wallet_id_checked(wallet)?;
                self.wallets.insert(wallet.clone());
                self.peer_to_wallet.insert(peer.to_string(), wallet);
                Ok(())
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct NodeEphemeral {
            reg: Arc<Mutex<RegistryData>>,
        }

        impl NodeEphemeral {
            pub fn new() -> Self {
                Self {
                    reg: Arc::new(Mutex::new(RegistryData::new())),
                }
            }

            pub fn ephemeral(&self) -> Arc<Mutex<RegistryData>> {
                Arc::clone(&self.reg)
            }

            pub fn register_wallet_strict(
                &self,
                wallet: &str,
                join_height: u64,
            ) -> Result<String, ErrorDetection> {
                self.reg
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "registry poisoned".into(),
                    })?
                    .register_wallet_strict(wallet, join_height)
            }
        }
    }

    pub mod por_005_time_management {
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::Duration;

        #[derive(Debug, Clone)]
        pub struct TimeConfig {
            genesis_time_unix: u64,
            block_interval_secs: u64,
            failover_window_secs: u64,
            proposal_deadline_secs: u64,
        }

        impl TimeConfig {
            pub fn from_genesis_ts(genesis_time_unix: u64) -> Self {
                Self {
                    genesis_time_unix: genesis_time_unix.max(1),
                    block_interval_secs: GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS,
                    failover_window_secs: GlobalConfiguration::FAILOVER_WINDOW_SECS,
                    proposal_deadline_secs: GlobalConfiguration::FAILOVER_PROPOSAL_DEADLINE_SECS,
                }
            }
        }

        #[derive(Debug, Clone)]
        pub struct TimeManager {
            cfg: TimeConfig,
        }

        impl TimeManager {
            pub fn new(cfg: TimeConfig) -> Self {
                Self { cfg }
            }

            pub fn new_from_genesis_file(path: &str) -> Result<Self, ErrorDetection> {
                let data = std::fs::read_to_string(path).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: e.to_string(),
                    }
                })?;

                let mut ts = 946_684_800u64;

                if let Some(pos) = data.find("timestamp") {
                    let tail = &data[pos..];
                    let digits: String = tail.chars().filter(|c| c.is_ascii_digit()).collect();
                    if let Ok(parsed) = digits.parse::<u64>() {
                        ts = parsed.max(1);
                    }
                }

                Ok(Self::new(TimeConfig::from_genesis_ts(ts)))
            }

            pub fn now_unix() -> u64 {
                946_684_800 + 300
            }

            pub fn current_slot(&self, now: u64) -> u64 {
                now.saturating_sub(self.cfg.genesis_time_unix)
                    / self.cfg.block_interval_secs.max(1)
            }

            pub fn slot_start_unix(&self, slot: u64) -> u64 {
                self.cfg
                    .genesis_time_unix
                    .saturating_add(slot.saturating_mul(self.cfg.block_interval_secs.max(1)))
            }

            pub fn block_interval(&self) -> Duration {
                Duration::from_secs(self.cfg.block_interval_secs.max(1))
            }

            pub fn failover_window_secs(&self) -> u64 {
                self.cfg.failover_window_secs.max(1)
            }

            pub fn proposal_deadline_secs(&self) -> u64 {
                self.cfg.proposal_deadline_secs.max(1)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// network stubs
// ─────────────────────────────────────────────────────────────────────────────

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }

    pub mod p2p_003_behaviour {
        #[derive(Debug, Clone, Default)]
        pub struct RemzarBehaviour;

        #[derive(Debug, Clone)]
        pub enum OutEvent {
            Ignored,
        }
    }

    pub mod p2p_010_netcmd {
        #[derive(Debug, Clone)]
        pub enum NetCmd {
            Noop,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// storage stubs
// ─────────────────────────────────────────────────────────────────────────────

mod storage {
    pub mod rocksdb_005_manager {
        use crate::blockchain::block_002_blocks::Block;
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone)]
        pub struct RockDBManager {
            inner: Arc<Mutex<MockDb>>,
        }

        #[derive(Debug, Clone, Default)]
        struct MockDb {
            has_state: bool,
            block0: Option<Block>,
            kv: BTreeMap<(String, Vec<u8>), Vec<u8>>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz(has_state: bool, block0: Option<Block>) -> Self {
                Self {
                    inner: Arc::new(Mutex::new(MockDb {
                        has_state,
                        block0,
                        kv: BTreeMap::new(),
                    })),
                }
            }

            pub fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, ErrorDetection> {
                self.inner
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
                    .map(|db| if index == 0 { db.block0.clone() } else { None })
            }

            pub fn read(
                &self,
                cf: &str,
                key: &[u8],
            ) -> Result<Option<Vec<u8>>, ErrorDetection> {
                let db = self.inner.lock().map_err(|_| ErrorDetection::StorageError {
                    message: "db poisoned".into(),
                })?;

                if cf == GlobalConfiguration::STATE_COLUMN_NAME && key == b"__account_state__" {
                    if db.has_state {
                        return Ok(Some(vec![1, 2, 3, 4]));
                    }
                    return Ok(None);
                }

                Ok(db.kv.get(&(cf.to_string(), key.to_vec())).cloned())
            }

            pub fn write(
                &self,
                cf: &str,
                key: &[u8],
                value: &[u8],
            ) -> Result<(), ErrorDetection> {
                self.inner
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })?
                    .kv
                    .insert((cf.to_string(), key.to_vec()), value.to_vec());
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// reorganization stubs
// ─────────────────────────────────────────────────────────────────────────────

mod reorganization {
    pub mod reorg_006_manager {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use std::sync::{Arc, Mutex, MutexGuard};

        #[derive(Debug, Clone)]
        pub struct ReorgManager {
            _db: Arc<RockDBManager>,
        }

        impl ReorgManager {
            pub fn mainnet_default(db: Arc<RockDBManager>) -> Self {
                Self { _db: db }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// runtime stubs
// ─────────────────────────────────────────────────────────────────────────────

mod runtime {
    pub mod p2p_001_sync_builders {
        #[derive(Debug, Clone)]
        pub struct P2pSync {
            has_synced: bool,
            is_syncing: bool,
            has_background_sync_work: bool,
            last_synced_index: Option<u64>,
        }

        impl P2pSync {
            pub fn new_for_fuzz(
                has_synced: bool,
                is_syncing: bool,
                has_background_sync_work: bool,
                last_synced_index: Option<u64>,
            ) -> Self {
                Self {
                    has_synced,
                    is_syncing,
                    has_background_sync_work,
                    last_synced_index,
                }
            }

            pub fn has_synced(&self) -> bool {
                self.has_synced
            }

            pub fn is_syncing(&self) -> bool {
                self.is_syncing
            }

            pub fn has_background_sync_work(&self) -> bool {
                self.has_background_sync_work
            }

            pub fn last_synced_index(&self) -> Option<u64> {
                self.last_synced_index
            }
        }
    }

    pub mod p2p_006_sync_runtime {
        #[derive(Debug, Clone)]
        pub struct NodeOpts {
            pub founder: bool,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// blockchain stubs plus real 005 include
// ─────────────────────────────────────────────────────────────────────────────

mod blockchain {
    pub mod block_001_metadata {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockMetadata {
            pub index: u64,
            pub timestamp: u64,
            #[serde(with = "serde_big_array::BigArray")]
            pub previous_hash: [u8; 64],
            #[serde(with = "serde_big_array::BigArray")]
            pub merkle_root: [u8; 64],
            pub guardian_signature: Vec<u8>,
            pub puzzle_proof: Option<()>,
            pub size: u64,
        }

        impl BlockMetadata {
            pub fn new_for_fuzz(index: u64, previous_hash: [u8; 64], timestamp: u64) -> Self {
                let mut merkle_root = [0x22u8; 64];
                merkle_root[..8].copy_from_slice(&index.to_be_bytes());

                Self {
                    index,
                    timestamp,
                    previous_hash,
                    merkle_root,
                    guardian_signature: Vec::new(),
                    puzzle_proof: None,
                    size: 1024,
                }
            }
        }
    }

    pub mod block_002_blocks {
        use crate::blockchain::block_001_metadata::BlockMetadata;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct Block {
            pub metadata: BlockMetadata,
            pub batch_key: Option<String>,
            pub miner: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub block_hash: [u8; 64],
            pub reward: u64,
        }

        impl Block {
            pub fn new_stub(
                index: u64,
                previous_hash: [u8; 64],
                timestamp: u64,
                miner: String,
            ) -> Self {
                let mut block_hash = previous_hash;
                block_hash[0] ^= index as u8;
                block_hash[1] ^= (index >> 8) as u8;

                Self {
                    metadata: BlockMetadata::new_for_fuzz(index, previous_hash, timestamp),
                    batch_key: None,
                    miner,
                    block_hash,
                    reward: if index == 0 { 0 } else { 1 },
                }
            }

            pub fn miner_wallet(&self) -> &str {
                &self.miner
            }
        }
    }

    pub mod mempool {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_003_detection_system::DetectionSystem;
        use std::sync::{Arc, Mutex, MutexGuard};

        #[derive(Debug)]
        pub struct MemPool {
            _db: Arc<RockDBManager>,
            _detection: Arc<DetectionSystem>,
        }

        impl MemPool {
            pub fn new(db: Arc<RockDBManager>, detection: Arc<DetectionSystem>) -> Self {
                Self {
                    _db: db,
                    _detection: detection,
                }
            }
        }
    }

    pub mod transaction_005_tx_account_tree {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone)]
        pub struct AccountModelTree {
            db: RockDBManager,
            loaded: bool,
        }

        impl AccountModelTree {
            pub fn load_state(db: RockDBManager) -> Result<Self, ErrorDetection> {
                match db.read(GlobalConfiguration::STATE_COLUMN_NAME, b"__account_state__")? {
                    Some(_) => Ok(Self { db, loaded: true }),
                    None => Err(ErrorDetection::NotFound {
                        resource: "Account state".into(),
                    }),
                }
            }

            pub fn latest_block_height(&self) -> usize {
                if self.loaded { 0 } else { 0 }
            }

            pub fn reload_from_db(&mut self) {}

            pub fn reload_from_db_to_height(&mut self, _height: u64) -> Result<(), ErrorDetection> {
                Ok(())
            }
        }
    }

    pub mod blockchain_004_orchestration_run {
        use crate::blockchain::mempool::MemPool;
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
        use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
        use crate::consensus::por_005_time_management::TimeManager;
        use crate::network::p2p_003_behaviour::RemzarBehaviour;
        use crate::network::p2p_010_netcmd::NetCmd;
        use crate::reorganization::reorg_006_manager::ReorgManager;
        use crate::runtime::p2p_001_sync_builders::P2pSync;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::Swarm;
        use fips204::ml_dsa_65;
        use std::sync::{Arc, Mutex, MutexGuard};
        use tokio::sync::{mpsc, Mutex as TokioMutex};

        pub struct OrchestrationLoopArgs {
            pub db: Arc<RockDBManager>,
            pub node_ephemeral: NodeEphemeral,
            pub mempool: Arc<MemPool>,
            pub sync_engine: Arc<TokioMutex<P2pSync>>,
            pub signing_key: Arc<ml_dsa_65::PrivateKey>,
            pub tm: Arc<TimeManager>,
            pub reorg_manager: ReorgManager,
            pub local_wallet: String,
            pub console_bus: ConsoleBus,
        }

        pub struct OrchestrationLoop {
            args: OrchestrationLoopArgs,
        }

        impl OrchestrationLoop {
            pub fn new(args: OrchestrationLoopArgs) -> Self {
                // Assert startup wiring produced a canonical wallet by this point.
                let _ = crate::utility::helper::canon_wallet_id_checked(&args.local_wallet);
                Self { args }
            }

            pub async fn run_until_ctrl_c(
                &self,
                chain: &mut AccountModelTree,
                swarm: &mut Swarm<RemzarBehaviour>,
                net_rx: Option<mpsc::Receiver<NetCmd>>,
                opts: &NodeOpts,
            ) -> Result<(), ErrorDetection> {
                let _ = chain.latest_block_height();
                let _ = swarm.local_peer_id();
                let _ = net_rx.is_some();
                let _ = opts.founder;

                // IMPORTANT: return immediately.
                // The real StartBlockchain file calls run_until_ctrl_c(),
                // but a fuzz target must never wait for an OS Ctrl-C signal.
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REAL FILE UNDER TEST
// ─────────────────────────────────────────────────────────────────────────────

#[path = "../../src/blockchain/blockchain_005_start.rs"]
mod blockchain_005_start;

use blockchain::block_002_blocks::Block;
use blockchain_005_start::StartBlockchain;
use network::p2p_003_behaviour::RemzarBehaviour;
use runtime::p2p_001_sync_builders::P2pSync;
use runtime::p2p_006_sync_runtime::NodeOpts;
use storage::rocksdb_005_manager::RockDBManager;
use tokio::sync::Mutex as TokioMutex;

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz helpers
// ─────────────────────────────────────────────────────────────────────────────

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u64::from_le_bytes(out)
}

fn fuzz_hash(data: &[u8], salt: usize) -> [u8; 64] {
    let mut out = [0u8; 64];

    for i in 0..64 {
        out[i] = byte_at(data, salt + i, i as u8)
            ^ byte_at(data, salt + i.wrapping_mul(7), 0xA5)
            ^ (salt as u8)
            ^ (i as u8);
    }

    if out == [0u8; 64] {
        out[0] = 1;
    }

    out
}

fn canonical_wallet(data: &[u8], salt: usize) -> String {
    format!("r{}", hex::encode(fuzz_hash(data, salt)))
}

fn maybe_wallet(data: &[u8], salt: usize) -> String {
    match byte_at(data, salt, 0) % 8 {
        0 => String::new(),
        1 => "not-a-wallet".to_string(),
        2 => "r1234".to_string(),
        3 => format!("x{}", hex::encode(fuzz_hash(data, salt + 1))),
        4 => canonical_wallet(data, salt + 2).to_ascii_uppercase(),
        5 => format!(" {} ", canonical_wallet(data, salt + 3)),
        6 => canonical_wallet(data, salt + 4),
        _ => "rzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
    }
}

fn make_signing_key(data: &[u8]) -> fips204::ml_dsa_65::PrivateKey {
    let mut seed = [0u8; 32];

    for i in 0..32 {
        seed[i] = byte_at(data, 1000 + i, i as u8);
    }

    let (_pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
    sk
}

fn make_swarm(data: &[u8]) -> Swarm<RemzarBehaviour> {
    let local_peer = PeerId::from_seed(byte_at(data, 80, 1));
    let connected_count = usize::from(byte_at(data, 81, 0) % 4);
    let listener_count = usize::from(byte_at(data, 82, 0) % 3);

    let connected = (0..connected_count)
        .map(|i| PeerId::from_seed(byte_at(data, 90 + i, i as u8)))
        .collect::<Vec<_>>();

    let listeners = (0..listener_count)
        .map(|i| {
            Multiaddr::from_bytes(vec![
                byte_at(data, 110 + i, i as u8),
                byte_at(data, 120 + i, i as u8),
                byte_at(data, 130 + i, i as u8),
            ])
        })
        .collect::<Vec<_>>();

    Swarm::new_for_fuzz(local_peer, RemzarBehaviour::default(), connected, listeners)
}

fn maybe_set_genesis_env(data: &[u8]) -> Option<std::path::PathBuf> {
    match byte_at(data, 200, 0) % 4 {
        0 => {
            remove_env_var("REMZAR_GENESIS_PATH");
            None
        }
        1 => {
            set_env_var(
                "REMZAR_GENESIS_PATH",
                "/definitely/not/a/real/remzar/genesis.json",
            );
            None
        }
        _ => {
            let path = std::env::temp_dir().join(format!(
                "remzar_start_fuzz_genesis_{}_{}.json",
                std::process::id(),
                hex::encode(&fuzz_hash(data, 300)[..8])
            ));

            let ts = match byte_at(data, 201, 0) % 4 {
                0 => 1,
                1 => 946_684_800,
                2 => read_u64(data, 220),
                _ => u64::MAX.saturating_sub(read_u64(data, 240) % 1024),
            };

            let json = if byte_at(data, 202, 0) & 1 == 1 {
                format!(r#"{{"timestamp":{ts},"data":"genesis"}}"#)
            } else {
                String::from_utf8_lossy(&data[..data.len().min(256)]).to_string()
            };

            if std::fs::write(&path, json).is_ok() {
                if let Some(path_str) = path.to_str() {
                    set_env_var("REMZAR_GENESIS_PATH", path_str);
                    return Some(path);
                }
            }

            None
        }
    }
}

fn exercise_start(data: &[u8]) {
    let has_state = byte_at(data, 0, 0) & 1 == 1;

    let local_wallet = maybe_wallet(data, 8);

    let block0 = if byte_at(data, 1, 0) & 1 == 1 {
        Some(Block::new_stub(
            0,
            fuzz_hash(data, 32),
            match byte_at(data, 2, 0) % 4 {
                0 => 1,
                1 => 946_684_800,
                2 => read_u64(data, 48),
                _ => u64::MAX.saturating_sub(read_u64(data, 56) % 1024),
            },
            if local_wallet.trim().is_empty() {
                canonical_wallet(data, 64)
            } else {
                local_wallet.trim().to_string()
            },
        ))
    } else {
        None
    };

    let db = RockDBManager::new_for_fuzz(has_state, block0);

    let sync_engine = Arc::new(TokioMutex::new(P2pSync::new_for_fuzz(
        byte_at(data, 3, 0) & 1 == 1,
        byte_at(data, 4, 0) & 1 == 1,
        byte_at(data, 5, 0) & 1 == 1,
        Some(read_u64(data, 160) % 128),
    )));

    let signing_key = Arc::new(make_signing_key(data));

    let start = StartBlockchain::new(
        db,
        local_wallet,
        Arc::clone(&sync_engine),
        Arc::clone(&signing_key),
    );

    // Public constructor invariants.
    let _ = start.wallet_registry.sorted_wallets();
    let _ = start.db_manager.get_block_by_index(0);

    let mut swarm = make_swarm(data);

    let opts = NodeOpts {
        founder: byte_at(data, 6, 0) & 1 == 1,
    };

    let _env_guard = lock_env();
    let env_file = maybe_set_genesis_env(data);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let Ok(rt) = rt else {
        if let Some(path) = env_file {
            let _ = std::fs::remove_file(path);
        }
        remove_env_var("REMZAR_GENESIS_PATH");
        return;
    };

    rt.block_on(async {
        let _ = start.run(&mut swarm, &opts).await;
    });

    if let Some(path) = env_file {
        let _ = std::fs::remove_file(path);
    }

    remove_env_var("REMZAR_GENESIS_PATH");
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz entry
// ─────────────────────────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    exercise_start(data);
});