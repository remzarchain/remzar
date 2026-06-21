#![no_main]

extern crate self as libp2p;

use fips204::traits::KeyGen;
use libfuzzer_sys::fuzz_target;
use std::{collections::VecDeque, sync::Arc};

// ─────────────────────────────────────────────────────────────────────────────
// Minimal libp2p stand-in
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId {
    bytes: [u8; 32],
    text: [u8; 69],
    text_len: usize,
}

impl PeerId {
    pub fn random() -> Self {
        Self::from_seed(0xA5)
    }

    pub fn from_seed(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_add(1);
        }

        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut text = [0u8; 69];
        text[..5].copy_from_slice(b"peer_");

        for (i, b) in bytes.iter().copied().enumerate() {
            let pos = 5 + (i * 2);
            text[pos] = HEX[usize::from(b >> 4)];
            text[pos + 1] = HEX[usize::from(b & 0x0f)];
        }

        Self {
            bytes,
            text,
            text_len: 69,
        }
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.text[..self.text_len]).unwrap_or("peer_invalid")
    }

    pub fn to_base58(&self) -> String {
        self.as_str().to_string()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiaddr(Vec<u8>);

impl Multiaddr {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

pub mod gossipsub {
    use crate::PeerId;

    #[derive(Debug, Clone)]
    pub struct Message {
        pub data: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub struct MessageId(pub Vec<u8>);

    #[derive(Debug, Clone)]
    pub enum Event {
        Message {
            propagation_source: PeerId,
            message_id: MessageId,
            message: Message,
        },
        Subscribed,
        Unsubscribed,
    }
}

pub mod swarm {
    use super::{Multiaddr, PeerId};
    use std::collections::VecDeque;

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
        events: VecDeque<SwarmEvent<crate::network::p2p_003_behaviour::OutEvent>>,
    }

    impl<B> Swarm<B> {
        pub fn new_for_fuzz(
            local_peer_id: PeerId,
            behaviour: B,
            connected_peers: Vec<PeerId>,
            listeners: Vec<Multiaddr>,
            events: VecDeque<SwarmEvent<crate::network::p2p_003_behaviour::OutEvent>>,
        ) -> Self {
            Self {
                local_peer_id,
                behaviour,
                connected_peers,
                listeners,
                events,
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

    impl<B: Unpin> futures::Stream for Swarm<B> {
        type Item = SwarmEvent<crate::network::p2p_003_behaviour::OutEvent>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let this = self.get_mut();
            std::task::Poll::Ready(this.events.pop_front())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// commandline
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
// utility
// ─────────────────────────────────────────────────────────────────────────────

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const BLOCK_CREATION_INTERVAL_SECS: u64 = 30;

            // Required by the real src/utility/time_policy.rs.
            pub const SLOT_GATE_DRIFT_SECS: u64 = 2;
            pub const MAX_FUTURE_SKEW_SECS: u64 = 2 * 60 * 60;

            pub const HEARTBEAT_TX_INTERVAL_SECS: u64 = 300;
            pub const CANONICAL_RENEW_INTERVAL_BLOCKS: u64 = 10;
            pub const DEAD_PEER_EVICTION_SECS: u64 = 60;
            pub const HEARTBEAT_GRACE_SECS: u64 = 0;
            pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
            pub const MIN_BLOCK_SIZE: u64 = 64;
            pub const MAX_TXS_PER_BLOCK: u64 = 7_500;
            pub const BLOCK_OVERHEAD_RESERVE: usize = 16 * 1024;
            pub const MAX_BLOCK_REWARD: u64 = 5_000_000_000;
            pub const BLOCKMINT_DATA_COLUMN_NAME: &'static str = "blockmint_data";
            pub const TRANSACTION_BATCH_COLUMN_NAME: &'static str = "transaction_batch";
            pub const GLOBAL_COLUMN_NAME: &'static str = "global";
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError { message: String, tx_id: Option<String> },
            SerializationError { details: String },
            StorageError { message: String },
            DatabaseError { details: String },
            BlockchainError { details: String },
            CryptographicError { message: String },
            ProtocolError { message: String },
            TimestampError { message: String, details: String, source: Option<String> },
            NotFound { resource: String },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, .. } => write!(f, "{message}"),
                    Self::SerializationError { details } => write!(f, "{details}"),
                    Self::StorageError { message } => write!(f, "{message}"),
                    Self::DatabaseError { details } => write!(f, "{details}"),
                    Self::BlockchainError { details } => write!(f, "{details}"),
                    Self::CryptographicError { message } => write!(f, "{message}"),
                    Self::ProtocolError { message } => write!(f, "{message}"),
                    Self::TimestampError { message, details, .. } => write!(f, "{message}: {details}"),
                    Self::NotFound { resource } => write!(f, "{resource} not found"),
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    // Required by the real orchestration files.
    //
    // They import:
    // crate::utility::time_policy::TimePolicy
    pub mod time_policy {
        pub use crate::real_time_policy::*;
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let lower = id.trim().to_ascii_lowercase();
            let b = lower.as_bytes();

            if lower.len() != REMZAR_WALLET_LEN || b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "invalid wallet".into(),
                    tx_id: None,
                });
            }

            if !b[1..].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(ErrorDetection::ValidationError {
                    message: "invalid wallet hex".into(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }

        pub fn quorum_threshold_checked(n: usize) -> Result<usize, ErrorDetection> {
            if n == 0 {
                return Err(ErrorDetection::ValidationError {
                    message: "empty validator set".into(),
                    tx_id: None,
                });
            }
            Ok((n / 2).saturating_add(1))
        }

        pub fn has_quorum(live: usize, total: usize) -> bool {
            total > 0 && live >= (total / 2).saturating_add(1)
        }
    }
}

#[path = "../../src/utility/time_policy.rs"]
mod real_time_policy;

// ─────────────────────────────────────────────────────────────────────────────
// consensus
// ─────────────────────────────────────────────────────────────────────────────

mod consensus {
    pub mod por_000_ephemeral_registration {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::{
            collections::{BTreeMap, BTreeSet},
            sync::{Arc, Mutex},
            time::Duration,
        };

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

            pub fn register_peer_for_wallet(
                &self,
                peer: &str,
                wallet: &str,
            ) -> Result<(), ErrorDetection> {
                self.reg
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "registry poisoned".into(),
                    })?
                    .register_peer_for_wallet(peer, wallet)
            }

            pub fn set_join_height(&self, wallet: &str, join_height: u64) -> Result<(), ErrorDetection> {
                self.register_wallet_strict(wallet, join_height).map(|_| ())
            }

            pub fn evict_inactive_validators(&self, _max: Duration, _grace: Duration) {}
            pub fn finalize_heartbeat_round(&self) {}
            pub fn begin_heartbeat_round(&self) {}

            pub fn note_heartbeat_round(
                &self,
                wallet: &str,
                tip_snapshot: u64,
            ) -> Result<String, ErrorDetection> {
                self.register_wallet_strict(wallet, tip_snapshot)
            }

            pub fn unregister_by_peer(&self, peer: &str) -> Option<String> {
                self.reg.lock().ok()?.peer_to_wallet.remove(peer)
            }
        }
    }

    pub mod por_004_puzzle_proof {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct PorPuzzleProof {
            pub height: u64,
            pub validator: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }
    }

    pub mod por_005_time_management {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::time::Duration;

        const UNIX_2000_SECS: u64 = 946_684_800;

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
                    genesis_time_unix: genesis_time_unix.max(UNIX_2000_SECS),
                    block_interval_secs: 30,
                    failover_window_secs: 7,
                    proposal_deadline_secs: 24,
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

            pub fn new_checked(cfg: TimeConfig) -> Result<Self, ErrorDetection> {
                if cfg.genesis_time_unix < UNIX_2000_SECS {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "invalid fuzz TimeManager genesis_time_unix={} < UNIX_2000_SECS={}",
                            cfg.genesis_time_unix, UNIX_2000_SECS
                        ),
                        tx_id: None,
                    });
                }

                if cfg.block_interval_secs == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid fuzz TimeManager block_interval_secs=0".into(),
                        tx_id: None,
                    });
                }

                if cfg.failover_window_secs == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid fuzz TimeManager failover_window_secs=0".into(),
                        tx_id: None,
                    });
                }

                if cfg.proposal_deadline_secs == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid fuzz TimeManager proposal_deadline_secs=0".into(),
                        tx_id: None,
                    });
                }

                Ok(Self { cfg })
            }

            pub fn now_unix() -> u64 {
                UNIX_2000_SECS + 300
            }

            pub fn current_slot(&self, now: u64) -> u64 {
                now.saturating_sub(self.cfg.genesis_time_unix)
                    / self.cfg.block_interval_secs.max(1)
            }

            pub fn current_slot_checked(&self, now: u64) -> Result<u64, ErrorDetection> {
                if now < UNIX_2000_SECS {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "invalid fuzz timestamp: now={} < UNIX_2000_SECS={}",
                            now, UNIX_2000_SECS
                        ),
                        tx_id: None,
                    });
                }

                Ok(self.current_slot(now))
            }

            pub fn slot_start_unix(&self, slot: u64) -> u64 {
                self.cfg
                    .genesis_time_unix
                    .saturating_add(slot.saturating_mul(self.cfg.block_interval_secs.max(1)))
            }

            pub fn slot_start_unix_checked(&self, slot: u64) -> Result<u64, ErrorDetection> {
                let interval = self.cfg.block_interval_secs.max(1);
                let offset = slot.checked_mul(interval).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "slot_start_unix overflow in fuzz TimeManager: slot={} interval={}",
                            slot, interval
                        ),
                        tx_id: None,
                    }
                })?;

                self.cfg.genesis_time_unix.checked_add(offset).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "slot_start_unix overflow in fuzz TimeManager: genesis={} offset={}",
                            self.cfg.genesis_time_unix, offset
                        ),
                        tx_id: None,
                    }
                })
            }

            pub fn secs_into_slot_checked(
                &self,
                slot: u64,
                now: u64,
            ) -> Result<u64, ErrorDetection> {
                if now < UNIX_2000_SECS {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "invalid fuzz timestamp: now={} < UNIX_2000_SECS={}",
                            now, UNIX_2000_SECS
                        ),
                        tx_id: None,
                    });
                }

                let slot_start = self.slot_start_unix_checked(slot)?;
                Ok(now.saturating_sub(slot_start))
            }

            pub fn block_interval(&self) -> Duration {
                Duration::from_secs(self.cfg.block_interval_secs.max(1))
            }

            pub fn block_interval_secs(&self) -> u64 {
                self.cfg.block_interval_secs.max(1)
            }

            pub fn failover_window_secs(&self) -> u64 {
                self.cfg.failover_window_secs.max(1)
            }

            pub fn proposal_deadline_secs(&self) -> u64 {
                self.cfg.proposal_deadline_secs.max(1)
            }

            pub fn failover_max_rounds(&self) -> u64 {
                self.proposal_deadline_secs()
                    .div_euclid(self.failover_window_secs())
                    .max(1)
            }

            pub fn round_in_slot(&self, slot: u64, now: u64) -> u64 {
                let slot_start = self.slot_start_unix(slot);
                let elapsed = now.saturating_sub(slot_start);
                let raw_round = elapsed.div_euclid(self.failover_window_secs());
                raw_round.min(self.failover_max_rounds().saturating_sub(1))
            }
        }
    }

    pub mod por_006_committee_eligibility {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use std::collections::BTreeMap;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct CommitteeStatusUpdate {
            pub is_live: bool,
            pub has_synced: bool,
            pub local_tip: u64,
            pub network_tip: u64,
            pub peers_connected: usize,
            pub connected_wallet_peers: usize,
        }

        impl CommitteeStatusUpdate {
            pub fn validate_invariants(&self) -> Result<(), ErrorDetection> {
                if self.connected_wallet_peers > self.peers_connected {
                    return Err(ErrorDetection::ValidationError {
                        message: "connected_wallet_peers > peers_connected".into(),
                        tx_id: None,
                    });
                }
                Ok(())
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct CommitteeEligibility {
            updates: BTreeMap<String, CommitteeStatusUpdate>,
        }

        impl CommitteeEligibility {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn update_local_status(
                &mut self,
                wallet: &str,
                update: CommitteeStatusUpdate,
            ) -> Result<(), ErrorDetection> {
                update.validate_invariants()?;
                let wallet = canon_wallet_id_checked(wallet)?;
                self.updates.insert(wallet, update);
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// network
// ─────────────────────────────────────────────────────────────────────────────

mod network {
    pub mod p2p_006_reqresp {
        pub type Hash = [u8; 64];
    }

    pub mod p2p_003_behaviour {
        use crate::PeerId;

        #[derive(Debug, Clone)]
        pub struct Gossipsub {
            peers: Vec<PeerId>,
        }

        impl Gossipsub {
            pub fn new(peers: Vec<PeerId>) -> Self {
                Self { peers }
            }

            pub fn all_peers(&self) -> impl Iterator<Item = &PeerId> {
                self.peers.iter()
            }
        }

        #[derive(Debug, Clone, Default)]
        pub struct Kademlia {
            calls: usize,
        }

        impl Kademlia {
            pub fn get_closest_peers(&mut self, _peer: PeerId) -> Result<(), ()> {
                self.calls = self.calls.saturating_add(1);
                Ok(())
            }
        }

        #[derive(Debug, Clone)]
        pub struct RemzarBehaviour {
            pub gossipsub: Gossipsub,
            pub kademlia: Kademlia,
        }

        impl RemzarBehaviour {
            pub fn new_for_fuzz(subscribers: Vec<PeerId>) -> Self {
                Self {
                    gossipsub: Gossipsub::new(subscribers),
                    kademlia: Kademlia::default(),
                }
            }
        }

        #[derive(Debug, Clone)]
        pub enum OutEvent {
            Gossip(Box<crate::gossipsub::Event>),
            Ignored,
        }
    }

    pub mod p2p_008_broadcast {
        use crate::blockchain::block_002_blocks::Block;
        use crate::blockchain::transaction_001_tx::Transaction;
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
        use crate::network::p2p_003_behaviour::RemzarBehaviour;
        use crate::network::p2p_010_netcmd::{ChatMessage, FileChunk};
        use crate::network::p2p_013_peer_mesh::PeerMeshAnnounce;
        use crate::swarm::Swarm;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub struct Broadcaster<'a> {
            _swarm: &'a mut Swarm<RemzarBehaviour>,
        }

        impl<'a> Broadcaster<'a> {
            pub fn new(swarm: &'a mut Swarm<RemzarBehaviour>) -> Self {
                Self { _swarm: swarm }
            }

            pub fn join_all_topics(&mut self) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn send_transaction(&mut self, _tx: &Transaction) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_tx_kind(&mut self, _tx: &TxKind) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_block(&mut self, _block: &Block) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_register_node(&mut self, _tx: &RegisterNodeTx) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_peer_mesh_announce(&mut self, _ann: &PeerMeshAnnounce) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_por_puzzle_proof(&mut self, _proof: &PorPuzzleProof) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_chat(&mut self, _chat: &ChatMessage) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn send_file_chunk(&mut self, _chunk: &FileChunk) -> Result<(), ErrorDetection> { Ok(()) }
        }

        pub const REGISTER_TOPIC_STR: &str = "remzar/register";
    }

    pub mod p2p_010_netcmd {
        use crate::blockchain::block_002_blocks::Block;
        use crate::blockchain::transaction_001_tx::Transaction;
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;

        #[derive(Debug, Clone)]
        pub struct ChatMessage {
            pub from_wallet: String,
            pub to_wallet: String,
            pub body: Vec<u8>,
        }

        #[derive(Debug, Clone)]
        pub struct FileChunk {
            pub file_id: Vec<u8>,
            pub chunk_index: u64,
            pub bytes: Vec<u8>,
        }

        #[derive(Debug, Clone)]
        pub enum NetCmd {
            SendTx(Transaction),
            SendTxKind(TxKind),
            SendBlock(Block),
            SendRegister(RegisterNodeTx),
            SendAosPuzzleProof(PorPuzzleProof),
            SendChat(ChatMessage),
            SendFileChunk(FileChunk),
            SendPeerMeshAnnounce(crate::network::p2p_013_peer_mesh::PeerMeshAnnounce),
        }
    }

    pub mod p2p_013_peer_mesh {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::{Multiaddr, PeerId};

        #[derive(Debug, Clone)]
        pub struct PeerMeshAnnounce {
            pub peer_id: PeerId,
            pub listen_addrs: Vec<Multiaddr>,
            pub wallet: Option<String>,
            pub timestamp_unix: u64,
        }

        impl PeerMeshAnnounce {
            pub fn from_local(
                peer_id: PeerId,
                listen_addrs: &[Multiaddr],
                wallet: Option<&str>,
                timestamp_unix: u64,
            ) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    peer_id,
                    listen_addrs: listen_addrs.to_vec(),
                    wallet: wallet.map(str::to_string),
                    timestamp_unix,
                })
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// storage / reorg
// ─────────────────────────────────────────────────────────────────────────────

mod storage {
    pub mod rocksdb_006_manager_ext {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ForkBlockStatus {
            Validated,
        }

        #[derive(Debug, Clone)]
        pub struct ForkBlockMeta {
            pub parent_hash: [u8; 64],
            pub height: u64,
            pub cumulative_score: u128,
            pub status: ForkBlockStatus,
            pub received_at_unix_secs: u64,
        }
    }

    pub mod rocksdb_005_manager {
        use crate::blockchain::block_002_blocks::Block;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::{
            collections::BTreeMap,
            sync::{Arc, Mutex},
        };

        #[derive(Debug, Clone)]
        pub struct RockDBManager {
            inner: Arc<Mutex<MockDb>>,
        }

        #[derive(Debug, Clone, Default)]
        struct MockDb {
            tip_height: u64,
            blocks_by_index: BTreeMap<u64, Block>,
            blocks_by_hash: BTreeMap<[u8; 64], Block>,
            kv: BTreeMap<(String, Vec<u8>), Vec<u8>>,
        }

        impl RockDBManager {
            pub fn new_for_fuzz(tip_height: u64, parent_hash: [u8; 64], miner: String) -> Self {
                let block = Block::new_stub(tip_height, parent_hash, miner);
                let mut blocks_by_index = BTreeMap::new();
                let mut blocks_by_hash = BTreeMap::new();
                blocks_by_index.insert(tip_height, block.clone());
                blocks_by_hash.insert(block.block_hash, block);

                Self {
                    inner: Arc::new(Mutex::new(MockDb {
                        tip_height,
                        blocks_by_index,
                        blocks_by_hash,
                        kv: BTreeMap::new(),
                    })),
                }
            }

            pub fn get_tip_height(&self) -> Result<u64, ErrorDetection> {
                self.inner.lock().map(|db| db.tip_height).map_err(|_| ErrorDetection::StorageError {
                    message: "db poisoned".into(),
                })
            }

            pub fn set_tip_height(&self, height: u64) -> Result<(), ErrorDetection> {
                self.inner.lock().map(|mut db| db.tip_height = height).map_err(|_| ErrorDetection::StorageError {
                    message: "db poisoned".into(),
                })
            }

            pub fn set_latest_block_index(&self, height: u64) -> Result<(), ErrorDetection> {
                self.set_tip_height(height)
            }

            pub fn get_latest_block_hash(&self) -> Result<[u8; 64], ErrorDetection> {
                self.inner
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
                    .and_then(|db| {
                        db.blocks_by_index
                            .get(&db.tip_height)
                            .or_else(|| db.blocks_by_index.iter().next_back().map(|(_, block)| block))
                            .map(|block| block.block_hash)
                            .ok_or_else(|| ErrorDetection::NotFound {
                                resource: "latest block".into(),
                            })
                    })
            }

            pub fn set_addr_index_height(&self, _height: u64) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn get_block_by_index(&self, index: u64) -> Result<Option<Block>, ErrorDetection> {
                self.inner
                    .lock()
                    .map(|db| db.blocks_by_index.get(&index).cloned())
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
            }

            pub fn get_block_by_hash(&self, hash: &[u8; 64]) -> Option<Block> {
                self.inner.lock().ok()?.blocks_by_hash.get(hash).cloned()
            }

            pub fn index_block_by_hash(&self, hash: &[u8; 64], bytes: &[u8]) -> Result<(), ErrorDetection> {
                let block = postcard::from_bytes::<Block>(bytes)
                    .unwrap_or_else(|_| Block::new_stub(0, *hash, crate::canonical_wallet(&[], 1)));
                self.inner
                    .lock()
                    .map(|mut db| {
                        db.blocks_by_hash.insert(*hash, block);
                    })
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
            }

            pub fn read(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, ErrorDetection> {
                self.inner
                    .lock()
                    .map(|db| db.kv.get(&(cf.to_string(), key.to_vec())).cloned())
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
            }

            pub fn write(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<(), ErrorDetection> {
                self.inner
                    .lock()
                    .map(|mut db| {
                        db.kv.insert((cf.to_string(), key.to_vec()), value.to_vec());
                    })
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
            }

            pub fn delete(&self, cf: &str, key: &[u8]) -> Result<(), ErrorDetection> {
                self.inner
                    .lock()
                    .map(|mut db| {
                        db.kv.remove(&(cf.to_string(), key.to_vec()));
                    })
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "db poisoned".into(),
                    })
            }

            pub fn delete_canonical_hash_range(&self, _start: u64, _end: u64) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn flush_blockchain_db(&self) -> Result<(), ErrorDetection> {
                Ok(())
            }
        }
    }
}

mod reorganization {
    pub mod reorg_005_fork_choice {
        #[derive(Debug, Clone)]
        pub struct ReorgPlan {
            pub old_tip_height: u64,
            pub new_tip_height: u64,
            pub common_ancestor_height: u64,
            pub old_tip_hash: [u8; 64],
            pub new_tip_hash: [u8; 64],
            pub common_ancestor_hash: [u8; 64],
            detach: Vec<u64>,
            attach: Vec<u64>,
        }

        impl ReorgPlan {
            pub fn detach_heights(&self) -> &[u64] { &self.detach }
            pub fn attach_heights(&self) -> &[u64] { &self.attach }
        }

        #[derive(Debug, Clone)]
        pub enum ForkAction {
            Stay,
            Reorg(ReorgPlan),
            NeedMoreData { missing_hash: [u8; 64], context: String },
        }
    }

    pub mod reorg_001_block_index {
        use crate::blockchain::block_002_blocks::Block;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::storage::rocksdb_006_manager_ext::ForkBlockMeta;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct ReorgBlockIndex {
            _db: Arc<RockDBManager>,
        }

        impl ReorgBlockIndex {
            pub fn new(db: Arc<RockDBManager>) -> Self { Self { _db: db } }
            pub fn get_meta(&self, _hash: &[u8; 64]) -> Result<Option<ForkBlockMeta>, ErrorDetection> { Ok(None) }
            pub fn ingest_validated_block(&self, _b: &Block, _m: ForkBlockMeta, _bb: Option<&[u8]>) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn has_meta(&self, _hash: &[u8; 64]) -> Result<bool, ErrorDetection> { Ok(false) }
            pub fn mark_canonical(&self, _hash: &[u8; 64]) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn mark_side_branch(&self, _hash: &[u8; 64]) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod reorg_002_chain_view {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct ReorgChainView { _db: Arc<RockDBManager> }

        impl ReorgChainView {
            pub fn new(db: Arc<RockDBManager>) -> Self { Self { _db: db } }
            pub fn set_hash_at_height(&self, _height: u64, _hash: &[u8; 64]) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn set_tip(&self, _hash: &[u8; 64], _height: u64) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod reorg_004_batch_index {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct ReorgBatchIndex { _db: Arc<RockDBManager> }

        impl ReorgBatchIndex {
            pub fn new(db: Arc<RockDBManager>) -> Self { Self { _db: db } }
            pub fn set_canonical_batch_at_height(&self, _height: u64, _bytes: &[u8]) -> Result<(), ErrorDetection> { Ok(()) }
        }
    }

    pub mod reorg_006_manager {
        use crate::blockchain::block_002_blocks::Block;
        use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::reorganization::reorg_005_fork_choice::ForkAction;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct ReorgManager {
            _db: Arc<RockDBManager>,
        }

        impl ReorgManager {
            pub fn mainnet_default(db: Arc<RockDBManager>) -> Self {
                Self { _db: db }
            }

            pub fn handle_new_block(
                &self,
                _block: &Block,
                _chain: &mut AccountModelTree,
                _miner: Option<&mut BlockchainBuilder>,
            ) -> Result<ForkAction, ErrorDetection> {
                Ok(ForkAction::Stay)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// runtime
// ─────────────────────────────────────────────────────────────────────────────

mod runtime {
    pub mod p2p_001_sync_builders {
        use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
        use crate::network::p2p_003_behaviour::{OutEvent, RemzarBehaviour};
        use crate::swarm::{Swarm, SwarmEvent};

        pub const REGISTRATION_TOPIC: &str = "remzar/register";

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

            pub fn has_synced(&self) -> bool { self.has_synced }
            pub fn is_syncing(&self) -> bool { self.is_syncing }
            pub fn has_background_sync_work(&self) -> bool { self.has_background_sync_work }
            pub fn last_synced_index(&self) -> Option<u64> { self.last_synced_index }
            pub fn poll_peers_for_height(&mut self, _swarm: &mut Swarm<RemzarBehaviour>) {}
            pub fn on_local_tip_advanced(&mut self) { self.has_synced = true; }

            pub fn on_swarm_event(
                &mut self,
                _event: SwarmEvent<OutEvent>,
                _swarm: &mut Swarm<RemzarBehaviour>,
                _miner: Option<&mut BlockchainBuilder>,
            ) {}
        }
    }

    pub mod p2p_005_sync_gossipsub {
        use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
        use crate::blockchain::mempool::MemPool;
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::consensus::por_000_ephemeral_registration::RegistryData;
        use crate::gossipsub::Event;
        use crate::network::p2p_003_behaviour::RemzarBehaviour;
        use crate::runtime::p2p_001_sync_builders::P2pSync;
        use crate::runtime::p2p_006_sync_runtime::NodeOpts;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::swarm::Swarm;
        use crate::PeerId;
        use std::sync::Arc;

        #[allow(clippy::too_many_arguments)]
        pub fn handle_gossipsub(
            _event: Event,
            _src: PeerId,
            _swarm: &mut Swarm<RemzarBehaviour>,
            _chain: &mut AccountModelTree,
            _db1: &Arc<RockDBManager>,
            _db2: &Arc<RockDBManager>,
            _mempool: &Arc<MemPool>,
            _reg: &mut RegistryData,
            _sync: &mut P2pSync,
            _miner: Option<&mut BlockchainBuilder>,
            _local_wallet: &str,
            _opts: &NodeOpts,
        ) {
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
// blockchain
// ─────────────────────────────────────────────────────────────────────────────

mod blockchain {
    pub mod transaction_001_tx {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct Transaction {
            pub id: Vec<u8>,
        }
    }

    pub mod transaction_002_tx_register {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct RegisterNodeTx {
            wallet: String,
            pub timestamp: u64,
        }

        impl RegisterNodeTx {
            pub fn new(wallet: String) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    wallet: canon_wallet_id_checked(&wallet)?,
                    timestamp: 946_684_800,
                })
            }

            pub fn validate(&self) -> Result<(), ErrorDetection> {
                canon_wallet_id_checked(&self.wallet)?;
                Ok(())
            }

            pub fn wallet_str(&self) -> &str {
                &self.wallet
            }
        }
    }

    pub mod transaction_004_tx_kind {
        use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum TxKind {
            RegisterNode(RegisterNodeTx),
            Transfer { id: Vec<u8>, amount: u64 },
            NftMint(Vec<u8>),
            NftTransfer(Vec<u8>),
        }

        impl TxKind {
            pub fn validate(&self) -> Result<(), ErrorDetection> {
                match self {
                    Self::RegisterNode(tx) => tx.validate(),
                    Self::Transfer { amount, .. } if *amount == 0 => {
                        Err(ErrorDetection::ValidationError {
                            message: "zero transfer".into(),
                            tx_id: None,
                        })
                    }
                    _ => Ok(()),
                }
            }

            pub fn tag(&self) -> &'static str {
                match self {
                    Self::RegisterNode(_) => "RegisterNode",
                    Self::Transfer { .. } => "Transfer",
                    Self::NftMint(_) => "NftMint",
                    Self::NftTransfer(_) => "NftTransfer",
                }
            }
        }
    }

    pub mod block_003_puzzleproof {
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct BlockPuzzleProof {
            pub height: u64,
            pub validator: String,
            #[serde(with = "serde_big_array::BigArray")]
            pub prev_block_hash: [u8; 64],
            pub output: u128,
        }

        impl BlockPuzzleProof {
            pub fn from_gossip(proof: &PorPuzzleProof) -> Result<Self, ErrorDetection> {
                let out = Self {
                    height: proof.height,
                    validator: canon_wallet_id_checked(&proof.validator)?,
                    prev_block_hash: proof.prev_block_hash,
                    output: proof.output,
                };
                out.validate_structural()?;
                Ok(out)
            }

            pub fn validate_structural(&self) -> Result<(), ErrorDetection> {
                canon_wallet_id_checked(&self.validator)?;
                if self.height == 0 || self.output == 0 || self.prev_block_hash == [0u8; 64] {
                    return Err(ErrorDetection::ValidationError {
                        message: "invalid proof".into(),
                        tx_id: None,
                    });
                }
                Ok(())
            }
        }
    }

    pub mod block_001_metadata {
        use crate::blockchain::block_003_puzzleproof::BlockPuzzleProof;
        use fips204::ml_dsa_65;
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
            pub puzzle_proof: Option<BlockPuzzleProof>,
            pub size: u64,
        }

        impl BlockMetadata {
            pub fn new_for_fuzz(index: u64, previous_hash: [u8; 64]) -> Self {
                let mut merkle_root = [0x22u8; 64];
                merkle_root[..8].copy_from_slice(&index.to_be_bytes());

                Self {
                    index,
                    timestamp: 946_684_800 + index.saturating_mul(30),
                    previous_hash,
                    merkle_root,
                    guardian_signature: vec![0u8; ml_dsa_65::SIG_LEN],
                    puzzle_proof: None,
                    size: 1024,
                }
            }

            pub fn set_puzzle_proof(&mut self, proof: Option<BlockPuzzleProof>) {
                self.puzzle_proof = proof;
            }
        }
    }

    pub mod block_002_blocks {
        use crate::blockchain::block_001_metadata::BlockMetadata;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use crate::utility::helper::canon_wallet_id_checked;
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
            pub fn new_stub(index: u64, previous_hash: [u8; 64], miner: String) -> Self {
                let mut block_hash = previous_hash;
                block_hash[0] ^= index as u8;
                block_hash[1] ^= (index >> 8) as u8;

                Self {
                    metadata: BlockMetadata::new_for_fuzz(index, previous_hash),
                    batch_key: None,
                    miner,
                    block_hash,
                    reward: if index == 0 { 0 } else { 1 },
                }
            }

            pub fn new(
                metadata: BlockMetadata,
                batch_key: Option<String>,
                miner: String,
                reward: u64,
            ) -> Result<Self, ErrorDetection> {
                let miner = canon_wallet_id_checked(&miner)?;
                let mut block_hash = metadata.previous_hash;
                block_hash[..8].copy_from_slice(&metadata.index.to_be_bytes());
                Ok(Self {
                    metadata,
                    batch_key,
                    miner,
                    block_hash,
                    reward,
                })
            }

            pub fn serialize_for_storage(&self) -> Result<Vec<u8>, ErrorDetection> {
                postcard::to_allocvec(self).map_err(|e| ErrorDetection::SerializationError {
                    details: e.to_string(),
                })
            }

            pub fn miner_wallet(&self) -> &str {
                &self.miner
            }
        }
    }

    pub mod transaction_005_tx_batch {
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct TransactionBatch {
            pub index: u64,
            pub timestamp: u64,
            pub transactions: Vec<TxKind>,
        }

        impl TransactionBatch {
            pub fn deserialize(data: &[u8]) -> Result<Self, ErrorDetection> {
                if data.is_empty() {
                    return Err(ErrorDetection::SerializationError {
                        details: "empty".into(),
                    });
                }
                Ok(Self {
                    index: data[0] as u64,
                    timestamp: 946_684_800,
                    transactions: Vec::new(),
                })
            }

            pub fn serialize(&self) -> Result<Vec<u8>, ErrorDetection> {
                Ok(vec![self.index as u8])
            }
        }
    }

    pub mod mempool {
        use crate::blockchain::transaction_004_tx_kind::TxKind;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Mutex;

        #[derive(Debug, Default)]
        pub struct MemPool {
            staged: Mutex<Vec<TxKind>>,
        }

        impl MemPool {
            pub fn new_for_fuzz() -> Self {
                Self::default()
            }

            pub fn add_tx_kind(&self, kind: &TxKind) -> Result<(), ErrorDetection> {
                kind.validate()?;
                self.staged
                    .lock()
                    .map_err(|_| ErrorDetection::StorageError {
                        message: "mempool poisoned".into(),
                    })?
                    .push(kind.clone());
                Ok(())
            }
        }
    }

    pub mod transaction_005_tx_account_tree {
        use crate::blockchain::block_002_blocks::Block;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        #[derive(Debug, Clone)]
        pub struct AccountModelTree {
            blocks: Vec<Block>,
        }

        impl AccountModelTree {
            pub fn new_for_fuzz(genesis: Block) -> Self {
                Self { blocks: vec![genesis] }
            }

            pub fn latest_block_height(&self) -> usize {
                self.blocks.last().map(|b| b.metadata.index as usize).unwrap_or(0)
            }

            pub fn get_block_by_index(&self, index: usize) -> Result<Block, ErrorDetection> {
                self.blocks
                    .iter()
                    .find(|b| b.metadata.index as usize == index)
                    .cloned()
                    .ok_or_else(|| ErrorDetection::NotFound {
                        resource: format!("block_{index}"),
                    })
            }

            pub fn add_block(&mut self, block: Block) -> Result<(), ErrorDetection> {
                self.blocks.push(block);
                Ok(())
            }

            pub fn apply_batch(
                &mut self,
                _batch: &crate::blockchain::transaction_005_tx_batch::TransactionBatch,
            ) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn commit(&mut self) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn flush_balances(&self) -> Result<(), ErrorDetection> {
                Ok(())
            }

            pub fn reload_from_db(&mut self) {}

            pub fn reload_from_db_to_height(&mut self, height: u64) -> Result<(), ErrorDetection> {
                self.blocks.retain(|b| b.metadata.index <= height);
                Ok(())
            }
        }

        pub struct ChainLogic;

        impl ChainLogic {
            pub fn rollback_to(chain: &mut AccountModelTree, hash: [u8; 64]) -> Result<(), ErrorDetection> {
                if let Some(pos) = chain.blocks.iter().position(|b| b.block_hash == hash) {
                    chain.blocks.truncate(pos + 1);
                }
                Ok(())
            }
        }
    }

    pub mod blockchain_001_builder {
        use crate::blockchain::block_002_blocks::Block;
        use crate::blockchain::mempool::MemPool;
        use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
        use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
        use crate::consensus::por_000_ephemeral_registration::RegistryData;
        use crate::consensus::por_004_puzzle_proof::PorPuzzleProof;
        use crate::consensus::por_005_time_management::TimeManager;
        use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use fips204::ml_dsa_65;
        use std::sync::Arc;

        #[derive(Debug, Clone)]
        pub struct ValidatorState;

        impl ValidatorState {
            pub fn rebuild_from_chain(&mut self, _chain: Option<&AccountModelTree>) -> Result<(), ErrorDetection> { Ok(()) }
            pub fn multi_validator_ever_seen(&mut self) -> Result<bool, ErrorDetection> { Ok(false) }
            pub fn apply_block(&mut self, _block: &Block, _batch: &TransactionBatch) -> Result<(), ErrorDetection> { Ok(()) }
        }

        #[derive(Debug, Clone)]
        pub struct ConsensusFacade {
            eligibility: CommitteeEligibility,
            pending: Option<PorPuzzleProof>,
            runtime_tip: Option<(u64, [u8; 64])>,
            rebuilt_at_tip: Option<u64>,
        }

        impl ConsensusFacade {
            pub fn new() -> Self {
                Self {
                    eligibility: CommitteeEligibility::new(),
                    pending: None,
                    runtime_tip: None,
                    rebuilt_at_tip: None,
                }
            }

            pub fn committee_eligibility_mut(&mut self) -> &mut CommitteeEligibility { &mut self.eligibility }

            pub fn clear_runtime_canonical_tip_context(&mut self) {
                self.runtime_tip = None;
            }

            pub fn reset_runtime_proposal_safety_state(&mut self, h: u64, hash: [u8; 64]) {
                self.runtime_tip = Some((h, hash));
                self.rebuilt_at_tip = Some(h);
            }

            pub fn note_validator_state_rebuilt_to_tip(&mut self, h: u64) {
                self.rebuilt_at_tip = Some(h);
            }

            pub fn set_runtime_canonical_tip_context(&mut self, h: u64, hash: [u8; 64]) {
                self.runtime_tip = Some((h, hash));
            }

            pub fn local_wallet_can_attempt_mint_at(
                &self,
                height: u64,
                prev_hash: [u8; 64],
            ) -> Result<(), ErrorDetection> {
                if height == 0 {
                    return Err(ErrorDetection::ValidationError {
                        message: "fuzz mint preflight denied: height 0".into(),
                        tx_id: None,
                    });
                }

                let required_tip = height.saturating_sub(1);

                match self.runtime_tip {
                    Some((tip_height, tip_hash)) if tip_height == required_tip && tip_hash == prev_hash => {}
                    Some((tip_height, _)) => {
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "fuzz mint preflight denied: tip mismatch required={} observed={}",
                                required_tip, tip_height
                            ),
                            tx_id: None,
                        });
                    }
                    None => {
                        return Err(ErrorDetection::ValidationError {
                            message: "fuzz mint preflight denied: missing runtime tip context".into(),
                            tx_id: None,
                        });
                    }
                }

                match self.rebuilt_at_tip {
                    Some(rebuilt) if rebuilt == required_tip => Ok(()),
                    Some(rebuilt) => Err(ErrorDetection::ValidationError {
                        message: format!(
                            "fuzz mint preflight denied: validator state rebuilt at {}, required {}",
                            rebuilt, required_tip
                        ),
                        tx_id: None,
                    }),
                    None => Err(ErrorDetection::ValidationError {
                        message: "fuzz mint preflight denied: missing validator rebuild marker".into(),
                        tx_id: None,
                    }),
                }
            }

            pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> { self.pending.take() }
            pub fn set_pending_puzzle_proof(&mut self, proof: Option<PorPuzzleProof>) { self.pending = proof; }
        }

        #[derive(Debug, Clone)]
        pub struct BlockchainBuilder {
            db: Arc<RockDBManager>,
            local_wallet: String,
            validator_state: ValidatorState,
            consensus: ConsensusFacade,
            can_create_block: bool,
        }

        impl BlockchainBuilder {
            pub fn new(
                db: Arc<RockDBManager>,
                _mempool: Arc<MemPool>,
                local_wallet: String,
                _tm: Arc<TimeManager>,
                _signing_key: Arc<ml_dsa_65::PrivateKey>,
            ) -> Result<Self, ErrorDetection> {
                Ok(Self {
                    db,
                    local_wallet,
                    validator_state: ValidatorState,
                    consensus: ConsensusFacade::new(),
                    can_create_block: true,
                })
            }

            pub fn consensus(&self) -> &ConsensusFacade { &self.consensus }
            pub fn consensus_mut(&mut self) -> &mut ConsensusFacade { &mut self.consensus }
            pub fn validator_state_mut(&mut self) -> &mut ValidatorState { &mut self.validator_state }
            pub fn set_registry(&mut self, _reg: RegistryData) {}
            pub fn heartbeat(&mut self) {}
            pub fn take_pending_puzzle_proof(&mut self) -> Option<PorPuzzleProof> {
                self.consensus.take_pending_puzzle_proof()
            }

            pub fn create_new_block(&mut self, is_synced: bool) -> Result<Block, ErrorDetection> {
                if !is_synced || !self.can_create_block {
                    return Err(ErrorDetection::ValidationError {
                        message: "not ready".into(),
                        tx_id: None,
                    });
                }

                let tip = self.db.get_tip_height()?;
                let parent = self
                    .db
                    .get_block_by_index(tip)?
                    .map(|b| b.block_hash)
                    .unwrap_or([1u8; 64]);
                let next = tip.saturating_add(1);

                self.consensus.set_pending_puzzle_proof(Some(PorPuzzleProof {
                    height: next,
                    validator: self.local_wallet.clone(),
                    prev_block_hash: parent,
                    output: 123,
                }));

                Ok(Block::new_stub(next, parent, self.local_wallet.clone()))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// token stubs
// ─────────────────────────────────────────────────────────────────────────────

mod tokens {
    pub mod nft_001 {
        use crate::storage::rocksdb_005_manager::RockDBManager;
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;
        use std::sync::Arc;

        pub fn apply_nft_mint(
            _db: &Arc<RockDBManager>,
            _tx: &Vec<u8>,
            _signer_wallet: &str,
            _height: u64,
            _timestamp: u64,
        ) -> Result<(), ErrorDetection> {
            Ok(())
        }

        pub fn apply_nft_transfer(
            _db: &Arc<RockDBManager>,
            _tx: &Vec<u8>,
            _signer_wallet: &str,
            _height: u64,
            _timestamp: u64,
        ) -> Result<(), ErrorDetection> {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// display expected by real 003 via `super::blockchain_002_orchestration_display`
// ─────────────────────────────────────────────────────────────────────────────

mod blockchain_002_orchestration_display {
    use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
    use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
    use crate::storage::rocksdb_005_manager::RockDBManager;
    use std::sync::Arc;

    #[derive(Debug, Clone)]
    pub struct OrchestrationDisplay {
        pub log_sequence: bool,
        _db: Arc<RockDBManager>,
        _console_bus: ConsoleBus,
    }

    impl OrchestrationDisplay {
        pub fn new(db: Arc<RockDBManager>, console_bus: ConsoleBus) -> Self {
            Self {
                log_sequence: false,
                _db: db,
                _console_bus: console_bus,
            }
        }

        pub fn print_new_blocks_since(
            &self,
            _chain: &AccountModelTree,
            last_logged_tip: &mut u64,
            last_minted_height: &mut Option<u64>,
        ) {
            if let Some(h) = *last_minted_height {
                *last_logged_tip = (*last_logged_tip).max(h);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// REAL FILES UNDER TEST
// ─────────────────────────────────────────────────────────────────────────────

#[path = "../../src/blockchain/blockchain_003_orchestration_engine.rs"]
mod blockchain_003_orchestration_engine;

#[path = "../../src/blockchain/blockchain_004_orchestration_run.rs"]
mod blockchain_004_orchestration_run;

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz helpers
// ─────────────────────────────────────────────────────────────────────────────

use blockchain::block_002_blocks::Block;
use blockchain::mempool::MemPool;
use blockchain::transaction_005_tx_account_tree::AccountModelTree;
use blockchain_004_orchestration_run::{OrchestrationLoop, OrchestrationLoopArgs};
use commandline::s_04_view_blockchain_console::ConsoleBus;
use consensus::por_000_ephemeral_registration::NodeEphemeral;
use consensus::por_005_time_management::{TimeConfig, TimeManager};
use network::p2p_003_behaviour::{OutEvent, RemzarBehaviour};
use network::p2p_010_netcmd::NetCmd;
use reorganization::reorg_006_manager::ReorgManager;
use runtime::p2p_001_sync_builders::P2pSync;
use runtime::p2p_006_sync_runtime::NodeOpts;
use storage::rocksdb_005_manager::RockDBManager;
use tokio::sync::{mpsc, oneshot};

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
            ^ byte_at(data, salt + i.wrapping_mul(7), 0xAA)
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

fn make_signing_key(data: &[u8]) -> fips204::ml_dsa_65::PrivateKey {
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = byte_at(data, 1000 + i, i as u8);
    }
    let (_pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&seed);
    sk
}

fn make_swarm(
    data: &[u8],
    local_wallet: &str,
    node: &NodeEphemeral,
) -> libp2p::swarm::Swarm<RemzarBehaviour> {
    let local_peer = PeerId::from_seed(byte_at(data, 10, 1));
    let connected_count = usize::from(byte_at(data, 11, 0) % 6);
    let subscriber_count = usize::from(byte_at(data, 12, 0) % 6);
    let listener_count = usize::from(byte_at(data, 13, 0) % 4);

    let mut connected = Vec::new();
    for i in 0..connected_count {
        let peer = PeerId::from_seed(byte_at(data, 20 + i, i as u8));
        if byte_at(data, 40 + i, 0) & 1 == 1 {
            let _ = node.register_peer_for_wallet(&peer.to_base58(), local_wallet);
        }
        connected.push(peer);
    }

    let subscribers = connected
        .iter()
        .copied()
        .take(subscriber_count)
        .collect::<Vec<_>>();

    let listeners = (0..listener_count)
        .map(|i| {
            Multiaddr::from_bytes(vec![
                byte_at(data, 60 + i, i as u8),
                byte_at(data, 70 + i, i as u8),
                byte_at(data, 80 + i, i as u8),
            ])
        })
        .collect::<Vec<_>>();

    let mut events = VecDeque::new();

    if byte_at(data, 90, 0) & 1 == 1 {
        events.push_back(libp2p::swarm::SwarmEvent::Behaviour(OutEvent::Ignored));
    }

    if byte_at(data, 91, 0) & 1 == 1 {
        events.push_back(libp2p::swarm::SwarmEvent::ConnectionClosed {
            peer_id: PeerId::from_seed(byte_at(data, 92, 9)),
            event: None,
        });
    }

    if byte_at(data, 93, 0) & 1 == 1 {
        events.push_back(libp2p::swarm::SwarmEvent::Behaviour(OutEvent::Gossip(Box::new(
            libp2p::gossipsub::Event::Message {
                propagation_source: PeerId::from_seed(byte_at(data, 94, 7)),
                message_id: libp2p::gossipsub::MessageId(vec![byte_at(data, 95, 0)]),
                message: libp2p::gossipsub::Message {
                    data: data.iter().take(64).copied().collect(),
                },
            },
        ))));
    }

    libp2p::swarm::Swarm::new_for_fuzz(
        local_peer,
        RemzarBehaviour::new_for_fuzz(subscribers),
        connected,
        listeners,
        events,
    )
}

fn make_net_cmd(data: &[u8], wallet: &str) -> Option<NetCmd> {
    match byte_at(data, 200, 0) % 4 {
        0 => None,
        1 => Some(NetCmd::SendTx(blockchain::transaction_001_tx::Transaction {
            id: data.iter().take(32).copied().collect(),
        })),
        2 => Some(NetCmd::SendTxKind(
            blockchain::transaction_004_tx_kind::TxKind::Transfer {
                id: data.iter().skip(3).take(16).copied().collect(),
                amount: (read_u64(data, 210) % 1_000_000).saturating_add(1),
            },
        )),
        _ => blockchain::transaction_002_tx_register::RegisterNodeTx::new(wallet.to_string())
            .ok()
            .map(NetCmd::SendRegister),
    }
}

fn exercise_run_loop(data: &[u8]) {
    let local_wallet = canonical_wallet(data, 300);
    let parent_hash = fuzz_hash(data, 400);
    let tip = read_u64(data, 500) % 8;

    let db = Arc::new(RockDBManager::new_for_fuzz(
        tip,
        parent_hash,
        local_wallet.clone(),
    ));

    let node = NodeEphemeral::new();
    let _ = node.register_wallet_strict(&local_wallet, tip);

    let mempool = Arc::new(MemPool::new_for_fuzz());
    let sync_engine = Arc::new(tokio::sync::Mutex::new(P2pSync::new_for_fuzz(
        byte_at(data, 600, 1) & 1 == 1,
        byte_at(data, 601, 0) & 1 == 1,
        byte_at(data, 602, 0) & 1 == 1,
        Some(read_u64(data, 603) % 16),
    )));

    let signing_key = Arc::new(make_signing_key(data));
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(946_684_800)));
    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));

    let loop_under_test = OrchestrationLoop::new(OrchestrationLoopArgs {
        db: Arc::clone(&db),
        node_ephemeral: node.clone(),
        mempool,
        sync_engine,
        signing_key,
        tm,
        reorg_manager,
        local_wallet: local_wallet.clone(),
        console_bus: ConsoleBus::new(),
    });

    let genesis = Block::new_stub(tip, parent_hash, local_wallet.clone());
    let mut chain = AccountModelTree::new_for_fuzz(genesis);
    let mut swarm = make_swarm(data, &local_wallet, &node);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (net_tx, net_rx) = mpsc::channel::<NetCmd>(4);

    if let Some(cmd) = make_net_cmd(data, &local_wallet) {
        let _ = net_tx.try_send(cmd);
    }

    let opts = NodeOpts {
        founder: byte_at(data, 700, 0) & 1 == 1,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    let Ok(rt) = rt else {
        return;
    };

    rt.block_on(async move {
        let _shutdown_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = shutdown_tx.send(());
        });

        let _ = loop_under_test
            .run_loop(&mut chain, &mut swarm, shutdown_rx, Some(net_rx), &opts)
            .await;
    });
}

fuzz_target!(|data: &[u8]| {
    exercise_run_loop(data);
});