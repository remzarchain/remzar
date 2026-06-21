// src/network/p2p_013_peer_mesh.rs

use anyhow::{Result, anyhow};
use libp2p::{Multiaddr, PeerId, Swarm};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    network::{
        p2p_003_behaviour::RemzarBehaviour,
        p2p_009_events::{attach_peer_to_addr, kad_ready_addrs, split_multiaddr_base_and_peer},
        p2p_011_peerbook::PeerBook,
    },
    utility::helper::canon_wallet_id_checked,
};

/// Dedicated gossipsub topic for runtime peer-mesh announcements.
pub const PEER_MESH_TOPIC_STR: &str = "/remzar/peer_mesh/1.0.0";

/// Hard cap for a serialized PeerMeshAnnounce on the wire.
pub const PEER_MESH_MAX_WIRE_BYTES: usize = 64 * 1024;

/// Max number of listen addrs carried in one announce.
const MAX_LISTEN_ADDRS: usize = 32;

/// Max serialized bytes for a single Multiaddr.
const MAX_MULTIADDR_BYTES: usize = 256;

/// Max wallet text bytes (defensive bound before canonicalization).
const MAX_WALLET_TEXT_BYTES: usize = 256;

/// Conservative max PeerId text size.
const MAX_PEER_ID_TEXT_BYTES: usize = 128;

/// Runtime peer announcement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerMeshAnnounce {
    /// Sender peer id as base58 text.
    pub peer_id: String,

    /// Listen addresses as text Multiaddrs.
    pub listen_addrs: Vec<String>,

    /// Optional canonical wallet id.
    pub wallet: Option<String>,

    /// Sender wall-clock timestamp (seconds since UNIX epoch).
    pub timestamp_unix: u64,
}

/// Output of a validated / normalized announcement.
#[derive(Debug, Clone)]
pub struct NormalizedPeerMesh {
    pub peer_id: PeerId,
    pub full_dial_addrs: Vec<Multiaddr>,
    pub kad_base_addrs: Vec<Multiaddr>,
    pub wallet: Option<String>,
    pub timestamp_unix: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum PeerMeshCodecError {
    #[error("wire payload too large: got {got} bytes (max {max})")]
    TooLarge { got: usize, max: usize },

    #[error("postcard encode failed: {0}")]
    Encode(postcard::Error),

    #[error("postcard decode failed: {0}")]
    Decode(#[from] postcard::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum PeerMeshValidationError {
    #[error("empty peer_id")]
    EmptyPeerId,

    #[error("peer_id too large: {0} bytes")]
    PeerIdTooLarge(usize),

    #[error("invalid peer_id: {0}")]
    InvalidPeerId(String),

    #[error("too many listen addrs: {got} (max {max})")]
    TooManyListenAddrs { got: usize, max: usize },

    #[error("invalid multiaddr text: {0}")]
    InvalidMultiaddr(String),

    #[error("multiaddr too large: {0} bytes")]
    MultiaddrTooLarge(usize),

    #[error("wallet too large: {0} bytes")]
    WalletTooLarge(usize),

    #[error("invalid wallet: {0}")]
    InvalidWallet(String),

    #[error("no usable listen addrs after normalization")]
    NoUsableListenAddrs,
}

pub type PeerMeshCodecResult<T> = std::result::Result<T, PeerMeshCodecError>;
pub type PeerMeshValidationResult<T> = std::result::Result<T, PeerMeshValidationError>;

impl PeerMeshAnnounce {
    /// Build a local announcement from native libp2p types.
    pub fn from_local(
        peer_id: PeerId,
        listen_addrs: &[Multiaddr],
        wallet: Option<&str>,
        timestamp_unix: u64,
    ) -> Result<Self> {
        let wallet = match wallet {
            Some(w) if !w.trim().is_empty() => {
                Some(canon_wallet_id_checked(w).map_err(|e| {
                    anyhow!("peer mesh local wallet canonicalization failed: {:?}", e)
                })?)
            }
            _ => None,
        };

        let mut uniq = BTreeSet::<String>::new();
        for a in listen_addrs.iter().take(MAX_LISTEN_ADDRS) {
            if a.to_vec().len() <= MAX_MULTIADDR_BYTES {
                uniq.insert(a.to_string());
            }
        }

        Ok(Self {
            peer_id: peer_id.to_base58(),
            listen_addrs: uniq.into_iter().collect(),
            wallet,
            timestamp_unix,
        })
    }

    /// Encode with a hard wire cap.
    pub fn encode_to_wire(&self) -> PeerMeshCodecResult<Vec<u8>> {
        let bytes = postcard::to_stdvec(self).map_err(PeerMeshCodecError::Encode)?;
        if bytes.len() > PEER_MESH_MAX_WIRE_BYTES {
            return Err(PeerMeshCodecError::TooLarge {
                got: bytes.len(),
                max: PEER_MESH_MAX_WIRE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decode with a hard wire cap.
    pub fn decode_from_wire(bytes: &[u8]) -> PeerMeshCodecResult<Self> {
        if bytes.len() > PEER_MESH_MAX_WIRE_BYTES {
            return Err(PeerMeshCodecError::TooLarge {
                got: bytes.len(),
                max: PEER_MESH_MAX_WIRE_BYTES,
            });
        }
        postcard::from_bytes(bytes).map_err(PeerMeshCodecError::Decode)
    }

    /// Validate and normalize into native libp2p-ready structures.
    pub fn normalize(&self) -> PeerMeshValidationResult<NormalizedPeerMesh> {
        if self.peer_id.trim().is_empty() {
            return Err(PeerMeshValidationError::EmptyPeerId);
        }
        if self.peer_id.len() > MAX_PEER_ID_TEXT_BYTES {
            return Err(PeerMeshValidationError::PeerIdTooLarge(self.peer_id.len()));
        }

        let peer_id = self
            .peer_id
            .parse::<PeerId>()
            .map_err(|e| PeerMeshValidationError::InvalidPeerId(e.to_string()))?;

        if self.listen_addrs.len() > MAX_LISTEN_ADDRS {
            return Err(PeerMeshValidationError::TooManyListenAddrs {
                got: self.listen_addrs.len(),
                max: MAX_LISTEN_ADDRS,
            });
        }

        let wallet = match &self.wallet {
            Some(w) => {
                if w.len() > MAX_WALLET_TEXT_BYTES {
                    return Err(PeerMeshValidationError::WalletTooLarge(w.len()));
                }
                Some(
                    canon_wallet_id_checked(w)
                        .map_err(|e| PeerMeshValidationError::InvalidWallet(format!("{:?}", e)))?,
                )
            }
            None => None,
        };

        let mut full = BTreeSet::<Multiaddr>::new();

        for raw in &self.listen_addrs {
            let parsed = raw
                .parse::<Multiaddr>()
                .map_err(|_| PeerMeshValidationError::InvalidMultiaddr(raw.clone()))?;

            let raw_len = parsed.to_vec().len();
            if raw_len > MAX_MULTIADDR_BYTES {
                return Err(PeerMeshValidationError::MultiaddrTooLarge(raw_len));
            }

            // Normalize any incoming addr to a FULL dialable form bound to the
            // announced peer id.
            let normalized_full = match split_multiaddr_base_and_peer(&parsed) {
                (base, Some(existing_pid)) if existing_pid == peer_id => {
                    attach_peer_to_addr(base, &peer_id)
                }
                (base, None) => attach_peer_to_addr(base, &peer_id),
                (base, Some(_different_pid)) => {
                    // Defensive: if sender shipped a mismatched trailing /p2p,
                    // discard that trailing component and rebind to the announced peer id.
                    attach_peer_to_addr(base, &peer_id)
                }
            };

            if normalized_full.to_vec().len() <= MAX_MULTIADDR_BYTES {
                full.insert(normalized_full);
            }
        }

        if full.is_empty() {
            return Err(PeerMeshValidationError::NoUsableListenAddrs);
        }

        let full_dial_addrs: Vec<Multiaddr> = full.into_iter().collect();
        let kad_base_addrs = kad_ready_addrs(&full_dial_addrs);

        Ok(NormalizedPeerMesh {
            peer_id,
            full_dial_addrs,
            kad_base_addrs,
            wallet,
            timestamp_unix: self.timestamp_unix,
        })
    }

    /// Convenience: true if the announcement is from `local_peer_id`.
    pub fn is_self_for(&self, local_peer_id: &PeerId) -> bool {
        self.peer_id == local_peer_id.to_base58() || self.peer_id == local_peer_id.to_string()
    }

    /// Helpful routing/metrics label.
    pub fn kind_str(&self) -> &'static str {
        "PeerMeshAnnounce"
    }
}

impl NormalizedPeerMesh {
    /// Apply to PeerBook + Kademlia.
    pub fn apply_to_discovery(
        &self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peerbook: &mut PeerBook,
        mark_success: bool,
    ) -> Result<()> {
        // PeerBook gets FULL dialable addrs.
        peerbook.upsert(&self.peer_id, self.full_dial_addrs.clone(), mark_success);

        // Kademlia gets BASE transport addrs only.
        for base in &self.kad_base_addrs {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&self.peer_id, base.clone());
        }

        Ok(())
    }

    /// Return a defensively cloned wallet, if any.
    pub fn wallet(&self) -> Option<&str> {
        self.wallet.as_deref()
    }

    /// Build an outbound announcement from already-normalized data.
    pub fn to_announce(&self) -> PeerMeshAnnounce {
        PeerMeshAnnounce {
            peer_id: self.peer_id.to_base58(),
            listen_addrs: self
                .full_dial_addrs
                .iter()
                .map(ToString::to_string)
                .collect(),
            wallet: self.wallet.clone(),
            timestamp_unix: self.timestamp_unix,
        }
    }
}

pub fn decode_and_normalize_peer_mesh(
    wire: &[u8],
    local_peer_id: &PeerId,
) -> Result<Option<NormalizedPeerMesh>> {
    let msg = PeerMeshAnnounce::decode_from_wire(wire)
        .map_err(|e| anyhow!("peer mesh decode failed: {e}"))?;

    if msg.is_self_for(local_peer_id) {
        return Ok(None);
    }

    let norm = msg
        .normalize()
        .map_err(|e| anyhow!("peer mesh normalize failed: {e}"))?;

    if norm.peer_id == *local_peer_id {
        return Ok(None);
    }

    Ok(Some(norm))
}

pub fn build_local_peer_mesh_wire(
    local_peer_id: PeerId,
    listen_addrs: &[Multiaddr],
    wallet: Option<&str>,
    timestamp_unix: u64,
) -> Result<Vec<u8>> {
    let msg = PeerMeshAnnounce::from_local(local_peer_id, listen_addrs, wallet, timestamp_unix)?;
    msg.encode_to_wire()
        .map_err(|e| anyhow!("peer mesh encode failed: {e}"))
}
