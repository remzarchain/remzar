// src/network/p2p_004_peerdiscovery.rs

use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use anyhow::Result;
use libp2p::{Multiaddr, kad::NoKnownPeers, multiaddr::Protocol};
use std::collections::HashMap;

/// Defensive cap: maximum number of multiaddrs we will process per call.
const MAX_PEERDISCOVERY_ADDRS_PER_CALL: usize = 256;

/// Defensive cap: maximum size of a Multiaddr when serialized (bytes).
const MAX_MULTIADDR_BYTES: usize = 256;

/// Split a multiaddr.
#[inline(always)]
fn split_multiaddr_base_and_peer(addr: &Multiaddr) -> (Multiaddr, Option<String>) {
    let mut comps: Vec<_> = addr.iter().collect();

    match comps.last().cloned() {
        Some(Protocol::P2p(peer_id)) => {
            comps.pop();
            let base: Multiaddr = comps.into_iter().collect();
            (base, Some(peer_id.to_string()))
        }
        _ => (addr.clone(), None),
    }
}

#[inline(always)]
fn is_multiaddr_reasonable(addr: &Multiaddr) -> bool {
    addr.to_vec().len() <= MAX_MULTIADDR_BYTES
}

/// Insert every `/p2p/<PeerId>` component found in `addrs` into the local DHT.
pub fn add_peerdiscovery_peers(
    behaviour: &mut RemzarBehaviour,
    addrs: &[Multiaddr],
    detection: &DetectionSystem,
) -> Result<(), ErrorDetection> {
    // Fail-fast on obviously invalid / abusive input sizes.
    if addrs.len() > MAX_PEERDISCOVERY_ADDRS_PER_CALL {
        return Err(ErrorDetection::DatabaseError {
            details: format!(
                "peer discovery addr list too large: {} (max {})",
                addrs.len(),
                MAX_PEERDISCOVERY_ADDRS_PER_CALL
            ),
        });
    }

    // Build a deterministic map.
    let mut peer_to_base_addr: HashMap<String, Multiaddr> = HashMap::new();

    for addr in addrs {
        if !is_multiaddr_reasonable(addr) {
            return Err(ErrorDetection::DatabaseError {
                details: format!(
                    "multiaddr too large: {} bytes (max {})",
                    addr.to_vec().len(),
                    MAX_MULTIADDR_BYTES
                ),
            });
        }

        let (base_addr, maybe_peer_id_str) = split_multiaddr_base_and_peer(addr);

        let Some(peer_id_str) = maybe_peer_id_str else {
            // Ignore non-/p2p addrs here; discovery seeding expects explicit peer identities.
            continue;
        };

        if !is_multiaddr_reasonable(&base_addr) {
            return Err(ErrorDetection::DatabaseError {
                details: format!(
                    "base multiaddr too large after stripping /p2p: {} bytes (max {})",
                    base_addr.to_vec().len(),
                    MAX_MULTIADDR_BYTES
                ),
            });
        }

        // Ignore pathological empty bases (defensive; usually impossible for valid dial addrs).
        if base_addr.iter().next().is_none() {
            continue;
        }

        // Keep only the first occurrence per peer id for deterministic behavior.
        peer_to_base_addr.entry(peer_id_str).or_insert(base_addr);
    }

    // Nothing usable to add.
    if peer_to_base_addr.is_empty() {
        return Ok(());
    }

    // Stable, deduped PeerId list for Sybil guard.
    let extracted: Vec<(String, u64)> = peer_to_base_addr
        .keys()
        .map(|peer_id_str| (peer_id_str.clone(), 1u64))
        .collect();

    detection.detect_sybil_attack(extracted.clone())?;

    // Safe to add to Kad using BASE addresses only.
    for (peer_id_str, _) in extracted {
        let peer_id = peer_id_str
            .parse()
            .map_err(|e| ErrorDetection::DatabaseError {
                details: format!("Failed to parse peer ID '{}': {e}", peer_id_str),
            })?;

        let base_addr = peer_to_base_addr
            .get(&peer_id_str)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!("No base address found for peer ID '{peer_id_str}'"),
            })?
            .clone();

        behaviour.kademlia.add_address(&peer_id, base_addr);
    }

    Ok(())
}

/// Kick-off a Kademlia bootstrap query, but ignore the “no peers yet” case.
pub fn kick_off_peerdiscovery(behaviour: &mut RemzarBehaviour) -> Result<()> {
    match behaviour.kademlia.bootstrap() {
        Ok(_) | Err(NoKnownPeers()) => Ok(()),
    }
}
