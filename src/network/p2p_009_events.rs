// src/network/p2p_009_events.rs

use libp2p::{
    Multiaddr, PeerId,
    core::connection::ConnectedPoint,
    gossipsub::Event as GossipsubEvent,
    identify::{Event as IdentifyEvent, Info as IdentifyInfo},
    kad::Event as KademliaEvent,
    multiaddr::Protocol,
    ping::Event as PingEvent,
    request_response::Event as ReqRespEvent,
    swarm::{ConnectionError, ConnectionId, SwarmEvent},
};

use crate::network::{
    p2p_003_behaviour::OutEvent,
    p2p_006_reqresp::{BlockTxRequest, BlockTxResponse},
    p2p_007_handshake::{PqHandshakeRequest, PqHandshakeResponse, VersionInfo},
};

use std::collections::HashSet;

#[derive(Debug)]
pub enum P2pEvent {
    Ping(Box<PingEvent>),
    Gossip(Box<GossipsubEvent>),
    Kad(Box<KademliaEvent>),
    Identify(Box<IdentifyEvent>),
    BlockTx(Box<ReqRespEvent<BlockTxRequest, BlockTxResponse>>),
    Version(Box<ReqRespEvent<VersionInfo, VersionInfo>>),
    Pq(Box<ReqRespEvent<PqHandshakeRequest, PqHandshakeResponse>>),

    NewListenAddr(Multiaddr),
    ExpiredListenAddr(Multiaddr),
    IncomingConnection {
        connection_id: ConnectionId,
        local_addr: Multiaddr,
        send_back_addr: Multiaddr,
    },
    ConnectionEstablished {
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    },
    ConnectionClosed {
        peer_id: PeerId,
        cause: Option<ConnectionError>,
    },
    Dialing {
        peer_id: Option<PeerId>,
    },

    Other,
}

/* ─────────────────────────────────────────────────────────────
Defensive bounds (no crypto impact)
───────────────────────────────────────────────────────────── */

/// Hard cap: how many addrs we ingest per Identify event.
const MAX_IDENTIFY_ADDRS_PER_EVENT: usize = 64;

/// Hard cap: how many addrs we ingest per Kademlia event variant.
const MAX_KAD_ADDRS_PER_EVENT: usize = 64;

/// Hard cap: how large a serialized Multiaddr may be (bytes).
/// Helps avoid pathological / oversized addresses from untrusted peers.
const MAX_MULTIADDR_BYTES: usize = 256;

/* ─── OutEvent → P2pEvent ──────────────────────────────────────────── */
impl From<OutEvent> for P2pEvent {
    fn from(e: OutEvent) -> Self {
        match e {
            OutEvent::Ping(e) => Self::Ping(e),
            OutEvent::Gossip(e) => Self::Gossip(e),
            OutEvent::Kad(e) => Self::Kad(e),
            OutEvent::Identify(e) => Self::Identify(e),
            OutEvent::BlockTx(e) => Self::BlockTx(e),
            OutEvent::Version(e) => Self::Version(e),
            OutEvent::Pq(e) => Self::Pq(e),
        }
    }
}

/* ─── SwarmEvent → P2pEvent helper ─────────────────────────────────── */
pub fn map_swarm_event(ev: SwarmEvent<OutEvent>) -> P2pEvent {
    match ev {
        SwarmEvent::Behaviour(inner) => inner.into(),
        SwarmEvent::NewListenAddr { address, .. } => P2pEvent::NewListenAddr(address),
        SwarmEvent::ExpiredListenAddr { address, .. } => P2pEvent::ExpiredListenAddr(address),
        SwarmEvent::IncomingConnection {
            connection_id,
            local_addr,
            send_back_addr,
            ..
        } => P2pEvent::IncomingConnection {
            connection_id,
            local_addr,
            send_back_addr,
        },
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => P2pEvent::ConnectionEstablished { peer_id, endpoint },
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            P2pEvent::ConnectionClosed { peer_id, cause }
        }
        SwarmEvent::Dialing { peer_id, .. } => P2pEvent::Dialing { peer_id },
        _ => P2pEvent::Other,
    }
}

#[inline(always)]
fn is_multiaddr_reasonable(addr: &Multiaddr) -> bool {
    addr.to_vec().len() <= MAX_MULTIADDR_BYTES
}

/// Split a Multiaddr into (base_addr_without_p2p, trailing_peer_in_addr).
#[inline(always)]
pub fn split_multiaddr_base_and_peer(addr: &Multiaddr) -> (Multiaddr, Option<PeerId>) {
    let mut comps: Vec<_> = addr.iter().collect();
    if let Some(Protocol::P2p(pid)) = comps.last().cloned() {
        comps.pop();
        let base: Multiaddr = comps.into_iter().collect();
        (base, Some(pid))
    } else {
        (addr.clone(), None)
    }
}

/// Given a base addr and a PeerId, append `/p2p/<PeerId>`.
#[inline(always)]
pub fn attach_peer_to_addr(mut base: Multiaddr, pid: &PeerId) -> Multiaddr {
    base.push(Protocol::P2p(*pid));
    base
}

/// Multiaddr is in full dialable form for a specific peer:
#[inline(always)]
pub fn ensure_dialable_addr_for_peer(addr: &Multiaddr, pid: &PeerId) -> Option<Multiaddr> {
    if !is_multiaddr_reasonable(addr) {
        return None;
    }

    let (base, trailing_peer) = split_multiaddr_base_and_peer(addr);

    if !is_multiaddr_reasonable(&base) {
        return None;
    }

    base.iter().next()?;

    match trailing_peer {
        Some(existing) if existing != *pid => None,
        Some(_) | None => Some(attach_peer_to_addr(base, pid)),
    }
}

/// Produce Kad-ready addrs (strip `/p2p/<PeerId>` if present), de-duped.
/// Defensive: skips over-large multiaddrs.
#[inline(always)]
pub fn kad_ready_addrs(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut out = Vec::with_capacity(addrs.len());
    let mut seen = HashSet::<String>::new();

    for a in addrs.iter() {
        if !is_multiaddr_reasonable(a) {
            continue;
        }
        let (base, _) = split_multiaddr_base_and_peer(a);

        if !is_multiaddr_reasonable(&base) {
            continue;
        }

        if base.iter().next().is_none() {
            continue;
        }

        let k = base.to_string();
        if seen.insert(k) {
            out.push(base);
        }
    }

    out
}

/// Simple dedupe of Multiaddrs, keeping first occurrence.
/// Defensive: skips over-large multiaddrs.
#[inline(always)]
pub fn dedupe_addrs(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    let mut seen = HashSet::<String>::new();
    let mut out = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !is_multiaddr_reasonable(&a) {
            continue;
        }
        let k = a.to_string();
        if seen.insert(k) {
            out.push(a);
        }
    }
    out
}

/// Convert a batch of addrs into FULL dialable addresses for a given peer, then dedupe.
#[inline(always)]
fn dialable_addrs_for_peer(
    pid: &PeerId,
    addrs: impl IntoIterator<Item = Multiaddr>,
) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for addr in addrs {
        if let Some(full) = ensure_dialable_addr_for_peer(&addr, pid) {
            out.push(full);
        }
    }
    dedupe_addrs(out)
}

/* ─────────────────────────────────────────────────────────────────────
Convenience extractors for PeerBook ingestion
───────────────────────────────────────────────────────────────────── */

/// From Identify::Received, collect all listen addrs advertised by the remote.
pub fn extract_peer_addrs_from_identify(ev: &IdentifyEvent) -> Option<(PeerId, Vec<Multiaddr>)> {
    match ev {
        IdentifyEvent::Received { peer_id, info, .. } => {
            let IdentifyInfo { listen_addrs, .. } = info;
            if listen_addrs.is_empty() {
                return None;
            }

            let mut bounded =
                Vec::with_capacity(listen_addrs.len().min(MAX_IDENTIFY_ADDRS_PER_EVENT));
            for a in listen_addrs.iter().take(MAX_IDENTIFY_ADDRS_PER_EVENT) {
                if is_multiaddr_reasonable(a) {
                    bounded.push(a.clone());
                }
            }

            let dialable = dialable_addrs_for_peer(peer_id, bounded);
            if dialable.is_empty() {
                return None;
            }

            Some((*peer_id, dialable))
        }
        _ => None,
    }
}

/// From Kademlia events, pull any addresses that can be persisted.
pub fn extract_peer_addrs_from_kad(ev: &KademliaEvent) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let mut out: Vec<(PeerId, Vec<Multiaddr>)> = Vec::new();

    match ev {
        KademliaEvent::RoutingUpdated {
            peer, addresses, ..
        } => {
            let mut addrs: Vec<Multiaddr> = Vec::new();
            for a in addresses.iter().take(MAX_KAD_ADDRS_PER_EVENT) {
                if is_multiaddr_reasonable(a) {
                    addrs.push(a.clone());
                }
            }

            let dialable = dialable_addrs_for_peer(peer, addrs);
            if !dialable.is_empty() {
                out.push((*peer, dialable));
            }
        }

        KademliaEvent::RoutablePeer { peer, address }
        | KademliaEvent::PendingRoutablePeer { peer, address } => {
            let dialable = dialable_addrs_for_peer(peer, vec![address.clone()]);
            if !dialable.is_empty() {
                out.push((*peer, dialable));
            }
        }

        _ => {}
    }

    out
}
