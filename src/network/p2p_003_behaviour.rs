use anyhow::{Result, anyhow};
use libp2p::{
    Multiaddr, PeerId,
    gossipsub::{
        Behaviour as Gossipsub, Config as GossipsubConfig, ConfigBuilder as GossipsubConfigBuilder,
        Event as GossipsubEvent, MessageAuthenticity, ValidationMode,
    },
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    identity::Keypair,
    kad::{
        Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent, NoKnownPeers,
        QueryId, store::MemoryStore,
    },
    ping::{Behaviour as Ping, Event as PingEvent},
    request_response::Event as RequestResponseEvent,
    swarm::NetworkBehaviour,
};
use std::{collections::HashSet, time::Duration};

/* Block / Tx request-response ---------------------------------------- */
use crate::network::p2p_006_reqresp::{
    BlockTxExchange, BlockTxRequest, BlockTxResponse, build_blocktx_exchange,
};

/* Version handshake request-response --------------------------------- */
use crate::network::p2p_007_handshake::{
    PqExchange, PqHandshakeRequest, PqHandshakeResponse, VersionExchange, VersionInfo,
    build_pq_exchange, build_version_exchange,
};

use crate::network::p2p_009_events::kad_ready_addrs;

/* ───────────── defensive limits (no crypto impact) ───────────── */

/// Hard cap for a single gossipsub payload (bytes).
const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 2 * 1024 * 1024;

/// Cap the number of messages that can be bundled into a single RPC.
const GOSSIPSUB_MAX_MESSAGES_PER_RPC: usize = 16;

/// Cap internal queueing in gossipsub connection handlers to reduce memory pressure under load.
const GOSSIPSUB_CONN_HANDLER_QUEUE_LEN: usize = 32;

/// Defensive bound on how many identify-learned listen addrs we ingest at once.
const MAX_IDENTIFY_ADDRS_INGEST: usize = 64;

/// Defensive bound on how many Kad-ready base addrs we add for one peer in one call.
const MAX_KAD_READY_ADDRS_PER_PEER: usize = 64;

/// Defensive bound for a single Multiaddr serialized length (bytes).
const MAX_MULTIADDR_BYTES: usize = 256;

/// Keep Kad queries short. Five minutes lets unhelpful peers tie up liveness state.
const KAD_QUERY_TIMEOUT_SECS: u64 = 30;

/// Identify is useful but should not churn constantly.
const IDENTIFY_INTERVAL_SECS: u64 = 45;

/* ───────────── composite behaviour ───────────── */

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "OutEvent")]
pub struct RemzarBehaviour {
    pub ping: Ping,
    pub gossipsub: Gossipsub,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub blocktx: BlockTxExchange,
    pub version: VersionExchange,
    pub pq: PqExchange,
}

/* ───────────── unified event enum ───────────── */

#[derive(Debug)]
pub enum OutEvent {
    Ping(Box<PingEvent>),
    Gossip(Box<GossipsubEvent>),
    Kad(Box<KademliaEvent>),
    Identify(Box<IdentifyEvent>),
    BlockTx(Box<RequestResponseEvent<BlockTxRequest, BlockTxResponse>>),
    Version(Box<RequestResponseEvent<VersionInfo, VersionInfo>>),
    Pq(Box<RequestResponseEvent<PqHandshakeRequest, PqHandshakeResponse>>),
}

impl From<PingEvent> for OutEvent {
    fn from(e: PingEvent) -> Self {
        Self::Ping(Box::new(e))
    }
}

impl From<GossipsubEvent> for OutEvent {
    fn from(e: GossipsubEvent) -> Self {
        Self::Gossip(Box::new(e))
    }
}

impl From<KademliaEvent> for OutEvent {
    fn from(e: KademliaEvent) -> Self {
        Self::Kad(Box::new(e))
    }
}

impl From<IdentifyEvent> for OutEvent {
    fn from(e: IdentifyEvent) -> Self {
        Self::Identify(Box::new(e))
    }
}

impl From<RequestResponseEvent<BlockTxRequest, BlockTxResponse>> for OutEvent {
    fn from(e: RequestResponseEvent<BlockTxRequest, BlockTxResponse>) -> Self {
        Self::BlockTx(Box::new(e))
    }
}

impl From<RequestResponseEvent<VersionInfo, VersionInfo>> for OutEvent {
    fn from(e: RequestResponseEvent<VersionInfo, VersionInfo>) -> Self {
        Self::Version(Box::new(e))
    }
}

impl From<RequestResponseEvent<PqHandshakeRequest, PqHandshakeResponse>> for OutEvent {
    fn from(e: RequestResponseEvent<PqHandshakeRequest, PqHandshakeResponse>) -> Self {
        Self::Pq(Box::new(e))
    }
}

/* ───────────── constructor ───────────── */

impl RemzarBehaviour {
    pub fn new(keypair: Keypair) -> Result<Self> {
        let peer_id = PeerId::from(keypair.public());

        // 1) Ping
        let ping = Ping::default();

        // 2) Gossipsub (strict + defensive caps)
        let gs_cfg: GossipsubConfig = GossipsubConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .heartbeat_interval(Duration::from_millis(700))
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .max_messages_per_rpc(Some(GOSSIPSUB_MAX_MESSAGES_PER_RPC))
            .connection_handler_queue_len(GOSSIPSUB_CONN_HANDLER_QUEUE_LEN)
            .build()
            .map_err(|e| anyhow!("gossipsub config build error: {e}"))?;

        let gossipsub = Gossipsub::new(MessageAuthenticity::Signed(keypair.clone()), gs_cfg)
            .map_err(|e| anyhow!("gossipsub init error: {e}"))?;

        // 3) Kademlia (short bounded query timeout)
        let mut kad_cfg = KademliaConfig::default();
        kad_cfg.set_query_timeout(Duration::from_secs(KAD_QUERY_TIMEOUT_SECS));
        let kademlia = Kademlia::with_config(peer_id, MemoryStore::new(peer_id), kad_cfg);

        // 4) Identify
        let identify_cfg = IdentifyConfig::new("/remzar/1.0.0".into(), keypair.public())
            .with_interval(Duration::from_secs(IDENTIFY_INTERVAL_SECS))
            .with_push_listen_addr_updates(true);

        let identify = Identify::new(identify_cfg);

        // 5) Block/Tx req/resp
        let blocktx = build_blocktx_exchange();

        // 6) Version handshake req/resp
        let version = build_version_exchange();

        // 7) PQ handshake req/resp
        let pq = build_pq_exchange();

        Ok(Self {
            ping,
            gossipsub,
            kademlia,
            identify,
            blocktx,
            version,
            pq,
        })
    }

    /* ───────────── local guard helpers ───────────── */

    fn check_multiaddr_bounds(addr: &Multiaddr) -> Result<()> {
        let len = addr.to_vec().len();

        if len == 0 {
            return Err(anyhow!("multiaddr is empty"));
        }

        if len > MAX_MULTIADDR_BYTES {
            return Err(anyhow!(
                "multiaddr too large: {len} bytes (max {MAX_MULTIADDR_BYTES})"
            ));
        }

        Ok(())
    }

    fn kad_ready_addrs_bounded(addrs: &[Multiaddr]) -> Result<Vec<Multiaddr>> {
        if addrs.len() > MAX_IDENTIFY_ADDRS_INGEST {
            return Err(anyhow!(
                "too many multiaddrs to ingest: {} (max {})",
                addrs.len(),
                MAX_IDENTIFY_ADDRS_INGEST
            ));
        }

        for addr in addrs {
            Self::check_multiaddr_bounds(addr)?;
        }

        let mut out = Vec::new();
        let mut seen = HashSet::new();

        for base in kad_ready_addrs(addrs) {
            Self::check_multiaddr_bounds(&base)?;

            let key = base.to_string();
            if !seen.insert(key) {
                continue;
            }

            if out.len() >= MAX_KAD_READY_ADDRS_PER_PEER {
                return Err(anyhow!(
                    "too many Kad-ready addrs for peer: exceeded max {}",
                    MAX_KAD_READY_ADDRS_PER_PEER
                ));
            }

            out.push(base);
        }

        Ok(out)
    }

    /* ───────────── helpers you call from runtime/event loop ───────────── */

    /// Seed a bootstrap peer into Kad before calling `kad_bootstrap_checked()`.
    /// Kad should receive BASE transport addrs, not `/p2p/<PeerId>` suffixed addrs.
    pub fn kad_add_bootstrap(&mut self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        for base in Self::kad_ready_addrs_bounded(&[addr])? {
            self.kademlia.add_address(&peer, base);
        }
        Ok(())
    }

    /// Kick off a DHT bootstrap.
    pub fn kad_bootstrap_checked(&mut self) -> Result<QueryId> {
        self.kademlia
            .bootstrap()
            .map_err(|_e: NoKnownPeers| anyhow!("kad bootstrap: no known peers"))
    }

    /// Walk Kad towards a target peer id.
    pub fn kad_get_closest_peers_checked(&mut self, target: PeerId) -> Result<QueryId> {
        Ok(self.kademlia.get_closest_peers(target))
    }

    /// Feed Identify-learned listen addrs into Kad.
    pub fn ingest_identify_addrs(&mut self, peer: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        if addrs.len() > MAX_IDENTIFY_ADDRS_INGEST {
            return Err(anyhow!(
                "too many identify addrs from peer {peer}: {} > {}",
                addrs.len(),
                MAX_IDENTIFY_ADDRS_INGEST
            ));
        }

        for base in Self::kad_ready_addrs_bounded(addrs)? {
            self.kademlia.add_address(peer, base);
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Backwards-compatible wrappers (keep existing call sites working)
    // ─────────────────────────────────────────────────────────────

    /// Seed a bootstrap peer into Kad before calling `kad_bootstrap_checked()`.
    pub fn kad_add_bootstrap_legacy(&mut self, peer: PeerId, addr: Multiaddr) {
        _ = self.kad_add_bootstrap(peer, addr);
    }

    /// Kick off a DHT bootstrap (legacy wrapper).
    pub fn kad_bootstrap(&mut self) {
        _ = self.kad_bootstrap_checked();
    }

    /// Walk Kad towards a target peer id (legacy wrapper).
    pub fn kad_get_closest_peers(&mut self, target: PeerId) {
        _ = self.kad_get_closest_peers_checked(target);
    }
}
