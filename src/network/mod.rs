//! Network Module
//!
//! This module implements all networking components for the Remzar project, with a primary focus
//! on peer-to-peer (P2P) networking protocols, discovery, and communication handlers.
//!
//! Included submodules:
//! - P2P transport and protocol definition
//! - Peer behavior and event handling
//! - Peer discovery and handshake processes
//! - Request/response (req/resp) messaging
//! - Broadcast and network command orchestration

pub mod p2p_001_transport;
pub mod p2p_002_protocal;
pub mod p2p_003_behaviour;
pub mod p2p_004_peerdiscovery;
pub mod p2p_005_pq_fips203kem;
pub mod p2p_006_reqresp;
pub mod p2p_007_handshake;
pub mod p2p_008_broadcast;
pub mod p2p_009_events;
pub mod p2p_010_netcmd;
pub mod p2p_011_peerbook;
pub mod p2p_012_janitor_peerbook;
pub mod p2p_013_peer_mesh;
pub mod p2p_014_chat;
pub mod p2p_015_chat_store;
pub mod p2p_016_file_store;
pub mod p2p_017_conn_guard;
pub mod p2p_018_last_resort_guards;
pub mod p2p_019_inflight_limiter;
