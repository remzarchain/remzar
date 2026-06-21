//! p2p_004_sync_entrypoint

use super::p2p_001_sync_builders::{
    MAX_HEIGHT_POLL_PEERS, MAX_PENDING_VERSIONS, MAX_RETRIES, P2pSync, genesis_hash_bytes_64,
};
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_007_handshake::{Services, VersionInfo};
use libp2p::PeerId;
use libp2p::swarm::Swarm;

impl P2pSync {
    pub fn poll_peers_for_height(&mut self, swarm: &mut Swarm<RemzarBehaviour>) {
        self.update_sync_pointers();

        // Gather all connected peers via gossipsub.
        let peers: Vec<PeerId> = swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .map(|(peer, _)| *peer)
            .take(MAX_HEIGHT_POLL_PEERS)
            .collect();

        if peers.is_empty() {
            // No connected peers — try to auto-dial from PeerBook and keep Kad alive.
            self.autodial_known_peers(swarm);
            self.kad_periodic_bootstrap(swarm);
            self.kad_random_walk(swarm);

            // Do NOT blindly collapse sync_target back to local_tip here.
            self.update_sync_pointers();

            let local_tip = self.db.get_tip_height().unwrap_or(0);
            let highest_target = self
                .sync_target
                .max(self.queued_sync_target.unwrap_or(0))
                .max(local_tip);

            self.sync_target = highest_target;
            self.downloaded = local_tip;
            self.total_to_download = highest_target;

            if highest_target > local_tip {
                self.queued_sync_target = Some(highest_target);
            } else {
                self.queued_sync_target = None;
            }

            self.update_sync_state();
            return;
        }

        if self.pending_versions.len() >= MAX_PENDING_VERSIONS {
            self.autodial_known_peers(swarm);
            self.kad_periodic_bootstrap(swarm);
            self.kad_random_walk(swarm);
            self.update_sync_state();
            return;
        }

        // Compute once per polling round.
        let genesis_id_64 = genesis_hash_bytes_64();

        // Broadcast our version/height request to peers (bounded).
        for peer in peers.into_iter().take(MAX_HEIGHT_POLL_PEERS) {
            if self.pending_versions.len() >= MAX_PENDING_VERSIONS {
                break;
            }

            let req = VersionInfo {
                protocol_version: 1,
                chain_height: 0, // ask for their height
                services: Services::NODE,
                user_agent: "remzar-sync/1.0".into(),
                genesis_hash: Some(genesis_id_64),
            };

            let req_id = swarm.behaviour_mut().version.send_request(&peer, req);
            self.pending_versions.insert(req_id, peer);
        }

        // Opportunistic dial (keeps mesh healthy) and Kad bootstrap.
        self.autodial_known_peers(swarm);
        self.kad_periodic_bootstrap(swarm);
        self.kad_random_walk(swarm);

        self.update_sync_state();
    }

    #[inline(always)]
    fn defer_sync_until_pq(&mut self, desired_target: u64) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        // Preserve the highest known catch-up target.
        let effective_target = desired_target
            .max(local_tip)
            .max(self.sync_target)
            .max(self.queued_sync_target.unwrap_or(0));

        self.sync_target = effective_target;
        self.downloaded = local_tip;
        self.total_to_download = effective_target;

        if effective_target > local_tip {
            self.queued_sync_target = Some(effective_target);
        } else {
            self.queued_sync_target = None;
        }

        // Recompute from the authoritative state model instead of directly
        // toggling participation flags here.
        self.update_sync_state();
    }

    #[inline(always)]
    fn can_start_block_sync_with_peer(
        &mut self,
        swarm: &Swarm<RemzarBehaviour>,
        peer: PeerId,
        desired_target: u64,
    ) -> bool {
        let connected = swarm.is_connected(&peer);
        let pq_ready = self.is_pq_ready(&peer);

        if !connected {
            self.defer_sync_until_pq(desired_target);
            return false;
        }

        if pq_ready {
            return true;
        }

        self.defer_sync_until_pq(desired_target);
        false
    }

    /// Single safe send path for the next sync index.
    #[inline(always)]
    fn request_index_from_peer(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        idx: u64,
    ) {
        let connected = swarm.is_connected(&peer);
        let has_block = self.db_has_block_index(idx);

        if !connected {
            let target = self
                .sync_target
                .max(self.queued_sync_target.unwrap_or(0))
                .max(idx);

            self.defer_sync_until_pq(target);
            return;
        }

        // If the block is already present (e.g. crash/restart between block+batch),
        // skip re-requesting the block and ensure the batch request exists instead.
        if has_block {
            self.issue_batch_request_if_absent(swarm, peer, idx, MAX_RETRIES);

            return;
        }

        self.issue_block_request_if_absent(swarm, peer, idx, MAX_RETRIES);
    }

    pub(super) fn request_next_block(&mut self, swarm: &mut Swarm<RemzarBehaviour>, peer: PeerId) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let effective_target = self
            .sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(local_tip);

        self.sync_target = effective_target;
        self.downloaded = local_tip;
        self.total_to_download = effective_target;

        if local_tip < effective_target {
            if !self.can_start_block_sync_with_peer(&*swarm, peer, effective_target) {
                self.update_sync_state();
                return;
            }

            let next_idx = local_tip.saturating_add(1);

            self.request_index_from_peer(swarm, peer, next_idx);
            self.update_sync_state();
        } else {
            self.queued_sync_target = None;
            self.update_sync_state();
        }
    }

    pub fn begin_sync_to_target(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        peer_tip: u64,
    ) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let previous_target = self.sync_target.max(self.queued_sync_target.unwrap_or(0));

        let new_target = previous_target.max(local_tip).max(peer_tip);

        self.sync_target = new_target;
        self.downloaded = local_tip;
        self.total_to_download = new_target;

        if new_target <= local_tip {
            self.queued_sync_target = None;
            self.update_sync_state();
            return;
        }

        // PQ is mandatory before any block/batch requests are emitted.
        if !self.can_start_block_sync_with_peer(&*swarm, peer, new_target) {
            self.update_sync_state();
            return;
        }

        // At this point PQ is ready and the peer is connected, so this queued
        // target is now actively being resumed.
        self.queued_sync_target = None;

        self.downloaded = local_tip;
        self.total_to_download = self.sync_target;

        if self.downloaded >= self.sync_target {
            self.update_sync_state();
            return;
        }

        let next_idx = self.downloaded.saturating_add(1);

        self.request_index_from_peer(swarm, peer, next_idx);

        self.update_sync_state();
    }

    pub fn on_local_tip_advanced(&mut self) {
        self.update_sync_pointers();

        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let highest_target = self
            .sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(local_tip);

        // Never decrease target; only move it forward if local grows.
        self.sync_target = highest_target;
        self.downloaded = local_tip;
        self.total_to_download = highest_target;

        if local_tip >= highest_target {
            self.queued_sync_target = None;
        } else {
            self.queued_sync_target = Some(highest_target);
        }

        // Single authority for flags:
        self.update_sync_state();
    }
}
