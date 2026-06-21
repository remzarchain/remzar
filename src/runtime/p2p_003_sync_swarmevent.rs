//! p2p_003_sync_swarmevent

use super::p2p_001_sync_builders::{
    MAX_PENDING_BATCHES, MAX_PENDING_BLOCKS, MAX_RETRIES, P2pSync, REGISTRATION_TOPIC,
    ZERO_HASH_64, exceeds_consensus_cap, genesis_hash_bytes_64, ip_from_multiaddr, now_millis,
    usize_to_u64_saturating,
};
use super::p2p_002_sync_handlers::BatchTxResponseContext;
use crate::blockchain::blockchain_001_builder::BlockchainBuilder;
use crate::network::p2p_003_behaviour::RemzarBehaviour;
use crate::network::p2p_005_pq_fips203kem::PQ_NONCE_LEN;
use crate::network::p2p_006_reqresp::{BlockTxRequest, BlockTxResponse};
use crate::network::p2p_007_handshake::{
    Services, VersionInfo, build_outbound_pq_offer, finalize_inbound_pq_response,
    handle_inbound_pq_request,
};
use crate::network::p2p_008_broadcast::Broadcaster;
use crate::network::p2p_009_events::{
    attach_peer_to_addr, extract_peer_addrs_from_identify, extract_peer_addrs_from_kad,
    kad_ready_addrs, split_multiaddr_base_and_peer,
};
use crate::network::p2p_012_janitor_peerbook::JanitorConfig;
use crate::network::p2p_013_peer_mesh::PeerMeshAnnounce;
use crate::network::p2p_017_conn_guard::GuardDecision;
use crate::network::p2p_018_last_resort_guards::{
    ActionClass, LastResortDecision, LastResortDrop, LastResortGuards,
};
use crate::reorganization::reorg_001_block_index::ReorgBlockIndex;
use crate::reorganization::reorg_007_branch_hydration::{HydrationAdvance, HydrationFailure};
use crate::utility::time_policy::TimePolicy;
use libp2p::gossipsub::IdentTopic;
use libp2p::{Multiaddr, PeerId, swarm::Swarm};
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

/* ─────────────────────────────────────────────────────────────
Defensive live-event-loop guardrails
───────────────────────────────────────────────────────────── */

/// Protocol version this runtime expects in the version handshake.
const EXPECTED_PROTOCOL_VERSION: u32 = 1;

/// PQ handshakes are a version/admission-class action.
const PQ_HANDSHAKE_COST_TOKENS: u32 = 2;

/// Extra score for a peer that responds on a request id that belonged to a different peer.
const RESPONSE_PEER_MISMATCH_BADNESS: i32 = 10;

impl P2pSync {
    #[inline]
    fn is_sync_by_index_request(request: &BlockTxRequest) -> bool {
        matches!(
            request,
            BlockTxRequest::GetBlockByIndex { .. } | BlockTxRequest::GetBatchByIndex { .. }
        )
    }

    #[inline]
    fn soft_allows_duplicate_sync_request(request: &BlockTxRequest, drop: LastResortDrop) -> bool {
        matches!(drop, LastResortDrop::DuplicateRequest) && Self::is_sync_by_index_request(request)
    }

    #[inline]
    fn send_blocktx_not_found_response(
        swarm: &mut Swarm<RemzarBehaviour>,
        channel: libp2p::request_response::ResponseChannel<BlockTxResponse>,
    ) {
        _ = swarm
            .behaviour_mut()
            .blocktx
            .send_response(channel, BlockTxResponse::NotFound);
    }

    #[inline]
    fn expected_genesis_hash_for_version() -> [u8; 64] {
        genesis_hash_bytes_64()
    }

    #[inline]
    fn version_info_matches_local_chain(info: &VersionInfo) -> bool {
        info.validate_untrusted_with_expectations(
            EXPECTED_PROTOCOL_VERSION,
            Some(Self::expected_genesis_hash_for_version()),
        )
        .is_ok()
    }

    #[inline]
    fn reject_protocol_peer(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
        badness: i32,
        context: &'static str,
    ) {
        warn!(
            target: "p2p",
            "rejecting peer {} after protocol violation in {}",
            peer,
            context
        );

        self.last_resort
            .report_misbehavior(Instant::now(), peer, badness);
        self.cleanup_pending_for_peer(&*swarm, peer, false);
        self.clear_pq_peer_state(&peer);

        if let Ok(mut pb) = self.peerbook.lock() {
            pb.observe_failure(&peer);
            _ = pb.save();
        }

        _ = swarm.disconnect_peer_id(peer);
    }

    #[inline]
    fn reject_if_response_peer_mismatch(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        actual_peer: PeerId,
        expected_peer: PeerId,
        context: &'static str,
    ) -> bool {
        if actual_peer == expected_peer {
            return false;
        }

        warn!(
            target: "p2p",
            "dropping {} response from peer {} because request belonged to {}",
            context,
            actual_peer,
            expected_peer
        );

        self.reject_protocol_peer(swarm, actual_peer, RESPONSE_PEER_MISMATCH_BADNESS, context);
        true
    }

    #[inline]
    fn allow_inbound_pq_request(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
    ) -> bool {
        let now = Instant::now();
        let admitted = self.admitted_peers.contains(&peer);
        let peer_ip = self.peer_ip.get(&peer).copied();

        match self.last_resort.check_action(
            crate::network::p2p_018_last_resort_guards::LastResortActionRequest {
                now,
                peer_id: peer,
                admitted,
                peer_ip,
                action: ActionClass::Version,
                cost_tokens: PQ_HANDSHAKE_COST_TOKENS,
                dup_key: None,
            },
        ) {
            LastResortDecision::Allow => true,
            LastResortDecision::Drop(drop) => {
                self.handle_last_resort_drop(swarm, peer, drop, "Pq(Request)");
                self.clear_pq_peer_state(&peer);
                false
            }
        }
    }

    #[inline]
    fn pick_idle_sync_resume_peer(&self, swarm: &Swarm<RemzarBehaviour>) -> Option<PeerId> {
        let mut first_connected: Option<PeerId> = None;

        for (peer, _) in swarm.behaviour().gossipsub.all_peers() {
            let peer = *peer;

            if !swarm.is_connected(&peer) {
                continue;
            }

            if first_connected.is_none() {
                first_connected = Some(peer);
            }

            if self.is_pq_ready(&peer) {
                return Some(peer);
            }
        }

        first_connected
    }

    #[inline]
    fn reissue_idle_sync_work_if_needed(&mut self, swarm: &mut Swarm<RemzarBehaviour>) -> bool {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let target = self
            .sync_target
            .max(self.queued_sync_target.unwrap_or(0))
            .max(local_tip);

        if target <= local_tip {
            return false;
        }

        let idle_sync_work = self.pending_blocks.is_empty()
            && self.block_queue.is_empty()
            && self.pending_batches.is_empty()
            && self.batch_queue.is_empty();

        if !idle_sync_work {
            return false;
        }

        let catchup_expected =
            self.syncing || self.queued_sync_target.is_some() || self.sync_target > local_tip;

        if !catchup_expected {
            return false;
        }

        self.sync_target = target;
        self.queued_sync_target = Some(target);
        self.downloaded = local_tip;
        self.total_to_download = target;
        self.syncing = true;
        self.has_synced = false;

        let Some(peer) = self.pick_idle_sync_resume_peer(&*swarm) else {
            self.update_sync_state();
            return false;
        };

        self.request_next_block(swarm, peer);
        true
    }

    #[inline]
    fn emit_local_peer_mesh_announce(swarm: &mut Swarm<RemzarBehaviour>, wallet: Option<&str>) {
        let has_subscribers = swarm.behaviour().gossipsub.all_peers().next().is_some();
        if !has_subscribers {
            return;
        }

        let listen_addrs: Vec<_> = swarm.listeners().cloned().collect();
        if listen_addrs.is_empty() {
            return;
        }

        let timestamp_unix = match TimePolicy::now_unix_secs_runtime() {
            Ok(t) => t,
            Err(..) => {
                return;
            }
        };

        let ann = match PeerMeshAnnounce::from_local(
            *swarm.local_peer_id(),
            &listen_addrs,
            wallet.filter(|w| !w.trim().is_empty()),
            timestamp_unix,
        ) {
            Ok(a) => a,
            Err(..) => {
                return;
            }
        };

        if ann.listen_addrs.is_empty() {
            return;
        }

        _ = Broadcaster::new(swarm).send_peer_mesh_announce(&ann);
    }

    #[inline]
    fn build_pq_offer_nonce_for_peer(&self, peer: &PeerId) -> [u8; PQ_NONCE_LEN] {
        let now_ms = now_millis();
        let local_tip = self.db.get_tip_height().unwrap_or(0);
        let peer_text = peer.to_string();
        let peer_bytes = peer_text.as_bytes();

        let pending_pq_len = u64::try_from(self.pending_pq.len()).unwrap_or(u64::MAX);
        let pq_initiators_len = u64::try_from(self.pq_initiators.len()).unwrap_or(u64::MAX);

        let mut state = now_ms
            ^ u128::from(local_tip).checked_shl(17).unwrap_or(0)
            ^ u128::from(self.sync_target).checked_shl(41).unwrap_or(0)
            ^ u128::from(pending_pq_len).checked_shl(3).unwrap_or(0)
            ^ u128::from(pq_initiators_len).checked_shl(11).unwrap_or(0);

        let mut nonce = [0u8; PQ_NONCE_LEN];
        let peer_len = peer_bytes.len();

        for (i, slot) in nonce.iter_mut().enumerate() {
            let peer_b = if peer_len == 0 {
                0
            } else {
                let peer_index = i.checked_rem(peer_len).unwrap_or(0);
                peer_bytes.get(peer_index).copied().unwrap_or(0)
            };

            let i_u64 = u64::try_from(i).unwrap_or(u64::MAX);
            let i_u8 = u8::try_from(i).unwrap_or(u8::MAX);

            state ^= u128::from(peer_b);
            state ^= u128::from(i_u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            state = state.rotate_left(17).wrapping_mul(0xd6e8_feb8_6659_fd93);

            let shift_index = i.checked_rem(16).unwrap_or(0);
            let shift_bits = shift_index.checked_mul(8).unwrap_or(0);
            let shift = u32::try_from(shift_bits).unwrap_or(0);

            let state_byte = u8::try_from((state >> shift) & 0xff).unwrap_or(0);
            *slot = state_byte ^ peer_b ^ i_u8.wrapping_mul(31);
        }

        if nonce.iter().all(|b| *b == 0) {
            nonce[0] = 1;
        }

        nonce
    }

    fn preserve_sync_target_for_pq_retry(&mut self) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);
        let target = self.sync_target.max(self.queued_sync_target.unwrap_or(0));

        if target > local_tip {
            self.queued_sync_target = Some(target);
            self.downloaded = local_tip;
            self.total_to_download = target;
            self.syncing = true;
            self.has_synced = false;
            self.update_sync_state();
        }
    }

    fn try_start_fresh_pq_offer(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
    ) -> bool {
        if self.is_pq_ready(&peer) {
            return true;
        }

        if !swarm.is_connected(&peer) {
            self.update_sync_state();
            return false;
        }

        // Do not lose a pending catch-up target when resetting stale PQ state.
        self.preserve_sync_target_for_pq_retry();

        // Drop any stale initiator/request state before creating a new single-use keypair.
        self.clear_pq_peer_state(&peer);

        if !self.can_issue_more_pq_requests() {
            self.update_sync_state();
            return false;
        }

        let offer_nonce = self.build_pq_offer_nonce_for_peer(&peer);

        match build_outbound_pq_offer(&mut self.pq_manager, offer_nonce) {
            Ok((state, req)) => {
                let req_id = swarm.behaviour_mut().pq.send_request(&peer, req);

                self.pending_pq.insert(req_id, peer);
                self.pq_initiators.insert(peer, state);

                self.update_sync_state();
                true
            }
            Err(..) => {
                self.clear_pq_peer_state(&peer);
                self.update_sync_state();
                false
            }
        }
    }

    fn resume_queued_sync_after_pq_ready(
        &mut self,
        swarm: &mut Swarm<RemzarBehaviour>,
        peer: PeerId,
    ) {
        let local_tip = self.db.get_tip_height().unwrap_or(0);

        let Some(target) = self.queued_sync_target.take() else {
            self.update_sync_state();
            return;
        };

        let effective_target = target.max(self.sync_target).max(local_tip);

        if effective_target <= local_tip {
            self.update_sync_state();
            return;
        }

        self.begin_sync_to_target(swarm, peer, effective_target);
    }

    pub fn on_swarm_event(
        &mut self,
        event: libp2p::swarm::SwarmEvent<crate::network::p2p_003_behaviour::OutEvent>,
        swarm: &mut Swarm<RemzarBehaviour>,
        miner: Option<&mut BlockchainBuilder>,
    ) {
        use libp2p::request_response::{Event, OutboundFailure};

        let local_wallet_for_mesh: Option<String> =
            miner.as_ref().map(|m| m.consensus().local_wallet().clone());

        match event {
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let remote_addr: Multiaddr = endpoint.get_remote_address().clone();
                let now = Instant::now();

                if let Some(ip) = ip_from_multiaddr(&remote_addr) {
                    self.peer_ip.insert(peer_id, ip);
                }

                match self
                    .conn_guard
                    .on_connection_established(peer_id, &remote_addr, now)
                {
                    GuardDecision::Allow => {}
                    GuardDecision::Drop(..) => {
                        if let Ok(mut pb) = self.peerbook.lock() {
                            pb.observe_failure(&peer_id);
                            _ = pb.save();
                        }

                        self.cleanup_pending_for_peer(&*swarm, peer_id, false);
                        self.clear_pq_peer_state(&peer_id);

                        _ = swarm.disconnect_peer_id(peer_id);
                        return;
                    }
                }

                let topic = IdentTopic::new(REGISTRATION_TOPIC);
                _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);

                let addr_vec =
                    self.filter_multiaddr_bounds(vec![match split_multiaddr_base_and_peer(
                        &remote_addr,
                    ) {
                        (base, Some(existing_pid)) if existing_pid == peer_id => {
                            attach_peer_to_addr(base, &peer_id)
                        }
                        (base, None) => attach_peer_to_addr(base, &peer_id),
                        (_, Some(_other_pid)) => remote_addr.clone(),
                    }]);

                if let Ok(mut pb) = self.peerbook.lock() {
                    pb.upsert(&peer_id, addr_vec.clone(), true);
                    _ = pb.save();
                }

                for a in kad_ready_addrs(&addr_vec) {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, a);
                }
                _ = swarm.behaviour_mut().kademlia.bootstrap();

                Self::emit_local_peer_mesh_announce(swarm, local_wallet_for_mesh.as_deref());

                self.autodial_known_peers(swarm);
                self.poll_peers_for_height(swarm);
                self.drive_branch_hydration_requests(swarm);
            }

            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.conn_guard.on_connection_closed(peer_id);
                self.last_resort.on_peer_disconnected(peer_id);
                self.admitted_peers.remove(&peer_id);
                self.peer_ip.remove(&peer_id);
                self.clear_pq_peer_state(&peer_id);
                self.cleanup_pending_for_peer(&*swarm, peer_id, true);

                self.autodial_known_peers(swarm);
                self.kad_periodic_bootstrap(swarm);
                self.kad_random_walk(swarm);
                self.drive_branch_hydration_requests(swarm);
            }

            libp2p::swarm::SwarmEvent::OutgoingConnectionError {
                peer_id: Some(pid), ..
            } => {
                if let Ok(mut pb) = self.peerbook.lock() {
                    pb.observe_failure(&pid);
                    _ = pb.save();
                }

                self.clear_pq_peer_state(&pid);

                _ = self.janitor.sweep_stale_peers(&JanitorConfig::default());

                self.autodial_known_peers(swarm);
                self.kad_periodic_bootstrap(swarm);
                self.kad_random_walk(swarm);
                self.drive_branch_hydration_requests(swarm);
            }

            libp2p::swarm::SwarmEvent::Behaviour(
                crate::network::p2p_003_behaviour::OutEvent::Identify(ev),
            ) => {
                if let Some((pid, addrs)) = extract_peer_addrs_from_identify(&ev) {
                    let addrs = self.filter_multiaddr_bounds(addrs);

                    if let Ok(mut pb) = self.peerbook.lock() {
                        pb.upsert(&pid, addrs.clone(), true);
                        _ = pb.save();
                    }

                    for a in kad_ready_addrs(&addrs) {
                        swarm.behaviour_mut().kademlia.add_address(&pid, a);
                    }
                    _ = swarm.behaviour_mut().kademlia.bootstrap();
                }

                Self::emit_local_peer_mesh_announce(swarm, local_wallet_for_mesh.as_deref());

                self.autodial_known_peers(swarm);
                self.drive_branch_hydration_requests(swarm);
            }

            libp2p::swarm::SwarmEvent::Behaviour(
                crate::network::p2p_003_behaviour::OutEvent::Kad(ev),
            ) => {
                for (pid, addrs) in extract_peer_addrs_from_kad(&ev) {
                    let addrs = self.filter_multiaddr_bounds(addrs);

                    if let Ok(mut pb) = self.peerbook.lock() {
                        pb.upsert(&pid, addrs.clone(), false);
                        _ = pb.save();
                    }

                    for a in kad_ready_addrs(&addrs) {
                        swarm.behaviour_mut().kademlia.add_address(&pid, a);
                    }
                }

                self.autodial_known_peers(swarm);
                self.kad_periodic_bootstrap(swarm);
                self.kad_random_walk(swarm);
                self.drive_branch_hydration_requests(swarm);
            }

            libp2p::swarm::SwarmEvent::Behaviour(
                crate::network::p2p_003_behaviour::OutEvent::Version(ev),
            ) => match *ev {
                Event::Message { peer, message, .. } => {
                    use libp2p::request_response::Message;

                    match message {
                        Message::Response {
                            request_id,
                            response,
                            ..
                        } => {
                            if let Some(origin_peer) = self.pending_versions.remove(&request_id) {
                                if self.reject_if_response_peer_mismatch(
                                    swarm,
                                    peer,
                                    origin_peer,
                                    "Version(Response)",
                                ) {
                                    return;
                                }

                                if !Self::version_info_matches_local_chain(&response) {
                                    self.reject_protocol_peer(
                                        swarm,
                                        origin_peer,
                                        RESPONSE_PEER_MISMATCH_BADNESS,
                                        "Version(Response::Validation)",
                                    );
                                    return;
                                }

                                match self.conn_guard.try_admit(origin_peer) {
                                    GuardDecision::Allow => {
                                        self.admitted_peers.insert(origin_peer);
                                    }
                                    GuardDecision::Drop(..) => {
                                        self.cleanup_pending_for_peer(&*swarm, origin_peer, false);
                                        self.clear_pq_peer_state(&origin_peer);

                                        _ = swarm.disconnect_peer_id(origin_peer);
                                        return;
                                    }
                                }

                                let genesis_exists =
                                    self.db.get_block_by_index(0).ok().flatten().is_some();

                                if !genesis_exists {
                                    self.sync_target = response.chain_height;
                                    self.total_to_download = response.chain_height;
                                    self.downloaded = 0;
                                    self.syncing = true;
                                    self.has_synced = false;

                                    self.issue_block_request_if_absent(
                                        swarm,
                                        origin_peer,
                                        0,
                                        MAX_RETRIES,
                                    );

                                    self.tried_genesis = true;
                                    self.update_sync_state();
                                } else {
                                    let local_height = self.db.get_tip_height().unwrap_or(0);
                                    self.update_sync_pointers();

                                    let current_target = self.sync_target.max(local_height);
                                    if response.chain_height > current_target {
                                        self.begin_sync_to_target(
                                            swarm,
                                            origin_peer,
                                            response.chain_height,
                                        );
                                    } else {
                                        self.update_sync_state();
                                    }
                                }

                                let already_pending_pq = self
                                    .pending_pq
                                    .values()
                                    .any(|pending_peer| *pending_peer == origin_peer);

                                if !self.is_pq_ready(&origin_peer)
                                    && !already_pending_pq
                                    && !self.pq_initiators.contains_key(&origin_peer)
                                {
                                    self.try_start_fresh_pq_offer(swarm, origin_peer);
                                }
                            }
                        }

                        Message::Request {
                            request, channel, ..
                        } => {
                            if !Self::version_info_matches_local_chain(&request) {
                                self.reject_protocol_peer(
                                    swarm,
                                    peer,
                                    RESPONSE_PEER_MISMATCH_BADNESS,
                                    "Version(Request::Validation)",
                                );
                                return;
                            }

                            let now = Instant::now();
                            let admitted = self.admitted_peers.contains(&peer);
                            let peer_ip = self.peer_ip.get(&peer).copied();

                            match self.last_resort.check_action(
                                crate::network::p2p_018_last_resort_guards::LastResortActionRequest {
                                    now,
                                    peer_id: peer,
                                    admitted,
                                    peer_ip,
                                    action: ActionClass::Version,
                                    cost_tokens: 1,
                                    dup_key: None,
                                },
                            ) {
                                LastResortDecision::Allow => {}
                                LastResortDecision::Drop(drop) => {
                                    self.handle_last_resort_drop(
                                        swarm,
                                        peer,
                                        drop,
                                        "Version(Request)",
                                    );
                                    return;
                                }
                            }

                            match self.conn_guard.try_admit(peer) {
                                GuardDecision::Allow => {
                                    self.admitted_peers.insert(peer);
                                }
                                GuardDecision::Drop(..) => {
                                    self.cleanup_pending_for_peer(&*swarm, peer, false);
                                    self.clear_pq_peer_state(&peer);

                                    _ = swarm.disconnect_peer_id(peer);
                                    return;
                                }
                            }

                            let local_height = self.db.get_tip_height().unwrap_or(0);
                            let resp = VersionInfo {
                                protocol_version: EXPECTED_PROTOCOL_VERSION,
                                chain_height: local_height,
                                services: Services::NODE,
                                user_agent: "remzar/v0.1.0".into(),
                                genesis_hash: Some(genesis_hash_bytes_64()),
                            };

                            _ = swarm.behaviour_mut().version.send_response(channel, resp);
                        }
                    }
                }

                Event::OutboundFailure {
                    peer: _,
                    request_id,
                    error,
                    ..
                } => {
                    if let Some(origin_peer) = self.pending_versions.remove(&request_id) {
                        if let Ok(mut pb) = self.peerbook.lock() {
                            pb.observe_failure(&origin_peer);
                            _ = pb.save();
                        }

                        if matches!(error, OutboundFailure::Timeout) {
                            self.last_resort
                                .report_misbehavior(Instant::now(), origin_peer, 1);
                        }
                    }
                }

                Event::InboundFailure { .. } | Event::ResponseSent { .. } => {}
            },

            libp2p::swarm::SwarmEvent::Behaviour(
                crate::network::p2p_003_behaviour::OutEvent::Pq(ev),
            ) => match *ev {
                Event::Message { peer, message, .. } => {
                    use libp2p::request_response::Message;

                    match message {
                        Message::Response {
                            request_id,
                            response,
                            ..
                        } => {
                            if let Some(origin_peer) = self.pending_pq.remove(&request_id) {
                                if self.reject_if_response_peer_mismatch(
                                    swarm,
                                    peer,
                                    origin_peer,
                                    "Pq(Response)",
                                ) {
                                    return;
                                }

                                if let Some(mut state) = self.pq_initiators.remove(&origin_peer) {
                                    match finalize_inbound_pq_response(
                                        &mut self.pq_manager,
                                        &mut state,
                                        response,
                                    ) {
                                        Ok(mut session_key) => {
                                            self.mark_pq_ready(origin_peer);

                                            session_key.zeroize();

                                            self.resume_queued_sync_after_pq_ready(
                                                swarm,
                                                origin_peer,
                                            );
                                        }
                                        Err(..) => {
                                            self.clear_pq_peer_state(&origin_peer);

                                            self.try_start_fresh_pq_offer(swarm, origin_peer);
                                        }
                                    }
                                } else {
                                    self.clear_pq_peer_state(&origin_peer);

                                    self.try_start_fresh_pq_offer(swarm, origin_peer);
                                }
                            }
                        }

                        Message::Request {
                            request, channel, ..
                        } => {
                            if !self.allow_inbound_pq_request(swarm, peer) {
                                return;
                            }

                            match handle_inbound_pq_request(&mut self.pq_manager, request) {
                                Ok((response, mut session_key)) => {
                                    if swarm
                                        .behaviour_mut()
                                        .pq
                                        .send_response(channel, response)
                                        .is_err()
                                    {
                                        self.clear_pq_peer_state(&peer);
                                    } else {
                                        self.mark_pq_ready(peer);
                                        self.resume_queued_sync_after_pq_ready(swarm, peer);
                                    }

                                    session_key.zeroize();
                                }
                                Err(..) => {
                                    self.clear_pq_peer_state(&peer);
                                }
                            }
                        }
                    }
                }

                Event::OutboundFailure {
                    peer: _,
                    request_id,
                    error,
                    ..
                } => {
                    if let Some(origin_peer) = self.pending_pq.remove(&request_id) {
                        self.clear_pq_peer_state(&origin_peer);

                        if let Ok(mut pb) = self.peerbook.lock() {
                            pb.observe_failure(&origin_peer);
                            _ = pb.save();
                        }

                        if matches!(error, OutboundFailure::Timeout) {
                            self.last_resort
                                .report_misbehavior(Instant::now(), origin_peer, 1);
                        }

                        self.try_start_fresh_pq_offer(swarm, origin_peer);
                    }
                }

                Event::InboundFailure { peer, .. } => {
                    self.clear_pq_peer_state(&peer);
                }

                Event::ResponseSent { .. } => {}
            },

            libp2p::swarm::SwarmEvent::Behaviour(
                crate::network::p2p_003_behaviour::OutEvent::BlockTx(ev),
            ) => 'blocktx: {
                match *ev {
                    Event::Message { peer, message, .. } => {
                        use libp2p::request_response::Message;

                        match message {
                            Message::Response {
                                request_id,
                                response,
                                ..
                            } => {
                                if let Some((origin_peer, idx, retries_left)) =
                                    self.pending_blocks.remove(&request_id)
                                {
                                    if self.reject_if_response_peer_mismatch(
                                        swarm,
                                        peer,
                                        origin_peer,
                                        "BlockTx(BlockResponse)",
                                    ) {
                                        if retries_left > 0 && !self.db_has_block_index(idx) {
                                            let next_retries = retries_left.saturating_sub(1);
                                            self.push_block_retry(origin_peer, idx, next_retries);
                                        }
                                        return;
                                    }

                                    self.handle_block_tx_response(
                                        swarm,
                                        origin_peer,
                                        idx,
                                        retries_left,
                                        response,
                                        miner,
                                    );
                                } else if let Some(pending_batch) =
                                    self.pending_batches.remove(&request_id)
                                {
                                    let origin_peer = pending_batch.peer;
                                    let idx = pending_batch.idx;
                                    let retries_left = pending_batch.retries_left;
                                    let expected_block_hash = pending_batch.expected_block_hash;

                                    if self.reject_if_response_peer_mismatch(
                                        swarm,
                                        peer,
                                        origin_peer,
                                        "BlockTx(BatchResponse)",
                                    ) {
                                        let applied = self.db.get_addr_index_height().unwrap_or(0);
                                        if retries_left > 0 && idx > applied {
                                            let next_retries = retries_left.saturating_sub(1);
                                            self.push_batch_retry(origin_peer, idx, next_retries);
                                        }
                                        return;
                                    }

                                    // Current handler API is still idx-based.
                                    self.handle_batch_tx_response(
                                        swarm,
                                        BatchTxResponseContext {
                                            origin_peer,
                                            idx,
                                            expected_block_hash,
                                            retries_left,
                                        },
                                        response,
                                        miner,
                                    );
                                } else {
                                    match response {
                                        BlockTxResponse::BlockData(block) => {
                                            let db_for_persist = Arc::clone(&self.db);
                                            let db_for_parent = Arc::clone(&self.db);

                                            match self.branch_hydration.on_block_received(
                                                request_id,
                                                &block,
                                                move |b| {
                                                    let block_index =
                                                        ReorgBlockIndex::new(Arc::clone(
                                                            &db_for_persist,
                                                        ));

                                                    let (cumulative_score, status) =
                                                        match block_index
                                                            .get_meta(&b.metadata.previous_hash)?
                                                        {
                                                            Some(parent_meta) => (
                                                                parent_meta
                                                                    .cumulative_score
                                                                    .saturating_add(1),
                                                                crate::storage::rocksdb_006_manager_ext::ForkBlockStatus::Validated,
                                                            ),
                                                            None
                                                                if b.metadata.index == 0
                                                                    || b.metadata.previous_hash
                                                                        == ZERO_HASH_64 =>
                                                            {
                                                                (
                                                                    0u128,
                                                                    crate::storage::rocksdb_006_manager_ext::ForkBlockStatus::Validated,
                                                                )
                                                            }
                                                            None => (
                                                                b.metadata.index as u128,
                                                                crate::storage::rocksdb_006_manager_ext::ForkBlockStatus::Orphan,
                                                            ),
                                                        };

                                                    let meta = crate::storage::rocksdb_006_manager_ext::ForkBlockMeta {
                                                        parent_hash: b.metadata.previous_hash,
                                                        height: b.metadata.index,
                                                        cumulative_score,
                                                        status,
                                                        received_at_unix_secs: TimePolicy::now_unix_secs_runtime()
                                                            .unwrap_or(0),
                                                    };

                                                    block_index.put_block_and_meta(b, &meta)
                                                },
                                                move |hash| {
                                                    let block_index =
                                                        ReorgBlockIndex::new(Arc::clone(
                                                            &db_for_parent,
                                                        ));
                                                    block_index.has_meta(hash).unwrap_or(false)
                                                },
                                            ) {
                                                Ok(HydrationAdvance::AcceptedComplete { .. })
                                                | Ok(HydrationAdvance::AcceptedNeedsParent { .. })
                                                | Ok(HydrationAdvance::AcceptedUnblockedChildren { .. }) => {
                                                    self.drive_branch_hydration_requests(swarm);
                                                }
                                                Ok(HydrationAdvance::Ignored) | Err(..) => {}
                                            }
                                        }
                                        BlockTxResponse::NotFound => {
                                            match self.branch_hydration.on_not_found(request_id) {
                                                HydrationFailure::RetryScheduled { .. } => {
                                                    self.drive_branch_hydration_requests(swarm);
                                                }
                                                HydrationFailure::Exhausted { .. }
                                                | HydrationFailure::UnknownRequest => {}
                                            }
                                        }
                                        BlockTxResponse::BatchData(_)
                                        | BlockTxResponse::TxData(_) => {}
                                    }
                                }
                            }

                            Message::Request {
                                request, channel, ..
                            } => {
                                let peer_id = peer;

                                let now = Instant::now();
                                let admitted = self.admitted_peers.contains(&peer_id);
                                let peer_ip = self.peer_ip.get(&peer_id).copied();

                                let request_is_sync_by_index =
                                    Self::is_sync_by_index_request(&request);

                                let (action, cost_tokens, dup_key) = match &request {
                                    BlockTxRequest::GetBlock { hash } => (
                                        ActionClass::BlockTxGetBlock,
                                        3,
                                        Some(LastResortGuards::dup_key_from_str(&format!(
                                            "GetBlock:{}",
                                            hex::encode(hash)
                                        ))),
                                    ),
                                    BlockTxRequest::GetBlockByIndex { index } => (
                                        ActionClass::BlockTxGetBlock,
                                        3,
                                        Some(LastResortGuards::dup_key_from_str(&format!(
                                            "GetBlockByIndex:{index}"
                                        ))),
                                    ),
                                    BlockTxRequest::GetBatchByIndex { index } => (
                                        ActionClass::BlockTxGetBatch,
                                        4,
                                        Some(LastResortGuards::dup_key_from_str(&format!(
                                            "GetBatchByIndex:{index}"
                                        ))),
                                    ),
                                    BlockTxRequest::GetBatchByHash { hash } => (
                                        ActionClass::BlockTxGetBatch,
                                        4,
                                        Some(LastResortGuards::dup_key_from_str(&format!(
                                            "GetBatchByHash:{}",
                                            hex::encode(hash)
                                        ))),
                                    ),
                                    BlockTxRequest::GetTx { hash } => (
                                        ActionClass::BlockTxGetTx,
                                        2,
                                        Some(LastResortGuards::dup_key_from_str(&format!(
                                            "GetTx:{}",
                                            hex::encode(hash)
                                        ))),
                                    ),
                                };

                                match self.last_resort.check_action(
                                    crate::network::p2p_018_last_resort_guards::LastResortActionRequest {
                                        now,
                                        peer_id,
                                        admitted,
                                        peer_ip,
                                        action,
                                        cost_tokens,
                                        dup_key,
                                    },
                                ) {
                                    LastResortDecision::Allow => {}
                                    LastResortDecision::Drop(drop) => {
                                        if !Self::soft_allows_duplicate_sync_request(&request, drop) {
                                            self.handle_last_resort_drop(
                                                swarm,
                                                peer_id,
                                                drop,
                                                "BlockTx(Request)",
                                            );

                                            if request_is_sync_by_index {
                                                Self::send_blocktx_not_found_response(
                                                    swarm,
                                                    channel,
                                                );
                                            }

                                            break 'blocktx;
                                        }
                                    }
                                }

                                let _inflight_permit =
                                    match self.last_resort.try_begin_inflight(now, &peer_id) {
                                        crate::network::p2p_018_last_resort_guards::LastResortInflightDecision::Allow(p) => p,
                                        crate::network::p2p_018_last_resort_guards::LastResortInflightDecision::Drop(drop) => {
                                            self.handle_last_resort_drop(
                                                swarm,
                                                peer_id,
                                                drop,
                                                "BlockTx(Request::Inflight)",
                                            );

                                            if request_is_sync_by_index {
                                                Self::send_blocktx_not_found_response(
                                                    swarm,
                                                    channel,
                                                );
                                            }

                                            break 'blocktx;
                                        }
                                    };

                                let resp = match request {
                                    BlockTxRequest::GetBlock { ref hash } => {
                                        match self.db.get_block_by_hash(hash) {
                                            Some(b) => match b.serialize_for_storage() {
                                                Ok(bytes) => {
                                                    if exceeds_consensus_cap(bytes.len()) {
                                                        BlockTxResponse::NotFound
                                                    } else {
                                                        let bytes_u64 =
                                                            usize_to_u64_saturating(bytes.len());

                                                        match self
                                                            .last_resort
                                                            .check_bytes(now, peer_id, bytes_u64)
                                                        {
                                                            LastResortDecision::Allow => {
                                                                BlockTxResponse::BlockData(
                                                                    Box::new(b),
                                                                )
                                                            }
                                                            LastResortDecision::Drop(drop) => {
                                                                self.handle_last_resort_drop(
                                                                    swarm,
                                                                    peer_id,
                                                                    drop,
                                                                    "BlockTx(Request::GetBlock::Bytes)",
                                                                );
                                                                BlockTxResponse::NotFound
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(_) => BlockTxResponse::NotFound,
                                            },
                                            None => BlockTxResponse::NotFound,
                                        }
                                    }

                                    BlockTxRequest::GetTx { ref hash } => self
                                        .mempool
                                        .get_transaction(hash)
                                        .ok()
                                        .flatten()
                                        .map(|tx| BlockTxResponse::TxData(Box::new(tx)))
                                        .unwrap_or(BlockTxResponse::NotFound),

                                    BlockTxRequest::GetBatchByIndex { index } => {
                                        match self.db.get_batch_bytes_by_index(index).ok().flatten()
                                        {
                                            Some(bytes) => {
                                                if exceeds_consensus_cap(bytes.len()) {
                                                    BlockTxResponse::NotFound
                                                } else {
                                                    let bytes_u64 =
                                                        usize_to_u64_saturating(bytes.len());

                                                    match self
                                                        .last_resort
                                                        .check_bytes(now, peer_id, bytes_u64)
                                                    {
                                                        LastResortDecision::Allow => {
                                                            BlockTxResponse::BatchData(bytes)
                                                        }
                                                        LastResortDecision::Drop(drop) => {
                                                            self.handle_last_resort_drop(
                                                                swarm,
                                                                peer_id,
                                                                drop,
                                                                "BlockTx(Request::GetBatchByIndex::Bytes)",
                                                            );
                                                            BlockTxResponse::NotFound
                                                        }
                                                    }
                                                }
                                            }
                                            None => BlockTxResponse::NotFound,
                                        }
                                    }

                                    BlockTxRequest::GetBatchByHash { ref hash } => {
                                        match self.db.get_batch_by_block_hash(hash).ok().flatten() {
                                            Some(bytes) => {
                                                if exceeds_consensus_cap(bytes.len()) {
                                                    BlockTxResponse::NotFound
                                                } else {
                                                    let bytes_u64 =
                                                        usize_to_u64_saturating(bytes.len());

                                                    match self
                                                        .last_resort
                                                        .check_bytes(now, peer_id, bytes_u64)
                                                    {
                                                        LastResortDecision::Allow => {
                                                            BlockTxResponse::BatchData(bytes)
                                                        }
                                                        LastResortDecision::Drop(drop) => {
                                                            self.handle_last_resort_drop(
                                                                swarm,
                                                                peer_id,
                                                                drop,
                                                                "BlockTx(Request::GetBatchByHash::Bytes)",
                                                            );
                                                            BlockTxResponse::NotFound
                                                        }
                                                    }
                                                }
                                            }
                                            None => BlockTxResponse::NotFound,
                                        }
                                    }

                                    BlockTxRequest::GetBlockByIndex { index } => {
                                        match self.db.get_block_hash_by_index(index).ok() {
                                            Some(h) => match self.db.get_block_by_hash(&h) {
                                                Some(b) => match b.serialize_for_storage() {
                                                    Ok(bytes) => {
                                                        if exceeds_consensus_cap(bytes.len()) {
                                                            BlockTxResponse::NotFound
                                                        } else {
                                                            let bytes_u64 = usize_to_u64_saturating(
                                                                bytes.len(),
                                                            );

                                                            match self.last_resort.check_bytes(
                                                                now, peer_id, bytes_u64,
                                                            ) {
                                                                LastResortDecision::Allow => {
                                                                    BlockTxResponse::BlockData(
                                                                        Box::new(b),
                                                                    )
                                                                }
                                                                LastResortDecision::Drop(drop) => {
                                                                    self.handle_last_resort_drop(
                                                                        swarm,
                                                                        peer_id,
                                                                        drop,
                                                                        "BlockTx(Request::GetBlockByIndex::Bytes)",
                                                                    );
                                                                    BlockTxResponse::NotFound
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(_) => BlockTxResponse::NotFound,
                                                },
                                                None => BlockTxResponse::NotFound,
                                            },
                                            None => BlockTxResponse::NotFound,
                                        }
                                    }
                                };

                                _ = swarm.behaviour_mut().blocktx.send_response(channel, resp);
                            }
                        }
                    }

                    Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    } => {
                        if let Some((origin_peer, idx, retries_left)) =
                            self.pending_blocks.remove(&request_id)
                        {
                            if let Ok(mut pb) = self.peerbook.lock() {
                                pb.observe_failure(&origin_peer);
                                _ = pb.save();
                            }

                            if matches!(error, OutboundFailure::Timeout) {
                                self.last_resort
                                    .report_misbehavior(Instant::now(), origin_peer, 1);
                            }

                            if retries_left > 0 && !self.db_has_block_index(idx) {
                                let next_retries = retries_left.saturating_sub(1);

                                let retry_peer = self.pick_retry_peer(&*swarm, origin_peer).filter(
                                    |candidate| *candidate != origin_peer && *candidate != peer,
                                );

                                if let Some(retry_peer) = retry_peer {
                                    self.push_block_retry(retry_peer, idx, next_retries);
                                }
                            }
                        } else if let Some(pending_batch) = self.pending_batches.remove(&request_id)
                        {
                            let origin_peer = pending_batch.peer;
                            let idx = pending_batch.idx;
                            let retries_left = pending_batch.retries_left;

                            if let Ok(mut pb) = self.peerbook.lock() {
                                pb.observe_failure(&origin_peer);
                                _ = pb.save();
                            }

                            if matches!(error, OutboundFailure::Timeout) {
                                self.last_resort
                                    .report_misbehavior(Instant::now(), origin_peer, 1);
                            }

                            let applied = self.db.get_addr_index_height().unwrap_or(0);
                            if retries_left > 0 && idx > applied {
                                let next_retries = retries_left.saturating_sub(1);

                                let retry_peer = self.pick_retry_peer(&*swarm, origin_peer).filter(
                                    |candidate| *candidate != origin_peer && *candidate != peer,
                                );

                                if let Some(retry_peer) = retry_peer {
                                    self.push_batch_retry(retry_peer, idx, next_retries);
                                }
                            }
                        } else {
                            match self.branch_hydration.on_request_failed(request_id) {
                                HydrationFailure::RetryScheduled { .. } => {
                                    self.drive_branch_hydration_requests(swarm);
                                }
                                HydrationFailure::Exhausted { .. }
                                | HydrationFailure::UnknownRequest => {}
                            }
                        }
                    }

                    Event::InboundFailure { .. } | Event::ResponseSent { .. } => {}
                }
            }

            _ => {}
        }

        let now = Instant::now();
        let timed_out = self.conn_guard.sweep_timeouts(now);
        for pid in timed_out {
            self.cleanup_pending_for_peer(&*swarm, pid, false);
            self.clear_pq_peer_state(&pid);

            _ = swarm.disconnect_peer_id(pid);
        }

        if self.syncing
            && self.pending_blocks.is_empty()
            && self.pending_blocks.len() < MAX_PENDING_BLOCKS
        {
            while let Some((peer, idx, retries_left)) = self.block_queue.pop_front() {
                if self.db_has_block_index(idx) {
                    let applied = self.db.get_addr_index_height().unwrap_or(0);

                    if idx > applied {
                        let issued =
                            self.issue_batch_request_if_absent(swarm, peer, idx, MAX_RETRIES);

                        if issued {
                            break;
                        }
                    }

                    continue;
                }

                let issued = self.issue_block_request_if_absent(swarm, peer, idx, retries_left);

                if issued {
                    break;
                }
            }
        }

        if self.syncing
            && self.pending_batches.is_empty()
            && self.pending_batches.len() < MAX_PENDING_BATCHES
        {
            while let Some((peer, idx, retries_left)) = self.batch_queue.pop_front() {
                let applied = self.db.get_addr_index_height().unwrap_or(0);

                if idx <= applied {
                    continue;
                }

                let issued = self.issue_batch_request_if_absent(swarm, peer, idx, retries_left);

                if issued {
                    break;
                }
            }
        }

        self.reissue_idle_sync_work_if_needed(swarm);

        self.drive_branch_hydration_requests(swarm);
        self.autodial_known_peers(swarm);
        self.kad_periodic_bootstrap(swarm);
        self.kad_random_walk(swarm);

        self.update_sync_state();

        if self.has_synced && !self.syncing {
            let tip = self.db.get_tip_height().unwrap_or(0);
            let idx = self.db.get_addr_index_height().unwrap_or(0);

            if tip > idx {
                self.chain.reload_from_db();
                _ = self.db.set_addr_index_height(tip);
            }
        }
    }
}
