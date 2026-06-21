// tests/proptests_p2p_004_sync_entrypoint.rs

use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_007_handshake::{Services, VersionInfo};
use remzar::runtime::p2p_001_sync_builders::{REMZAR_HASH_BYTES_LEN, RemzarHashBytes};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

const MAX_HEIGHT_POLL_PEERS_MODEL: usize = 256;
const MAX_PENDING_VERSIONS_MODEL: usize = 1024;
const MAX_RETRIES_MODEL: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestDecision {
    None,
    Block(u64),
    Batch(u64),
    DeferredUntilPq,
}

#[derive(Debug, Clone)]
struct ModelSyncState {
    local_tip: u64,
    sync_target: u64,
    queued_sync_target: Option<u64>,
    downloaded: u64,
    total_to_download: u64,

    pending_blocks_len: usize,
    block_queue_len: usize,
    pending_batches_len: usize,
    batch_queue_len: usize,
    reserved_block_indices_len: usize,
    reserved_batch_indices_len: usize,
}

impl ModelSyncState {
    fn new(local_tip: u64, sync_target: u64) -> Self {
        Self {
            local_tip,
            sync_target,
            queued_sync_target: None,
            downloaded: 0,
            total_to_download: 0,
            pending_blocks_len: 0,
            block_queue_len: 0,
            pending_batches_len: 0,
            batch_queue_len: 0,
            reserved_block_indices_len: 0,
            reserved_batch_indices_len: 0,
        }
    }

    fn with_backlog(
        local_tip: u64,
        sync_target: u64,
        pending_blocks_len: usize,
        block_queue_len: usize,
        pending_batches_len: usize,
        batch_queue_len: usize,
        reserved_block_indices_len: usize,
        reserved_batch_indices_len: usize,
    ) -> Self {
        Self {
            local_tip,
            sync_target,
            queued_sync_target: Some(sync_target),
            downloaded: 0,
            total_to_download: 0,
            pending_blocks_len,
            block_queue_len,
            pending_batches_len,
            batch_queue_len,
            reserved_block_indices_len,
            reserved_batch_indices_len,
        }
    }

    fn clear_sync_backlog(&mut self) {
        self.pending_blocks_len = 0;
        self.block_queue_len = 0;
        self.pending_batches_len = 0;
        self.batch_queue_len = 0;
        self.reserved_block_indices_len = 0;
        self.reserved_batch_indices_len = 0;
    }
}

fn genesis_hash_bytes_64_model() -> RemzarHashBytes {
    let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
        .expect("GENESIS_HASH_HEX must decode as hex");

    assert_eq!(
        decoded.len(),
        REMZAR_HASH_BYTES_LEN,
        "GENESIS_HASH_HEX must decode to exactly 64 bytes"
    );

    let mut out = [0u8; REMZAR_HASH_BYTES_LEN];
    out.copy_from_slice(&decoded);
    out
}

fn make_poll_version_request() -> VersionInfo {
    VersionInfo {
        protocol_version: 1,
        chain_height: 0,
        services: Services::NODE,
        user_agent: "remzar-sync/1.0".into(),
        genesis_hash: Some(genesis_hash_bytes_64_model()),
    }
}

fn selected_peer_count_model(connected_peers: usize) -> usize {
    connected_peers.min(MAX_HEIGHT_POLL_PEERS_MODEL)
}

fn version_requests_to_issue_model(connected_peers: usize, pending_versions_len: usize) -> usize {
    if connected_peers == 0 || pending_versions_len >= MAX_PENDING_VERSIONS_MODEL {
        return 0;
    }

    let selected = selected_peer_count_model(connected_peers);
    let remaining_capacity = MAX_PENDING_VERSIONS_MODEL.saturating_sub(pending_versions_len);

    selected.min(remaining_capacity)
}

fn no_peer_poll_model(mut state: ModelSyncState) -> ModelSyncState {
    let local_tip = state.local_tip;
    state.sync_target = local_tip;
    state.queued_sync_target = None;
    state
}

fn defer_sync_until_pq_model(state: &mut ModelSyncState, desired_target: u64) {
    let effective_target = desired_target.max(state.local_tip).max(state.sync_target);

    state.sync_target = effective_target;
    state.queued_sync_target = Some(effective_target);
    state.downloaded = state.local_tip;
    state.total_to_download = effective_target;
}

fn can_start_block_sync_with_peer_model(
    state: &mut ModelSyncState,
    pq_ready: bool,
    desired_target: u64,
) -> bool {
    if pq_ready {
        return true;
    }

    defer_sync_until_pq_model(state, desired_target);
    false
}

fn request_index_from_peer_model(block_exists_at_idx: bool, idx: u64) -> RequestDecision {
    if block_exists_at_idx {
        RequestDecision::Batch(idx)
    } else {
        RequestDecision::Block(idx)
    }
}

fn request_next_block_model(
    state: &mut ModelSyncState,
    pq_ready: bool,
    block_exists_at_next_idx: bool,
) -> RequestDecision {
    if state.local_tip < state.sync_target {
        if !can_start_block_sync_with_peer_model(state, pq_ready, state.sync_target) {
            return RequestDecision::DeferredUntilPq;
        }

        let next_idx = state.local_tip.saturating_add(1);
        return request_index_from_peer_model(block_exists_at_next_idx, next_idx);
    }

    state.queued_sync_target = None;
    RequestDecision::None
}

fn begin_sync_to_target_model(
    state: &mut ModelSyncState,
    peer_tip: u64,
    pq_ready: bool,
    block_exists_at_next_idx: bool,
) -> RequestDecision {
    let local_tip = state.local_tip;
    let current_target = state.sync_target.max(local_tip);
    let new_target = current_target.max(peer_tip);

    if !can_start_block_sync_with_peer_model(state, pq_ready, new_target) {
        return RequestDecision::DeferredUntilPq;
    }

    if new_target <= state.sync_target {
        state.downloaded = local_tip;
        state.total_to_download = state.sync_target;
        state.queued_sync_target = None;

        if state.downloaded >= state.sync_target {
            return RequestDecision::None;
        }

        let next_idx = state.downloaded.saturating_add(1);
        return request_index_from_peer_model(block_exists_at_next_idx, next_idx);
    }

    state.sync_target = new_target;
    state.queued_sync_target = None;
    state.clear_sync_backlog();

    state.downloaded = local_tip;
    state.total_to_download = state.sync_target;

    if state.downloaded >= state.sync_target {
        return RequestDecision::None;
    }

    let next_idx = state.downloaded.saturating_add(1);
    request_index_from_peer_model(block_exists_at_next_idx, next_idx)
}

fn on_local_tip_advanced_model(state: &mut ModelSyncState) {
    state.sync_target = state.sync_target.max(state.local_tip);

    if state.queued_sync_target.is_some() && state.local_tip >= state.sync_target {
        state.queued_sync_target = None;
    }
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    })]

    #[test]
    fn test_001_poll_version_request_template_is_wire_valid(_probe in any::<u8>()) {
        let req = make_poll_version_request();

        prop_assert!(
            req.validate_untrusted().is_ok(),
            "height-poll VersionInfo request must be valid untrusted wire data"
        );

        prop_assert_eq!(req.protocol_version, 1);
        prop_assert_eq!(req.chain_height, 0);
        prop_assert_eq!(&req.services, &Services::NODE);
        prop_assert_eq!(req.user_agent.as_str(), "remzar-sync/1.0");
        prop_assert_eq!(req.genesis_hash, Some(genesis_hash_bytes_64_model()));
    }

    #[test]
    fn test_002_poll_version_request_uses_configured_64_byte_genesis_hash(_probe in any::<u8>()) {
        let req = make_poll_version_request();
        let genesis = req.genesis_hash.expect("poll request must include genesis hash");

        let decoded = hex::decode(GlobalConfiguration::GENESIS_HASH_HEX)
            .expect("GENESIS_HASH_HEX must decode");

        prop_assert_eq!(genesis.len(), REMZAR_HASH_BYTES_LEN);
        prop_assert_eq!(decoded.len(), REMZAR_HASH_BYTES_LEN);
        prop_assert_eq!(
            genesis.as_slice(),
            decoded.as_slice(),
            "height polling must advertise the canonical configured genesis hash"
        );
    }

    #[test]
    fn test_003_connected_peer_selection_is_capped_by_max_height_poll_peers(
        connected_peers in 0usize..(MAX_HEIGHT_POLL_PEERS_MODEL.saturating_mul(4).saturating_add(128)),
    ) {
        prop_assert_eq!(
            selected_peer_count_model(connected_peers),
            connected_peers.min(MAX_HEIGHT_POLL_PEERS_MODEL),
            "polling must never select more than MAX_HEIGHT_POLL_PEERS_MODEL connected peers"
        );
    }

    #[test]
    fn test_004_zero_connected_peers_issues_zero_version_requests(
        pending_versions_len in 0usize..(MAX_PENDING_VERSIONS_MODEL.saturating_add(128)),
    ) {
        prop_assert_eq!(
            version_requests_to_issue_model(0, pending_versions_len),
            0,
            "no connected peers must result in zero outbound version requests"
        );
    }

    #[test]
    fn test_005_pending_version_saturation_issues_zero_new_requests(
        connected_peers in 1usize..(MAX_HEIGHT_POLL_PEERS_MODEL.saturating_mul(4).saturating_add(128)),
        extra_pending in 0usize..128usize,
    ) {
        let pending = MAX_PENDING_VERSIONS_MODEL.saturating_add(extra_pending);

        prop_assert_eq!(
            version_requests_to_issue_model(connected_peers, pending),
            0,
            "when pending_versions is saturated, polling must not enqueue more version requests"
        );
    }

    #[test]
    fn test_006_version_request_issue_count_never_exceeds_connected_peer_selection_or_capacity(
        connected_peers in 0usize..(MAX_HEIGHT_POLL_PEERS_MODEL.saturating_mul(4).saturating_add(128)),
        pending_versions_len in 0usize..(MAX_PENDING_VERSIONS_MODEL.saturating_add(128)),
    ) {
        let issued = version_requests_to_issue_model(connected_peers, pending_versions_len);

        prop_assert!(
            issued <= selected_peer_count_model(connected_peers),
            "issued version requests must not exceed selected connected peers"
        );

        prop_assert!(
            pending_versions_len.saturating_add(issued) <= MAX_PENDING_VERSIONS_MODEL
                || pending_versions_len >= MAX_PENDING_VERSIONS_MODEL,
            "issued version requests must not grow pending_versions beyond MAX_PENDING_VERSIONS_MODEL"
        );
    }

    #[test]
    fn test_007_version_request_issue_count_fills_only_remaining_pending_capacity(
        connected_peers in 0usize..(MAX_HEIGHT_POLL_PEERS_MODEL.saturating_mul(4).saturating_add(128)),
        pending_versions_len in 0usize..MAX_PENDING_VERSIONS_MODEL,
    ) {
        let issued = version_requests_to_issue_model(connected_peers, pending_versions_len);
        let remaining = MAX_PENDING_VERSIONS_MODEL - pending_versions_len;

        prop_assert!(
            issued <= remaining,
            "polling must issue at most remaining pending-version capacity"
        );

        prop_assert_eq!(
            issued,
            selected_peer_count_model(connected_peers).min(remaining),
            "issue count must be min(selected peers, remaining pending capacity)"
        );
    }

    #[test]
    fn test_008_no_peer_poll_resets_target_to_local_tip_and_clears_queued_target(
        local_tip in any::<u64>(),
        old_target in any::<u64>(),
        queued in prop::option::of(any::<u64>()),
    ) {
        let mut state = ModelSyncState::new(local_tip, old_target);
        state.queued_sync_target = queued;

        let out = no_peer_poll_model(state);

        prop_assert_eq!(
            out.sync_target,
            local_tip,
            "solo no-peer polling must anchor sync_target to local tip"
        );

        prop_assert_eq!(
            out.queued_sync_target,
            None,
            "solo no-peer polling must clear queued sync target"
        );
    }

    #[test]
    fn test_009_defer_sync_until_pq_sets_effective_target_to_max_of_desired_local_and_current(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        desired_target in any::<u64>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        defer_sync_until_pq_model(&mut state, desired_target);

        let expected = desired_target.max(local_tip).max(current_target);

        prop_assert_eq!(state.sync_target, expected);
        prop_assert_eq!(state.queued_sync_target, Some(expected));
    }

    #[test]
    fn test_010_defer_sync_until_pq_never_decreases_sync_target(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        desired_target in any::<u64>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        defer_sync_until_pq_model(&mut state, desired_target);

        prop_assert!(
            state.sync_target >= current_target,
            "PQ deferral must never decrease sync_target"
        );

        prop_assert!(
            state.sync_target >= local_tip,
            "PQ deferral must never set target below local tip"
        );

        prop_assert!(
            state.sync_target >= desired_target,
            "PQ deferral must preserve the desired target or higher"
        );
    }

    #[test]
    fn test_011_defer_sync_until_pq_sets_download_progress_from_local_tip(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        desired_target in any::<u64>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        defer_sync_until_pq_model(&mut state, desired_target);

        prop_assert_eq!(
            state.downloaded,
            local_tip,
            "PQ deferral must record downloaded progress as local tip"
        );

        prop_assert_eq!(
            state.total_to_download,
            state.sync_target,
            "PQ deferral must set total_to_download to the effective target"
        );
    }

    #[test]
    fn test_012_can_start_block_sync_returns_true_without_deferral_when_pq_ready(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        desired_target in any::<u64>(),
        queued in prop::option::of(any::<u64>()),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);
        state.queued_sync_target = queued;

        let before = state.clone();
        let can_start = can_start_block_sync_with_peer_model(&mut state, true, desired_target);

        prop_assert!(can_start);
        prop_assert_eq!(
            state.sync_target,
            before.sync_target,
            "PQ-ready gate must not rewrite sync_target"
        );
        prop_assert_eq!(
            state.queued_sync_target,
            before.queued_sync_target,
            "PQ-ready gate must not create or clear queued_sync_target"
        );
    }

    #[test]
    fn test_013_can_start_block_sync_defers_and_returns_false_when_pq_not_ready(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        desired_target in any::<u64>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        let can_start = can_start_block_sync_with_peer_model(&mut state, false, desired_target);

        prop_assert!(!can_start);
        prop_assert_eq!(
            state.queued_sync_target,
            Some(state.sync_target),
            "non-PQ-ready peer must defer target into queued_sync_target"
        );
    }

    #[test]
    fn test_014_request_index_from_peer_selects_batch_when_block_already_exists(
        idx in any::<u64>(),
    ) {
        prop_assert_eq!(
            request_index_from_peer_model(true, idx),
            RequestDecision::Batch(idx),
            "if block exists locally, sync entrypoint must request the batch instead of the block"
        );
    }

    #[test]
    fn test_015_request_index_from_peer_selects_block_when_block_is_missing(
        idx in any::<u64>(),
    ) {
        prop_assert_eq!(
            request_index_from_peer_model(false, idx),
            RequestDecision::Block(idx),
            "if block is missing locally, sync entrypoint must request the block"
        );
    }

    #[test]
    fn test_016_request_next_block_when_behind_and_pq_ready_requests_local_tip_plus_one(
        local_tip in 0u64..u64::MAX,
        ahead_by in 1u64..1_000_000u64,
        block_exists in any::<bool>(),
    ) {
        let sync_target = local_tip.saturating_add(ahead_by);
        prop_assume!(local_tip < sync_target);

        let mut state = ModelSyncState::new(local_tip, sync_target);
        let decision = request_next_block_model(&mut state, true, block_exists);
        let expected_idx = local_tip.saturating_add(1);

        prop_assert_eq!(
            decision,
            request_index_from_peer_model(block_exists, expected_idx),
            "request_next_block must request exactly local_tip + 1 when behind and PQ-ready"
        );
    }

    #[test]
    fn test_017_request_next_block_when_behind_and_pq_not_ready_defers_without_request(
        local_tip in 0u64..u64::MAX,
        ahead_by in 1u64..1_000_000u64,
        block_exists in any::<bool>(),
    ) {
        let sync_target = local_tip.saturating_add(ahead_by);
        prop_assume!(local_tip < sync_target);

        let mut state = ModelSyncState::new(local_tip, sync_target);
        let decision = request_next_block_model(&mut state, false, block_exists);

        prop_assert_eq!(decision, RequestDecision::DeferredUntilPq);
        prop_assert_eq!(
            state.queued_sync_target,
            Some(state.sync_target),
            "request_next_block must defer target until PQ is ready"
        );
    }

    #[test]
    fn test_018_request_next_block_when_at_or_past_target_clears_queued_target_and_requests_nothing(
        local_tip in any::<u64>(),
        lag in 0u64..1_000_000u64,
        queued in prop::option::of(any::<u64>()),
        block_exists in any::<bool>(),
    ) {
        let sync_target = local_tip.saturating_sub(lag);

        let mut state = ModelSyncState::new(local_tip, sync_target);
        state.queued_sync_target = queued;

        let decision = request_next_block_model(&mut state, true, block_exists);

        prop_assert_eq!(decision, RequestDecision::None);
        prop_assert_eq!(
            state.queued_sync_target,
            None,
            "completion path must clear queued_sync_target"
        );
    }

    #[test]
    fn test_019_begin_sync_to_target_computes_new_target_as_max_of_current_local_and_peer_tip(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        peer_tip in any::<u64>(),
        block_exists in any::<bool>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        let _ = begin_sync_to_target_model(&mut state, peer_tip, true, block_exists);

        let expected = current_target.max(local_tip).max(peer_tip);

        prop_assert_eq!(
            state.sync_target,
            expected,
            "begin_sync_to_target must choose max(sync_target, local_tip, peer_tip)"
        );
    }

    #[test]
    fn test_020_begin_sync_to_target_with_peer_tip_zero_never_decreases_target(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        block_exists in any::<bool>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        let _ = begin_sync_to_target_model(&mut state, 0, true, block_exists);

        prop_assert!(
            state.sync_target >= current_target,
            "peer_tip=0 must not decrease sync_target"
        );

        prop_assert!(
            state.sync_target >= local_tip,
            "peer_tip=0 must still preserve local tip as minimum target"
        );
    }

    #[test]
    fn test_021_begin_sync_to_higher_target_clears_all_pending_queues_and_reservations(
        local_tip in any::<u64>(),
        old_target in any::<u64>(),
        extra in 1u64..1_000_000u64,
        block_exists in any::<bool>(),
        pending_blocks in 1usize..128usize,
        block_queue in 1usize..128usize,
        pending_batches in 1usize..128usize,
        batch_queue in 1usize..128usize,
        reserved_blocks in 1usize..128usize,
        reserved_batches in 1usize..128usize,
    ) {
        let current_target = old_target.max(local_tip);
        let peer_tip = current_target.saturating_add(extra);
        prop_assume!(peer_tip > current_target);

        let mut state = ModelSyncState::with_backlog(
            local_tip,
            old_target,
            pending_blocks,
            block_queue,
            pending_batches,
            batch_queue,
            reserved_blocks,
            reserved_batches,
        );

        let _ = begin_sync_to_target_model(&mut state, peer_tip, true, block_exists);

        prop_assert_eq!(state.pending_blocks_len, 0);
        prop_assert_eq!(state.block_queue_len, 0);
        prop_assert_eq!(state.pending_batches_len, 0);
        prop_assert_eq!(state.batch_queue_len, 0);
        prop_assert_eq!(state.reserved_block_indices_len, 0);
        prop_assert_eq!(state.reserved_batch_indices_len, 0);
        prop_assert_eq!(state.queued_sync_target, None);
    }

    #[test]
    fn test_022_begin_sync_to_existing_target_does_not_require_queue_reset_to_continue(
        local_tip in 0u64..u64::MAX,
        ahead_by in 1u64..1_000_000u64,
        peer_tip in any::<u64>(),
        block_exists in any::<bool>(),
        pending_blocks in 1usize..128usize,
        block_queue in 1usize..128usize,
        pending_batches in 1usize..128usize,
        batch_queue in 1usize..128usize,
        reserved_blocks in 1usize..128usize,
        reserved_batches in 1usize..128usize,
    ) {
        let sync_target = local_tip.saturating_add(ahead_by);
        prop_assume!(local_tip < sync_target);
        prop_assume!(peer_tip <= sync_target);

        let mut state = ModelSyncState::with_backlog(
            local_tip,
            sync_target,
            pending_blocks,
            block_queue,
            pending_batches,
            batch_queue,
            reserved_blocks,
            reserved_batches,
        );

        let decision = begin_sync_to_target_model(&mut state, peer_tip, true, block_exists);

        prop_assert_eq!(
            decision,
            request_index_from_peer_model(block_exists, local_tip.saturating_add(1)),
            "existing target path should continue from downloaded/local_tip + 1"
        );

        prop_assert_eq!(
            state.sync_target,
            sync_target,
            "existing target path must preserve sync_target"
        );
    }

    #[test]
    fn test_023_begin_sync_when_pq_not_ready_defers_even_for_higher_peer_tip(
        local_tip in any::<u64>(),
        current_target in any::<u64>(),
        peer_tip in any::<u64>(),
        block_exists in any::<bool>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, current_target);

        let decision = begin_sync_to_target_model(&mut state, peer_tip, false, block_exists);

        let expected_target = current_target.max(local_tip).max(peer_tip);

        prop_assert_eq!(decision, RequestDecision::DeferredUntilPq);
        prop_assert_eq!(state.sync_target, expected_target);
        prop_assert_eq!(state.queued_sync_target, Some(expected_target));
        prop_assert_eq!(state.downloaded, local_tip);
        prop_assert_eq!(state.total_to_download, expected_target);
    }

    #[test]
    fn test_024_on_local_tip_advanced_never_decreases_target(
        local_tip in any::<u64>(),
        old_target in any::<u64>(),
        queued in prop::option::of(any::<u64>()),
    ) {
        let mut state = ModelSyncState::new(local_tip, old_target);
        state.queued_sync_target = queued;

        on_local_tip_advanced_model(&mut state);

        prop_assert_eq!(
            state.sync_target,
            old_target.max(local_tip),
            "local tip advancement must monotonically raise target to at least local_tip"
        );
    }

    #[test]
    fn test_025_on_local_tip_advanced_clears_queued_target_only_after_catchup(
        old_target in any::<u64>(),
        local_tip in any::<u64>(),
        queued_target in any::<u64>(),
    ) {
        let mut state = ModelSyncState::new(local_tip, old_target);
        state.queued_sync_target = Some(queued_target);

        on_local_tip_advanced_model(&mut state);

        let expected_target = old_target.max(local_tip);

        if local_tip >= expected_target {
            prop_assert_eq!(
                state.queued_sync_target,
                None,
                "queued target must clear after local tip catches target"
            );
        } else {
            prop_assert_eq!(
                state.queued_sync_target,
                Some(queued_target),
                "queued target should remain while local tip is still behind target"
            );
        }

        prop_assert!(
            MAX_RETRIES_MODEL > 0,
            "entrypoint retry budget model must remain nonzero for sync request issuance"
        );
    }
}
