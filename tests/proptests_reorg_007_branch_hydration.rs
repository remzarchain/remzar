use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;
use libp2p::{PeerId, request_response::OutboundRequestId};

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_007_branch_hydration::{
    BlockHash, Hydration, HydrationAdvance, HydrationConfig, HydrationFailure, HydrationReason,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const UNIX_2000: u64 = 946_684_800;

static NEXT_PEER_SEED: AtomicU64 = AtomicU64::new(1);

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp())
        .unwrap_or(UNIX_2000)
        .max(UNIX_2000)
}

fn valid_timestamp(seed: u64) -> u64 {
    let now = now_secs();
    let span = now.saturating_sub(UNIX_2000).saturating_add(1);

    UNIX_2000.saturating_add(seed % span)
}

fn hash64(tag: u8, seed: u64) -> BlockHash {
    let fill = match tag {
        0 => 1,
        0xFF => 0xFE,
        value => value,
    };

    let mut out = [fill; 64];
    out[..8].copy_from_slice(&seed.to_be_bytes());

    if out == [0u8; 64] {
        out[63] = 1;
    }

    if out == [0xFFu8; 64] {
        out[63] = 0xFE;
    }

    out
}

fn distinct_hash64(tag: u8, seed: u64, other: BlockHash) -> BlockHash {
    let mut out = hash64(tag, seed);

    if out == other {
        out[63] ^= 1;

        if out == [0u8; 64] || out == [0xFFu8; 64] {
            out[63] = 0x7F;
        }
    }

    out
}

fn wallet(seed: u64) -> String {
    format!("r{:0128x}", seed)
}

fn signature(seed: u64, tag: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let base = u8::try_from(seed % 200).expect("seed modulo 200 must fit into u8");
    let byte = base.saturating_add(tag.max(1));

    [byte; ml_dsa_65::SIG_LEN]
}

fn block_with_parent(height: u64, parent_hash: BlockHash, seed: u64, tag: u8) -> Block {
    if height == 0 {
        assert_eq!(
            parent_hash, [0u8; 64],
            "height zero test block must use zero previous_hash"
        );
    } else {
        assert_ne!(
            parent_hash, [0u8; 64],
            "non-genesis test block must use nonzero previous_hash"
        );
    }

    let mut merkle_root = hash64(tag.wrapping_add(0x80), seed.wrapping_add(1));

    if merkle_root == parent_hash {
        merkle_root[63] ^= 1;
    }

    let metadata = BlockMetadata::new(
        height,
        valid_timestamp(seed),
        parent_hash,
        merkle_root,
        signature(seed, tag),
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_hydration_{height}_{seed}_{tag}")),
        wallet(seed.wrapping_add(u64::from(tag))),
        0,
    )
    .expect("generated valid hydration test block should construct")
}

fn genesis_block(seed: u64, tag: u8) -> Block {
    block_with_parent(0, [0u8; 64], seed, tag)
}

fn child_block(parent: &Block, seed: u64, tag: u8) -> Block {
    block_with_parent(
        parent.metadata.index.saturating_add(1),
        parent.block_hash,
        seed,
        tag,
    )
}

fn cfg(
    max_retries_per_hash: u8,
    retry_cooldown_ms: u64,
    max_tracked_hashes: usize,
    auto_chase_parent: bool,
) -> HydrationConfig {
    HydrationConfig {
        max_retries_per_hash,
        retry_cooldown: Duration::from_millis(retry_cooldown_ms),
        max_tracked_hashes,
        auto_chase_parent,
    }
}

fn fast_cfg(
    max_retries_per_hash: u8,
    max_tracked_hashes: usize,
    auto_chase_parent: bool,
) -> HydrationConfig {
    cfg(
        max_retries_per_hash,
        0,
        max_tracked_hashes,
        auto_chase_parent,
    )
}

fn peer() -> PeerId {
    let _ = NEXT_PEER_SEED.fetch_add(1, Ordering::Relaxed);
    PeerId::random()
}

fn req_id(seed: u64) -> OutboundRequestId {
    let value = seed.saturating_add(1);

    unsafe { std::mem::transmute::<u64, OutboundRequestId>(value) }
}

fn note(
    hydration: &mut Hydration,
    peer: PeerId,
    hash: BlockHash,
    height: Option<u64>,
    reason: HydrationReason,
    context: &'static str,
) {
    hydration.note_need_more_data(peer, hash, height, reason, context);
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_default_config_and_default_mainnet_start_empty(
        _case in any::<u8>(),
    ) {
        let cfg = HydrationConfig::default();

        prop_assert_eq!(cfg.max_retries_per_hash, 6);
        prop_assert_eq!(cfg.retry_cooldown, Duration::from_millis(800));
        prop_assert_eq!(cfg.max_tracked_hashes, 4096);
        prop_assert!(cfg.auto_chase_parent);

        let hydration = Hydration::default_mainnet();

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(hydration.snapshot_lines().is_empty());
    }

    // 02/25
    #[test]
    fn test_002_new_with_custom_config_starts_empty_and_does_not_emit_requests(
        max_retries in 1u8..16u8,
        cap in 1usize..64usize,
        auto_chase in any::<bool>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(max_retries, cap, auto_chase));

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(hydration.next_request().is_none());
    }

    // 03/25
    #[test]
    fn test_003_note_need_more_data_tracks_hash_and_schedules_one_request(
        hash_seed in any::<u64>(),
        source_height in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let hash = hash64(0x11, hash_seed);

        note(
            &mut hydration,
            peer,
            hash,
            Some(source_height),
            HydrationReason::ForkChoiceNeedMoreData,
            "fork-choice missing parent",
        );

        prop_assert_eq!(hydration.tracked_len(), 1);
        prop_assert!(hydration.is_tracking(&hash));
        prop_assert!(!hydration.is_inflight_hash(&hash));

        let next = hydration
            .next_request()
            .expect("newly noted missing hash must be schedulable");

        prop_assert_eq!(next, (peer, hash));
        prop_assert!(
            hydration.next_request().is_none(),
            "queue must not duplicate a single note"
        );
    }

    // 04/25
    #[test]
    fn test_004_repeated_note_for_same_hash_deduplicates_and_refreshes_peer_reason_context(
        hash_seed in any::<u64>(),
        source_height in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let first_peer = peer();
        let refreshed_peer = peer();
        let hash = hash64(0x12, hash_seed);

        note(
            &mut hydration,
            first_peer,
            hash,
            None,
            HydrationReason::Explicit,
            "old context",
        );

        note(
            &mut hydration,
            refreshed_peer,
            hash,
            Some(source_height),
            HydrationReason::MissingParent,
            "new context",
        );

        prop_assert_eq!(
            hydration.tracked_len(),
            1,
            "same missing hash must not create duplicate pending entries"
        );

        let next = hydration
            .next_request()
            .expect("deduplicated hash should remain schedulable");

        prop_assert_eq!(
            next,
            (refreshed_peer, hash),
            "duplicate note must refresh the origin peer used by scheduler"
        );

        let lines = hydration.snapshot_lines();
        let expected_source_height = format!("source_height=Some({})", source_height);

        prop_assert_eq!(lines.len(), 1);
        prop_assert!(lines[0].contains("reason=MissingParent"));
        prop_assert!(lines[0].contains("context=new context"));
        prop_assert!(lines[0].contains(&expected_source_height));
    }

    // 05/25
    #[test]
    fn test_005_max_tracked_hashes_refuses_new_hashes_but_allows_refreshing_existing_hash(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 1, true));
        let peer_a = peer();
        let peer_b = peer();
        let hash_a = hash64(0x13, seed_a);
        let hash_b = distinct_hash64(0x14, seed_b, hash_a);

        note(&mut hydration, peer_a, hash_a, Some(10), HydrationReason::Explicit, "first");
        note(&mut hydration, peer_b, hash_b, Some(20), HydrationReason::Explicit, "over cap");

        prop_assert_eq!(
            hydration.tracked_len(),
            1,
            "new hash must be refused once max_tracked_hashes is reached"
        );

        prop_assert!(hydration.is_tracking(&hash_a));
        prop_assert!(!hydration.is_tracking(&hash_b));

        note(&mut hydration, peer_b, hash_a, Some(30), HydrationReason::MissingParent, "refresh");

        prop_assert_eq!(hydration.tracked_len(), 1);

        let next = hydration
            .next_request()
            .expect("existing hash refresh must remain schedulable");

        prop_assert_eq!(
            next,
            (peer_b, hash_a),
            "refresh of already tracked hash must be allowed even when cap is full"
        );
    }

    // 06/25
    #[test]
    fn test_006_mark_issued_moves_hash_to_inflight_and_blocks_rescheduling_until_result(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let hash = hash64(0x15, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(1), HydrationReason::Explicit, "issue");

        let scheduled = hydration
            .next_request()
            .expect("hash should be schedulable before mark_issued");

        prop_assert_eq!(scheduled, (peer, hash));

        hydration.mark_issued(request_id, hash);

        prop_assert_eq!(hydration.inflight_len(), 1);
        prop_assert!(hydration.is_inflight_hash(&hash));
        prop_assert!(
            hydration.next_request().is_none(),
            "in-flight hash must not be rescheduled"
        );
    }

    // 07/25
    #[test]
    fn test_007_mark_issued_for_unknown_hash_is_noop(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let hash = hash64(0x16, hash_seed);

        hydration.mark_issued(req_id(request_seed), hash);

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(!hydration.is_inflight_hash(&hash));
    }

    // 08/25
    #[test]
    fn test_008_request_failed_for_unknown_request_returns_unknown_request_and_preserves_state(
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));

        prop_assert_eq!(
            hydration.on_request_failed(req_id(request_seed)),
            HydrationFailure::UnknownRequest
        );

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
    }

    // 09/25
    #[test]
    fn test_009_request_failed_schedules_retry_and_clears_inflight_flag(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let hash = hash64(0x17, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(7), HydrationReason::ForkChoiceNeedMoreData, "retry");
        let scheduled = hydration.next_request().expect("hash should schedule");
        prop_assert_eq!(scheduled, (peer, hash));

        hydration.mark_issued(request_id, hash);

        prop_assert_eq!(
            hydration.on_request_failed(request_id),
            HydrationFailure::RetryScheduled {
                hash,
                retries_left: 2,
            }
        );

        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(!hydration.is_inflight_hash(&hash));
        prop_assert!(hydration.is_tracking(&hash));

        prop_assert_eq!(
            hydration.next_request(),
            Some((peer, hash)),
            "failed request with retries left must be requeued"
        );
    }

    // 10/25
    #[test]
    fn test_010_request_failed_exhausts_hash_at_zero_retries_and_stops_rescheduling(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(1, 16, true));
        let peer = peer();
        let hash = hash64(0x18, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(8), HydrationReason::Explicit, "exhaust");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));

        hydration.mark_issued(request_id, hash);

        prop_assert_eq!(
            hydration.on_request_failed(request_id),
            HydrationFailure::Exhausted { hash }
        );

        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(hydration.is_tracking(&hash));
        prop_assert!(
            hydration.next_request().is_none(),
            "exhausted hash must not be scheduled again"
        );

        let lines = hydration.snapshot_lines();
        prop_assert_eq!(lines.len(), 1);
        prop_assert!(lines[0].contains("exhausted=true"));
        prop_assert!(lines[0].contains("retries_left=0"));
    }

    // 11/25
    #[test]
    fn test_011_not_found_uses_same_retry_path_as_request_failed(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(4, 16, true));
        let peer = peer();
        let hash = hash64(0x19, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(9), HydrationReason::MissingParent, "not found");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        prop_assert_eq!(
            hydration.on_not_found(request_id),
            HydrationFailure::RetryScheduled {
                hash,
                retries_left: 3,
            }
        );

        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
    }

    // 12/25
    #[test]
    fn test_012_not_found_exhausts_when_last_retry_is_consumed(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(1, 16, true));
        let peer = peer();
        let hash = hash64(0x1A, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(10), HydrationReason::MissingParent, "not found exhausted");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        prop_assert_eq!(
            hydration.on_not_found(request_id),
            HydrationFailure::Exhausted { hash }
        );

        prop_assert!(hydration.next_request().is_none());
        prop_assert!(hydration.is_tracking(&hash));
    }

    // 13/25
    #[test]
    fn test_013_clear_if_known_removes_pending_hash_and_ready_queue_entry(
        hash_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let hash = hash64(0x1B, hash_seed);

        note(&mut hydration, peer, hash, Some(11), HydrationReason::Explicit, "clear");

        prop_assert_eq!(hydration.tracked_len(), 1);
        prop_assert!(hydration.is_tracking(&hash));

        hydration.clear_if_known(&hash);

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert!(!hydration.is_tracking(&hash));
        prop_assert!(hydration.next_request().is_none());
    }

    // 14/25
    #[test]
    fn test_014_clear_if_known_during_inflight_makes_later_failure_unknown_and_clears_inflight_entry(
        hash_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let hash = hash64(0x1C, hash_seed);
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(12), HydrationReason::Explicit, "clear inflight");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));

        hydration.mark_issued(request_id, hash);
        prop_assert_eq!(hydration.inflight_len(), 1);

        hydration.clear_if_known(&hash);

        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(
            hydration.on_request_failed(request_id),
            HydrationFailure::UnknownRequest,
            "failure after clear_if_known must not resurrect pending state"
        );
        prop_assert_eq!(hydration.inflight_len(), 0);
    }

    // 15/25
    #[test]
    fn test_015_on_block_received_for_unknown_request_is_ignored_and_does_not_call_persist(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let block = genesis_block(seed, 0x21);
        let mut persisted = false;

        let advance = hydration
            .on_block_received(
                req_id(request_seed),
                &block,
                |_block| {
                    persisted = true;
                    Ok(())
                },
                |_parent| true,
            )
            .expect("unknown request block receive should not error");

        prop_assert_eq!(advance, HydrationAdvance::Ignored);
        prop_assert!(!persisted);
        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
    }

    // 16/25
    #[test]
    fn test_016_on_block_received_after_pending_was_cleared_is_ignored_and_clears_inflight(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let block = genesis_block(seed, 0x22);
        let hash = block.block_hash;
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(0), HydrationReason::Explicit, "cleared before receive");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        hydration.clear_if_known(&hash);

        let advance = hydration
            .on_block_received(request_id, &block, |_block| Ok(()), |_parent| true)
            .expect("cleared pending receive should not error");

        prop_assert_eq!(advance, HydrationAdvance::Ignored);
        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert_eq!(hydration.tracked_len(), 0);
    }

    // 17/25
    #[test]
    fn test_017_on_block_received_with_wrong_hash_ignores_block_requeues_expected_hash_and_keeps_pending(
        expected_seed in any::<u64>(),
        wrong_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let expected_hash = hash64(0x23, expected_seed);
        let wrong_block = genesis_block(wrong_seed, 0x24);
        prop_assume!(wrong_block.block_hash != expected_hash);

        let request_id = req_id(request_seed);

        note(&mut hydration, peer, expected_hash, Some(0), HydrationReason::Explicit, "wrong hash");
        prop_assert_eq!(hydration.next_request(), Some((peer, expected_hash)));
        hydration.mark_issued(request_id, expected_hash);

        let advance = hydration
            .on_block_received(request_id, &wrong_block, |_block| Ok(()), |_parent| true)
            .expect("wrong block hash should not error");

        prop_assert_eq!(advance, HydrationAdvance::Ignored);
        prop_assert_eq!(hydration.inflight_len(), 0);
        prop_assert!(hydration.is_tracking(&expected_hash));
        prop_assert_eq!(
            hydration.next_request(),
            Some((peer, expected_hash)),
            "wrong-hash response with retries left must requeue expected hash"
        );
    }

    // 18/25
    #[test]
    fn test_018_on_block_received_with_wrong_hash_exhausts_when_last_retry_is_consumed(
        expected_seed in any::<u64>(),
        wrong_seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(1, 16, true));
        let peer = peer();
        let expected_hash = hash64(0x25, expected_seed);
        let wrong_block = genesis_block(wrong_seed, 0x26);
        prop_assume!(wrong_block.block_hash != expected_hash);

        let request_id = req_id(request_seed);

        note(&mut hydration, peer, expected_hash, Some(0), HydrationReason::Explicit, "wrong hash exhausted");
        prop_assert_eq!(hydration.next_request(), Some((peer, expected_hash)));
        hydration.mark_issued(request_id, expected_hash);

        let advance = hydration
            .on_block_received(request_id, &wrong_block, |_block| Ok(()), |_parent| true)
            .expect("wrong block hash should not error");

        prop_assert_eq!(advance, HydrationAdvance::Ignored);
        prop_assert!(hydration.is_tracking(&expected_hash));
        prop_assert!(hydration.next_request().is_none());

        let lines = hydration.snapshot_lines();
        prop_assert_eq!(lines.len(), 1);
        prop_assert!(lines[0].contains("exhausted=true"));
        prop_assert!(lines[0].contains("retries_left=0"));
    }

    // 19/25
    #[test]
    fn test_019_on_block_received_accepts_genesis_block_as_complete_and_removes_pending(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let block = genesis_block(seed, 0x27);
        let hash = block.block_hash;
        let request_id = req_id(request_seed);
        let mut persisted_hash = None;

        note(&mut hydration, peer, hash, Some(0), HydrationReason::Explicit, "genesis receive");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        let advance = hydration
            .on_block_received(
                request_id,
                &block,
                |block| {
                    persisted_hash = Some(block.block_hash);
                    Ok(())
                },
                |_parent| false,
            )
            .expect("valid genesis receive should succeed");

        prop_assert_eq!(advance, HydrationAdvance::AcceptedComplete { hash });
        prop_assert_eq!(persisted_hash, Some(hash));
        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
    }

    // 20/25
    #[test]
    fn test_020_on_block_received_accepts_non_genesis_block_as_complete_when_parent_meta_is_known(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let parent = genesis_block(seed, 0x28);
        let child = child_block(&parent, seed.wrapping_add(1), 0x29);
        let hash = child.block_hash;
        let parent_hash = parent.block_hash;
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(1), HydrationReason::ForkChoiceNeedMoreData, "child receive");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        let advance = hydration
            .on_block_received(request_id, &child, |_block| Ok(()), |hash| *hash == parent_hash)
            .expect("valid child with known parent should succeed");

        prop_assert_eq!(advance, HydrationAdvance::AcceptedComplete { hash });
        prop_assert_eq!(hydration.tracked_len(), 0);
        prop_assert_eq!(hydration.inflight_len(), 0);
    }

    // 21/25
    #[test]
    fn test_021_on_block_received_auto_chases_missing_parent_and_records_child_waiting_on_parent(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let parent = genesis_block(seed, 0x2A);
        let child = child_block(&parent, seed.wrapping_add(1), 0x2B);
        let child_hash = child.block_hash;
        let parent_hash = parent.block_hash;
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, child_hash, Some(1), HydrationReason::ForkChoiceNeedMoreData, "child needs parent");
        prop_assert_eq!(hydration.next_request(), Some((peer, child_hash)));
        hydration.mark_issued(request_id, child_hash);

        let advance = hydration
            .on_block_received(request_id, &child, |_block| Ok(()), |_parent| false)
            .expect("valid child with missing parent should succeed");

        prop_assert_eq!(
            advance,
            HydrationAdvance::AcceptedNeedsParent {
                hash: child_hash,
                missing_parent: parent_hash,
            }
        );

        prop_assert!(!hydration.is_tracking(&child_hash));
        prop_assert!(hydration.is_tracking(&parent_hash));

        prop_assert_eq!(
            hydration.next_request(),
            Some((peer, parent_hash)),
            "missing parent must be scheduled next"
        );
    }

    // 22/25
    #[test]
    fn test_022_auto_chase_disabled_accepts_child_complete_even_when_parent_meta_is_missing(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, false));
        let peer = peer();
        let parent = genesis_block(seed, 0x2C);
        let child = child_block(&parent, seed.wrapping_add(1), 0x2D);
        let hash = child.block_hash;
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, hash, Some(1), HydrationReason::ForkChoiceNeedMoreData, "no auto chase");
        prop_assert_eq!(hydration.next_request(), Some((peer, hash)));
        hydration.mark_issued(request_id, hash);

        let advance = hydration
            .on_block_received(request_id, &child, |_block| Ok(()), |_parent| false)
            .expect("auto chase disabled should accept block without chasing parent");

        prop_assert_eq!(advance, HydrationAdvance::AcceptedComplete { hash });
        prop_assert_eq!(hydration.tracked_len(), 0);
    }

    // 23/25
    #[test]
    fn test_023_accepting_parent_with_waiting_children_reports_unblocked_children(
        seed in any::<u64>(),
        request_seed in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer = peer();
        let parent = genesis_block(seed, 0x2E);
        let child = child_block(&parent, seed.wrapping_add(1), 0x2F);
        let parent_hash = parent.block_hash;
        let child_hash = child.block_hash;
        let request_id = req_id(request_seed);

        note(&mut hydration, peer, parent_hash, Some(0), HydrationReason::MissingParent, "parent with waiters");
        hydration.note_child_waiting_on_parent(parent_hash, child_hash);

        prop_assert_eq!(hydration.next_request(), Some((peer, parent_hash)));
        hydration.mark_issued(request_id, parent_hash);

        let advance = hydration
            .on_block_received(request_id, &parent, |_block| Ok(()), |_parent| true)
            .expect("accepted parent should unblock waiting child");

        match advance {
            HydrationAdvance::AcceptedUnblockedChildren {
                hash,
                children_unblocked,
            } => {
                prop_assert_eq!(hash, parent_hash);
                prop_assert_eq!(children_unblocked, vec![child_hash]);
            }
            other => {
                prop_assert!(
                    false,
                    "expected AcceptedUnblockedChildren, got {:?}",
                    other
                );
            }
        }

        prop_assert_eq!(hydration.tracked_len(), 0);
    }

    // 24/25
    #[test]
    fn test_024_peer_disconnected_clears_that_peer_inflight_requests_and_requeues_with_retry_left(
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        request_seed_a in any::<u64>(),
        request_seed_b in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(3, 16, true));
        let peer_a = peer();
        let peer_b = peer();

        let hash_a = hash64(0x30, seed_a);
        let hash_b = distinct_hash64(0x31, seed_b, hash_a);
        let request_a = req_id(request_seed_a);
        let request_b = req_id(request_seed_b.saturating_add(10_000));

        note(&mut hydration, peer_a, hash_a, Some(1), HydrationReason::Explicit, "peer a");
        note(&mut hydration, peer_b, hash_b, Some(2), HydrationReason::Explicit, "peer b");

        prop_assert_eq!(hydration.next_request(), Some((peer_a, hash_a)));
        hydration.mark_issued(request_a, hash_a);

        prop_assert_eq!(hydration.next_request(), Some((peer_b, hash_b)));
        hydration.mark_issued(request_b, hash_b);

        prop_assert_eq!(hydration.inflight_len(), 2);
        prop_assert!(hydration.is_inflight_hash(&hash_a));
        prop_assert!(hydration.is_inflight_hash(&hash_b));

        hydration.on_peer_disconnected(peer_a);

        prop_assert_eq!(
            hydration.inflight_len(),
            1,
            "disconnect must remove only request IDs associated with disconnected peer"
        );

        prop_assert!(!hydration.is_inflight_hash(&hash_a));
        prop_assert!(hydration.is_inflight_hash(&hash_b));

        prop_assert_eq!(
            hydration.next_request(),
            Some((peer_a, hash_a)),
            "hash from disconnected peer with retries left must be requeued"
        );
    }

    // 25/25
    #[test]
    fn test_025_snapshot_lines_expose_diagnostic_state_and_log_summary_never_panics(
        hash_seed in any::<u64>(),
        source_height in any::<u64>(),
    ) {
        let mut hydration = Hydration::new(fast_cfg(5, 16, true));
        let peer = peer();
        let hash = hash64(0x32, hash_seed);

        note(
            &mut hydration,
            peer,
            hash,
            Some(source_height),
            HydrationReason::ForkChoiceNeedMoreData,
            "diagnostic context",
        );

        let lines = hydration.snapshot_lines();
        let expected_source_height = format!("source_height=Some({})", source_height);

        prop_assert_eq!(lines.len(), 1);
        prop_assert!(lines[0].contains(&hex::encode(hash)));
        prop_assert!(lines[0].contains("in_flight=false"));
        prop_assert!(lines[0].contains("exhausted=false"));
        prop_assert!(lines[0].contains("retries_left=5"));
        prop_assert!(lines[0].contains(&expected_source_height));
        prop_assert!(lines[0].contains("reason=ForkChoiceNeedMoreData"));
        prop_assert!(lines[0].contains("context=diagnostic context"));

        hydration.log_summary();
    }
}
