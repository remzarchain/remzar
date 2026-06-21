use fips204::ml_dsa_65;
use libp2p::{PeerId, request_response::OutboundRequestId};
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::reorganization::reorg_007_branch_hydration::{
    BlockHash, Hydration, HydrationAdvance, HydrationConfig, HydrationFailure, HydrationReason,
};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use std::collections::HashSet;
use std::time::Duration;

type TestResult = Result<(), ErrorDetection>;

fn storage_error(message: String) -> ErrorDetection {
    ErrorDetection::StorageError { message }
}

#[allow(unsafe_code)]
fn request_id(id: u64) -> OutboundRequestId {
    assert_eq!(
        std::mem::size_of::<OutboundRequestId>(),
        std::mem::size_of::<u64>()
    );
    assert_eq!(
        std::mem::align_of::<OutboundRequestId>(),
        std::mem::align_of::<u64>()
    );

    // SAFETY: libp2p 0.56 defines OutboundRequestId as a private newtype over u64.
    // This test-only helper avoids network construction just to obtain deterministic IDs.
    unsafe { std::mem::transmute::<u64, OutboundRequestId>(id) }
}

fn peer() -> PeerId {
    PeerId::random()
}

fn deterministic_hash(seed: u64) -> BlockHash {
    std::array::from_fn(|idx| {
        let idx_u64 = match u64::try_from(idx) {
            Ok(v) => v,
            Err(_) => 0,
        };
        let value = seed
            .wrapping_mul(37)
            .wrapping_add(idx_u64.wrapping_mul(17))
            .wrapping_add(11);
        let bytes = value.to_le_bytes();
        match bytes.first() {
            Some(byte) => *byte,
            None => 0,
        }
    })
}

fn timestamp_at(height: u64) -> u64 {
    GlobalConfiguration::MIN_TIMESTAMP_SECS
        .saturating_add(1_000)
        .saturating_add(height.saturating_mul(GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS))
}

fn make_metadata(height: u64, parent_hash: BlockHash, tag: u64) -> BlockMetadata {
    let merkle_seed = 10_000u64
        .saturating_add(height.saturating_mul(1_000))
        .saturating_add(tag);

    let merkle_root = deterministic_hash(merkle_seed);
    let guardian_signature = if height == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        [7u8; ml_dsa_65::SIG_LEN]
    };

    BlockMetadata::new(
        height,
        timestamp_at(height),
        parent_hash,
        merkle_root,
        guardian_signature,
        None,
        512,
    )
}

fn make_block(height: u64, parent_hash: BlockHash, tag: u64) -> Result<Block, ErrorDetection> {
    let metadata = make_metadata(height, parent_hash, tag);
    let batch_key = Some(format!("hydration-batch-key-height-{height}-tag-{tag}"));

    Block::new(
        metadata,
        batch_key,
        GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        0,
    )
}

fn cfg_zero_cooldown(
    max_retries: u8,
    max_tracked: usize,
    auto_chase_parent: bool,
) -> HydrationConfig {
    HydrationConfig {
        max_retries_per_hash: max_retries,
        retry_cooldown: Duration::from_millis(0),
        max_tracked_hashes: max_tracked,
        auto_chase_parent,
    }
}

fn cfg_long_cooldown(
    max_retries: u8,
    max_tracked: usize,
    auto_chase_parent: bool,
) -> HydrationConfig {
    HydrationConfig {
        max_retries_per_hash: max_retries,
        retry_cooldown: Duration::from_secs(60),
        max_tracked_hashes: max_tracked,
        auto_chase_parent,
    }
}

fn note(
    hydration: &mut Hydration,
    origin_peer: PeerId,
    hash: BlockHash,
    source_height: Option<u64>,
    reason: HydrationReason,
    context: &'static str,
) {
    hydration.note_need_more_data(origin_peer, hash, source_height, reason, context);
}

fn issue_one(
    hydration: &mut Hydration,
    origin_peer: PeerId,
    hash: BlockHash,
    req_id: OutboundRequestId,
) {
    note(
        hydration,
        origin_peer,
        hash,
        Some(1),
        HydrationReason::Explicit,
        "issue one",
    );
    let request = hydration.next_request();
    assert_eq!(request, Some((origin_peer, hash)));
    hydration.mark_issued(req_id, hash);
}

fn persist_ok(_block: &Block) -> Result<(), ErrorDetection> {
    Ok(())
}

fn persist_err(_block: &Block) -> Result<(), ErrorDetection> {
    Err(storage_error("persist failure from test".to_owned()))
}

fn parent_known(_hash: &BlockHash) -> bool {
    true
}

fn parent_missing(_hash: &BlockHash) -> bool {
    false
}

fn assert_retry(result: HydrationFailure, hash: BlockHash, retries_left: u8) {
    assert_eq!(
        result,
        HydrationFailure::RetryScheduled { hash, retries_left }
    );
}

fn assert_exhausted(result: HydrationFailure, hash: BlockHash) {
    assert_eq!(result, HydrationFailure::Exhausted { hash });
}

fn assert_unknown_request(result: HydrationFailure) {
    assert_eq!(result, HydrationFailure::UnknownRequest);
}

fn assert_snapshot_contains_line(hydration: &Hydration, needle: &str) {
    let joined = hydration.snapshot_lines().join("\n");
    assert!(
        joined.contains(needle),
        "snapshot did not contain {needle}; snapshot={joined}"
    );
}

// ─────────────────────────────────────────────────────────────
// 1–20: config and initial state vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_001_default_config_max_retries_vector() {
    let cfg = HydrationConfig::default();
    assert_eq!(cfg.max_retries_per_hash, 6);
}

#[test]
fn test_002_default_config_retry_cooldown_vector() {
    let cfg = HydrationConfig::default();
    assert_eq!(cfg.retry_cooldown, Duration::from_millis(800));
}

#[test]
fn test_003_default_config_max_tracked_vector() {
    let cfg = HydrationConfig::default();
    assert_eq!(cfg.max_tracked_hashes, 4096);
}

#[test]
fn test_004_default_config_auto_chase_enabled_vector() {
    let cfg = HydrationConfig::default();
    assert!(cfg.auto_chase_parent);
}

#[test]
fn test_005_custom_config_fields_preserved_vector() {
    let cfg = cfg_zero_cooldown(2, 7, false);
    assert_eq!(cfg.max_retries_per_hash, 2);
    assert_eq!(cfg.retry_cooldown, Duration::from_millis(0));
    assert_eq!(cfg.max_tracked_hashes, 7);
    assert!(!cfg.auto_chase_parent);
}

#[test]
fn test_006_reason_debug_explicit_vector() {
    let rendered = format!("{:?}", HydrationReason::Explicit);
    assert!(rendered.contains("Explicit"));
}

#[test]
fn test_007_reason_copy_eq_vector() {
    let reason = HydrationReason::MissingParent;
    let copied = reason;
    assert_eq!(copied, HydrationReason::MissingParent);
}

#[test]
fn test_008_advance_debug_complete_vector() {
    let hash = deterministic_hash(8);
    let advance = HydrationAdvance::AcceptedComplete { hash };
    let rendered = format!("{advance:?}");
    assert!(rendered.contains("AcceptedComplete"));
}

#[test]
fn test_009_failure_debug_retry_vector() {
    let hash = deterministic_hash(9);
    let failure = HydrationFailure::RetryScheduled {
        hash,
        retries_left: 1,
    };
    let rendered = format!("{failure:?}");
    assert!(rendered.contains("RetryScheduled"));
}

#[test]
fn test_010_new_hydration_empty_state_vector() {
    let hydration = Hydration::new(HydrationConfig::default());
    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
}

#[test]
fn test_011_default_mainnet_empty_state_vector() {
    let hydration = Hydration::default_mainnet();
    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
}

#[test]
fn test_012_missing_hash_not_tracking_vector() {
    let hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(12);
    assert!(!hydration.is_tracking(&hash));
}

#[test]
fn test_013_missing_hash_not_inflight_vector() {
    let hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(13);
    assert!(!hydration.is_inflight_hash(&hash));
}

#[test]
fn test_014_next_request_empty_returns_none_vector() {
    let mut hydration = Hydration::default_mainnet();
    assert!(hydration.next_request().is_none());
}

#[test]
fn test_015_snapshot_empty_is_empty_vector() {
    let hydration = Hydration::default_mainnet();
    assert!(hydration.snapshot_lines().is_empty());
}

#[test]
fn test_016_log_summary_empty_succeeds_vector() {
    let hydration = Hydration::default_mainnet();
    hydration.log_summary();
}

#[test]
fn test_017_block_hash_helper_is_64_bytes_vector() {
    let hash = deterministic_hash(17);
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_018_request_id_helper_is_deterministic_vector() {
    let first = request_id(18);
    let second = request_id(18);
    assert_eq!(first, second);
}

#[test]
fn test_019_request_id_helper_distinguishes_values_vector() {
    let first = request_id(19);
    let second = request_id(20);
    assert_ne!(first, second);
}

#[test]
fn test_020_make_genesis_block_for_hydration_vector() -> TestResult {
    let block = make_block(0, [0u8; 64], 20)?;
    assert_eq!(block.metadata.index, 0);
    assert_eq!(block.metadata.previous_hash, [0u8; 64]);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 21–40: note, dedupe, queueing, and caps
// ─────────────────────────────────────────────────────────────

#[test]
fn test_021_note_need_more_data_tracks_hash_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(21);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        Some(21),
        HydrationReason::ForkChoiceNeedMoreData,
        "need parent",
    );

    assert_eq!(hydration.tracked_len(), 1);
    assert!(hydration.is_tracking(&hash));
}

#[test]
fn test_022_note_need_more_data_enqueues_request_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(22);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        Some(22),
        HydrationReason::ForkChoiceNeedMoreData,
        "need parent",
    );

    assert_eq!(hydration.next_request(), Some((origin, hash)));
}

#[test]
fn test_023_repeated_note_same_hash_dedupes_tracking_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(23);
    let origin = peer();

    for _ in 0..10 {
        note(
            &mut hydration,
            origin,
            hash,
            Some(23),
            HydrationReason::Explicit,
            "dedupe",
        );
    }

    assert_eq!(hydration.tracked_len(), 1);
}

#[test]
fn test_024_repeated_note_same_hash_dedupes_queue_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(24);
    let origin = peer();

    for _ in 0..10 {
        note(
            &mut hydration,
            origin,
            hash,
            Some(24),
            HydrationReason::Explicit,
            "dedupe queue",
        );
    }

    assert_eq!(hydration.next_request(), Some((origin, hash)));
    assert!(hydration.next_request().is_none());
}

#[test]
fn test_025_existing_note_refreshes_origin_peer_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(25);
    let first_peer = peer();
    let second_peer = peer();

    note(
        &mut hydration,
        first_peer,
        hash,
        Some(25),
        HydrationReason::Explicit,
        "first peer",
    );
    note(
        &mut hydration,
        second_peer,
        hash,
        Some(25),
        HydrationReason::MissingParent,
        "second peer",
    );

    assert_eq!(hydration.next_request(), Some((second_peer, hash)));
}

#[test]
fn test_026_existing_note_preserves_first_source_height_when_some_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(26);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        Some(26),
        HydrationReason::Explicit,
        "first height",
    );
    note(
        &mut hydration,
        origin,
        hash,
        Some(99),
        HydrationReason::MissingParent,
        "second height",
    );

    let line = hydration.snapshot_lines().join("\n");
    assert!(line.contains("source_height=Some(26)"));
}

#[test]
fn test_027_existing_note_fills_source_height_when_none_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(27);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        None,
        HydrationReason::Explicit,
        "none first",
    );
    note(
        &mut hydration,
        origin,
        hash,
        Some(27),
        HydrationReason::MissingParent,
        "some second",
    );

    let line = hydration.snapshot_lines().join("\n");
    assert!(line.contains("source_height=Some(27)"));
}

#[test]
fn test_028_existing_note_refreshes_reason_and_context_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(28);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        Some(28),
        HydrationReason::Explicit,
        "old context",
    );
    note(
        &mut hydration,
        origin,
        hash,
        Some(28),
        HydrationReason::MissingParent,
        "new context",
    );

    assert_snapshot_contains_line(&hydration, "reason=MissingParent");
    assert_snapshot_contains_line(&hydration, "context=new context");
}

#[test]
fn test_029_queue_order_is_fifo_vector() {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let h1 = deterministic_hash(291);
    let h2 = deterministic_hash(292);
    let h3 = deterministic_hash(293);

    note(
        &mut hydration,
        origin,
        h1,
        Some(1),
        HydrationReason::Explicit,
        "one",
    );
    note(
        &mut hydration,
        origin,
        h2,
        Some(2),
        HydrationReason::Explicit,
        "two",
    );
    note(
        &mut hydration,
        origin,
        h3,
        Some(3),
        HydrationReason::Explicit,
        "three",
    );

    assert_eq!(hydration.next_request(), Some((origin, h1)));
    assert_eq!(hydration.next_request(), Some((origin, h2)));
    assert_eq!(hydration.next_request(), Some((origin, h3)));
}

#[test]
fn test_030_max_tracked_zero_refuses_new_hash_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 0, true));
    let hash = deterministic_hash(30);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(30),
        HydrationReason::Explicit,
        "cap zero",
    );

    assert_eq!(hydration.tracked_len(), 0);
    assert!(hydration.next_request().is_none());
}

#[test]
fn test_031_max_tracked_one_accepts_first_refuses_second_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 1, true));
    let origin = peer();
    let h1 = deterministic_hash(311);
    let h2 = deterministic_hash(312);

    note(
        &mut hydration,
        origin,
        h1,
        Some(1),
        HydrationReason::Explicit,
        "first",
    );
    note(
        &mut hydration,
        origin,
        h2,
        Some(2),
        HydrationReason::Explicit,
        "second",
    );

    assert_eq!(hydration.tracked_len(), 1);
    assert!(hydration.is_tracking(&h1));
    assert!(!hydration.is_tracking(&h2));
}

#[test]
fn test_032_max_tracked_one_allows_refresh_existing_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 1, true));
    let h1 = deterministic_hash(32);
    let first_peer = peer();
    let second_peer = peer();

    note(
        &mut hydration,
        first_peer,
        h1,
        Some(1),
        HydrationReason::Explicit,
        "first",
    );
    note(
        &mut hydration,
        second_peer,
        h1,
        Some(1),
        HydrationReason::MissingParent,
        "refresh",
    );

    assert_eq!(hydration.tracked_len(), 1);
    assert_eq!(hydration.next_request(), Some((second_peer, h1)));
}

#[test]
fn test_033_note_child_waiting_on_untracked_parent_is_noop_vector() {
    let mut hydration = Hydration::default_mainnet();
    let parent = deterministic_hash(331);
    let child = deterministic_hash(332);

    hydration.note_child_waiting_on_parent(parent, child);

    assert_eq!(hydration.tracked_len(), 0);
}

#[test]
fn test_034_snapshot_after_single_note_contains_hash_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(34);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(34),
        HydrationReason::Explicit,
        "snapshot hash",
    );

    assert_snapshot_contains_line(&hydration, &hex::encode(hash));
}

#[test]
fn test_035_snapshot_after_single_note_contains_context_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(35);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(35),
        HydrationReason::Explicit,
        "snapshot context",
    );

    assert_snapshot_contains_line(&hydration, "snapshot context");
}

#[test]
fn test_036_snapshot_after_single_note_contains_retries_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(4, 10, true));
    let hash = deterministic_hash(36);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(36),
        HydrationReason::Explicit,
        "snapshot retries",
    );

    assert_snapshot_contains_line(&hydration, "retries_left=4");
}

#[test]
fn test_037_snapshot_after_single_note_contains_inflight_false_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(37);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(37),
        HydrationReason::Explicit,
        "snapshot inflight",
    );

    assert_snapshot_contains_line(&hydration, "in_flight=false");
}

#[test]
fn test_038_clear_if_known_removes_pending_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(38);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(38),
        HydrationReason::Explicit,
        "clear",
    );
    hydration.clear_if_known(&hash);

    assert_eq!(hydration.tracked_len(), 0);
    assert!(!hydration.is_tracking(&hash));
}

#[test]
fn test_039_clear_if_known_removes_ready_queue_entry_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(39);

    note(
        &mut hydration,
        peer(),
        hash,
        Some(39),
        HydrationReason::Explicit,
        "clear queue",
    );
    hydration.clear_if_known(&hash);

    assert!(hydration.next_request().is_none());
}

#[test]
fn test_040_clear_if_known_unknown_hash_is_noop_vector() {
    let mut hydration = Hydration::default_mainnet();
    let known = deterministic_hash(401);
    let unknown = deterministic_hash(402);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        known,
        Some(40),
        HydrationReason::Explicit,
        "known",
    );
    hydration.clear_if_known(&unknown);

    assert_eq!(hydration.tracked_len(), 1);
    assert_eq!(hydration.next_request(), Some((origin, known)));
}

// ─────────────────────────────────────────────────────────────
// 41–60: issuing, failures, cooldown, exhaustion, peer disconnect
// ─────────────────────────────────────────────────────────────

#[test]
fn test_041_mark_issued_known_hash_sets_inflight_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(41);
    let origin = peer();
    let req = request_id(41);

    issue_one(&mut hydration, origin, hash, req);

    assert_eq!(hydration.inflight_len(), 1);
    assert!(hydration.is_inflight_hash(&hash));
}

#[test]
fn test_042_mark_issued_unknown_hash_is_noop_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(42);

    hydration.mark_issued(request_id(42), hash);

    assert_eq!(hydration.inflight_len(), 0);
    assert!(!hydration.is_inflight_hash(&hash));
}

#[test]
fn test_043_next_request_skips_inflight_hash_vector() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(43);
    let origin = peer();

    issue_one(&mut hydration, origin, hash, request_id(43));

    assert!(hydration.next_request().is_none());
}

#[test]
fn test_044_failed_unknown_request_returns_unknown_vector() {
    let mut hydration = Hydration::default_mainnet();

    assert_unknown_request(hydration.on_request_failed(request_id(44)));
}

#[test]
fn test_045_not_found_unknown_request_returns_unknown_vector() {
    let mut hydration = Hydration::default_mainnet();

    assert_unknown_request(hydration.on_not_found(request_id(45)));
}

#[test]
fn test_046_request_failed_schedules_retry_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let hash = deterministic_hash(46);
    let origin = peer();
    let req = request_id(46);

    issue_one(&mut hydration, origin, hash, req);
    let failure = hydration.on_request_failed(req);

    assert_retry(failure, hash, 2);
    assert!(!hydration.is_inflight_hash(&hash));
    assert_eq!(hydration.inflight_len(), 0);
}

#[test]
fn test_047_not_found_schedules_retry_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let hash = deterministic_hash(47);
    let origin = peer();
    let req = request_id(47);

    issue_one(&mut hydration, origin, hash, req);
    let failure = hydration.on_not_found(req);

    assert_retry(failure, hash, 2);
}

#[test]
fn test_048_request_failed_requeues_when_cooldown_zero_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let hash = deterministic_hash(48);
    let origin = peer();
    let req = request_id(48);

    issue_one(&mut hydration, origin, hash, req);
    assert_retry(hydration.on_request_failed(req), hash, 2);

    assert_eq!(hydration.next_request(), Some((origin, hash)));
}

#[test]
fn test_049_request_failed_respects_retry_cooldown_vector() {
    let mut hydration = Hydration::new(cfg_long_cooldown(3, 10, true));
    let hash = deterministic_hash(49);
    let origin = peer();
    let req = request_id(49);

    issue_one(&mut hydration, origin, hash, req);
    assert_retry(hydration.on_request_failed(req), hash, 2);

    assert!(hydration.next_request().is_none());
}

#[test]
fn test_050_request_failed_exhausts_after_one_retry_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let hash = deterministic_hash(50);
    let origin = peer();
    let req = request_id(50);

    issue_one(&mut hydration, origin, hash, req);
    let failure = hydration.on_request_failed(req);

    assert_exhausted(failure, hash);
    assert!(
        hydration
            .snapshot_lines()
            .join("\n")
            .contains("exhausted=true")
    );
}

#[test]
fn test_051_exhausted_hash_is_not_requeued_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let hash = deterministic_hash(51);
    let origin = peer();
    let req = request_id(51);

    issue_one(&mut hydration, origin, hash, req);
    assert_exhausted(hydration.on_request_failed(req), hash);

    assert!(hydration.next_request().is_none());
}

#[test]
fn test_052_two_failures_decrement_retries_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let hash = deterministic_hash(52);
    let origin = peer();

    issue_one(&mut hydration, origin, hash, request_id(521));
    assert_retry(hydration.on_request_failed(request_id(521)), hash, 2);

    assert_eq!(hydration.next_request(), Some((origin, hash)));
    hydration.mark_issued(request_id(522), hash);
    assert_retry(hydration.on_request_failed(request_id(522)), hash, 1);
}

#[test]
fn test_053_failure_after_clear_if_known_returns_unknown_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let hash = deterministic_hash(53);
    let origin = peer();
    let req = request_id(53);

    issue_one(&mut hydration, origin, hash, req);
    hydration.clear_if_known(&hash);

    assert_unknown_request(hydration.on_request_failed(req));
}

#[test]
fn test_054_peer_disconnect_unknown_peer_noop_vector() {
    let mut hydration = Hydration::default_mainnet();
    hydration.on_peer_disconnected(peer());

    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
}

#[test]
fn test_055_peer_disconnect_requeues_pending_hash_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let hash = deterministic_hash(55);

    note(
        &mut hydration,
        origin,
        hash,
        Some(55),
        HydrationReason::Explicit,
        "disconnect",
    );
    hydration.on_peer_disconnected(origin);

    assert_eq!(hydration.next_request(), Some((origin, hash)));
    assert_snapshot_contains_line(&hydration, "retries_left=2");
}

#[test]
fn test_056_peer_disconnect_clears_matching_inflight_request_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let hash = deterministic_hash(56);

    issue_one(&mut hydration, origin, hash, request_id(56));
    assert_eq!(hydration.inflight_len(), 1);

    hydration.on_peer_disconnected(origin);

    assert_eq!(hydration.inflight_len(), 0);
    assert!(!hydration.is_inflight_hash(&hash));
}

#[test]
fn test_057_peer_disconnect_does_not_affect_other_peer_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let peer_a = peer();
    let peer_b = peer();
    let hash_a = deterministic_hash(571);
    let hash_b = deterministic_hash(572);

    issue_one(&mut hydration, peer_a, hash_a, request_id(571));
    issue_one(&mut hydration, peer_b, hash_b, request_id(572));

    hydration.on_peer_disconnected(peer_a);

    assert_eq!(hydration.inflight_len(), 1);
    assert!(hydration.is_inflight_hash(&hash_b));
}

#[test]
fn test_058_peer_disconnect_exhausts_when_one_retry_left_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let origin = peer();
    let hash = deterministic_hash(58);

    note(
        &mut hydration,
        origin,
        hash,
        Some(58),
        HydrationReason::Explicit,
        "disconnect exhaust",
    );
    hydration.on_peer_disconnected(origin);

    assert_snapshot_contains_line(&hydration, "exhausted=true");
    assert!(hydration.next_request().is_none());
}

#[test]
fn test_059_peer_disconnect_multiple_hashes_same_peer_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let h1 = deterministic_hash(591);
    let h2 = deterministic_hash(592);

    note(
        &mut hydration,
        origin,
        h1,
        Some(1),
        HydrationReason::Explicit,
        "one",
    );
    note(
        &mut hydration,
        origin,
        h2,
        Some(2),
        HydrationReason::Explicit,
        "two",
    );

    hydration.on_peer_disconnected(origin);

    assert_eq!(hydration.tracked_len(), 2);
    assert_snapshot_contains_line(&hydration, "retries_left=2");
}

#[test]
fn test_060_log_summary_with_pending_and_inflight_succeeds_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let hash = deterministic_hash(60);

    issue_one(&mut hydration, origin, hash, request_id(60));
    hydration.log_summary();
}

// ─────────────────────────────────────────────────────────────
// 61–80: on_block_received vectors
// ─────────────────────────────────────────────────────────────

#[test]
fn test_061_received_unknown_request_is_ignored_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let block = make_block(0, [0u8; 64], 61)?;

    let advance = hydration.on_block_received(request_id(61), &block, persist_ok, parent_known)?;

    assert_eq!(advance, HydrationAdvance::Ignored);
    Ok(())
}

#[test]
fn test_062_received_matching_genesis_block_complete_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 62)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(62));

    let advance = hydration.on_block_received(request_id(62), &block, persist_ok, parent_known)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedComplete {
            hash: block.block_hash
        }
    );
    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
    Ok(())
}

#[test]
fn test_063_received_matching_non_genesis_with_known_parent_complete_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent = deterministic_hash(630);
    let block = make_block(1, parent, 631)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(63));

    let advance = hydration.on_block_received(request_id(63), &block, persist_ok, parent_known)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedComplete {
            hash: block.block_hash
        }
    );
    Ok(())
}

#[test]
fn test_064_received_matching_non_genesis_missing_parent_chases_parent_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent = deterministic_hash(640);
    let block = make_block(1, parent, 641)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(64));

    let advance =
        hydration.on_block_received(request_id(64), &block, persist_ok, parent_missing)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedNeedsParent {
            hash: block.block_hash,
            missing_parent: parent
        }
    );
    assert!(hydration.is_tracking(&parent));
    Ok(())
}

#[test]
fn test_065_received_missing_parent_next_request_is_parent_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent = deterministic_hash(650);
    let block = make_block(1, parent, 651)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(65));
    let _advance =
        hydration.on_block_received(request_id(65), &block, persist_ok, parent_missing)?;

    assert_eq!(hydration.next_request(), Some((origin, parent)));
    Ok(())
}

#[test]
fn test_066_received_with_auto_chase_disabled_completes_even_when_parent_missing_vector()
-> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, false));
    let origin = peer();
    let parent = deterministic_hash(660);
    let block = make_block(1, parent, 661)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(66));

    let advance =
        hydration.on_block_received(request_id(66), &block, persist_ok, parent_missing)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedComplete {
            hash: block.block_hash
        }
    );
    assert!(!hydration.is_tracking(&parent));
    Ok(())
}

#[test]
fn test_067_received_wrong_hash_is_ignored_and_requeued_vector() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let expected = deterministic_hash(671);
    let wrong_block = make_block(0, [0u8; 64], 672)?;

    issue_one(&mut hydration, origin, expected, request_id(67));

    let advance =
        hydration.on_block_received(request_id(67), &wrong_block, persist_ok, parent_known)?;

    assert_eq!(advance, HydrationAdvance::Ignored);
    assert_eq!(hydration.next_request(), Some((origin, expected)));
    assert_snapshot_contains_line(&hydration, "retries_left=2");
    Ok(())
}

#[test]
fn test_068_received_wrong_hash_exhausts_when_no_retries_left_vector() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let origin = peer();
    let expected = deterministic_hash(681);
    let wrong_block = make_block(0, [0u8; 64], 682)?;

    issue_one(&mut hydration, origin, expected, request_id(68));

    let advance =
        hydration.on_block_received(request_id(68), &wrong_block, persist_ok, parent_known)?;

    assert_eq!(advance, HydrationAdvance::Ignored);
    assert_snapshot_contains_line(&hydration, "exhausted=true");
    assert!(hydration.next_request().is_none());
    Ok(())
}

#[test]
fn test_069_received_persist_error_propagates_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 69)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(69));

    let result = hydration.on_block_received(request_id(69), &block, persist_err, parent_known);

    assert!(matches!(result, Err(ErrorDetection::StorageError { .. })));
    Ok(())
}

#[test]
fn test_070_received_after_clear_is_ignored_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 70)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(70));
    hydration.clear_if_known(&block.block_hash);

    let advance = hydration.on_block_received(request_id(70), &block, persist_ok, parent_known)?;

    assert_eq!(advance, HydrationAdvance::Ignored);
    Ok(())
}

#[test]
fn test_071_waiting_child_unblocked_when_parent_received_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent_block = make_block(1, deterministic_hash(710), 711)?;
    let child_hash = deterministic_hash(712);

    note(
        &mut hydration,
        origin,
        parent_block.block_hash,
        Some(1),
        HydrationReason::MissingParent,
        "parent",
    );
    hydration.note_child_waiting_on_parent(parent_block.block_hash, child_hash);
    let _request = hydration.next_request();
    hydration.mark_issued(request_id(71), parent_block.block_hash);

    let advance =
        hydration.on_block_received(request_id(71), &parent_block, persist_ok, parent_known)?;

    match advance {
        HydrationAdvance::AcceptedUnblockedChildren {
            hash,
            children_unblocked,
        } => {
            assert_eq!(hash, parent_block.block_hash);
            assert_eq!(children_unblocked, vec![child_hash]);
        }
        other => panic!("expected AcceptedUnblockedChildren, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_072_multiple_waiting_children_unblocked_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent_block = make_block(1, deterministic_hash(720), 721)?;
    let child_a = deterministic_hash(722);
    let child_b = deterministic_hash(723);

    note(
        &mut hydration,
        origin,
        parent_block.block_hash,
        Some(1),
        HydrationReason::MissingParent,
        "parent",
    );
    hydration.note_child_waiting_on_parent(parent_block.block_hash, child_a);
    hydration.note_child_waiting_on_parent(parent_block.block_hash, child_b);
    let _request = hydration.next_request();
    hydration.mark_issued(request_id(72), parent_block.block_hash);

    let advance =
        hydration.on_block_received(request_id(72), &parent_block, persist_ok, parent_known)?;

    match advance {
        HydrationAdvance::AcceptedUnblockedChildren {
            children_unblocked, ..
        } => {
            let set = children_unblocked.into_iter().collect::<HashSet<_>>();
            assert!(set.contains(&child_a));
            assert!(set.contains(&child_b));
            assert_eq!(set.len(), 2);
        }
        other => panic!("expected AcceptedUnblockedChildren, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_073_duplicate_waiting_child_dedupes_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent_block = make_block(1, deterministic_hash(730), 731)?;
    let child = deterministic_hash(732);

    note(
        &mut hydration,
        origin,
        parent_block.block_hash,
        Some(1),
        HydrationReason::MissingParent,
        "parent",
    );
    hydration.note_child_waiting_on_parent(parent_block.block_hash, child);
    hydration.note_child_waiting_on_parent(parent_block.block_hash, child);
    let _request = hydration.next_request();
    hydration.mark_issued(request_id(73), parent_block.block_hash);

    let advance =
        hydration.on_block_received(request_id(73), &parent_block, persist_ok, parent_known)?;

    match advance {
        HydrationAdvance::AcceptedUnblockedChildren {
            children_unblocked, ..
        } => assert_eq!(children_unblocked.len(), 1),
        other => panic!("expected AcceptedUnblockedChildren, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_074_parent_chase_records_waiting_child_in_snapshot_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let parent = deterministic_hash(740);
    let block = make_block(1, parent, 741)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(74));
    let _advance =
        hydration.on_block_received(request_id(74), &block, persist_ok, parent_missing)?;

    assert!(
        hydration
            .snapshot_lines()
            .join("\n")
            .contains("MissingParent")
    );
    Ok(())
}

#[test]
fn test_075_received_parent_for_genesis_zero_parent_does_not_chase_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let genesis = make_block(0, [0u8; 64], 75)?;

    issue_one(&mut hydration, origin, genesis.block_hash, request_id(75));

    let advance =
        hydration.on_block_received(request_id(75), &genesis, persist_ok, parent_missing)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedComplete {
            hash: genesis.block_hash
        }
    );
    assert_eq!(hydration.tracked_len(), 0);
    Ok(())
}

#[test]
fn test_076_non_genesis_zero_parent_block_is_rejected_by_constructor_vector() -> TestResult {
    let result = make_block(1, [0u8; 64], 76);

    match result {
        Err(ErrorDetection::ValidationError { message, .. }) => {
            assert!(message.contains("previous_hash"));
            assert!(message.contains("all zeros"));
            assert!(message.contains("index 1"));
        }
        other => panic!("expected non-genesis zero-parent block to be rejected, got {other:?}"),
    }

    Ok(())
}

#[test]
fn test_077_received_block_removes_inflight_entry_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 77)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(77));
    assert_eq!(hydration.inflight_len(), 1);

    let _advance = hydration.on_block_received(request_id(77), &block, persist_ok, parent_known)?;

    assert_eq!(hydration.inflight_len(), 0);
    Ok(())
}

#[test]
fn test_078_received_wrong_hash_removes_inflight_entry_vector() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let expected = deterministic_hash(781);
    let wrong = make_block(0, [0u8; 64], 782)?;

    issue_one(&mut hydration, origin, expected, request_id(78));
    let _advance = hydration.on_block_received(request_id(78), &wrong, persist_ok, parent_known)?;

    assert_eq!(hydration.inflight_len(), 0);
    Ok(())
}

#[test]
fn test_079_block_received_can_increment_persist_counter_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 79)?;
    let mut persisted = 0usize;

    issue_one(&mut hydration, origin, block.block_hash, request_id(79));

    let _advance = hydration.on_block_received(
        request_id(79),
        &block,
        |_block| {
            persisted = persisted.saturating_add(1);
            Ok(())
        },
        parent_known,
    )?;

    assert_eq!(persisted, 1);
    Ok(())
}

#[test]
fn test_080_unknown_request_does_not_call_persist_vector() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let block = make_block(0, [0u8; 64], 80)?;
    let mut persisted = 0usize;

    let _advance = hydration.on_block_received(
        request_id(80),
        &block,
        |_block| {
            persisted = persisted.saturating_add(1);
            Ok(())
        },
        parent_known,
    )?;

    assert_eq!(persisted, 0);
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// 81–100: property, fuzz-style, adversarial, and load tests
// ─────────────────────────────────────────────────────────────

#[test]
fn test_081_property_note_many_distinct_hashes_tracks_all() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();

    for seed in 0u64..32u64 {
        note(
            &mut hydration,
            origin,
            deterministic_hash(8_100u64.saturating_add(seed)),
            Some(seed),
            HydrationReason::Explicit,
            "property many",
        );
    }

    assert_eq!(hydration.tracked_len(), 32);
}

#[test]
fn test_082_property_next_request_drains_many_hashes_fifo() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();
    let mut hashes = Vec::new();

    for seed in 0u64..16u64 {
        let hash = deterministic_hash(8_200u64.saturating_add(seed));
        hashes.push(hash);
        note(
            &mut hydration,
            origin,
            hash,
            Some(seed),
            HydrationReason::Explicit,
            "fifo many",
        );
    }

    for hash in hashes {
        assert_eq!(hydration.next_request(), Some((origin, hash)));
    }

    assert!(hydration.next_request().is_none());
}

#[test]
fn test_083_property_mark_issued_many_hashes_inflight_count() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();

    for seed in 0u64..16u64 {
        let hash = deterministic_hash(8_300u64.saturating_add(seed));
        note(
            &mut hydration,
            origin,
            hash,
            Some(seed),
            HydrationReason::Explicit,
            "issue many",
        );
        let _request = hydration.next_request();
        hydration.mark_issued(request_id(8_300u64.saturating_add(seed)), hash);
    }

    assert_eq!(hydration.inflight_len(), 16);
}

#[test]
fn test_084_property_fail_many_requests_requeues_all_zero_cooldown() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();
    let mut hashes = Vec::new();

    for seed in 0u64..8u64 {
        let hash = deterministic_hash(8_400u64.saturating_add(seed));
        hashes.push(hash);
        issue_one(
            &mut hydration,
            origin,
            hash,
            request_id(8_400u64.saturating_add(seed)),
        );
    }

    for seed in 0u64..8u64 {
        let hash = deterministic_hash(8_400u64.saturating_add(seed));
        assert_retry(
            hydration.on_request_failed(request_id(8_400u64.saturating_add(seed))),
            hash,
            2,
        );
    }

    for hash in hashes {
        assert_eq!(hydration.next_request(), Some((origin, hash)));
    }
}

#[test]
fn test_085_property_peer_disconnect_many_hashes_same_peer_requeues() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();

    for seed in 0u64..16u64 {
        note(
            &mut hydration,
            origin,
            deterministic_hash(8_500u64.saturating_add(seed)),
            Some(seed),
            HydrationReason::Explicit,
            "disconnect many",
        );
    }

    hydration.on_peer_disconnected(origin);

    assert_eq!(hydration.tracked_len(), 16);
    assert_snapshot_contains_line(&hydration, "retries_left=2");
}

#[test]
fn test_086_property_clear_many_known_hashes() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();
    let mut hashes = Vec::new();

    for seed in 0u64..16u64 {
        let hash = deterministic_hash(8_600u64.saturating_add(seed));
        hashes.push(hash);
        note(
            &mut hydration,
            origin,
            hash,
            Some(seed),
            HydrationReason::Explicit,
            "clear many",
        );
    }

    for hash in &hashes {
        hydration.clear_if_known(hash);
    }

    assert_eq!(hydration.tracked_len(), 0);
    assert!(hydration.next_request().is_none());
}

#[test]
fn test_087_fuzz_repeated_same_hash_refreshes_without_growth() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let hash = deterministic_hash(8_700);

    for seed in 0u64..64u64 {
        note(
            &mut hydration,
            peer(),
            hash,
            Some(seed),
            HydrationReason::Explicit,
            "same hash fuzz",
        );
    }

    assert_eq!(hydration.tracked_len(), 1);
}

#[test]
fn test_088_fuzz_variable_reasons_snapshot_last_reason_wins() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let hash = deterministic_hash(8_800);
    let origin = peer();

    note(
        &mut hydration,
        origin,
        hash,
        Some(1),
        HydrationReason::ForkChoiceNeedMoreData,
        "first",
    );
    note(
        &mut hydration,
        origin,
        hash,
        Some(1),
        HydrationReason::MissingParent,
        "second",
    );
    note(
        &mut hydration,
        origin,
        hash,
        Some(1),
        HydrationReason::Explicit,
        "third",
    );

    assert_snapshot_contains_line(&hydration, "reason=Explicit");
    assert_snapshot_contains_line(&hydration, "context=third");
}

#[test]
fn test_089_fuzz_wrong_hash_responses_eventually_exhaust() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();
    let expected = deterministic_hash(8_900);

    for attempt in 0u64..3u64 {
        let wrong = make_block(0, [0u8; 64], 8_900u64.saturating_add(attempt))?;
        if attempt == 0 {
            issue_one(
                &mut hydration,
                origin,
                expected,
                request_id(8_900u64.saturating_add(attempt)),
            );
        } else {
            let _request = hydration.next_request();
            hydration.mark_issued(request_id(8_900u64.saturating_add(attempt)), expected);
        }

        let _advance = hydration.on_block_received(
            request_id(8_900u64.saturating_add(attempt)),
            &wrong,
            persist_ok,
            parent_known,
        )?;
    }

    assert_snapshot_contains_line(&hydration, "exhausted=true");
    Ok(())
}

#[test]
fn test_090_adversarial_hash_mismatch_does_not_call_persist() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 10, true));
    let origin = peer();
    let expected = deterministic_hash(9_000);
    let wrong = make_block(0, [0u8; 64], 9_001)?;
    let mut persisted = 0usize;

    issue_one(&mut hydration, origin, expected, request_id(90));

    let _advance = hydration.on_block_received(
        request_id(90),
        &wrong,
        |_block| {
            persisted = persisted.saturating_add(1);
            Ok(())
        },
        parent_known,
    )?;

    assert_eq!(persisted, 0);
    Ok(())
}

#[test]
fn test_091_adversarial_parent_chase_reuses_tracking_slot_after_child_received() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 1, true));
    let origin = peer();
    let parent = deterministic_hash(9_100);
    let block = make_block(1, parent, 9_101)?;

    issue_one(&mut hydration, origin, block.block_hash, request_id(91));

    let advance =
        hydration.on_block_received(request_id(91), &block, persist_ok, parent_missing)?;

    assert_eq!(
        advance,
        HydrationAdvance::AcceptedNeedsParent {
            hash: block.block_hash,
            missing_parent: parent,
        }
    );
    assert!(!hydration.is_tracking(&block.block_hash));
    assert!(hydration.is_tracking(&parent));
    assert_eq!(hydration.tracked_len(), 1);
    assert_eq!(hydration.next_request(), Some((origin, parent)));

    Ok(())
}

#[test]
fn test_092_adversarial_peer_disconnect_exhausted_hash_remains_tracked() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let origin = peer();
    let hash = deterministic_hash(9_200);

    note(
        &mut hydration,
        origin,
        hash,
        Some(92),
        HydrationReason::Explicit,
        "exhaust remains",
    );
    hydration.on_peer_disconnected(origin);

    assert!(hydration.is_tracking(&hash));
    assert_snapshot_contains_line(&hydration, "exhausted=true");
}

#[test]
fn test_093_adversarial_clear_exhausted_hash_removes_it() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(1, 10, true));
    let origin = peer();
    let hash = deterministic_hash(9_300);

    note(
        &mut hydration,
        origin,
        hash,
        Some(93),
        HydrationReason::Explicit,
        "clear exhausted",
    );
    hydration.on_peer_disconnected(origin);
    hydration.clear_if_known(&hash);

    assert!(!hydration.is_tracking(&hash));
}

#[test]
fn test_094_adversarial_unknown_mark_issued_then_failure_is_unknown() {
    let mut hydration = Hydration::default_mainnet();
    let hash = deterministic_hash(9_400);
    let req = request_id(94);

    hydration.mark_issued(req, hash);

    assert_unknown_request(hydration.on_request_failed(req));
}

#[test]
fn test_095_adversarial_not_found_after_successful_receive_is_unknown() -> TestResult {
    let mut hydration = Hydration::default_mainnet();
    let origin = peer();
    let block = make_block(0, [0u8; 64], 95)?;
    let req = request_id(95);

    issue_one(&mut hydration, origin, block.block_hash, req);
    let _advance = hydration.on_block_received(req, &block, persist_ok, parent_known)?;

    assert_unknown_request(hydration.on_not_found(req));
    Ok(())
}

#[test]
fn test_096_load_track_256_hashes_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 512, true));
    let origin = peer();

    for seed in 0u64..256u64 {
        note(
            &mut hydration,
            origin,
            deterministic_hash(9_600u64.saturating_add(seed)),
            Some(seed),
            HydrationReason::Explicit,
            "load track",
        );
    }

    assert_eq!(hydration.tracked_len(), 256);
}

#[test]
fn test_097_load_issue_128_hashes_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 256, true));
    let origin = peer();

    for seed in 0u64..128u64 {
        let hash = deterministic_hash(9_700u64.saturating_add(seed));
        note(
            &mut hydration,
            origin,
            hash,
            Some(seed),
            HydrationReason::Explicit,
            "load issue",
        );
    }

    for seed in 0u64..128u64 {
        let hash = deterministic_hash(9_700u64.saturating_add(seed));
        assert_eq!(hydration.next_request(), Some((origin, hash)));
        hydration.mark_issued(request_id(9_700u64.saturating_add(seed)), hash);
    }

    assert_eq!(hydration.inflight_len(), 128);
}

#[test]
fn test_098_load_fail_128_hashes_and_requeue_vector() {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 256, true));
    let origin = peer();

    for seed in 0u64..128u64 {
        let hash = deterministic_hash(9_800u64.saturating_add(seed));
        issue_one(
            &mut hydration,
            origin,
            hash,
            request_id(9_800u64.saturating_add(seed)),
        );
    }

    for seed in 0u64..128u64 {
        let hash = deterministic_hash(9_800u64.saturating_add(seed));
        assert_retry(
            hydration.on_request_failed(request_id(9_800u64.saturating_add(seed))),
            hash,
            2,
        );
    }

    assert_eq!(hydration.inflight_len(), 0);
    assert_eq!(hydration.tracked_len(), 128);
}

#[test]
fn test_099_load_receive_64_genesis_blocks_complete_vector() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 128, true));
    let origin = peer();

    for seed in 0u64..64u64 {
        let block = make_block(0, [0u8; 64], 9_900u64.saturating_add(seed))?;
        let req = request_id(9_900u64.saturating_add(seed));
        issue_one(&mut hydration, origin, block.block_hash, req);

        let advance = hydration.on_block_received(req, &block, persist_ok, parent_known)?;
        assert_eq!(
            advance,
            HydrationAdvance::AcceptedComplete {
                hash: block.block_hash
            }
        );
    }

    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
    Ok(())
}

#[test]
fn test_100_end_to_end_child_then_parent_hydration_flow_vector() -> TestResult {
    let mut hydration = Hydration::new(cfg_zero_cooldown(3, 16, true));
    let origin = peer();

    let grandparent = make_block(0, [0u8; 64], 10_000)?;
    let parent = make_block(1, grandparent.block_hash, 10_001)?;
    let child = make_block(2, parent.block_hash, 10_002)?;

    issue_one(&mut hydration, origin, child.block_hash, request_id(1001));

    let first =
        hydration.on_block_received(request_id(1001), &child, persist_ok, parent_missing)?;

    assert_eq!(
        first,
        HydrationAdvance::AcceptedNeedsParent {
            hash: child.block_hash,
            missing_parent: parent.block_hash
        }
    );

    assert_eq!(hydration.next_request(), Some((origin, parent.block_hash)));
    hydration.mark_issued(request_id(1002), parent.block_hash);

    let second = hydration.on_block_received(request_id(1002), &parent, persist_ok, |hash| {
        *hash == grandparent.block_hash
    })?;

    match second {
        HydrationAdvance::AcceptedUnblockedChildren {
            hash,
            children_unblocked,
        } => {
            assert_eq!(hash, parent.block_hash);
            assert_eq!(children_unblocked, vec![child.block_hash]);
        }
        other => panic!("expected AcceptedUnblockedChildren, got {other:?}"),
    }

    assert_eq!(hydration.tracked_len(), 0);
    assert_eq!(hydration.inflight_len(), 0);
    Ok(())
}
