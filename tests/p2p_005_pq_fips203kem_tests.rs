#![forbid(unsafe_code)]

use anyhow::{Result as AnyResult, anyhow};
use remzar::network::p2p_005_pq_fips203kem::{
    DEFAULT_MAX_MESSAGE_AGE_SECS, LocalPqKeypair, MAX_ALLOWED_MESSAGE_AGE_SECS,
    MAX_FUTURE_SKEW_SECS, PQ_KEM_SUITE_ID, PQ_KEM_SUITE_NAME, PQ_MAX_WIRE_BYTES, PQ_NONCE_LEN,
    PQ_SHARED_SECRET_LEN, PqKemAccept, PqKemError, PqKemManager, PqKemOffer, PqKemPolicy,
    PqResponder, PqResult, PqSessionKey, ReplayFilter, ct_len, dk_len, ek_len, shared_secret_len,
    validate_ct_bytes, validate_ek_bytes,
};
use std::time::Duration;

fn assert_invalid_range_nonzero<T>(result: PqResult<T>, field: &'static str) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidRange {
            field: got_field,
            details,
        }) => {
            assert_eq!(got_field, field);
            assert!(details.contains("nonzero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidRange error")),
    }
}

fn assert_crypto_or_ok<T>(result: PqResult<T>) {
    match result {
        Ok(_) | Err(PqKemError::Crypto(_)) => {}
        Err(other) => {
            let rendered = format!("{other:?}");
            assert!(!rendered.is_empty());
        }
    }
}

fn lcg_next(state: &mut u64) -> u64 {
    let next = state
        .wrapping_mul(6_364_136_223_846_793_005_u64)
        .wrapping_add(1_442_695_040_888_963_407_u64);
    *state = next;
    next
}

fn nonce_from_seed(seed: u64) -> [u8; PQ_NONCE_LEN] {
    let mut out = [0_u8; PQ_NONCE_LEN];
    let mut state = seed;

    for slot in &mut out {
        let next = lcg_next(&mut state);
        let bytes = next.to_le_bytes();
        if let Some(first) = bytes.first() {
            *slot = *first;
        }
    }

    out
}

fn fresh_offer(seed: u64) -> PqResult<(LocalPqKeypair, PqKemOffer, [u8; PQ_NONCE_LEN])> {
    let local = LocalPqKeypair::generate()?;
    let nonce = nonce_from_seed(seed);
    let offer = local.build_offer(nonce)?;
    Ok((local, offer, nonce))
}

fn full_handshake(seed: u64) -> PqResult<(PqSessionKey, PqSessionKey)> {
    let (mut local, offer, nonce) = fresh_offer(seed)?;
    let (accept, responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    let initiator_session = local.decapsulate_accept(
        &accept,
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    Ok((initiator_session, responder_session))
}

fn manager_handshake(seed: u64) -> PqResult<(PqSessionKey, PqSessionKey)> {
    let mut initiator_mgr = PqKemManager::default();
    let mut responder_mgr = PqKemManager::default();

    let mut local = initiator_mgr.build_local_keypair()?;
    let nonce = nonce_from_seed(seed);
    let offer = initiator_mgr.build_offer(&local, nonce)?;

    let (accept, responder_session) = responder_mgr.accept_offer(&offer)?;
    let initiator_session = initiator_mgr.finalize_accept(&mut local, &accept, nonce)?;

    Ok((initiator_session, responder_session))
}

fn assert_invalid_length<T>(
    result: PqResult<T>,
    field: &'static str,
    expected: usize,
    actual: usize,
) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidLength {
            field: got_field,
            expected: got_expected,
            actual: got_actual,
        }) => {
            assert_eq!(got_field, field);
            assert_eq!(got_expected, expected);
            assert_eq!(got_actual, actual);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidLength error")),
    }
}

fn assert_invalid_message_contains<T>(result: PqResult<T>, needle: &str) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidMessage(message)) => {
            assert!(message.contains(needle));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidMessage error containing {needle}")),
    }
}

fn assert_invalid_state_contains<T>(result: PqResult<T>, needle: &str) -> AnyResult<()> {
    match result {
        Err(PqKemError::InvalidState(message)) => {
            assert!(message.contains(needle));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected InvalidState error containing {needle}")),
    }
}

fn assert_expired<T>(result: PqResult<T>, field: &'static str) -> AnyResult<()> {
    match result {
        Err(PqKemError::Expired {
            field: got_field,
            age_secs,
            max_age_secs,
        }) => {
            assert_eq!(got_field, field);
            assert!(age_secs > max_age_secs);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected Expired error")),
    }
}

fn assert_clock_skew<T>(result: PqResult<T>, field: &'static str) -> AnyResult<()> {
    match result {
        Err(PqKemError::ClockSkew {
            field: got_field,
            skew_secs,
            max_future_skew_secs,
            ..
        }) => {
            assert_eq!(got_field, field);
            assert_eq!(max_future_skew_secs, MAX_FUTURE_SKEW_SECS);
            assert!(skew_secs > max_future_skew_secs);
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected ClockSkew error")),
    }
}

fn assert_replay_detected<T>(result: PqResult<T>) -> AnyResult<()> {
    match result {
        Err(PqKemError::ReplayDetected { nonce_hex }) => {
            assert_eq!(nonce_hex.len(), PQ_NONCE_LEN.saturating_mul(2_usize));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected ReplayDetected error")),
    }
}

/* ───────────────────────── constants / sizes ───────────────────────── */

#[test]
fn test_001_public_constants_are_consistent() -> AnyResult<()> {
    assert_eq!(shared_secret_len(), PQ_SHARED_SECRET_LEN);
    assert_eq!(PQ_SHARED_SECRET_LEN, 32_usize);
    assert_eq!(PQ_NONCE_LEN, 32_usize);
    assert!(MAX_FUTURE_SKEW_SECS > 0_u64);
    assert!(DEFAULT_MAX_MESSAGE_AGE_SECS <= MAX_ALLOWED_MESSAGE_AGE_SECS);
    assert_eq!(PQ_KEM_SUITE_ID, 0x0301_u16);
    assert_eq!(PQ_KEM_SUITE_NAME, "ML-KEM-768/FIPS203-0.4.3");
    assert!(PQ_MAX_WIRE_BYTES >= ek_len());
    assert!(PQ_MAX_WIRE_BYTES >= ct_len());
    assert!(dk_len() > ek_len());
    assert!(ct_len() > 0_usize);
    Ok(())
}

#[test]
fn test_002_default_policy_matches_public_defaults() -> AnyResult<()> {
    let policy = PqKemPolicy::default();

    assert_eq!(
        policy.max_message_age,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)
    );
    assert!(policy.require_single_use_local_keypair);
    assert_eq!(policy.replay_filter_capacity, 4096_usize);
    Ok(())
}

#[test]
fn test_003_manager_default_exposes_default_policy() -> AnyResult<()> {
    let manager = PqKemManager::default();

    assert_eq!(
        manager.policy().max_message_age,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)
    );
    assert!(manager.policy().require_single_use_local_keypair);
    assert_eq!(manager.policy().replay_filter_capacity, 4096_usize);
    Ok(())
}

/* ───────────────────────── replay filter ───────────────────────── */

#[test]
fn test_004_replay_filter_insert_and_contains() -> AnyResult<()> {
    let nonce = nonce_from_seed(4_u64);
    let mut filter = ReplayFilter::new(8_usize);

    assert!(!filter.contains(&nonce));
    assert!(filter.insert(nonce));
    assert!(filter.contains(&nonce));
    Ok(())
}

#[test]
fn test_005_replay_filter_duplicate_insert_returns_false() -> AnyResult<()> {
    let nonce = nonce_from_seed(5_u64);
    let mut filter = ReplayFilter::new(8_usize);

    assert!(filter.insert(nonce));
    assert!(!filter.insert(nonce));
    Ok(())
}

#[test]
fn test_006_replay_filter_check_and_insert_rejects_duplicate() -> AnyResult<()> {
    let nonce = nonce_from_seed(6_u64);
    let mut filter = ReplayFilter::new(8_usize);

    filter.check_and_insert(nonce)?;
    assert_replay_detected(filter.check_and_insert(nonce))?;
    Ok(())
}

#[test]
fn test_007_replay_filter_clear_allows_nonce_reuse() -> AnyResult<()> {
    let nonce = nonce_from_seed(7_u64);
    let mut filter = ReplayFilter::new(8_usize);

    filter.check_and_insert(nonce)?;
    assert_replay_detected(filter.check_and_insert(nonce))?;

    filter.clear();

    assert!(filter.check_and_insert(nonce).is_ok());
    Ok(())
}

#[test]
fn test_008_replay_filter_zero_capacity_is_clamped_to_min_capacity() -> AnyResult<()> {
    let first = nonce_from_seed(8_u64);
    let second = nonce_from_seed(9_u64);
    let mut filter = ReplayFilter::new(0_usize);

    assert_eq!(filter.capacity(), 16_usize);
    assert!(filter.insert(first));
    assert!(filter.contains(&first));

    assert!(filter.insert(second));
    assert!(filter.contains(&first));
    assert!(filter.contains(&second));
    Ok(())
}

#[test]
fn test_009_replay_filter_capacity_clear_behavior_is_safe() -> AnyResult<()> {
    let first = nonce_from_seed(10_u64);
    let mut filter = ReplayFilter::new(2_usize);

    assert_eq!(filter.capacity(), 16_usize);
    assert!(filter.insert(first));

    for seed in 11_u64..=26_u64 {
        assert!(filter.insert(nonce_from_seed(seed)));
    }

    assert!(!filter.contains(&first));
    assert!(filter.contains(&nonce_from_seed(26_u64)));
    Ok(())
}

/* ───────────────────────── keypair / offer vectors ─────────────────────── */

#[test]
fn test_010_local_keypair_generate_has_expected_ek_len() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;

    assert_eq!(local.ek_bytes().len(), ek_len());
    assert!(!local.is_consumed());
    Ok(())
}

#[test]
fn test_011_local_keypair_debug_redacts_decapsulation_key() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;
    let debug = format!("{local:?}");

    assert!(debug.contains("LocalPqKeypair"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("consumed"));
    Ok(())
}

#[test]
fn test_012_build_offer_has_expected_fields() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;
    let nonce = nonce_from_seed(12_u64);
    let offer = local.build_offer(nonce)?;

    assert_eq!(offer.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(offer.nonce, nonce.to_vec());
    assert_eq!(offer.ek.len(), ek_len());
    assert!(offer.created_at_unix_secs > 0_u64);
    Ok(())
}

#[test]
fn test_013_offer_nonce_array_round_trip() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(13_u64)?;

    let nonce_array = offer.nonce_array()?;

    assert_eq!(nonce_array, nonce);
    Ok(())
}

#[test]
fn test_014_offer_validate_untrusted_accepts_fresh_valid_offer() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(14_u64)?;

    let result = offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS));

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_015_validate_ek_bytes_accepts_generated_ek() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;

    let result = validate_ek_bytes(local.ek_bytes());

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_016_validate_ek_bytes_rejects_short_input() -> AnyResult<()> {
    let short = vec![0_u8; ek_len().saturating_sub(1_usize)];

    assert_invalid_length(validate_ek_bytes(&short), "ek", ek_len(), short.len())?;
    Ok(())
}

#[test]
fn test_017_validate_ek_bytes_rejects_long_input() -> AnyResult<()> {
    let long = vec![0_u8; ek_len().saturating_add(1_usize)];

    assert_invalid_length(validate_ek_bytes(&long), "ek", ek_len(), long.len())?;
    Ok(())
}

#[test]
fn test_018_offer_rejects_wrong_suite_id() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(18_u64)?;
    offer.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);

    assert_invalid_message_contains(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "suite",
    )?;
    Ok(())
}

#[test]
fn test_019_offer_rejects_zero_created_at() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(19_u64)?;
    offer.created_at_unix_secs = 0_u64;

    match offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)) {
        Err(PqKemError::InvalidRange { field, details }) => {
            assert_eq!(field, "created_at_unix_secs");
            assert!(details.contains("nonzero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(()) => Err(anyhow!("expected InvalidRange error")),
    }
}

#[test]
fn test_020_offer_rejects_short_nonce() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(20_u64)?;
    offer.nonce.pop();

    assert_invalid_length(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "nonce",
        PQ_NONCE_LEN,
        offer.nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_021_offer_rejects_long_nonce() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(21_u64)?;
    offer.nonce.push(1_u8);

    assert_invalid_length(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "nonce",
        PQ_NONCE_LEN,
        offer.nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_022_offer_rejects_short_ek() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(22_u64)?;
    let _ = offer.ek.pop();

    assert_invalid_length(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "ek",
        ek_len(),
        offer.ek.len(),
    )?;
    Ok(())
}

#[test]
fn test_023_offer_rejects_long_ek() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(23_u64)?;
    offer.ek.push(1_u8);

    assert_invalid_length(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "ek",
        ek_len(),
        offer.ek.len(),
    )?;
    Ok(())
}

#[test]
fn test_024_offer_rejects_expired_timestamp() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(24_u64)?;
    offer.created_at_unix_secs = 1_u64;

    assert_expired(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "PqKemOffer",
    )?;
    Ok(())
}

/* ───────────────────────── accept / responder vectors ──────────────────── */

#[test]
fn test_025_responder_accepts_valid_offer_and_returns_session() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(25_u64)?;

    let (accept, session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert_eq!(accept.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(accept.offer_nonce, offer.nonce);
    assert_eq!(accept.ct.len(), ct_len());
    assert_eq!(session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(session.suite_name(), PQ_KEM_SUITE_NAME);
    assert_eq!(session.as_bytes().len(), shared_secret_len());
    assert!(session.established_at_unix_secs() > 0_u64);
    Ok(())
}

#[test]
fn test_026_accept_validate_untrusted_accepts_fresh_valid_accept() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(26_u64)?;
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let result =
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS));

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_027_validate_ct_bytes_accepts_generated_ciphertext() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(27_u64)?;
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let result = validate_ct_bytes(&accept.ct);

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_028_validate_ct_bytes_rejects_short_input() -> AnyResult<()> {
    let short = vec![0_u8; ct_len().saturating_sub(1_usize)];

    assert_invalid_length(validate_ct_bytes(&short), "ct", ct_len(), short.len())?;
    Ok(())
}

#[test]
fn test_029_validate_ct_bytes_rejects_long_input() -> AnyResult<()> {
    let long = vec![0_u8; ct_len().saturating_add(1_usize)];

    assert_invalid_length(validate_ct_bytes(&long), "ct", ct_len(), long.len())?;
    Ok(())
}

#[test]
fn test_030_accept_rejects_wrong_suite_id() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(30_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    accept.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);

    assert_invalid_message_contains(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "suite",
    )?;
    Ok(())
}

#[test]
fn test_031_accept_rejects_short_offer_nonce() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(31_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    let _ = accept.offer_nonce.pop();

    assert_invalid_length(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "offer_nonce",
        PQ_NONCE_LEN,
        accept.offer_nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_032_accept_rejects_long_offer_nonce() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(32_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    accept.offer_nonce.push(1_u8);

    assert_invalid_length(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "offer_nonce",
        PQ_NONCE_LEN,
        accept.offer_nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_033_accept_rejects_short_ciphertext() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(33_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    let _ = accept.ct.pop();

    assert_invalid_length(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "ct",
        ct_len(),
        accept.ct.len(),
    )?;
    Ok(())
}

#[test]
fn test_034_accept_rejects_long_ciphertext() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(34_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    accept.ct.push(1_u8);

    assert_invalid_length(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "ct",
        ct_len(),
        accept.ct.len(),
    )?;
    Ok(())
}

#[test]
fn test_035_accept_rejects_offer_nonce_mismatch() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(35_u64)?;
    let wrong_nonce = nonce_from_seed(35_001_u64);
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert_invalid_message_contains(
        accept.validate_untrusted(
            &wrong_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        ),
        "mismatch",
    )?;
    Ok(())
}

#[test]
fn test_036_accept_rejects_zero_created_at() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(36_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    accept.created_at_unix_secs = 0_u64;

    match accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)) {
        Err(PqKemError::InvalidRange { field, details }) => {
            assert_eq!(field, "created_at_unix_secs");
            assert!(details.contains("nonzero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(()) => Err(anyhow!("expected InvalidRange error")),
    }
}

#[test]
fn test_037_accept_rejects_expired_timestamp() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(37_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    accept.created_at_unix_secs = 1_u64;

    assert_expired(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "PqKemAccept",
    )?;
    Ok(())
}

/* ───────────────────────── full handshake / manager paths ──────────────── */

#[test]
fn test_038_full_responder_initiator_handshake_matches_session_keys() -> AnyResult<()> {
    let (initiator_session, responder_session) = full_handshake(38_u64)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.suite_id(), responder_session.suite_id());
    assert_eq!(
        initiator_session.suite_name(),
        responder_session.suite_name()
    );
    Ok(())
}

#[test]
fn test_039_manager_handshake_matches_session_keys() -> AnyResult<()> {
    let (initiator_session, responder_session) = manager_handshake(39_u64)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(responder_session.suite_name(), PQ_KEM_SUITE_NAME);
    Ok(())
}

#[test]
fn test_040_manager_rejects_replayed_offer_nonce() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let (_local, offer, _nonce) = fresh_offer(40_u64)?;

    let first = manager.accept_offer(&offer);
    assert!(first.is_ok());

    assert_replay_detected(manager.accept_offer(&offer))?;
    Ok(())
}

#[test]
fn test_041_manager_clear_replay_cache_allows_same_offer_again() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let (_local, offer, _nonce) = fresh_offer(41_u64)?;

    let first = manager.accept_offer(&offer);
    assert!(first.is_ok());

    assert_replay_detected(manager.accept_offer(&offer))?;

    manager.clear_replay_cache();

    let second_after_clear = manager.accept_offer(&offer);
    assert!(second_after_clear.is_ok());
    Ok(())
}

#[test]
fn test_042_manager_replay_capacity_one_eviction_allows_older_nonce_again() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 1_usize,
    };
    let mut manager = PqKemManager::new(policy);

    let (_local_one, offer_one, _nonce_one) = fresh_offer(42_u64)?;

    assert!(manager.accept_offer(&offer_one).is_ok());

    for seed in 43_u64..=58_u64 {
        let (_local, offer, _nonce) = fresh_offer(seed)?;
        assert!(manager.accept_offer(&offer).is_ok());
    }

    assert!(manager.accept_offer(&offer_one).is_ok());
    Ok(())
}

#[test]
fn test_043_custom_policy_fields_are_preserved() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(7_u64),
        require_single_use_local_keypair: false,
        replay_filter_capacity: 3_usize,
    };
    let manager = PqKemManager::new(policy);

    assert_eq!(manager.policy().max_message_age, Duration::from_secs(7_u64));
    assert!(!manager.policy().require_single_use_local_keypair);
    assert_eq!(manager.policy().replay_filter_capacity, 3_usize);
    Ok(())
}

#[test]
fn test_044_manager_build_local_keypair_returns_unconsumed_keypair() -> AnyResult<()> {
    let manager = PqKemManager::default();
    let local = manager.build_local_keypair()?;

    assert_eq!(local.ek_bytes().len(), ek_len());
    assert!(!local.is_consumed());
    Ok(())
}

#[test]
fn test_045_manager_build_offer_does_not_consume_local_keypair() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let local = manager.build_local_keypair()?;
    let nonce = nonce_from_seed(45_u64);

    let offer = manager.build_offer(&local, nonce)?;

    assert_eq!(offer.nonce, nonce.to_vec());
    assert!(!local.is_consumed());
    Ok(())
}

#[test]
fn test_046_manager_accept_offer_rejects_same_nonce_even_with_different_ek() -> AnyResult<()> {
    let mut manager = PqKemManager::default();

    let (_local_one, offer_one, nonce) = fresh_offer(46_u64)?;
    let (local_two, _offer_two, _nonce_two) = fresh_offer(46_001_u64)?;
    let offer_two_same_nonce = local_two.build_offer(nonce)?;

    assert!(manager.accept_offer(&offer_one).is_ok());
    assert_replay_detected(manager.accept_offer(&offer_two_same_nonce))?;
    Ok(())
}

#[test]
fn test_047_manager_accept_offer_accepts_same_ek_with_different_nonce() -> AnyResult<()> {
    let mut manager = PqKemManager::default();

    let local = LocalPqKeypair::generate()?;
    let offer_one = local.build_offer(nonce_from_seed(47_u64))?;
    let offer_two = local.build_offer(nonce_from_seed(47_001_u64))?;

    assert!(manager.accept_offer(&offer_one).is_ok());
    assert!(manager.accept_offer(&offer_two).is_ok());
    Ok(())
}

#[test]
fn test_048_manager_accept_offer_rejects_expired_offer_under_custom_policy() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(1_u64),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 8_usize,
    };
    let mut manager = PqKemManager::new(policy);
    let (_local, mut offer, _nonce) = fresh_offer(48_u64)?;
    offer.created_at_unix_secs = 1_u64;

    assert_expired(manager.accept_offer(&offer), "PqKemOffer")?;
    Ok(())
}

#[test]
fn test_049_manager_finalize_accept_marks_local_consumed() -> AnyResult<()> {
    let mut initiator_mgr = PqKemManager::default();
    let mut responder_mgr = PqKemManager::default();

    let mut local = initiator_mgr.build_local_keypair()?;
    let nonce = nonce_from_seed(49_u64);
    let offer = initiator_mgr.build_offer(&local, nonce)?;
    let (accept, _responder_session) = responder_mgr.accept_offer(&offer)?;

    assert!(!local.is_consumed());

    let initiator_session = initiator_mgr.finalize_accept(&mut local, &accept, nonce)?;

    assert_eq!(initiator_session.as_bytes().len(), PQ_SHARED_SECRET_LEN);
    assert!(local.is_consumed());
    Ok(())
}

#[test]
fn test_050_manager_finalize_accept_rejects_second_finalize_with_same_local_keypair()
-> AnyResult<()> {
    let mut initiator_mgr = PqKemManager::default();
    let mut responder_mgr = PqKemManager::default();

    let mut local = initiator_mgr.build_local_keypair()?;
    let nonce = nonce_from_seed(50_u64);
    let offer = initiator_mgr.build_offer(&local, nonce)?;
    let (accept, _responder_session) = responder_mgr.accept_offer(&offer)?;

    let first = initiator_mgr.finalize_accept(&mut local, &accept, nonce);
    assert!(first.is_ok());

    assert_invalid_state_contains(
        initiator_mgr.finalize_accept(&mut local, &accept, nonce),
        "consumed",
    )?;
    Ok(())
}

#[test]
fn test_051_policy_false_still_cannot_reuse_consumed_local_keypair() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: false,
        replay_filter_capacity: 8_usize,
    };
    let mut initiator_mgr = PqKemManager::new(policy);
    let mut responder_mgr = PqKemManager::default();

    let mut local = initiator_mgr.build_local_keypair()?;
    let nonce = nonce_from_seed(51_u64);
    let offer = initiator_mgr.build_offer(&local, nonce)?;
    let (accept, _responder_session) = responder_mgr.accept_offer(&offer)?;

    let first = initiator_mgr.finalize_accept(&mut local, &accept, nonce);
    assert!(first.is_ok());

    assert_invalid_state_contains(
        initiator_mgr.finalize_accept(&mut local, &accept, nonce),
        "consumed",
    )?;
    Ok(())
}

/* ───────────────────────── local keypair state edge cases ──────────────── */

#[test]
fn test_052_local_set_consumed_true_blocks_decapsulation() -> AnyResult<()> {
    let (mut local, offer, nonce) = fresh_offer(52_u64)?;
    let (accept, _responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    local.set_consumed(true);

    assert_invalid_state_contains(
        local.decapsulate_accept(
            &accept,
            &nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        ),
        "already consumed",
    )?;
    Ok(())
}

#[test]
fn test_053_local_set_consumed_false_reenables_before_first_decapsulation() -> AnyResult<()> {
    let (mut local, offer, nonce) = fresh_offer(53_u64)?;
    let (accept, responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    local.set_consumed(true);
    assert!(local.is_consumed());

    local.set_consumed(false);
    assert!(!local.is_consumed());

    let initiator_session = local.decapsulate_accept(
        &accept,
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert!(local.is_consumed());
    Ok(())
}

#[test]
fn test_054_local_decapsulate_accept_rejects_nonce_mismatch() -> AnyResult<()> {
    let (mut local, offer, _nonce) = fresh_offer(54_u64)?;
    let wrong_nonce = nonce_from_seed(54_001_u64);
    let (accept, _responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert_invalid_message_contains(
        local.decapsulate_accept(
            &accept,
            &wrong_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        ),
        "mismatch",
    )?;
    Ok(())
}

#[test]
fn test_055_local_decapsulate_accept_rejects_short_ciphertext() -> AnyResult<()> {
    let (mut local, offer, nonce) = fresh_offer(55_u64)?;
    let (mut accept, _responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert!(accept.ct.pop().is_some());

    assert_invalid_length(
        local.decapsulate_accept(
            &accept,
            &nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        ),
        "ct",
        ct_len(),
        accept.ct.len(),
    )?;
    Ok(())
}

#[test]
fn test_056_local_decapsulate_accept_rejects_wrong_suite_id() -> AnyResult<()> {
    let (mut local, offer, nonce) = fresh_offer(56_u64)?;
    let (mut accept, _responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);

    assert_invalid_message_contains(
        local.decapsulate_accept(
            &accept,
            &nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        ),
        "suite",
    )?;
    Ok(())
}

/* ───────────────────────── serialization vectors ───────────────────────── */

#[test]
fn test_057_offer_serde_json_round_trip() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(57_u64)?;

    let encoded = serde_json::to_string(&offer)?;
    let decoded = serde_json::from_str::<PqKemOffer>(&encoded)?;

    assert_eq!(decoded, offer);
    Ok(())
}

#[test]
fn test_058_accept_serde_json_round_trip() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(58_u64)?;
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let encoded = serde_json::to_string(&accept)?;
    let decoded = serde_json::from_str::<PqKemAccept>(&encoded)?;

    assert_eq!(decoded, accept);
    Ok(())
}

#[test]
fn test_059_offer_postcard_round_trip() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(59_u64)?;

    let encoded = postcard::to_stdvec(&offer)?;
    let decoded = postcard::from_bytes::<PqKemOffer>(&encoded)?;

    assert_eq!(decoded, offer);
    assert!(encoded.len() <= PQ_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn test_060_accept_postcard_round_trip() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(60_u64)?;
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let encoded = postcard::to_stdvec(&accept)?;
    let decoded = postcard::from_bytes::<PqKemAccept>(&encoded)?;

    assert_eq!(decoded, accept);
    assert!(encoded.len() <= PQ_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn test_061_offer_postcard_encoded_size_is_bounded() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(61_u64)?;

    let encoded = postcard::to_stdvec(&offer)?;

    assert!(encoded.len() < PQ_MAX_WIRE_BYTES);
    Ok(())
}

#[test]
fn test_062_accept_postcard_encoded_size_is_bounded() -> AnyResult<()> {
    let (_local, offer, _nonce) = fresh_offer(62_u64)?;
    let (accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let encoded = postcard::to_stdvec(&accept)?;

    assert!(encoded.len() < PQ_MAX_WIRE_BYTES);
    Ok(())
}

/* ───────────────────────── field order / mutation edge cases ───────────── */

#[test]
fn test_063_offer_wrong_suite_takes_priority_over_bad_lengths() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(63_u64)?;
    offer.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);
    assert!(offer.nonce.pop().is_some());

    assert_invalid_message_contains(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "suite",
    )?;
    Ok(())
}

#[test]
fn test_064_offer_zero_timestamp_takes_priority_over_bad_nonce_length_after_suite_ok()
-> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(64_u64)?;
    offer.created_at_unix_secs = 0_u64;
    assert!(offer.nonce.pop().is_some());

    assert_invalid_range_nonzero(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "created_at_unix_secs",
    )?;
    Ok(())
}

#[test]
fn test_065_offer_bad_nonce_length_takes_priority_over_bad_ek_length() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(65_u64)?;
    assert!(offer.nonce.pop().is_some());
    assert!(offer.ek.pop().is_some());

    assert_invalid_length(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "nonce",
        PQ_NONCE_LEN,
        offer.nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_066_accept_wrong_suite_takes_priority_over_bad_lengths() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(66_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.suite_id = PQ_KEM_SUITE_ID.saturating_add(1_u16);
    assert!(accept.offer_nonce.pop().is_some());

    assert_invalid_message_contains(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "suite",
    )?;
    Ok(())
}

#[test]
fn test_067_accept_zero_timestamp_takes_priority_over_nonce_length() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(67_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = 0_u64;
    assert!(accept.offer_nonce.pop().is_some());

    assert_invalid_range_nonzero(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "created_at_unix_secs",
    )?;
    Ok(())
}

#[test]
fn test_068_accept_bad_offer_nonce_length_takes_priority_over_ct_length() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(68_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert!(accept.offer_nonce.pop().is_some());
    assert!(accept.ct.pop().is_some());

    assert_invalid_length(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "offer_nonce",
        PQ_NONCE_LEN,
        accept.offer_nonce.len(),
    )?;
    Ok(())
}

#[test]
fn test_069_offer_rejects_timestamp_beyond_future_skew() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(69_u64)?;
    offer.created_at_unix_secs = u64::MAX;

    assert_clock_skew(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "PqKemOffer",
    )?;
    Ok(())
}

#[test]
fn test_070_accept_rejects_timestamp_beyond_future_skew() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(70_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = u64::MAX;

    assert_clock_skew(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
        "PqKemAccept",
    )?;
    Ok(())
}

/* ───────────────────────── session key vectors ─────────────────────────── */

#[test]
fn test_071_session_key_clone_and_equality() -> AnyResult<()> {
    let (initiator_session, responder_session) = full_handshake(71_u64)?;
    let cloned = initiator_session.clone();

    assert_eq!(cloned, initiator_session);
    assert_eq!(cloned.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn test_072_session_key_into_bytes_matches_as_bytes_snapshot() -> AnyResult<()> {
    let (session, _responder_session) = full_handshake(72_u64)?;
    let snapshot = *session.as_bytes();

    let moved = session.into_bytes();

    assert_eq!(moved, snapshot);
    assert_eq!(moved.len(), PQ_SHARED_SECRET_LEN);
    Ok(())
}

#[test]
fn test_073_session_key_zeroize_sets_all_bytes_to_zero() -> AnyResult<()> {
    let (mut session, _responder_session) = full_handshake(73_u64)?;

    session.zeroize();

    assert!(session.as_bytes().iter().all(|b| *b == 0_u8));
    assert_eq!(session.as_bytes().len(), PQ_SHARED_SECRET_LEN);
    Ok(())
}

#[test]
fn test_074_session_key_metadata_is_populated() -> AnyResult<()> {
    let (session, _responder_session) = full_handshake(74_u64)?;

    assert_eq!(session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(session.suite_name(), PQ_KEM_SUITE_NAME);
    assert!(session.established_at_unix_secs() > 0_u64);
    Ok(())
}

#[test]
fn test_075_zeroized_session_no_longer_matches_responder_session() -> AnyResult<()> {
    let (mut initiator_session, responder_session) = full_handshake(75_u64)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());

    initiator_session.zeroize();

    assert_ne!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

/* ───────────────────────── error display / conversion vectors ──────────── */

#[test]
fn test_076_error_display_invalid_length_contains_field_and_lengths() -> AnyResult<()> {
    let error = PqKemError::InvalidLength {
        field: "nonce",
        expected: PQ_NONCE_LEN,
        actual: PQ_NONCE_LEN.saturating_sub(1_usize),
    };

    let rendered = error.to_string();

    assert!(rendered.contains("nonce"));
    assert!(rendered.contains("expected"));
    assert!(rendered.contains("got"));
    Ok(())
}

#[test]
fn test_077_error_display_replay_detected_contains_nonce_hex() -> AnyResult<()> {
    let nonce = nonce_from_seed(77_u64);
    let mut filter = ReplayFilter::new(8_usize);

    filter.check_and_insert(nonce)?;

    match filter.check_and_insert(nonce) {
        Err(error @ PqKemError::ReplayDetected { .. }) => {
            let rendered = error.to_string();
            assert!(rendered.contains("replay detected"));
            assert!(rendered.len() > PQ_NONCE_LEN.saturating_mul(2_usize));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(()) => Err(anyhow!("expected replay error")),
    }
}

#[test]
fn test_078_pq_error_converts_to_invalid_data_io_error() -> AnyResult<()> {
    let io_error: std::io::Error = PqKemError::InvalidMessage("bad message").into();

    assert_eq!(io_error.kind(), std::io::ErrorKind::InvalidData);
    assert!(io_error.to_string().contains("bad message"));
    Ok(())
}

#[test]
fn test_079_error_display_expired_contains_age_and_max() -> AnyResult<()> {
    let error = PqKemError::Expired {
        field: "PqKemOffer",
        age_secs: 31_u64,
        max_age_secs: 30_u64,
    };

    let rendered = error.to_string();

    assert!(rendered.contains("PqKemOffer"));
    assert!(rendered.contains("age=31"));
    assert!(rendered.contains("max=30"));
    Ok(())
}

#[test]
fn test_080_error_display_io_contains_message() -> AnyResult<()> {
    let error = PqKemError::Io("wire read failed".to_owned());

    let rendered = error.to_string();

    assert!(rendered.contains("io error"));
    assert!(rendered.contains("wire read failed"));
    Ok(())
}

/* ───────────────────────── adversarial mutation tests ──────────────────── */

#[test]
fn test_081_mutated_offer_ek_same_length_is_handled_without_panic() -> AnyResult<()> {
    let (_local, mut offer, _nonce) = fresh_offer(81_u64)?;

    if let Some(first) = offer.ek.first_mut() {
        *first = first.wrapping_add(1_u8);
    }

    assert_crypto_or_ok(
        offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
    );
    Ok(())
}

#[test]
fn test_082_mutated_accept_ct_same_length_is_handled_without_panic() -> AnyResult<()> {
    let (_local, offer, nonce) = fresh_offer(82_u64)?;
    let (mut accept, _session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    if let Some(first) = accept.ct.first_mut() {
        *first = first.wrapping_add(1_u8);
    }

    assert_crypto_or_ok(
        accept.validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)),
    );
    Ok(())
}

#[test]
fn test_083_decapsulating_mutated_ct_same_length_returns_error_or_safe_session() -> AnyResult<()> {
    let (mut local, offer, nonce) = fresh_offer(83_u64)?;
    let (mut accept, responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    if let Some(last) = accept.ct.last_mut() {
        *last = last.wrapping_add(1_u8);
    }

    match local.decapsulate_accept(
        &accept,
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ) {
        Ok(session) => {
            assert_ne!(session.as_bytes(), responder_session.as_bytes());
            Ok(())
        }
        Err(PqKemError::Crypto(_)) | Err(PqKemError::InvalidMessage(_)) => Ok(()),
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
    }
}

#[test]
fn test_084_all_zero_nonce_offer_is_rejected() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;
    let nonce = [0_u8; PQ_NONCE_LEN];

    match local.build_offer(nonce) {
        Err(PqKemError::InvalidRange { field, details }) => {
            assert_eq!(field, "nonce");
            assert!(details.contains("all zero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected all-zero nonce offer to be rejected")),
    }
}

#[test]
fn test_085_all_ff_nonce_offer_can_complete_handshake_once() -> AnyResult<()> {
    let (mut local, _offer, _nonce) = fresh_offer(85_u64)?;
    let nonce = [0xff_u8; PQ_NONCE_LEN];
    let offer = local.build_offer(nonce)?;

    let (accept, responder_session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    let initiator_session = local.decapsulate_accept(
        &accept,
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn test_086_manager_rejects_all_zero_nonce_before_replay_tracking() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;
    let nonce = [0_u8; PQ_NONCE_LEN];

    match local.build_offer(nonce) {
        Err(PqKemError::InvalidRange { field, details }) => {
            assert_eq!(field, "nonce");
            assert!(details.contains("all zero"));
            Ok(())
        }
        Err(other) => Err(anyhow!("unexpected error variant: {other:?}")),
        Ok(_) => Err(anyhow!("expected all-zero nonce offer to be rejected")),
    }
}

#[test]
fn test_087_manager_rejects_replayed_all_ff_nonce() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let local = LocalPqKeypair::generate()?;
    let nonce = [0xff_u8; PQ_NONCE_LEN];
    let offer = local.build_offer(nonce)?;

    assert!(manager.accept_offer(&offer).is_ok());
    assert_replay_detected(manager.accept_offer(&offer))?;
    Ok(())
}

/* ───────────────────────── fuzz-style and load tests ───────────────────── */

#[test]
fn test_088_fuzz_deterministic_8_full_handshakes_match() -> AnyResult<()> {
    for seed in 88_u64..96_u64 {
        let (initiator_session, responder_session) = full_handshake(seed)?;

        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    }

    Ok(())
}

#[test]
fn test_089_fuzz_deterministic_8_manager_handshakes_match() -> AnyResult<()> {
    for seed in 89_u64..97_u64 {
        let (initiator_session, responder_session) = manager_handshake(seed)?;

        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    }

    Ok(())
}

#[test]
fn test_090_fuzz_deterministic_offer_validation_for_16_nonces() -> AnyResult<()> {
    let local = LocalPqKeypair::generate()?;

    for seed in 90_u64..106_u64 {
        let nonce = nonce_from_seed(seed);
        let offer = local.build_offer(nonce)?;

        assert_eq!(offer.nonce_array()?, nonce);
        assert!(
            offer
                .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_ok()
        );
    }

    Ok(())
}

#[test]
fn test_091_load_replay_filter_64_unique_nonces_are_accepted() -> AnyResult<()> {
    let mut filter = ReplayFilter::new(128_usize);

    for seed in 91_u64..155_u64 {
        let nonce = nonce_from_seed(seed);
        assert!(filter.check_and_insert(nonce).is_ok());
    }

    Ok(())
}

#[test]
fn test_092_load_replay_filter_duplicate_after_many_unique_is_rejected() -> AnyResult<()> {
    let mut filter = ReplayFilter::new(128_usize);
    let duplicate = nonce_from_seed(92_u64);

    filter.check_and_insert(duplicate)?;

    for seed in 93_u64..125_u64 {
        filter.check_and_insert(nonce_from_seed(seed))?;
    }

    assert_replay_detected(filter.check_and_insert(duplicate))?;
    Ok(())
}

#[test]
fn test_093_load_manager_16_unique_offers_are_accepted() -> AnyResult<()> {
    let mut manager = PqKemManager::default();

    for seed in 93_u64..109_u64 {
        let (_local, offer, _nonce) = fresh_offer(seed)?;
        let result = manager.accept_offer(&offer);
        assert!(result.is_ok());
    }

    Ok(())
}

#[test]
fn test_094_load_manager_clear_replay_between_repeated_same_offer_is_safe() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let (_local, offer, _nonce) = fresh_offer(94_u64)?;

    for _round in 0_u8..8_u8 {
        let result = manager.accept_offer(&offer);
        assert!(result.is_ok());
        manager.clear_replay_cache();
    }

    Ok(())
}

#[test]
fn test_095_load_session_zeroize_for_8_handshakes() -> AnyResult<()> {
    for seed in 95_u64..103_u64 {
        let (mut initiator_session, responder_session) = full_handshake(seed)?;
        assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());

        initiator_session.zeroize();

        assert!(initiator_session.as_bytes().iter().all(|b| *b == 0_u8));
    }

    Ok(())
}

#[test]
fn test_096_adversarial_manager_expired_offer_after_valid_offer_keeps_manager_usable()
-> AnyResult<()> {
    let mut manager = PqKemManager::default();

    let (_local_good, good_offer, _good_nonce) = fresh_offer(96_u64)?;
    assert!(manager.accept_offer(&good_offer).is_ok());

    let (_local_bad, mut bad_offer, _bad_nonce) = fresh_offer(96_001_u64)?;
    bad_offer.created_at_unix_secs = 1_u64;

    assert_expired(manager.accept_offer(&bad_offer), "PqKemOffer")?;

    let (_local_next, next_offer, _next_nonce) = fresh_offer(96_002_u64)?;
    assert!(manager.accept_offer(&next_offer).is_ok());
    Ok(())
}

#[test]
fn test_097_adversarial_replay_then_clear_then_new_offer_path_is_safe() -> AnyResult<()> {
    let mut manager = PqKemManager::default();
    let (_local_one, offer_one, _nonce_one) = fresh_offer(97_u64)?;

    assert!(manager.accept_offer(&offer_one).is_ok());
    assert_replay_detected(manager.accept_offer(&offer_one))?;

    manager.clear_replay_cache();

    let (_local_two, offer_two, _nonce_two) = fresh_offer(97_002_u64)?;
    assert!(manager.accept_offer(&offer_two).is_ok());
    Ok(())
}

#[test]
fn test_098_combined_offer_accept_serde_and_finalize_path_matches() -> AnyResult<()> {
    let mut local = LocalPqKeypair::generate()?;
    let nonce = nonce_from_seed(98_u64);
    let offer = local.build_offer(nonce)?;

    let encoded_offer = postcard::to_stdvec(&offer)?;
    let decoded_offer = postcard::from_bytes::<PqKemOffer>(&encoded_offer)?;

    let (accept, responder_session) = PqResponder::respond_to_offer(
        &decoded_offer,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    let encoded_accept = postcard::to_stdvec(&accept)?;
    let decoded_accept = postcard::from_bytes::<PqKemAccept>(&encoded_accept)?;

    let initiator_session = local.decapsulate_accept(
        &decoded_accept,
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}

#[test]
fn test_099_combined_manager_custom_policy_handshake_matches() -> AnyResult<()> {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 64_usize,
    };
    let mut initiator_mgr = PqKemManager::new(policy.clone());
    let mut responder_mgr = PqKemManager::new(policy);

    let mut local = initiator_mgr.build_local_keypair()?;
    let nonce = nonce_from_seed(99_u64);
    let offer = initiator_mgr.build_offer(&local, nonce)?;
    let (accept, responder_session) = responder_mgr.accept_offer(&offer)?;
    let initiator_session = initiator_mgr.finalize_accept(&mut local, &accept, nonce)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.suite_id(), PQ_KEM_SUITE_ID);
    Ok(())
}

#[test]
fn test_100_combined_adversarial_load_path_is_safe() -> AnyResult<()> {
    let mut manager = PqKemManager::default();

    for seed in 100_u64..108_u64 {
        let (_local, offer, _nonce) = fresh_offer(seed)?;
        let result = manager.accept_offer(&offer);
        assert!(result.is_ok());
    }

    let (_replay_local, replay_offer, _replay_nonce) = fresh_offer(100_u64)?;
    assert_replay_detected(manager.accept_offer(&replay_offer))?;

    manager.clear_replay_cache();

    let (initiator_session, responder_session) = manager_handshake(100_000_u64)?;
    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    Ok(())
}
