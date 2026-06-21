#![cfg(test)]
#![deny(unsafe_code)]

use remzar::network::p2p_005_pq_fips203kem::{
    DEFAULT_MAX_MESSAGE_AGE_SECS, LocalPqKeypair, PQ_KEM_SUITE_ID, PQ_KEM_SUITE_NAME,
    PQ_MAX_WIRE_BYTES, PQ_NONCE_LEN, PQ_SHARED_SECRET_LEN, PqKemAccept, PqKemError, PqKemManager,
    PqKemOffer, PqKemPolicy, PqResponder, ReplayFilter, ct_len, dk_len, ek_len, shared_secret_len,
    validate_ct_bytes, validate_ek_bytes,
};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn now_unix_for_test() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn nonce(seed: u8) -> [u8; PQ_NONCE_LEN] {
    let mut out = [0u8; PQ_NONCE_LEN];

    for (idx, byte) in out.iter_mut().enumerate() {
        let i = u8::try_from(idx).unwrap_or(0);
        *byte = seed
            .wrapping_add(i.wrapping_mul(17))
            .rotate_left(u32::from(i % 7));
    }

    out
}

fn expired_timestamp(extra_age_secs: u64) -> u64 {
    now_unix_for_test().saturating_sub(
        DEFAULT_MAX_MESSAGE_AGE_SECS
            .saturating_add(extra_age_secs)
            .saturating_add(1),
    )
}

fn short_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            let i = u8::try_from(idx % 251).unwrap_or(0);
            seed.wrapping_add(i)
        })
        .collect()
}

fn full_handshake(
    seed: u8,
) -> TestResult<(
    remzar::network::p2p_005_pq_fips203kem::PqSessionKey,
    remzar::network::p2p_005_pq_fips203kem::PqSessionKey,
    PqKemOffer,
    PqKemAccept,
)> {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let offer_nonce = nonce(seed);

    let offer = initiator.build_offer(&local, offer_nonce)?;
    let (accept, responder_session) = responder.accept_offer(&offer)?;
    let initiator_session = initiator.finalize_accept(&mut local, &accept, offer_nonce)?;

    Ok((initiator_session, responder_session, offer, accept))
}

fn assert_invalid_length(
    err: PqKemError,
    expected_field: &'static str,
    expected_len: usize,
    actual_len: usize,
) {
    match err {
        PqKemError::InvalidLength {
            field,
            expected,
            actual,
        } => {
            assert_eq!(field, expected_field);
            assert_eq!(expected, expected_len);
            assert_eq!(actual, actual_len);
        }
        other => panic!("expected InvalidLength, got {other:?}"),
    }
}

#[test]
fn e2e_01_public_constants_are_sane() -> TestResult {
    assert_eq!(PQ_SHARED_SECRET_LEN, 32);
    assert_eq!(shared_secret_len(), 32);
    assert_eq!(PQ_NONCE_LEN, 32);
    assert_eq!(PQ_MAX_WIRE_BYTES, 16 * 1024);
    assert_eq!(PQ_KEM_SUITE_ID, 0x0301);
    assert_eq!(PQ_KEM_SUITE_NAME, "ML-KEM-768/FIPS203-0.4.3");

    assert!(ek_len() > 0);
    assert!(dk_len() > 0);
    assert!(ct_len() > 0);

    Ok(())
}

#[test]
fn e2e_02_default_policy_matches_expected_runtime_defaults() -> TestResult {
    let policy = PqKemPolicy::default();

    assert_eq!(
        policy.max_message_age,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)
    );
    assert!(policy.require_single_use_local_keypair);
    assert_eq!(policy.replay_filter_capacity, 4096);

    Ok(())
}

#[test]
fn e2e_03_default_manager_exposes_default_policy() -> TestResult {
    let manager = PqKemManager::default();

    assert_eq!(
        manager.policy().max_message_age,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)
    );
    assert!(manager.policy().require_single_use_local_keypair);
    assert_eq!(manager.policy().replay_filter_capacity, 4096);

    Ok(())
}

#[test]
fn e2e_04_custom_policy_is_preserved_by_manager() -> TestResult {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(7),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 3,
    };

    let manager = PqKemManager::new(policy.clone());

    assert_eq!(manager.policy().max_message_age, policy.max_message_age);
    assert_eq!(
        manager.policy().require_single_use_local_keypair,
        policy.require_single_use_local_keypair
    );
    assert_eq!(
        manager.policy().replay_filter_capacity,
        policy.replay_filter_capacity
    );

    Ok(())
}

#[test]
fn e2e_05_local_keypair_generate_produces_valid_encapsulation_key_bytes() -> TestResult {
    let local = LocalPqKeypair::generate()?;

    assert_eq!(local.ek_bytes().len(), ek_len());
    validate_ek_bytes(local.ek_bytes())?;
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_06_local_keypair_debug_redacts_private_key() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let debug = format!("{local:?}");

    assert!(debug.contains("LocalPqKeypair"));
    assert!(debug.contains("ek_len"));
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("consumed"));

    Ok(())
}

#[test]
fn e2e_07_build_offer_has_expected_public_fields() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(7);
    let offer = local.build_offer(n)?;

    assert_eq!(offer.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(offer.nonce, n.to_vec());
    assert_eq!(offer.ek.len(), ek_len());
    assert!(offer.created_at_unix_secs > 0);
    validate_ek_bytes(&offer.ek)?;

    Ok(())
}

#[test]
fn e2e_08_offer_validate_accepts_fresh_valid_offer() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(8))?;

    offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    Ok(())
}

#[test]
fn e2e_09_offer_nonce_array_roundtrips() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(9);
    let offer = local.build_offer(n)?;

    assert_eq!(offer.nonce_array()?, n);

    Ok(())
}

#[test]
fn e2e_10_manager_build_offer_does_not_consume_local_keypair() -> TestResult {
    let mut manager = PqKemManager::default();
    let local = manager.build_local_keypair()?;

    let _offer = manager.build_offer(&local, nonce(10))?;

    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_11_manager_can_build_multiple_offers_from_unconsumed_local_keypair() -> TestResult {
    let mut manager = PqKemManager::default();
    let local = manager.build_local_keypair()?;

    let first = manager.build_offer(&local, nonce(11))?;
    let second = manager.build_offer(&local, nonce(12))?;

    assert_eq!(first.ek, second.ek);
    assert_ne!(first.nonce, second.nonce);
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_12_offer_rejects_wrong_suite_id() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(12))?;
    offer.suite_id = PQ_KEM_SUITE_ID.wrapping_add(1);

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("wrong suite id must fail");

    assert_eq!(err, PqKemError::InvalidMessage("unexpected PQ suite id"));

    Ok(())
}

#[test]
fn e2e_13_offer_rejects_zero_created_at() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(13))?;
    offer.created_at_unix_secs = 0;

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("zero timestamp must fail");

    match err {
        PqKemError::InvalidRange { field, details } => {
            assert_eq!(field, "created_at_unix_secs");
            assert_eq!(details, "must be nonzero");
        }
        other => panic!("expected InvalidRange, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_14_offer_rejects_short_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(14))?;
    offer.nonce.pop();

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("short nonce must fail");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, PQ_NONCE_LEN - 1);

    Ok(())
}

#[test]
fn e2e_15_offer_rejects_long_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(15))?;
    offer.nonce.push(0);

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("long nonce must fail");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, PQ_NONCE_LEN + 1);

    Ok(())
}

#[test]
fn e2e_16_offer_rejects_short_ek() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(16))?;
    offer.ek.pop();

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("short ek must fail");

    assert_invalid_length(err, "ek", ek_len(), ek_len() - 1);

    Ok(())
}

#[test]
fn e2e_17_offer_rejects_long_ek() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(17))?;
    offer.ek.push(0);

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("long ek must fail");

    assert_invalid_length(err, "ek", ek_len(), ek_len() + 1);

    Ok(())
}

#[test]
fn e2e_18_offer_rejects_expired_timestamp() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(18))?;
    offer.created_at_unix_secs = expired_timestamp(5);

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("expired offer must fail");

    match err {
        PqKemError::Expired {
            field,
            age_secs,
            max_age_secs,
        } => {
            assert_eq!(field, "PqKemOffer");
            assert!(age_secs > max_age_secs);
            assert_eq!(max_age_secs, DEFAULT_MAX_MESSAGE_AGE_SECS);
        }
        other => panic!("expected Expired, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_19_responder_accepts_valid_offer_and_returns_accept_plus_session() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(19))?;

    let (accept, session) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    assert_eq!(accept.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(accept.offer_nonce, offer.nonce);
    assert_eq!(accept.ct.len(), ct_len());
    assert_eq!(session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(session.suite_name(), PQ_KEM_SUITE_NAME);
    assert_eq!(session.as_bytes().len(), shared_secret_len());

    Ok(())
}

#[test]
fn e2e_20_accept_validate_accepts_fresh_valid_accept() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(20);
    let offer = local.build_offer(offer_nonce)?;

    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.validate_untrusted(
        &offer_nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    Ok(())
}

#[test]
fn e2e_21_accept_rejects_wrong_suite_id() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(21);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.suite_id = PQ_KEM_SUITE_ID.wrapping_add(1);

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("wrong suite id must fail");

    assert_eq!(err, PqKemError::InvalidMessage("unexpected PQ suite id"));

    Ok(())
}

#[test]
fn e2e_22_accept_rejects_zero_created_at() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(22);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = 0;

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("zero timestamp must fail");

    match err {
        PqKemError::InvalidRange { field, details } => {
            assert_eq!(field, "created_at_unix_secs");
            assert_eq!(details, "must be nonzero");
        }
        other => panic!("expected InvalidRange, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_23_accept_rejects_short_offer_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(23);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.offer_nonce.pop();

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("short offer_nonce must fail");

    assert_invalid_length(err, "offer_nonce", PQ_NONCE_LEN, PQ_NONCE_LEN - 1);

    Ok(())
}

#[test]
fn e2e_24_accept_rejects_long_offer_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(24);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.offer_nonce.push(0);

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("long offer_nonce must fail");

    assert_invalid_length(err, "offer_nonce", PQ_NONCE_LEN, PQ_NONCE_LEN + 1);

    Ok(())
}

#[test]
fn e2e_25_accept_rejects_short_ct() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(25);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.ct.pop();

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("short ct must fail");

    assert_invalid_length(err, "ct", ct_len(), ct_len() - 1);

    Ok(())
}

#[test]
fn e2e_26_accept_rejects_long_ct() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(26);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.ct.push(0);

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("long ct must fail");

    assert_invalid_length(err, "ct", ct_len(), ct_len() + 1);

    Ok(())
}

#[test]
fn e2e_27_accept_rejects_offer_nonce_mismatch() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(27);
    let wrong_nonce = nonce(127);
    let offer = local.build_offer(offer_nonce)?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let err = accept
        .validate_untrusted(
            &wrong_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("wrong expected nonce must fail");

    assert_eq!(err, PqKemError::InvalidMessage("offer_nonce mismatch"));

    Ok(())
}

#[test]
fn e2e_28_accept_rejects_expired_timestamp() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer_nonce = nonce(28);
    let offer = local.build_offer(offer_nonce)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = expired_timestamp(10);

    let err = accept
        .validate_untrusted(
            &offer_nonce,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("expired accept must fail");

    match err {
        PqKemError::Expired {
            field,
            age_secs,
            max_age_secs,
        } => {
            assert_eq!(field, "PqKemAccept");
            assert!(age_secs > max_age_secs);
            assert_eq!(max_age_secs, DEFAULT_MAX_MESSAGE_AGE_SECS);
        }
        other => panic!("expected Expired, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_29_full_handshake_establishes_identical_shared_secret() -> TestResult {
    let (initiator_session, responder_session, _, _) = full_handshake(29)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(responder_session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(initiator_session.suite_name(), PQ_KEM_SUITE_NAME);
    assert_eq!(responder_session.suite_name(), PQ_KEM_SUITE_NAME);

    Ok(())
}

#[test]
fn e2e_30_full_handshake_produces_nonzero_shared_secret() -> TestResult {
    let (initiator_session, responder_session, _, _) = full_handshake(30)?;

    assert_ne!(initiator_session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);
    assert_ne!(responder_session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_31_successful_finalize_consumes_local_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(31);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    assert!(!local.is_consumed());

    let _session = initiator.finalize_accept(&mut local, &accept, n)?;

    assert!(local.is_consumed());

    Ok(())
}

#[test]
fn e2e_32_second_finalize_with_same_local_keypair_fails_single_use() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(32);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    let _first = initiator.finalize_accept(&mut local, &accept, n)?;

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("second finalize must fail");

    match err {
        PqKemError::InvalidState(msg) => {
            assert!(
                msg.contains("single-use") || msg.contains("already consumed"),
                "unexpected InvalidState message: {msg}"
            );
        }
        other => panic!("expected InvalidState, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_33_mismatched_accept_nonce_does_not_consume_local_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(33);
    let wrong = nonce(133);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    let err = initiator
        .finalize_accept(&mut local, &accept, wrong)
        .expect_err("mismatched nonce must fail");

    assert_eq!(err, PqKemError::InvalidMessage("offer_nonce mismatch"));
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_34_invalid_accept_ct_length_does_not_consume_local_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(34);
    let offer = initiator.build_offer(&local, n)?;
    let (mut accept, _) = responder.accept_offer(&offer)?;
    accept.ct.pop();

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("short ct must fail");

    assert_invalid_length(err, "ct", ct_len(), ct_len() - 1);
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_35_replay_filter_detects_reused_nonce() -> TestResult {
    let mut filter = ReplayFilter::new(16);
    let n = nonce(35);

    filter.check_and_insert(n)?;

    let err = filter
        .check_and_insert(n)
        .expect_err("same nonce must be replay");

    match err {
        PqKemError::ReplayDetected { nonce_hex } => {
            assert_eq!(nonce_hex.len(), PQ_NONCE_LEN * 2);
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_36_replay_filter_clear_allows_nonce_reuse() -> TestResult {
    let mut filter = ReplayFilter::new(16);
    let n = nonce(36);

    filter.check_and_insert(n)?;
    assert!(filter.contains(&n));

    filter.clear();
    assert!(!filter.contains(&n));

    filter.check_and_insert(n)?;

    Ok(())
}

#[test]
fn e2e_37_replay_filter_capacity_clear_behavior_keeps_filter_bounded() -> TestResult {
    let n1 = nonce(37);
    let mut filter = ReplayFilter::new(2);

    assert_eq!(filter.capacity(), 16);

    assert!(filter.insert(n1));
    assert!(filter.contains(&n1));

    for seed in 38_u8..=53_u8 {
        assert!(filter.insert(nonce(seed)));
    }

    assert!(!filter.contains(&n1));
    assert_eq!(filter.len(), 16);

    filter.clear();

    assert!(filter.is_empty());
    assert!(!filter.contains(&n1));

    Ok(())
}

#[test]
fn e2e_38_replay_filter_zero_capacity_is_clamped_to_one() -> TestResult {
    let n1 = nonce(38);
    let mut filter = ReplayFilter::new(0);

    assert_eq!(filter.capacity(), 16);

    assert!(filter.insert(n1));
    assert!(filter.contains(&n1));

    for seed in 39_u8..=54_u8 {
        assert!(filter.insert(nonce(seed)));
    }

    assert!(!filter.contains(&n1));
    assert_eq!(filter.len(), 16);

    Ok(())
}

#[test]
fn e2e_39_manager_accept_offer_rejects_replayed_offer_nonce() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let local = initiator.build_local_keypair()?;
    let offer = initiator.build_offer(&local, nonce(42))?;

    let _first = responder.accept_offer(&offer)?;

    let err = responder
        .accept_offer(&offer)
        .expect_err("replayed offer must fail");

    match err {
        PqKemError::ReplayDetected { nonce_hex } => {
            assert_eq!(nonce_hex.len(), PQ_NONCE_LEN * 2);
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_40_manager_clear_replay_cache_allows_same_offer_again() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let local = initiator.build_local_keypair()?;
    let offer = initiator.build_offer(&local, nonce(43))?;

    let _first = responder.accept_offer(&offer)?;

    responder.clear_replay_cache();

    let (_second_accept, _second_session) = responder.accept_offer(&offer)?;

    Ok(())
}

#[test]
fn e2e_41_validate_ek_bytes_accepts_real_ek() -> TestResult {
    let local = LocalPqKeypair::generate()?;

    validate_ek_bytes(local.ek_bytes())?;

    Ok(())
}

#[test]
fn e2e_42_validate_ek_bytes_rejects_short_input() -> TestResult {
    let bytes = short_bytes(ek_len() - 1, 42);

    let err = validate_ek_bytes(&bytes).expect_err("short ek must fail");

    assert_invalid_length(err, "ek", ek_len(), ek_len() - 1);

    Ok(())
}

#[test]
fn e2e_43_validate_ek_bytes_rejects_long_input() -> TestResult {
    let bytes = short_bytes(ek_len() + 1, 43);

    let err = validate_ek_bytes(&bytes).expect_err("long ek must fail");

    assert_invalid_length(err, "ek", ek_len(), ek_len() + 1);

    Ok(())
}

#[test]
fn e2e_44_validate_ct_bytes_accepts_real_ciphertext() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(44))?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    validate_ct_bytes(&accept.ct)?;

    Ok(())
}

#[test]
fn e2e_45_validate_ct_bytes_rejects_short_input() -> TestResult {
    let bytes = short_bytes(ct_len() - 1, 45);

    let err = validate_ct_bytes(&bytes).expect_err("short ct must fail");

    assert_invalid_length(err, "ct", ct_len(), ct_len() - 1);

    Ok(())
}

#[test]
fn e2e_46_validate_ct_bytes_rejects_long_input() -> TestResult {
    let bytes = short_bytes(ct_len() + 1, 46);

    let err = validate_ct_bytes(&bytes).expect_err("long ct must fail");

    assert_invalid_length(err, "ct", ct_len(), ct_len() + 1);

    Ok(())
}

#[test]
fn e2e_47_session_key_into_bytes_roundtrips_secret() -> TestResult {
    let (session, _, _, _) = full_handshake(47)?;

    let before = *session.as_bytes();
    let after = session.into_bytes();

    assert_eq!(before, after);
    assert_eq!(after.len(), PQ_SHARED_SECRET_LEN);

    Ok(())
}

#[test]
fn e2e_48_session_key_zeroize_overwrites_secret() -> TestResult {
    let (mut session, _, _, _) = full_handshake(48)?;

    assert_ne!(session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    session.zeroize();

    assert_eq!(session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_49_pq_error_display_and_io_conversion_are_stable() -> TestResult {
    let err = PqKemError::InvalidLength {
        field: "ek",
        expected: ek_len(),
        actual: 1,
    };

    let text = err.to_string();
    assert!(text.contains("invalid length"));
    assert!(text.contains("ek"));

    let io_err: io::Error = err.into();
    assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
    assert!(io_err.to_string().contains("invalid length"));

    Ok(())
}

#[test]
fn e2e_50_full_manager_lifecycle_offer_accept_finalize_replay_clear_and_zeroize() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(50);

    let offer = initiator.build_offer(&local, n)?;
    offer.validate_untrusted(initiator.policy().max_message_age)?;

    let (accept, responder_session) = responder.accept_offer(&offer)?;
    validate_ct_bytes(&accept.ct)?;

    let mut initiator_session = initiator.finalize_accept(&mut local, &accept, n)?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert!(local.is_consumed());

    let replay_err = responder
        .accept_offer(&offer)
        .expect_err("same offer must replay-fail before clear");

    assert!(matches!(replay_err, PqKemError::ReplayDetected { .. }));

    responder.clear_replay_cache();

    let (_accept_after_clear, _session_after_clear) = responder.accept_offer(&offer)?;

    initiator_session.zeroize();
    assert_eq!(initiator_session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_51_offer_postcard_roundtrip_preserves_fields() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(51))?;

    let encoded = postcard::to_allocvec(&offer)?;
    let decoded: PqKemOffer = postcard::from_bytes(&encoded)?;

    assert_eq!(decoded, offer);
    decoded.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    Ok(())
}

#[test]
fn e2e_52_accept_postcard_roundtrip_preserves_fields() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(52);
    let offer = local.build_offer(n)?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let encoded = postcard::to_allocvec(&accept)?;
    let decoded: PqKemAccept = postcard::from_bytes(&encoded)?;

    assert_eq!(decoded, accept);
    decoded.validate_untrusted(&n, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    Ok(())
}

#[test]
fn e2e_53_serialized_offer_is_under_pq_wire_cap() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(53))?;

    let encoded = postcard::to_allocvec(&offer)?;

    assert!(encoded.len() < PQ_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_54_serialized_accept_is_under_pq_wire_cap() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(54))?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let encoded = postcard::to_allocvec(&accept)?;

    assert!(encoded.len() < PQ_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_55_serialized_offer_and_accept_together_are_under_wire_cap() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(55))?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let offer_bytes = postcard::to_allocvec(&offer)?;
    let accept_bytes = postcard::to_allocvec(&accept)?;

    assert!(offer_bytes.len().saturating_add(accept_bytes.len()) < PQ_MAX_WIRE_BYTES);

    Ok(())
}

#[test]
fn e2e_56_offer_nonce_array_rejects_empty_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(56))?;
    offer.nonce.clear();

    let err = offer.nonce_array().expect_err("empty nonce must fail");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, 0);

    Ok(())
}

#[test]
fn e2e_57_offer_nonce_array_rejects_oversized_nonce() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(57))?;
    offer.nonce.push(0xff);

    let err = offer.nonce_array().expect_err("oversized nonce must fail");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, PQ_NONCE_LEN + 1);

    Ok(())
}

#[test]
fn e2e_58_offer_future_timestamp_validates_as_not_expired() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(58))?;

    // Small future clock skew is tolerated, but large future timestamps are
    // rejected by the current FIPS203 freshness policy.
    offer.created_at_unix_secs = now_unix_for_test().saturating_add(1);

    offer.validate_untrusted(Duration::from_secs(1))?;

    Ok(())
}

#[test]
fn e2e_59_accept_future_timestamp_validates_as_not_expired() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(59);
    let offer = local.build_offer(n)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    // Small future clock skew is tolerated, but large future timestamps are
    // rejected by the current FIPS203 freshness policy.
    accept.created_at_unix_secs = now_unix_for_test().saturating_add(1);

    accept.validate_untrusted(&n, Duration::from_secs(1))?;

    Ok(())
}

#[test]
fn e2e_60_offer_recent_timestamp_within_age_validates() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(60))?;

    offer.created_at_unix_secs = now_unix_for_test().saturating_sub(2);

    offer.validate_untrusted(Duration::from_secs(60))?;

    Ok(())
}

#[test]
fn e2e_61_accept_recent_timestamp_within_age_validates() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(61);
    let offer = local.build_offer(n)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = now_unix_for_test().saturating_sub(2);

    accept.validate_untrusted(&n, Duration::from_secs(60))?;

    Ok(())
}

#[test]
fn e2e_62_accept_expiry_is_reported_before_nonce_mismatch() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(62);
    let wrong = nonce(162);
    let offer = local.build_offer(n)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.created_at_unix_secs = expired_timestamp(999);

    let err = accept
        .validate_untrusted(&wrong, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("expired accept must fail before nonce mismatch");

    match err {
        PqKemError::Expired {
            field,
            age_secs,
            max_age_secs,
        } => {
            assert_eq!(field, "PqKemAccept");
            assert!(age_secs > max_age_secs);
            assert_eq!(max_age_secs, DEFAULT_MAX_MESSAGE_AGE_SECS);
        }
        other => panic!("expected Expired, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_63_offer_validation_reports_nonce_length_before_ek_length() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(63))?;

    offer.nonce.pop();
    offer.ek.pop();

    let err = offer
        .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("bad nonce and ek must fail");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, PQ_NONCE_LEN - 1);

    Ok(())
}

#[test]
fn e2e_64_accept_validation_reports_offer_nonce_length_before_ct_length() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let n = nonce(64);
    let offer = local.build_offer(n)?;
    let (mut accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    accept.offer_nonce.pop();
    accept.ct.pop();

    let err = accept
        .validate_untrusted(&n, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
        .expect_err("bad offer_nonce and ct must fail");

    assert_invalid_length(err, "offer_nonce", PQ_NONCE_LEN, PQ_NONCE_LEN - 1);

    Ok(())
}

#[test]
fn e2e_65_replay_filter_duplicate_insert_returns_false() -> TestResult {
    let mut filter = ReplayFilter::new(16);
    let n = nonce(65);

    assert!(filter.insert(n));
    assert!(!filter.insert(n));

    Ok(())
}

#[test]
fn e2e_66_replay_filter_contains_returns_false_for_unknown_nonce() -> TestResult {
    let filter = ReplayFilter::new(16);

    assert!(!filter.contains(&nonce(66)));

    Ok(())
}

#[test]
fn e2e_67_replay_filter_capacity_one_evicts_previous_on_second_insert() -> TestResult {
    let n1 = nonce(67);
    let mut filter = ReplayFilter::new(1);

    assert_eq!(filter.capacity(), 16);

    assert!(filter.insert(n1));
    assert!(filter.contains(&n1));

    for seed in 68_u8..=83_u8 {
        assert!(filter.insert(nonce(seed)));
    }

    assert!(!filter.contains(&n1));
    assert_eq!(filter.len(), 16);

    Ok(())
}

#[test]
fn e2e_68_manager_replay_capacity_one_allows_old_nonce_after_eviction() -> TestResult {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 1,
    };

    let mut initiator = PqKemManager::default();
    let mut manager = PqKemManager::new(policy);

    let local_one = initiator.build_local_keypair()?;
    let offer_one = initiator.build_offer(&local_one, nonce(68))?;

    assert!(manager.accept_offer(&offer_one).is_ok());

    let replay_err = manager
        .accept_offer(&offer_one)
        .expect_err("same offer must replay-fail before eviction");

    match replay_err {
        PqKemError::ReplayDetected { nonce_hex } => {
            assert_eq!(nonce_hex.len(), PQ_NONCE_LEN * 2);
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }

    for seed in 69_u8..=84_u8 {
        let local = initiator.build_local_keypair()?;
        let offer = initiator.build_offer(&local, nonce(seed))?;
        assert!(manager.accept_offer(&offer).is_ok());
    }

    assert!(manager.accept_offer(&offer_one).is_ok());

    Ok(())
}

#[test]
fn e2e_69_manager_zero_replay_capacity_is_rejected_before_use() -> TestResult {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 0,
    };

    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::new(policy);

    let local = initiator.build_local_keypair()?;
    let offer = initiator.build_offer(&local, nonce(70))?;

    let err = responder
        .accept_offer(&offer)
        .expect_err("zero replay capacity policy must be rejected before use");

    match err {
        PqKemError::InvalidRange { field, details } => {
            assert_eq!(field, "replay_filter_capacity");
            assert_eq!(details, "must be nonzero");
        }
        other => panic!("expected InvalidRange, got {other:?}"),
    }

    Ok(())
}

#[test]
fn e2e_70_manager_accept_offer_rejects_short_nonce_before_crypto() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let local = initiator.build_local_keypair()?;
    let mut offer = initiator.build_offer(&local, nonce(71))?;
    offer.nonce.pop();

    let err = responder
        .accept_offer(&offer)
        .expect_err("short nonce must fail before responder crypto");

    assert_invalid_length(err, "nonce", PQ_NONCE_LEN, PQ_NONCE_LEN - 1);

    Ok(())
}

#[test]
fn e2e_71_manager_accept_offer_rejects_wrong_suite() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let local = initiator.build_local_keypair()?;
    let mut offer = initiator.build_offer(&local, nonce(72))?;
    offer.suite_id = PQ_KEM_SUITE_ID.wrapping_add(9);

    let err = responder
        .accept_offer(&offer)
        .expect_err("wrong suite must fail");

    assert_eq!(err, PqKemError::InvalidMessage("unexpected PQ suite id"));

    Ok(())
}

#[test]
fn e2e_72_responder_rejects_wrong_suite_offer() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(73))?;
    offer.suite_id = PQ_KEM_SUITE_ID.wrapping_add(1);

    let err =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .expect_err("wrong suite must fail");

    assert_eq!(err, PqKemError::InvalidMessage("unexpected PQ suite id"));

    Ok(())
}

#[test]
fn e2e_73_responder_rejects_short_ek_offer() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(74))?;
    offer.ek.pop();

    let err =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .expect_err("short ek must fail");

    assert_invalid_length(err, "ek", ek_len(), ek_len() - 1);

    Ok(())
}

#[test]
fn e2e_74_responder_rejects_expired_offer() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let mut offer = local.build_offer(nonce(75))?;
    offer.created_at_unix_secs = expired_timestamp(10);

    let err =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .expect_err("expired offer must fail");

    assert!(matches!(err, PqKemError::Expired { .. }));

    Ok(())
}

#[test]
fn e2e_75_finalize_rejects_accept_wrong_suite_without_consuming_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(76);
    let offer = initiator.build_offer(&local, n)?;
    let (mut accept, _) = responder.accept_offer(&offer)?;

    accept.suite_id = PQ_KEM_SUITE_ID.wrapping_add(1);

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("wrong suite accept must fail");

    assert_eq!(err, PqKemError::InvalidMessage("unexpected PQ suite id"));
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_76_finalize_rejects_accept_zero_timestamp_without_consuming_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(77);
    let offer = initiator.build_offer(&local, n)?;
    let (mut accept, _) = responder.accept_offer(&offer)?;

    accept.created_at_unix_secs = 0;

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("zero timestamp accept must fail");

    assert!(matches!(err, PqKemError::InvalidRange { .. }));
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_77_finalize_rejects_expired_accept_without_consuming_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(78);
    let offer = initiator.build_offer(&local, n)?;
    let (mut accept, _) = responder.accept_offer(&offer)?;

    accept.created_at_unix_secs = expired_timestamp(20);

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("expired accept must fail");

    assert!(matches!(err, PqKemError::Expired { .. }));
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_78_finalize_rejects_tampered_offer_nonce_without_consuming_keypair() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(79);
    let offer = initiator.build_offer(&local, n)?;
    let (mut accept, _) = responder.accept_offer(&offer)?;

    accept.offer_nonce[0] ^= 0xff;

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("tampered offer_nonce must fail");

    assert_eq!(err, PqKemError::InvalidMessage("offer_nonce mismatch"));
    assert!(!local.is_consumed());

    Ok(())
}

#[test]
fn e2e_79_direct_decapsulate_accept_succeeds_and_consumes_keypair() -> TestResult {
    let mut responder = PqKemManager::default();

    let mut local = LocalPqKeypair::generate()?;
    let n = nonce(80);
    let offer = local.build_offer(n)?;
    let (accept, responder_session) = responder.accept_offer(&offer)?;

    let initiator_session = local.decapsulate_accept(
        &accept,
        &n,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert!(local.is_consumed());

    Ok(())
}

#[test]
fn e2e_80_direct_decapsulate_accept_second_call_fails() -> TestResult {
    let mut responder = PqKemManager::default();

    let mut local = LocalPqKeypair::generate()?;
    let n = nonce(81);
    let offer = local.build_offer(n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    let _ = local.decapsulate_accept(
        &accept,
        &n,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )?;

    let err = local
        .decapsulate_accept(
            &accept,
            &n,
            Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        )
        .expect_err("second direct decapsulation must fail");

    assert!(matches!(err, PqKemError::InvalidState(_)));

    Ok(())
}

#[test]
fn e2e_81_set_consumed_true_blocks_finalize() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(82);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    local.set_consumed(true);

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("manually consumed keypair must fail");

    assert!(matches!(err, PqKemError::InvalidState(_)));
    assert!(local.is_consumed());

    Ok(())
}

#[test]
fn e2e_82_set_consumed_true_then_false_allows_finalize() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(83);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    local.set_consumed(true);
    assert!(local.is_consumed());

    local.set_consumed(false);
    assert!(!local.is_consumed());

    let _session = initiator.finalize_accept(&mut local, &accept, n)?;
    assert!(local.is_consumed());

    Ok(())
}

#[test]
fn e2e_83_policy_false_does_not_override_local_consumed_guard() -> TestResult {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: false,
        replay_filter_capacity: 4096,
    };

    let mut initiator = PqKemManager::new(policy);
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;
    let n = nonce(84);
    let offer = initiator.build_offer(&local, n)?;
    let (accept, _) = responder.accept_offer(&offer)?;

    let _first = initiator.finalize_accept(&mut local, &accept, n)?;

    let err = initiator
        .finalize_accept(&mut local, &accept, n)
        .expect_err("local keypair itself still enforces consumed guard");

    assert!(matches!(err, PqKemError::InvalidState(_)));

    Ok(())
}

#[test]
fn e2e_84_session_established_timestamp_is_bounded_by_handshake_window() -> TestResult {
    let start = now_unix_for_test();
    let (initiator_session, responder_session, _, _) = full_handshake(85)?;
    let end = now_unix_for_test();

    assert!(initiator_session.established_at_unix_secs() >= start);
    assert!(initiator_session.established_at_unix_secs() <= end);
    assert!(responder_session.established_at_unix_secs() >= start);
    assert!(responder_session.established_at_unix_secs() <= end);

    Ok(())
}

#[test]
fn e2e_85_offer_created_timestamp_is_bounded_by_build_window() -> TestResult {
    let local = LocalPqKeypair::generate()?;

    let start = now_unix_for_test();
    let offer = local.build_offer(nonce(86))?;
    let end = now_unix_for_test();

    assert!(offer.created_at_unix_secs >= start);
    assert!(offer.created_at_unix_secs <= end);

    Ok(())
}

#[test]
fn e2e_86_accept_created_timestamp_is_bounded_by_responder_window() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(87))?;

    let start = now_unix_for_test();
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;
    let end = now_unix_for_test();

    assert!(accept.created_at_unix_secs >= start);
    assert!(accept.created_at_unix_secs <= end);

    Ok(())
}

#[test]
fn e2e_87_session_zeroize_is_idempotent() -> TestResult {
    let (mut session, _, _, _) = full_handshake(88)?;

    session.zeroize();
    session.zeroize();
    session.zeroize();

    assert_eq!(session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_88_zeroized_session_into_bytes_returns_all_zeroes() -> TestResult {
    let (mut session, _, _, _) = full_handshake(89)?;

    session.zeroize();

    let bytes = session.into_bytes();

    assert_eq!(bytes, [0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_89_zeroizing_cloned_session_does_not_zero_original_copy() -> TestResult {
    let (session, _, _, _) = full_handshake(90)?;
    let mut cloned = session.clone();

    cloned.zeroize();

    assert_eq!(cloned.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);
    assert_ne!(session.as_bytes(), &[0u8; PQ_SHARED_SECRET_LEN]);

    Ok(())
}

#[test]
fn e2e_90_offer_clone_preserves_equality() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(91))?;
    let cloned = offer.clone();

    assert_eq!(cloned, offer);

    Ok(())
}

#[test]
fn e2e_91_accept_clone_preserves_equality() -> TestResult {
    let local = LocalPqKeypair::generate()?;
    let offer = local.build_offer(nonce(92))?;
    let (accept, _) =
        PqResponder::respond_to_offer(&offer, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))?;

    let cloned = accept.clone();

    assert_eq!(cloned, accept);

    Ok(())
}

#[test]
fn e2e_92_error_display_invalid_range_is_stable() -> TestResult {
    let err = PqKemError::InvalidRange {
        field: "created_at_unix_secs",
        details: "must be nonzero",
    };

    let text = err.to_string();

    assert!(text.contains("invalid range"));
    assert!(text.contains("created_at_unix_secs"));
    assert!(text.contains("must be nonzero"));

    Ok(())
}

#[test]
fn e2e_93_error_display_invalid_message_is_stable() -> TestResult {
    let err = PqKemError::InvalidMessage("offer_nonce mismatch");

    let text = err.to_string();

    assert!(text.contains("invalid message"));
    assert!(text.contains("offer_nonce mismatch"));

    Ok(())
}

#[test]
fn e2e_94_error_display_expired_is_stable() -> TestResult {
    let err = PqKemError::Expired {
        field: "PqKemOffer",
        age_secs: 99,
        max_age_secs: 30,
    };

    let text = err.to_string();

    assert!(text.contains("PqKemOffer expired"));
    assert!(text.contains("age=99"));
    assert!(text.contains("max=30"));

    Ok(())
}

#[test]
fn e2e_95_error_display_replay_detected_contains_nonce_hex() -> TestResult {
    let err = PqKemError::ReplayDetected {
        nonce_hex: "abcd".to_string(),
    };

    let text = err.to_string();

    assert!(text.contains("replay detected"));
    assert!(text.contains("abcd"));

    Ok(())
}

#[test]
fn e2e_96_error_display_crypto_is_stable() -> TestResult {
    let err = PqKemError::Crypto("kem failure");

    let text = err.to_string();

    assert!(text.contains("crypto error"));
    assert!(text.contains("kem failure"));

    Ok(())
}

#[test]
fn e2e_97_error_display_io_is_stable() -> TestResult {
    let err = PqKemError::Io("disk failure".to_string());

    let text = err.to_string();

    assert!(text.contains("io error"));
    assert!(text.contains("disk failure"));

    Ok(())
}

#[test]
fn e2e_98_corrupt_offer_postcard_decode_fails() -> TestResult {
    let bytes = short_bytes(64, 98);

    let decoded = postcard::from_bytes::<PqKemOffer>(&bytes);

    assert!(decoded.is_err());

    Ok(())
}

#[test]
fn e2e_99_corrupt_accept_postcard_decode_fails() -> TestResult {
    let bytes = short_bytes(64, 99);

    let decoded = postcard::from_bytes::<PqKemAccept>(&bytes);

    assert!(decoded.is_err());

    Ok(())
}

#[test]
fn e2e_100_full_two_offer_same_local_keypair_lifecycle_enforces_single_finalize() -> TestResult {
    let mut initiator = PqKemManager::default();
    let mut responder = PqKemManager::default();

    let mut local = initiator.build_local_keypair()?;

    let first_nonce = nonce(100);
    let second_nonce = nonce(101);

    let first_offer = initiator.build_offer(&local, first_nonce)?;
    let second_offer = initiator.build_offer(&local, second_nonce)?;

    let (first_accept, first_responder_session) = responder.accept_offer(&first_offer)?;
    let (second_accept, _second_responder_session) = responder.accept_offer(&second_offer)?;

    let first_initiator_session =
        initiator.finalize_accept(&mut local, &first_accept, first_nonce)?;

    assert_eq!(
        first_initiator_session.as_bytes(),
        first_responder_session.as_bytes()
    );
    assert!(local.is_consumed());

    let err = initiator
        .finalize_accept(&mut local, &second_accept, second_nonce)
        .expect_err("same local keypair must not finalize a second offer");

    assert!(matches!(err, PqKemError::InvalidState(_)));

    Ok(())
}
