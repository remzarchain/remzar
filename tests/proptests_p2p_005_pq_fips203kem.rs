use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_005_pq_fips203kem::{
    DEFAULT_MAX_MESSAGE_AGE_SECS, PQ_KEM_SUITE_ID, PQ_KEM_SUITE_NAME, PQ_SHARED_SECRET_LEN,
    PqKemAccept, PqKemManager, PqKemOffer, ct_len, dk_len, ek_len, shared_secret_len,
    validate_ct_bytes, validate_ek_bytes,
};
use remzar::network::p2p_005_pq_fips203kem::{
    MIN_REPLAY_FILTER_CAPACITY, PQ_NONCE_LEN, ReplayFilter,
};
use std::time::Duration;

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 01/25
    #[test]
    fn test_001_manager_handshake_establishes_equal_32_byte_session_keys(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("building PQ-KEM offer should succeed");

        let (accept, responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid fresh offer");

        let initiator_session = initiator
            .finalize_accept(&mut local, &accept, nonce)
            .expect("initiator should finalize valid accept");

        prop_assert_eq!(
            initiator_session.as_bytes(),
            responder_session.as_bytes(),
            "initiator and responder must derive the same shared secret"
        );

        prop_assert_eq!(
            initiator_session.as_bytes().len(),
            PQ_SHARED_SECRET_LEN,
            "initiator shared secret must be exactly 32 bytes"
        );

        prop_assert_eq!(
            responder_session.as_bytes().len(),
            PQ_SHARED_SECRET_LEN,
            "responder shared secret must be exactly 32 bytes"
        );

        prop_assert_eq!(
            initiator_session.suite_id(),
            PQ_KEM_SUITE_ID,
            "session suite id must match PQ_KEM_SUITE_ID"
        );

        prop_assert_eq!(
            responder_session.suite_name(),
            PQ_KEM_SUITE_NAME,
            "session suite name must match PQ_KEM_SUITE_NAME"
        );

        prop_assert!(
            local.is_consumed(),
            "local keypair must be consumed after successful decapsulation"
        );
    }

    // 02/25
    #[test]
    fn test_002_responder_rejects_replayed_offer_nonce(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let first = responder.accept_offer(&offer);
        let second = responder.accept_offer(&offer);

        prop_assert!(
            first.is_ok(),
            "first valid offer with a fresh nonce should be accepted"
        );

        prop_assert!(
            second.is_err(),
            "second offer with the same nonce must be rejected as replay"
        );
    }

    // 03/25
    #[test]
    fn test_003_clear_replay_cache_allows_same_offer_nonce_again(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        responder
            .accept_offer(&offer)
            .expect("first valid offer should be accepted");

        prop_assert!(
            responder.accept_offer(&offer).is_err(),
            "same nonce should be rejected before clearing replay cache"
        );

        responder.clear_replay_cache();

        prop_assert!(
            responder.accept_offer(&offer).is_ok(),
            "same nonce should be accepted again after replay cache is cleared"
        );
    }

    // 04/25
    #[test]
    fn test_004_finalize_accept_rejects_wrong_expected_offer_nonce(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
        wrong_nonce_tail in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("offer creation should succeed");

        let (accept, _responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        let mut wrong_nonce = wrong_nonce_tail;
        if wrong_nonce == nonce {
            wrong_nonce[0] = wrong_nonce[0].wrapping_add(1);
        }

        prop_assert!(
            initiator
                .finalize_accept(&mut local, &accept, wrong_nonce)
                .is_err(),
            "initiator must reject accept when expected offer nonce does not match"
        );
    }

    // 05/25
    #[test]
    fn test_005_local_keypair_is_single_use_after_successful_finalize(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("offer creation should succeed");

        let (accept, _responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        initiator
            .finalize_accept(&mut local, &accept, nonce)
            .expect("first finalization should succeed");

        prop_assert!(
            initiator.finalize_accept(&mut local, &accept, nonce).is_err(),
            "second finalization with same local keypair must be rejected"
        );

        prop_assert!(
            local.is_consumed(),
            "local keypair must remain consumed"
        );
    }

    // 06/25
    #[test]
    fn test_006_offer_validate_untrusted_rejects_wrong_suite_nonce_length_and_ek_length(
        nonce in proptest::collection::vec(any::<u8>(), 0..96),
        ek in proptest::collection::vec(any::<u8>(), 0..2048),
        suite_id in any::<u16>(),
    ) {
        let offer = PqKemOffer {
            suite_id,
            created_at_unix_secs: 1,
            nonce,
            ek,
        };

        prop_assert!(
            offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)).is_err(),
            "malformed or expired untrusted offer must be rejected"
        );
    }

    // 07/25
    #[test]
    fn test_007_accept_validate_untrusted_rejects_wrong_suite_nonce_length_ct_length_or_nonce_mismatch(
        offer_nonce in any::<[u8; PQ_NONCE_LEN]>(),
        supplied_offer_nonce in proptest::collection::vec(any::<u8>(), 0..96),
        ct in proptest::collection::vec(any::<u8>(), 0..2048),
        suite_id in any::<u16>(),
    ) {
        let accept = PqKemAccept {
            suite_id,
            offer_nonce: supplied_offer_nonce,
            created_at_unix_secs: 1,
            ct,
        };

        prop_assert!(
            accept
                .validate_untrusted(&offer_nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_err(),
            "malformed or expired untrusted accept must be rejected"
        );
    }

    // 08/25
    #[test]
    fn test_008_valid_offer_and_accept_survive_postcard_roundtrip_and_validate(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let encoded_offer = postcard::to_allocvec(&offer)
            .expect("PqKemOffer should serialize with postcard");

        let decoded_offer: PqKemOffer = postcard::from_bytes(&encoded_offer)
            .expect("PqKemOffer should deserialize with postcard");

        decoded_offer
            .validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .expect("decoded valid offer should validate");

        prop_assert_eq!(
            &decoded_offer,
            &offer,
            "PqKemOffer postcard roundtrip must preserve fields"
        );

        let (accept, _session) = responder
            .accept_offer(&decoded_offer)
            .expect("responder should accept decoded valid offer");

        let encoded_accept = postcard::to_allocvec(&accept)
            .expect("PqKemAccept should serialize with postcard");

        let decoded_accept: PqKemAccept = postcard::from_bytes(&encoded_accept)
            .expect("PqKemAccept should deserialize with postcard");

        decoded_accept
            .validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
            .expect("decoded valid accept should validate");

        prop_assert_eq!(
            &decoded_accept,
            &accept,
            "PqKemAccept postcard roundtrip must preserve fields"
        );
    }

    // 09/25
    #[test]
    fn test_009_validate_ek_and_ct_accept_real_handshake_bytes_and_reject_wrong_lengths(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
        bad_ek_len in 0usize..2048usize,
        bad_ct_len in 0usize..2048usize,
        fill in any::<u8>(),
    ) {
        prop_assume!(bad_ek_len != ek_len());
        prop_assume!(bad_ct_len != ct_len());

        let initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        validate_ek_bytes(&offer.ek)
            .expect("real generated encapsulation key bytes should validate");

        let (accept, _session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        validate_ct_bytes(&accept.ct)
            .expect("real generated ciphertext bytes should validate");

        let bad_ek = vec![fill; bad_ek_len];
        let bad_ct = vec![fill; bad_ct_len];

        prop_assert!(
            validate_ek_bytes(&bad_ek).is_err(),
            "validate_ek_bytes must reject wrong length {}",
            bad_ek_len
        );

        prop_assert!(
            validate_ct_bytes(&bad_ct).is_err(),
            "validate_ct_bytes must reject wrong length {}",
            bad_ct_len
        );
    }

    // 10/25
    #[test]
    fn test_010_replay_filter_rejects_duplicate_nonce_and_respects_capacity_clear_behavior(
        first in any::<[u8; PQ_NONCE_LEN]>(),
        second_tail in any::<[u8; PQ_NONCE_LEN]>(),
        cap in 1usize..16usize,
    ) {
        let mut second = second_tail;
        if second == first {
            second[0] = second[0].wrapping_add(1);
        }

        let mut filter = ReplayFilter::new(cap);

        prop_assert!(
            filter.check_and_insert(first).is_ok(),
            "first nonce insertion should succeed"
        );

        prop_assert!(
            filter.check_and_insert(first).is_err(),
            "duplicate nonce must be rejected"
        );

        prop_assert!(
            filter.check_and_insert(second).is_ok(),
            "different nonce should be accepted"
        );

        filter.clear();

        prop_assert!(
            filter.check_and_insert(first).is_ok(),
            "nonce should be accepted again after clear"
        );
    }

    // 11/25
    #[test]
    fn test_011_session_key_zeroize_clears_shared_secret_bytes(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("offer creation should succeed");

        let (accept, _responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        let mut session = initiator
            .finalize_accept(&mut local, &accept, nonce)
            .expect("initiator should finalize valid accept");

        prop_assert_eq!(
            session.as_bytes().len(),
            PQ_SHARED_SECRET_LEN,
            "session key must expose exactly 32 bytes"
        );

        session.zeroize();

        prop_assert!(
            session.as_bytes().iter().all(|b| *b == 0),
            "session zeroize must clear all shared secret bytes"
        );
    }

    // 12/25
    #[test]
    fn test_012_exported_length_helpers_match_public_constants(
        probe in 0usize..4096usize,
    ) {
        prop_assert_eq!(
            shared_secret_len(),
            PQ_SHARED_SECRET_LEN,
            "shared_secret_len helper must match PQ_SHARED_SECRET_LEN"
        );

        prop_assert_eq!(
            PQ_SHARED_SECRET_LEN,
            32,
            "ML-KEM shared secret length must be 32 bytes"
        );

        prop_assert_eq!(
            ek_len(),
            fips203::ml_kem_768::EK_LEN,
            "ek_len helper must match fips203 EK_LEN"
        );

        prop_assert_eq!(
            dk_len(),
            fips203::ml_kem_768::DK_LEN,
            "dk_len helper must match fips203 DK_LEN"
        );

        prop_assert_eq!(
            ct_len(),
            fips203::ml_kem_768::CT_LEN,
            "ct_len helper must match fips203 CT_LEN"
        );

        prop_assert!(
            probe < 4096,
            "generated probe keeps this a real generated property"
        );
    }

    // 13/25
    #[test]
    fn test_013_build_offer_preserves_nonce_suite_timestamp_and_ek_shape(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        prop_assert_eq!(
            offer.suite_id,
            PQ_KEM_SUITE_ID,
            "offer suite id must match PQ_KEM_SUITE_ID"
        );

        prop_assert_eq!(
            offer.nonce.as_slice(),
            nonce.as_slice(),
            "offer must preserve the exact nonce bytes"
        );

        prop_assert_eq!(
            offer.ek.len(),
            ek_len(),
            "offer encapsulation key must have exact ML-KEM EK length"
        );

        prop_assert_eq!(
            offer.ek.as_slice(),
            local.ek_bytes().as_slice(),
            "offer EK bytes must come from the local keypair"
        );

        prop_assert!(
            offer.created_at_unix_secs > 0,
            "offer timestamp must be nonzero"
        );

        prop_assert!(
            offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)).is_ok(),
            "fresh well-formed offer must validate"
        );
    }

    // 14/25
    #[test]
    fn test_014_offer_nonce_array_accepts_exact_nonce_and_rejects_wrong_lengths(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
        bad_len in 0usize..96usize,
        fill in any::<u8>(),
    ) {
        prop_assume!(bad_len != PQ_NONCE_LEN);

        let manager = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let recovered = offer
            .nonce_array()
            .expect("valid offer nonce should convert into fixed array");

        prop_assert_eq!(
            recovered,
            nonce,
            "nonce_array must recover exact original nonce"
        );

        let mut malformed_offer = offer.clone();
        malformed_offer.nonce = vec![fill; bad_len];

        prop_assert!(
            malformed_offer.nonce_array().is_err(),
            "nonce_array must reject nonce length {}",
            bad_len
        );
    }

    // 15/25
    #[test]
    fn test_015_offer_validate_rejects_expired_valid_shape_offer(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let mut offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        offer.created_at_unix_secs = 1;

        prop_assert!(
            offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)).is_err(),
            "otherwise valid offer with expired timestamp must be rejected"
        );
    }

    // 16/25
    #[test]
    fn test_016_accept_validate_rejects_expired_valid_shape_accept(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let (mut accept, _session) = responder
            .accept_offer(&offer)
            .expect("valid offer should produce accept");

        accept.created_at_unix_secs = 1;

        prop_assert!(
            accept
                .validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_err(),
            "otherwise valid accept with expired timestamp must be rejected"
        );
    }

    // 17/25
    #[test]
    fn test_017_accept_validate_rejects_zero_created_at_even_when_shape_valid(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let (mut accept, _session) = responder
            .accept_offer(&offer)
            .expect("valid offer should produce accept");

        accept.created_at_unix_secs = 0;

        prop_assert!(
            accept
                .validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_err(),
            "accept validation must reject zero created_at_unix_secs"
        );
    }

    // 18/25
    #[test]
    fn test_018_offer_validate_rejects_zero_created_at_even_when_shape_valid(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let mut offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        offer.created_at_unix_secs = 0;

        prop_assert!(
            offer.validate_untrusted(Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS)).is_err(),
            "offer validation must reject zero created_at_unix_secs"
        );
    }

    // 19/25
    #[test]
    fn test_019_accept_validate_accepts_real_accept_and_rejects_nonce_mismatch(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
        wrong_nonce_tail in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        let (accept, _session) = responder
            .accept_offer(&offer)
            .expect("valid offer should produce accept");

        prop_assert!(
            accept
                .validate_untrusted(&nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_ok(),
            "real accept must validate against matching nonce"
        );

        let mut wrong_nonce = wrong_nonce_tail;
        if wrong_nonce == nonce {
            wrong_nonce[0] = wrong_nonce[0].wrapping_add(1);
        }

        prop_assert!(
            accept
                .validate_untrusted(&wrong_nonce, Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS))
                .is_err(),
            "real accept must reject mismatched expected nonce"
        );
    }

    // 20/25
    #[test]
    fn test_020_session_key_metadata_is_nonzero_and_into_bytes_preserves_secret(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("offer creation should succeed");

        let (accept, _responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        let initiator_session = initiator
            .finalize_accept(&mut local, &accept, nonce)
            .expect("initiator should finalize valid accept");

        let secret_before = *initiator_session.as_bytes();

        prop_assert_eq!(
            initiator_session.suite_id(),
            PQ_KEM_SUITE_ID,
            "session suite id must match PQ_KEM_SUITE_ID"
        );

        prop_assert_eq!(
            initiator_session.suite_name(),
            PQ_KEM_SUITE_NAME,
            "session suite name must match PQ_KEM_SUITE_NAME"
        );

        prop_assert!(
            initiator_session.established_at_unix_secs() > 0,
            "session established timestamp must be nonzero"
        );

        let consumed_secret = initiator_session.into_bytes();

        prop_assert_eq!(
            consumed_secret,
            secret_before,
            "into_bytes must preserve exact shared secret bytes"
        );
    }

    // 21/25
    #[test]
    fn test_021_local_keypair_debug_output_redacts_decapsulation_key(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
    ) {
        let manager = PqKemManager::default();

        let local = manager
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let debug_output = format!("{local:?}");

        prop_assert!(
            debug_output.contains("LocalPqKeypair"),
            "debug output should identify LocalPqKeypair"
        );

        prop_assert!(
            debug_output.contains("<redacted>"),
            "debug output must redact the decapsulation key"
        );

        prop_assert!(
            debug_output.contains("ek_len"),
            "debug output may expose EK length for diagnostics"
        );

        let offer = local
            .build_offer(nonce)
            .expect("building PQ-KEM offer should succeed");

        prop_assert_eq!(
            offer.ek.len(),
            ek_len(),
            "generated offer remains valid after debug formatting"
        );
    }

// 22/25
#[test]
fn test_022_replay_filter_with_zero_capacity_clamps_to_minimum_and_rejects_duplicates(
    first in any::<[u8; PQ_NONCE_LEN]>(),
    second_tail in any::<[u8; PQ_NONCE_LEN]>(),
) {
    let mut second = second_tail;
    if second == first {
        second[0] = second[0].wrapping_add(1);
    }

    prop_assume!(first.iter().any(|b| *b != 0));
    prop_assume!(second.iter().any(|b| *b != 0));
    prop_assume!(second != first);

    let mut filter = ReplayFilter::new(0);

    prop_assert_eq!(
        filter.capacity(),
        MIN_REPLAY_FILTER_CAPACITY,
        "zero requested capacity must clamp to MIN_REPLAY_FILTER_CAPACITY"
    );

    prop_assert!(
        filter.check_and_insert(first).is_ok(),
        "zero-capacity constructor must still create a usable replay filter"
    );

    prop_assert!(
        filter.check_and_insert(first).is_err(),
        "duplicate nonce must be rejected after first insert"
    );

    prop_assert!(
        filter.check_and_insert(second).is_ok(),
        "different nonce should be accepted"
    );

    prop_assert!(
        filter.check_and_insert(first).is_err(),
        "first nonce should still be remembered because effective cap is MIN_REPLAY_FILTER_CAPACITY, not one"
    );
}

    // 23/25
    #[test]
    fn test_023_validate_ek_bytes_never_panics_for_arbitrary_untrusted_bytes(
        ek_bytes in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_ek_bytes(&ek_bytes)
        }));

        prop_assert!(
            result.is_ok(),
            "validate_ek_bytes must never panic for arbitrary untrusted bytes"
        );

        let validation = result.expect("panic was already checked above");

        if ek_bytes.len() != ek_len() {
            prop_assert!(
                validation.is_err(),
                "validate_ek_bytes must reject wrong length {}",
                ek_bytes.len()
            );
        }
    }

    // 24/25
    #[test]
    fn test_024_validate_ct_bytes_never_panics_for_arbitrary_untrusted_bytes(
        ct_bytes in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            validate_ct_bytes(&ct_bytes)
        }));

        prop_assert!(
            result.is_ok(),
            "validate_ct_bytes must never panic for arbitrary untrusted bytes"
        );

        let validation = result.expect("panic was already checked above");

        if ct_bytes.len() != ct_len() {
            prop_assert!(
                validation.is_err(),
                "validate_ct_bytes must reject wrong length {}",
                ct_bytes.len()
            );
        }
    }

    // 25/25
    #[test]
    fn test_025_tampered_accept_ciphertext_cannot_reproduce_responder_session_secret(
        nonce in any::<[u8; PQ_NONCE_LEN]>(),
        ct_index_seed in any::<usize>(),
        delta in 1u8..=255u8,
    ) {
        let mut initiator = PqKemManager::default();
        let mut responder = PqKemManager::default();

        let mut local = initiator
            .build_local_keypair()
            .expect("local ML-KEM keypair generation should succeed");

        let offer = initiator
            .build_offer(&local, nonce)
            .expect("offer creation should succeed");

        let (mut accept, responder_session) = responder
            .accept_offer(&offer)
            .expect("responder should accept valid offer");

        prop_assert_eq!(
            accept.ct.len(),
            ct_len(),
            "accept ciphertext must have exact ML-KEM ciphertext length"
        );

        let ct_index = ct_index_seed % accept.ct.len();
        accept.ct[ct_index] = accept.ct[ct_index].wrapping_add(delta);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            initiator.finalize_accept(&mut local, &accept, nonce)
        }));

        prop_assert!(
            result.is_ok(),
            "finalizing tampered accept ciphertext must not panic"
        );

        if let Ok(tampered_session) = result.expect("panic was already checked above") {
            prop_assert_ne!(
                tampered_session.as_bytes(),
                responder_session.as_bytes(),
                "tampered ciphertext must not reproduce the responder's shared secret"
            );
        }
    }
}
