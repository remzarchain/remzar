#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod utility {
    pub mod time_policy {
        use std::time::{SystemTime, UNIX_EPOCH};

        pub struct TimePolicy;

        impl TimePolicy {
            #[inline]
            pub fn now_unix_secs_runtime() -> Result<u64, &'static str> {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock before UNIX_EPOCH")
                    .map(|d| d.as_secs())
            }
        }
    }
}

#[path = "../../src/network/p2p_005_pq_fips203kem.rs"]
mod p2p_005_pq_fips203kem;

use p2p_005_pq_fips203kem::{
    ct_len, dk_len, ek_len, shared_secret_len, validate_ct_bytes, validate_ek_bytes, LocalPqKeypair,
    PqKemAccept, PqKemError, PqKemManager, PqKemOffer, PqKemPolicy, ReplayFilter,
    DEFAULT_MAX_MESSAGE_AGE_SECS, MAX_ALLOWED_MESSAGE_AGE_SECS, MAX_FUTURE_SKEW_SECS,
    PQ_KEM_SUITE_ID, PQ_KEM_SUITE_NAME, PQ_MAX_WIRE_BYTES, PQ_NONCE_LEN, PQ_SHARED_SECRET_LEN,
};

fn now_unix_secs_fuzz() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(946_684_800)
}

fn touch_error(err: &PqKemError) {
    let _ = err.to_string();

    let io_err: std::io::Error = err.clone().into();
    let _ = io_err.kind();
    let _ = io_err.to_string();

    match err {
        PqKemError::InvalidLength {
            field,
            expected,
            actual,
        } => {
            let _ = field.len();
            let _ = expected.saturating_add(*actual);
        }
        PqKemError::InvalidRange { field, details } => {
            let _ = field.len();
            let _ = details.len();
        }
        PqKemError::InvalidState(msg)
        | PqKemError::InvalidMessage(msg)
        | PqKemError::Crypto(msg) => {
            let _ = msg.len();
        }
        PqKemError::Expired {
            field,
            age_secs,
            max_age_secs,
        } => {
            let _ = field.len();
            let _ = age_secs.saturating_add(*max_age_secs);
        }
        PqKemError::ClockSkew {
            field,
            now_unix_secs,
            created_at_unix_secs,
            skew_secs,
            max_future_skew_secs,
        } => {
            let _ = field.len();
            let _ = now_unix_secs
                .saturating_add(*created_at_unix_secs)
                .saturating_add(*skew_secs)
                .saturating_add(*max_future_skew_secs);
        }
        PqKemError::ReplayDetected { nonce_hex } => {
            let _ = nonce_hex.len();
        }
        PqKemError::Io(msg) => {
            let _ = msg.len();
        }
    }
}

fn touch_result<T>(result: Result<T, PqKemError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            touch_error(&err);
            None
        }
    }
}

fn byte_at(data: &[u8], index: usize, fallback: u8) -> u8 {
    if data.is_empty() {
        fallback
    } else {
        data[index % data.len()]
    }
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    let mut out = [0u8; 2];

    for i in 0..2 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u16::from_le_bytes(out)
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut out = [0u8; 8];

    for i in 0..8 {
        out[i] = byte_at(data, offset + i, i as u8);
    }

    u64::from_le_bytes(out)
}

fn nonce_from_data(data: &[u8], salt: usize) -> [u8; PQ_NONCE_LEN] {
    let mut nonce = [0u8; PQ_NONCE_LEN];

    for i in 0..PQ_NONCE_LEN {
        let a = byte_at(data, salt.wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(17)).wrapping_add(3),
            (i as u8).wrapping_mul(3),
        );
        nonce[i] = a ^ b ^ (salt as u8).wrapping_add(i as u8);
    }

    if nonce == [0u8; PQ_NONCE_LEN] {
        nonce[0] = 1;
    }

    nonce
}

fn bytes_from_data(data: &[u8], salt: usize, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for i in 0..len {
        let a = byte_at(data, salt.wrapping_add(i), i as u8);
        let b = byte_at(
            data,
            salt.wrapping_add(i.wrapping_mul(31)).wrapping_add(7),
            (i as u8).wrapping_mul(11),
        );
        out.push(a ^ b ^ (salt as u8));
    }

    out
}

fn fuzz_len_near(data: &[u8], salt: usize, expected: usize) -> usize {
    match byte_at(data, salt, 0) % 9 {
        0 => 0,
        1 => expected.saturating_sub(1),
        2 => expected,
        3 => expected.saturating_add(1),
        4 => expected / 2,
        5 => expected.saturating_add(byte_at(data, salt + 1, 0) as usize % 64),
        6 => byte_at(data, salt + 2, 0) as usize,
        7 => expected.saturating_sub(byte_at(data, salt + 3, 0) as usize % expected.max(1)),
        _ => expected.min(PQ_MAX_WIRE_BYTES),
    }
}

fn mutate_vec(mut v: Vec<u8>, data: &[u8], salt: usize) -> Vec<u8> {
    match byte_at(data, salt, 0) % 8 {
        0 => {}
        1 => v.clear(),
        2 => v.push(byte_at(data, salt + 1, 0xA5)),
        3 => {
            if !v.is_empty() {
                let idx = byte_at(data, salt + 2, 0) as usize % v.len();
                v[idx] ^= 0xA5;
            }
        }
        4 => {
            if !v.is_empty() {
                let new_len = byte_at(data, salt + 3, 0) as usize % v.len();
                v.truncate(new_len);
            }
        }
        5 => {
            let add = byte_at(data, salt + 4, 0) as usize % 64;
            v.extend(bytes_from_data(data, salt + 5, add));
        }
        6 => {
            v = bytes_from_data(data, salt + 6, fuzz_len_near(data, salt + 7, v.len()));
        }
        _ => {
            if !v.is_empty() {
                let idx = byte_at(data, salt + 8, 0) as usize % v.len();
                let _ = v.remove(idx);
            }
        }
    }

    v
}

fn timestamp_from_data(data: &[u8], salt: usize) -> u64 {
    let now = now_unix_secs_fuzz();

    match byte_at(data, salt, 0) % 8 {
        0 => now,
        1 => 0,
        2 => now.saturating_sub(
            DEFAULT_MAX_MESSAGE_AGE_SECS
                .saturating_add(1)
                .saturating_add(read_u64(data, salt + 1) % 10_000),
        ),
        3 => now.saturating_add(read_u64(data, salt + 9) % (MAX_FUTURE_SKEW_SECS + 1)),
        4 => now.saturating_add(
            MAX_FUTURE_SKEW_SECS
                .saturating_add(1)
                .saturating_add(read_u64(data, salt + 17) % 10_000),
        ),
        5 => 946_684_800u64.saturating_add(read_u64(data, salt + 25) % 1_000_000),
        6 => u64::MAX.saturating_sub(read_u64(data, salt + 33) % 1_000_000),
        _ => now.saturating_sub(read_u64(data, salt + 41) % 300),
    }
}

fn max_age_from_data(data: &[u8], salt: usize) -> Duration {
    let secs = match byte_at(data, salt, 0) % 7 {
        0 => DEFAULT_MAX_MESSAGE_AGE_SECS,
        1 => 0,
        2 => 1,
        3 => MAX_ALLOWED_MESSAGE_AGE_SECS,
        4 => MAX_ALLOWED_MESSAGE_AGE_SECS.saturating_add(1),
        5 => read_u64(data, salt + 1) % MAX_ALLOWED_MESSAGE_AGE_SECS.max(1),
        _ => 1 + (read_u64(data, salt + 9) % MAX_ALLOWED_MESSAGE_AGE_SECS.max(1)),
    };

    Duration::from_secs(secs)
}

fn policy_from_data(data: &[u8], salt: usize) -> PqKemPolicy {
    let cap = match byte_at(data, salt + 31, 0) % 6 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 8,
        4 => 4096,
        _ => (read_u64(data, salt + 32) as usize % 128).saturating_add(1),
    };

    PqKemPolicy {
        max_message_age: max_age_from_data(data, salt),
        require_single_use_local_keypair: byte_at(data, salt + 40, 0) & 1 == 0,
        replay_filter_capacity: cap,
    }
}

fn make_random_offer(data: &[u8], salt: usize) -> PqKemOffer {
    let suite_id = match byte_at(data, salt, 0) % 4 {
        0 => PQ_KEM_SUITE_ID,
        1 => 0,
        2 => u16::MAX,
        _ => read_u16(data, salt + 1),
    };

    let nonce_len = fuzz_len_near(data, salt + 3, PQ_NONCE_LEN);
    let ek_len = fuzz_len_near(data, salt + 11, ek_len());

    PqKemOffer {
        suite_id,
        created_at_unix_secs: timestamp_from_data(data, salt + 19),
        nonce: bytes_from_data(data, salt + 61, nonce_len),
        ek: bytes_from_data(data, salt + 131, ek_len),
    }
}

fn make_random_accept(data: &[u8], salt: usize, expected_nonce: &[u8; PQ_NONCE_LEN]) -> PqKemAccept {
    let suite_id = match byte_at(data, salt, 0) % 4 {
        0 => PQ_KEM_SUITE_ID,
        1 => 0,
        2 => u16::MAX,
        _ => read_u16(data, salt + 1),
    };

    let offer_nonce = match byte_at(data, salt + 3, 0) % 4 {
        0 => expected_nonce.to_vec(),
        1 => Vec::new(),
        2 => bytes_from_data(data, salt + 4, fuzz_len_near(data, salt + 5, PQ_NONCE_LEN)),
        _ => {
            let mut n = expected_nonce.to_vec();
            if !n.is_empty() {
                let idx = byte_at(data, salt + 6, 0) as usize % n.len();
                n[idx] ^= 0x5A;
            }
            n
        }
    };

    let ct = bytes_from_data(data, salt + 71, fuzz_len_near(data, salt + 72, ct_len()));

    PqKemAccept {
        suite_id,
        offer_nonce,
        created_at_unix_secs: timestamp_from_data(data, salt + 151),
        ct,
    }
}

fn exercise_constants() {
    assert_eq!(PQ_NONCE_LEN, 32);
    assert_eq!(PQ_SHARED_SECRET_LEN, 32);
    assert_eq!(shared_secret_len(), PQ_SHARED_SECRET_LEN);
    assert_eq!(PQ_KEM_SUITE_NAME, "ML-KEM-768/FIPS203-0.4.3");

    assert!(ek_len() > 0);
    assert!(dk_len() > 0);
    assert!(ct_len() > 0);
    assert!(PQ_MAX_WIRE_BYTES >= ek_len());
    assert!(PQ_MAX_WIRE_BYTES >= ct_len());
}

fn exercise_policy(data: &[u8]) {
    let default_policy = PqKemPolicy::default();
    let _ = touch_result(default_policy.validate());

    let fuzz_policy = policy_from_data(data, 200);
    let _ = touch_result(fuzz_policy.validate());

    let manager = PqKemManager::new(fuzz_policy.clone());
    let _ = manager.policy().require_single_use_local_keypair;
    let _ = touch_result(manager.policy().validate());

    let zero_age = PqKemPolicy {
        max_message_age: Duration::from_secs(0),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 1,
    };
    let _ = touch_result(zero_age.validate());

    let over_age = PqKemPolicy {
        max_message_age: Duration::from_secs(MAX_ALLOWED_MESSAGE_AGE_SECS + 1),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 1,
    };
    let _ = touch_result(over_age.validate());

    let zero_replay_cap = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: true,
        replay_filter_capacity: 0,
    };
    let _ = touch_result(zero_replay_cap.validate());
}

fn exercise_replay_filter(data: &[u8]) {
    let cap = ((byte_at(data, 300, 0) as usize) % 8).saturating_add(1);
    let mut filter = ReplayFilter::new(cap);

    let first = nonce_from_data(data, 301);
    assert!(!filter.contains(&first));
    assert!(filter.insert(first));
    assert!(filter.contains(&first));
    assert!(!filter.insert(first));
    let _ = touch_result(filter.check_and_insert(first));

    let mut last = first;
    for i in 0..cap.saturating_add(4) {
        let mut n = nonce_from_data(data, 400 + i);
        n[0] ^= i as u8;
        n[1] ^= (i as u8).wrapping_mul(17);
        last = n;
        let _ = filter.insert(n);
    }

    assert!(filter.contains(&last));
    let _ = touch_result(filter.check_and_insert(last));

    filter.clear();
    assert!(!filter.contains(&last));
    let _ = touch_result(filter.check_and_insert(last));
    assert!(filter.contains(&last));
}

fn exercise_byte_validators(data: &[u8]) {
    let ek_random = bytes_from_data(data, 600, fuzz_len_near(data, 601, ek_len()));
    let _ = touch_result(validate_ek_bytes(&ek_random));

    let ct_random = bytes_from_data(data, 700, fuzz_len_near(data, 701, ct_len()));
    let _ = touch_result(validate_ct_bytes(&ct_random));

    if let Some(local) = touch_result(LocalPqKeypair::generate()) {
        let _ = touch_result(validate_ek_bytes(local.ek_bytes()));

        let mut mutated_ek = local.ek_bytes().to_vec();
        mutated_ek = mutate_vec(mutated_ek, data, 800);
        let _ = touch_result(validate_ek_bytes(&mutated_ek));
    }
}

fn exercise_valid_handshake(data: &[u8]) {
    let mut initiator_manager = PqKemManager::default();
    let mut responder_manager = PqKemManager::default();

    let Some(mut local) = touch_result(initiator_manager.build_local_keypair()) else {
        return;
    };

    let nonce = nonce_from_data(data, 1000);

    let Some(offer) = touch_result(initiator_manager.build_offer(&local, nonce)) else {
        return;
    };

    assert_eq!(offer.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(offer.nonce.len(), PQ_NONCE_LEN);
    assert_eq!(offer.ek.len(), ek_len());

    let _ = touch_result(offer.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));

    let Some(nonce_roundtrip) = touch_result(offer.nonce_array()) else {
        return;
    };
    assert_eq!(nonce_roundtrip, nonce);

    let Some((accept, mut responder_session)) = touch_result(responder_manager.accept_offer(&offer))
    else {
        return;
    };

    assert_eq!(accept.suite_id, PQ_KEM_SUITE_ID);
    assert_eq!(accept.offer_nonce, nonce.to_vec());
    assert_eq!(accept.ct.len(), ct_len());

    let _ = touch_result(validate_ct_bytes(&accept.ct));
    let _ = touch_result(accept.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));

    let Some(mut initiator_session) =
        touch_result(initiator_manager.finalize_accept(&mut local, &accept, nonce))
    else {
        return;
    };

    assert_eq!(initiator_session.as_bytes(), responder_session.as_bytes());
    assert_eq!(initiator_session.as_bytes().len(), shared_secret_len());
    assert_eq!(initiator_session.suite_id(), PQ_KEM_SUITE_ID);
    assert_eq!(initiator_session.suite_name(), PQ_KEM_SUITE_NAME);
    assert!(initiator_session.established_at_unix_secs() > 0);
    assert!(responder_session.established_at_unix_secs() > 0);
    assert!(local.is_consumed());

    let initiator_secret = initiator_session.clone().into_bytes();
    assert_eq!(initiator_secret.len(), PQ_SHARED_SECRET_LEN);

    initiator_session.zeroize();
    responder_session.zeroize();
    assert!(initiator_session.as_bytes().iter().all(|b| *b == 0));
    assert!(responder_session.as_bytes().iter().all(|b| *b == 0));

    let _ = touch_result(responder_manager.accept_offer(&offer));

    responder_manager.clear_replay_cache();
    let _ = touch_result(responder_manager.accept_offer(&offer));

    let _ = touch_result(initiator_manager.finalize_accept(&mut local, &accept, nonce));
}

fn exercise_single_use_modes(data: &[u8]) {
    let policy = PqKemPolicy {
        max_message_age: Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
        require_single_use_local_keypair: byte_at(data, 1200, 0) & 1 == 0,
        replay_filter_capacity: 16,
    };

    let mut initiator_manager = PqKemManager::new(policy);
    let mut responder_manager = PqKemManager::default();

    let Some(mut local) = touch_result(initiator_manager.build_local_keypair()) else {
        return;
    };

    let nonce = nonce_from_data(data, 1210);

    let Some(offer) = touch_result(initiator_manager.build_offer(&local, nonce)) else {
        return;
    };

    let Some((accept, _responder_session)) = touch_result(responder_manager.accept_offer(&offer))
    else {
        return;
    };

    local.set_consumed(byte_at(data, 1220, 0) & 1 == 1);
    let before = local.is_consumed();

    let result = initiator_manager.finalize_accept(&mut local, &accept, nonce);
    match result {
        Ok(session) => {
            assert_eq!(session.as_bytes().len(), PQ_SHARED_SECRET_LEN);
            assert!(local.is_consumed());
        }
        Err(err) => {
            touch_error(&err);
            let _ = before;
        }
    }
}

fn exercise_offer_validation(data: &[u8]) {
    let offer = make_random_offer(data, 1400);
    let max_age = max_age_from_data(data, 1500);

    let _ = touch_result(offer.validate_untrusted(max_age));
    let _ = touch_result(offer.nonce_array());

    if let Ok(bytes) = postcard::to_allocvec(&offer) {
        if let Ok(decoded) = postcard::from_bytes::<PqKemOffer>(&bytes) {
            assert_eq!(decoded, offer);
            let _ = touch_result(decoded.validate_untrusted(max_age));
        }

        let mut mutated = mutate_vec(bytes, data, 1510);
        if mutated.len() > PQ_MAX_WIRE_BYTES {
            mutated.truncate(PQ_MAX_WIRE_BYTES);
        }

        if let Ok(decoded) = postcard::from_bytes::<PqKemOffer>(&mutated) {
            let _ = touch_result(decoded.validate_untrusted(max_age));
            let _ = touch_result(decoded.nonce_array());
        }
    }

    let Some(local) = touch_result(LocalPqKeypair::generate()) else {
        return;
    };

    let nonce = nonce_from_data(data, 1600);
    let Some(valid_offer) = touch_result(local.build_offer(nonce)) else {
        return;
    };

    let mut wrong_suite = valid_offer.clone();
    wrong_suite.suite_id ^= 0xFFFF;
    let _ = touch_result(wrong_suite.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));

    let mut bad_nonce = valid_offer.clone();
    bad_nonce.nonce = mutate_vec(bad_nonce.nonce, data, 1610);
    let _ = touch_result(bad_nonce.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));

    let mut bad_ek = valid_offer.clone();
    bad_ek.ek = mutate_vec(bad_ek.ek, data, 1620);
    let _ = touch_result(bad_ek.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));

    let mut stale = valid_offer.clone();
    stale.created_at_unix_secs = now_unix_secs_fuzz()
        .saturating_sub(DEFAULT_MAX_MESSAGE_AGE_SECS)
        .saturating_sub(10);
    let _ = touch_result(stale.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));

    let mut future = valid_offer;
    future.created_at_unix_secs = now_unix_secs_fuzz()
        .saturating_add(MAX_FUTURE_SKEW_SECS)
        .saturating_add(10);
    let _ = touch_result(future.validate_untrusted(Duration::from_secs(
        DEFAULT_MAX_MESSAGE_AGE_SECS,
    )));
}

fn exercise_accept_validation(data: &[u8]) {
    let expected_nonce = nonce_from_data(data, 1800);
    let accept = make_random_accept(data, 1810, &expected_nonce);
    let max_age = max_age_from_data(data, 1900);

    let _ = touch_result(accept.validate_untrusted(&expected_nonce, max_age));

    if let Ok(bytes) = postcard::to_allocvec(&accept) {
        if let Ok(decoded) = postcard::from_bytes::<PqKemAccept>(&bytes) {
            assert_eq!(decoded, accept);
            let _ = touch_result(decoded.validate_untrusted(&expected_nonce, max_age));
        }

        let mut mutated = mutate_vec(bytes, data, 1910);
        if mutated.len() > PQ_MAX_WIRE_BYTES {
            mutated.truncate(PQ_MAX_WIRE_BYTES);
        }

        if let Ok(decoded) = postcard::from_bytes::<PqKemAccept>(&mutated) {
            let _ = touch_result(decoded.validate_untrusted(&expected_nonce, max_age));
        }
    }

    let mut initiator_manager = PqKemManager::default();
    let mut responder_manager = PqKemManager::default();

    let Some(local) = touch_result(initiator_manager.build_local_keypair()) else {
        return;
    };

    let nonce = nonce_from_data(data, 2000);
    let Some(offer) = touch_result(initiator_manager.build_offer(&local, nonce)) else {
        return;
    };

    let Some((valid_accept, _session)) = touch_result(responder_manager.accept_offer(&offer)) else {
        return;
    };

    let mut wrong_suite = valid_accept.clone();
    wrong_suite.suite_id ^= 0xFFFF;
    let _ = touch_result(wrong_suite.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));

    let mut wrong_nonce = valid_accept.clone();
    if !wrong_nonce.offer_nonce.is_empty() {
        wrong_nonce.offer_nonce[0] ^= 1;
    }
    let _ = touch_result(wrong_nonce.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));

    let mut bad_ct = valid_accept.clone();
    bad_ct.ct = mutate_vec(bad_ct.ct, data, 2010);
    let _ = touch_result(bad_ct.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));

    let mut stale = valid_accept.clone();
    stale.created_at_unix_secs = now_unix_secs_fuzz()
        .saturating_sub(DEFAULT_MAX_MESSAGE_AGE_SECS)
        .saturating_sub(10);
    let _ = touch_result(stale.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));

    let mut future = valid_accept;
    future.created_at_unix_secs = now_unix_secs_fuzz()
        .saturating_add(MAX_FUTURE_SKEW_SECS)
        .saturating_add(10);
    let _ = touch_result(future.validate_untrusted(
        &nonce,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    ));
}

fn exercise_manager_with_fuzz_policy(data: &[u8]) {
    let policy = policy_from_data(data, 2200);
    let mut manager = PqKemManager::new(policy);

    let local_result = manager.build_local_keypair();
    let Some(mut local) = touch_result(local_result) else {
        return;
    };

    let nonce = nonce_from_data(data, 2300);
    let offer_result = manager.build_offer(&local, nonce);
    let Some(offer) = touch_result(offer_result) else {
        return;
    };

    let accepted = manager.accept_offer(&offer);
    if let Some((accept, responder_session)) = touch_result(accepted) {
        assert_eq!(responder_session.as_bytes().len(), PQ_SHARED_SECRET_LEN);
        let _ = touch_result(manager.finalize_accept(&mut local, &accept, nonce));
    }

    manager.clear_replay_cache();
}

fn exercise_responder_direct(data: &[u8]) {
    let offer = make_random_offer(data, 2500);
    let _ = touch_result(p2p_005_pq_fips203kem::PqResponder::respond_to_offer(
        &offer,
        max_age_from_data(data, 2600),
    ));

    let Some(local) = touch_result(LocalPqKeypair::generate()) else {
        return;
    };

    let nonce = nonce_from_data(data, 2700);
    let Some(offer) = touch_result(local.build_offer(nonce)) else {
        return;
    };

    if let Some((accept, session)) = touch_result(p2p_005_pq_fips203kem::PqResponder::respond_to_offer(
        &offer,
        Duration::from_secs(DEFAULT_MAX_MESSAGE_AGE_SECS),
    )) {
        assert_eq!(accept.offer_nonce, nonce.to_vec());
        assert_eq!(session.as_bytes().len(), PQ_SHARED_SECRET_LEN);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_constants();
    exercise_policy(data);
    exercise_replay_filter(data);
    exercise_byte_validators(data);

    exercise_valid_handshake(data);

    exercise_single_use_modes(data);
    exercise_manager_with_fuzz_policy(data);

    exercise_offer_validation(data);
    exercise_accept_validation(data);
    exercise_responder_direct(data);
});