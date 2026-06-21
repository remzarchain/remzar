#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const SALT_SIZE: usize = 16;
            pub const NONCE_SIZE: usize = 12;

            pub const MLDSA65_SECRET_BYTES: usize = 4032;
            pub const MLDSA65_SECRET_HEX_LEN: usize = Self::MLDSA65_SECRET_BYTES * 2;
            pub const MAX_PRIVKEY_HEX_INPUT_LEN: usize = Self::MLDSA65_SECRET_HEX_LEN;

            pub const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;
            pub const MAX_ENCRYPTED_BLOB_BYTES: usize = 64 * 1024;

            pub const ARGON2_MEMORY_KIB: u32 = 32;
            pub const ARGON2_TIME_COST: u32 = 1;
            pub const ARGON2_LANES: u32 = 1;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone)]
        pub enum ErrorDetection {
            CryptographicError {
                message: String,
            },
            EncryptionError {
                message: String,
            },
            DecryptionError {
                message: String,
            },
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
            SerializationError {
                details: String,
            },
            InvalidSignatureFormat {
                format: String,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    ErrorDetection::CryptographicError { message } => {
                        write!(f, "CryptographicError: {message}")
                    }
                    ErrorDetection::EncryptionError { message } => {
                        write!(f, "EncryptionError: {message}")
                    }
                    ErrorDetection::DecryptionError { message } => {
                        write!(f, "DecryptionError: {message}")
                    }
                    ErrorDetection::ValidationError { message, tx_id } => match tx_id {
                        Some(id) => write!(f, "ValidationError: {message} tx_id={id}"),
                        None => write!(f, "ValidationError: {message}"),
                    },
                    ErrorDetection::SerializationError { details } => {
                        write!(f, "SerializationError: {details}")
                    }
                    ErrorDetection::InvalidSignatureFormat { format } => {
                        write!(f, "InvalidSignatureFormat: {format}")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        pub const PRYME_WALLET_LEN: usize = REMZAR_WALLET_LEN;
        pub const PRYME_WALLET_BODY_LEN: usize = REMZAR_WALLET_BODY_LEN;
        pub const PRYME_WALLET_PREFIX: u8 = REMZAR_WALLET_PREFIX;

        #[inline]
        pub fn derive_wallet_id_from_pubkey_bytes(pk_bytes: &[u8]) -> String {
            let mut hasher = blake3::Hasher::new();
            hasher.update(pk_bytes);

            let mut out = [0u8; 64];
            hasher.finalize_xof().fill(&mut out);

            format!("r{}", hex::encode(out))
        }

        #[inline]
        pub fn compute_address_from_public_key_bytes(pk_bytes: &[u8]) -> String {
            derive_wallet_id_from_pubkey_bytes(pk_bytes)
        }

        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invalid wallet length: expected {}, got {}",
                        REMZAR_WALLET_LEN,
                        s.len()
                    ),
                    tx_id: None,
                });
            }

            let bytes = s.as_bytes();

            if bytes.first().copied() != Some(b'r') && bytes.first().copied() != Some(b'R') {
                return Err(ErrorDetection::ValidationError {
                    message: "Invalid wallet prefix: expected r".to_string(),
                    tx_id: None,
                });
            }

            let body = &s[1..];

            if !body.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ErrorDetection::ValidationError {
                    message: "Invalid wallet body: expected 128 hex characters".to_string(),
                    tx_id: None,
                });
            }

            Ok(format!("r{}", body.to_ascii_lowercase()))
        }

        #[inline]
        pub fn wallet_id_matches_pubkey_bytes_checked(
            wallet_id: &str,
            pk_bytes: &[u8],
        ) -> Result<String, ErrorDetection> {
            let canonical = canon_wallet_id_checked(wallet_id)?;
            let derived = derive_wallet_id_from_pubkey_bytes(pk_bytes);

            if canonical != derived {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address does not match public key bytes".to_string(),
                    tx_id: None,
                });
            }

            Ok(canonical)
        }

        #[inline]
        pub fn parse_wallet_address(id: &str) -> Result<String, ErrorDetection> {
            canon_wallet_id_checked(id)
        }
    }

    pub mod hash_system_remzarhash {
        pub use crate::real_hash_system_remzarhash::*;
    }
}

#[path = "../../src/utility/hash_system_remzarhash.rs"]
pub mod real_hash_system_remzarhash;

#[path = "../../src/cryptography/ml_dsa_65_001_keypairs.rs"]
pub mod ml_dsa_65_001_keypairs;

#[path = "../../src/cryptography/ml_dsa_65_005_encryption.rs"]
pub mod ml_dsa_65_005_encryption;

#[path = "../../src/cryptography/ml_dsa_65_006_edwallet.rs"]
pub mod ml_dsa_65_006_edwallet;

pub mod cryptography {
    pub use crate::ml_dsa_65_001_keypairs;
    pub use crate::ml_dsa_65_005_encryption;
    pub use crate::ml_dsa_65_006_edwallet;
}

use fips204::ml_dsa_65;
use ml_dsa_65_005_encryption::Cryption;
use ml_dsa_65_006_edwallet::MLDSA65Wallet;
use utility::alpha_002_error_detection_system::ErrorDetection;
use utility::helper::{
    canon_wallet_id_checked, derive_wallet_id_from_pubkey_bytes,
    wallet_id_matches_pubkey_bytes_checked, REMZAR_WALLET_LEN,
};

const MAX_MESSAGE_LEN: usize = 512;
const MAX_FUZZ_BLOB_LEN: usize = 5992;

struct ValidWalletMaterial {
    public: [u8; ml_dsa_65::PK_LEN],
    address: String,
    encrypted_secret: Vec<u8>,
    secret: Vec<u8>,
    passphrase: &'static str,
}

fn touch_error(error: &ErrorDetection) {
    match error {
        ErrorDetection::CryptographicError { message } => {
            let _ = message.len();
        }
        ErrorDetection::EncryptionError { message } => {
            let _ = message.len();
        }
        ErrorDetection::DecryptionError { message } => {
            let _ = message.len();
        }
        ErrorDetection::ValidationError { message, tx_id } => {
            let _ = message.len();
            if let Some(tx_id) = tx_id {
                let _ = tx_id.len();
            }
        }
        ErrorDetection::SerializationError { details } => {
            let _ = details.len();
        }
        ErrorDetection::InvalidSignatureFormat { format } => {
            let _ = format.len();
        }
    }
}

fn touch_result<T>(result: Result<T, ErrorDetection>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            touch_error(&error);
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

fn fill_vec(data: &[u8], len: usize, salt: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    if data.is_empty() {
        out.resize(len, salt);
        return out;
    }

    for i in 0usize..len {
        let a = byte_at(data, i, salt);
        let b = byte_at(data, i.wrapping_mul(7).wrapping_add(3), salt.rotate_left(1));
        out.push(a ^ b ^ salt ^ (i as u8));
    }

    out
}

fn fill_array<const N: usize>(data: &[u8], salt: u8) -> [u8; N] {
    let mut out = [0u8; N];

    if data.is_empty() {
        out.fill(salt);
        return out;
    }

    for i in 0usize..N {
        let a = byte_at(data, i, salt);
        let b = byte_at(data, i.wrapping_mul(11).wrapping_add(5), salt.rotate_left(1));
        out[i] = a ^ b ^ salt ^ (i as u8);
    }

    out
}

fn mutate_bytes(buf: &mut [u8], data: &[u8], salt: usize) {
    if buf.is_empty() {
        return;
    }

    if data.is_empty() {
        let idx = salt % buf.len();
        buf[idx] ^= 0xA5;
        return;
    }

    let stride = ((data[0] as usize) % 31) + 1;

    for (i, byte) in data.iter().enumerate() {
        let idx = i
            .wrapping_mul(stride)
            .wrapping_add(salt)
            .wrapping_rem(buf.len());

        buf[idx] ^= *byte;
    }
}

fn mutate_length(mut buf: Vec<u8>, data: &[u8]) -> Vec<u8> {
    match byte_at(data, 0, 0) % 7 {
        0 => {
            buf.clear();
        }
        1 => {
            let new_len = byte_at(data, 1, 0) as usize % buf.len().saturating_add(1);
            buf.truncate(new_len);
        }
        2 => {
            buf.push(byte_at(data, 2, 0));
        }
        3 => {
            let extra_len = byte_at(data, 3, 0) as usize % 64;
            for i in 0usize..extra_len {
                buf.push(byte_at(data, i.wrapping_add(4), i as u8));
            }
        }
        4 => {
            if !buf.is_empty() {
                let idx = byte_at(data, 4, 0) as usize % buf.len();
                buf.remove(idx);
            }
        }
        5 => {
            if buf.len() > 1 {
                let remove = ((byte_at(data, 5, 0) as usize) % buf.len()).max(1);
                let new_len = buf.len().saturating_sub(remove);
                buf.truncate(new_len);
            }
        }
        _ => {}
    }

    if buf.len() > MAX_FUZZ_BLOB_LEN {
        buf.truncate(MAX_FUZZ_BLOB_LEN);
    }

    buf
}

fn make_passphrase(data: &[u8]) -> String {
    match byte_at(data, 6, 0) % 8 {
        0 => String::new(),
        1 => "     ".to_string(),
        2 => "remzar-wallet-fuzz-passphrase".to_string(),
        3 => "correct horse battery staple remzar wallet".to_string(),
        _ => {
            let len = (byte_at(data, 7, 0) as usize % 64) + 1;
            let mut s = String::with_capacity(len);

            for i in 0usize..len {
                let raw = byte_at(data, i.wrapping_add(8), 0x41);
                let printable = 33u8.wrapping_add(raw % 94);
                s.push(char::from(printable));
            }

            s
        }
    }
}

fn make_wrong_passphrase(passphrase: &str, data: &[u8]) -> String {
    let mut wrong = String::from("wrong-remzar-wallet-fuzz-passphrase-");

    for i in 0usize..8usize {
        let raw = byte_at(data, i.wrapping_add(17), i as u8);
        let printable = 33u8.wrapping_add(raw % 94);
        wrong.push(char::from(printable));
    }

    if wrong == passphrase {
        wrong.push('x');
    }

    wrong
}

fn make_message(data: &[u8]) -> Vec<u8> {
    match byte_at(data, 9, 0) % 5 {
        0 => Vec::new(),
        1 => b"remzar wallet fuzz message".to_vec(),
        _ => {
            let len = byte_at(data, 10, 0) as usize % (MAX_MESSAGE_LEN + 1);
            fill_vec(data, len, 0x6D)
        }
    }
}

fn make_address_candidate(data: &[u8], valid_address: Option<&str>) -> String {
    match byte_at(data, 11, 0) % 9 {
        0 => String::new(),
        1 => "r1234".to_string(),
        2 => "x1234567890abcdef".repeat(8),
        3 => {
            let mut s = String::from("r");
            s.push_str(&"0".repeat(128));
            s
        }
        4 => {
            let mut s = String::from("r");
            s.push_str(&"g".repeat(128));
            s
        }
        5 => {
            if let Some(address) = valid_address {
                address.to_ascii_uppercase()
            } else {
                "R".to_string() + &"A".repeat(128)
            }
        }
        6 => {
            if let Some(address) = valid_address {
                format!("  {address}  ")
            } else {
                "  r".to_string() + &"1".repeat(128) + "  "
            }
        }
        7 => {
            let len = byte_at(data, 12, 0) as usize % 180;
            let mut s = String::with_capacity(len);

            for i in 0usize..len {
                let raw = byte_at(data, i.wrapping_add(13), i as u8);
                let printable = 32u8.wrapping_add(raw % 95);
                s.push(char::from(printable));
            }

            s
        }
        _ => valid_address
            .unwrap_or("r00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            .to_string(),
    }
}

fn make_fuzz_blob(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let len = data.len().min(MAX_FUZZ_BLOB_LEN);
    data[..len].to_vec()
}

fn make_secret_candidate(data: &[u8], valid_secret: Option<&[u8]>) -> Vec<u8> {
    match byte_at(data, 14, 0) % 7 {
        0 => Vec::new(),
        1 => vec![0u8; 32],
        2 => fill_vec(data, ml_dsa_65::SK_LEN, 0xA7),
        3 => fill_vec(data, ml_dsa_65::SK_LEN.saturating_sub(1), 0xB7),
        4 => {
            let mut v = fill_vec(data, ml_dsa_65::SK_LEN, 0xC7);
            v.push(byte_at(data, 15, 0));
            v
        }
        5 => valid_secret.unwrap_or(&[]).to_vec(),
        _ => {
            let mut v = valid_secret.unwrap_or(&[]).to_vec();
            mutate_bytes(&mut v, data, 71);
            v
        }
    }
}

fn valid_material() -> Option<&'static ValidWalletMaterial> {
    static VALID: OnceLock<Option<ValidWalletMaterial>> = OnceLock::new();

    VALID
        .get_or_init(|| {
            let passphrase = "remzar-valid-wallet-fuzz-passphrase";
            let wallet = MLDSA65Wallet::new(passphrase).ok()?;

            let secret =
                Cryption::decrypt_private_key_bytes(&wallet.encrypted_secret, passphrase).ok()?;

            Some(ValidWalletMaterial {
                public: wallet.public,
                address: wallet.address,
                encrypted_secret: wallet.encrypted_secret,
                secret,
                passphrase,
            })
        })
        .as_ref()
}

fn wallet_from_material(material: &ValidWalletMaterial) -> MLDSA65Wallet {
    MLDSA65Wallet {
        public: material.public,
        address: material.address.clone(),
        encrypted_secret: material.encrypted_secret.clone(),
    }
}

fn assert_wallet_address_shape(address: &str) {
    assert_eq!(address.len(), REMZAR_WALLET_LEN);
    assert!(address.starts_with('r'));

    let body = &address[1..];

    assert_eq!(body.len(), 128);
    assert!(body.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()));
    assert!(body.as_bytes().iter().all(|byte| !byte.is_ascii_uppercase()));
}

fn exercise_address_validation(data: &[u8], valid_address: Option<&str>) {
    let candidate = make_address_candidate(data, valid_address);

    let _ = touch_result(canon_wallet_id_checked(&candidate));
    let _ = touch_result(MLDSA65Wallet::validate_address_format(&candidate));

    if let Some(address) = valid_address {
        let canonical = touch_result(canon_wallet_id_checked(address));
        if let Some(canonical) = canonical {
            assert_eq!(canonical, address);
        }

        let upper = address.to_ascii_uppercase();
        if let Some(canonical_upper) = touch_result(canon_wallet_id_checked(&upper)) {
            assert_eq!(canonical_upper, address);
        }

        let padded = format!("  {address}  ");
        if let Some(canonical_padded) = touch_result(canon_wallet_id_checked(&padded)) {
            assert_eq!(canonical_padded, address);
        }

        let _ = touch_result(MLDSA65Wallet::validate_address_format(address));
        let _ = touch_result(MLDSA65Wallet::validate_address_format(&upper));
    }
}

fn exercise_public_key_address_paths(data: &[u8], material: &ValidWalletMaterial) {
    let public = material.public;

    if let Some(address) = touch_result(MLDSA65Wallet::generate_address(&public)) {
        assert_eq!(address, material.address);
        assert_wallet_address_shape(&address);
    }

    let helper_address = derive_wallet_id_from_pubkey_bytes(&public);
    assert_eq!(helper_address, material.address);

    if let Some(canonical) =
        touch_result(wallet_id_matches_pubkey_bytes_checked(&material.address, &public))
    {
        assert_eq!(canonical, material.address);
    }

    let fuzz_public = fill_array::<{ ml_dsa_65::PK_LEN }>(data, 0x51);

    let _ = touch_result(MLDSA65Wallet::generate_address(&fuzz_public));
    let _ = touch_result(wallet_id_matches_pubkey_bytes_checked(
        &material.address,
        &fuzz_public,
    ));
}

fn exercise_from_parts(data: &[u8], material: &ValidWalletMaterial) {
    if let Some(restored) = touch_result(MLDSA65Wallet::from_parts(
        material.public,
        material.encrypted_secret.clone(),
    )) {
        assert_eq!(restored.address, material.address);
        let _ = touch_result(restored.validate_self());
    }

    let mut mutated_encrypted = material.encrypted_secret.clone();
    mutate_bytes(&mut mutated_encrypted, data, 31);
    let _ = touch_result(MLDSA65Wallet::from_parts(
        material.public,
        mutated_encrypted.clone(),
    ));

    let resized_encrypted = mutate_length(mutated_encrypted, data);
    let _ = touch_result(MLDSA65Wallet::from_parts(
        material.public,
        resized_encrypted,
    ));

    let fuzz_public = fill_array::<{ ml_dsa_65::PK_LEN }>(data, 0x91);
    let fuzz_blob = make_fuzz_blob(data);
    let _ = touch_result(MLDSA65Wallet::from_parts(fuzz_public, fuzz_blob));
}

fn exercise_secret_paths(data: &[u8], wallet: &MLDSA65Wallet, material: &ValidWalletMaterial) {
    if let Some(secret_hex) = touch_result(wallet.secret_key_hex(material.passphrase)) {
        assert_eq!(secret_hex.len(), ml_dsa_65::SK_LEN.saturating_mul(2));
        assert!(secret_hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));

        if let Ok(secret_bytes) = hex::decode(&secret_hex) {
            assert_eq!(secret_bytes.len(), ml_dsa_65::SK_LEN);

            if let Some(recovered) =
                touch_result(MLDSA65Wallet::address_from_secret_bytes(&secret_bytes))
            {
                assert_eq!(recovered, material.address);
            }
        }
    }

    let wrong_passphrase = make_wrong_passphrase(material.passphrase, data);
    let _ = touch_result(wallet.secret_key_hex(&wrong_passphrase));

    // Valid real secret must recover the same address.
    let _ = touch_result(MLDSA65Wallet::address_from_secret_bytes(&material.secret))
        .map(|recovered| {
            assert_eq!(recovered, material.address);
        });

    // Wrong-length secrets must reject cleanly without reaching fips204::get_public_key().
    let mut short_secret = material.secret.clone();
    short_secret.pop();
    let _ = touch_result(MLDSA65Wallet::address_from_secret_bytes(&short_secret));

    let mut long_secret = material.secret.clone();
    long_secret.push(byte_at(data, 41, 0));
    let _ = touch_result(MLDSA65Wallet::address_from_secret_bytes(&long_secret));

    let empty_secret: Vec<u8> = Vec::new();
    let _ = touch_result(MLDSA65Wallet::address_from_secret_bytes(&empty_secret));

    // Fuzz arbitrary bytes, but avoid exactly SK_LEN because malformed same-length.
    let mut fuzz_secret = make_fuzz_blob(data);
    if fuzz_secret.len() == ml_dsa_65::SK_LEN {
        fuzz_secret.pop();
    }
    let _ = touch_result(MLDSA65Wallet::address_from_secret_bytes(&fuzz_secret));
}

fn exercise_sign_verify(data: &[u8], wallet: &MLDSA65Wallet, material: &ValidWalletMaterial) {
    let message = make_message(data);

    if let Some(signature) = touch_result(wallet.sign(material.passphrase, &message)) {
        assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
        assert!(wallet.verify(&message, &signature));

        let mut tampered_signature = signature.clone();
        mutate_bytes(&mut tampered_signature, data, 53);
        let _ = wallet.verify(&message, &tampered_signature);

        if tampered_signature != signature {
            assert!(!wallet.verify(&message, &tampered_signature));
        }

        let mut tampered_message = message.clone();
        if tampered_message.is_empty() {
            tampered_message.push(1);
        } else {
            mutate_bytes(&mut tampered_message, data, 59);
        }

        if tampered_message != message {
            assert!(!wallet.verify(&tampered_message, &signature));
        }

        let resized_signature = mutate_length(signature.clone(), data);
        if resized_signature.len() != ml_dsa_65::SIG_LEN {
            assert!(!wallet.verify(&message, &resized_signature));
        } else {
            let _ = wallet.verify(&message, &resized_signature);
        }
    }

    let wrong_passphrase = make_wrong_passphrase(material.passphrase, data);
    let _ = touch_result(wallet.sign(&wrong_passphrase, &message));

    let fuzz_signature = make_fuzz_blob(data);
    let _ = wallet.verify(&message, &fuzz_signature);
}

fn exercise_wallet(data: &[u8], material: &ValidWalletMaterial) {
    let wallet = wallet_from_material(material);

    assert_wallet_address_shape(&wallet.address);

    let _ = touch_result(wallet.validate_self());

    exercise_address_validation(data, Some(&wallet.address));
    exercise_public_key_address_paths(data, material);
    exercise_from_parts(data, material);
    exercise_secret_paths(data, &wallet, material);
    exercise_sign_verify(data, &wallet, material);

    let mut bad_address_wallet = wallet_from_material(material);
    bad_address_wallet.address = make_address_candidate(data, None);
    let _ = touch_result(bad_address_wallet.validate_self());

    let mut bad_public_wallet = wallet_from_material(material);
    bad_public_wallet.public = fill_array::<{ ml_dsa_65::PK_LEN }>(data, 0xE1);
    let _ = touch_result(bad_public_wallet.validate_self());

    let mut bad_encrypted_wallet = wallet_from_material(material);
    mutate_bytes(&mut bad_encrypted_wallet.encrypted_secret, data, 83);
    let _ = touch_result(bad_encrypted_wallet.validate_self());
}

fn exercise_constructor(data: &[u8]) {
    let passphrase = make_passphrase(data);

    if let Some(wallet) = touch_result(MLDSA65Wallet::new(&passphrase)) {
        assert_wallet_address_shape(&wallet.address);
        assert_eq!(wallet.public.len(), ml_dsa_65::PK_LEN);
        assert!(!wallet.encrypted_secret.is_empty());

        let _ = touch_result(wallet.validate_self());

        let message = make_message(data);
        if let Some(signature) = touch_result(wallet.sign(&passphrase, &message)) {
            assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
            assert!(wallet.verify(&message, &signature));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_address_validation(data, None);

    if let Some(material) = valid_material() {
        exercise_wallet(data, material);
    }

    if byte_at(data, 16, 0) % 8 == 0 {
        exercise_constructor(data);
    }
});