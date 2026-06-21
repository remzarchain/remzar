use remzar::network::p2p_006_reqresp::Hash;
use remzar::tokens::nft_001::{NftMintTx, NftRecord, NftTransferTx};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

fn hash_from_seed(seed: u64) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"remzar-nft-001-test-hash-from-seed-v1");
    hasher.update(&seed.to_le_bytes());

    let mut out = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

fn manual_content_hash(content_bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(content_bytes);

    let mut out = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

fn wallet_from_seed(seed: u64) -> String {
    format!("r{}", hex::encode(hash_from_seed(seed)))
}

fn make_mint(seed: u64, content: &[u8]) -> NftMintTx {
    NftMintTx::from_content_bytes(
        hash_from_seed(seed),
        format!("NFT #{seed}"),
        format!("description #{seed}"),
        content,
    )
}

fn make_record(seed: u64) -> NftRecord {
    NftRecord {
        nft_id: hash_from_seed(seed),
        creator_wallet: wallet_from_seed(seed.wrapping_add(1)),
        owner_wallet: wallet_from_seed(seed.wrapping_add(2)),
        content_hash: hash_from_seed(seed.wrapping_add(3)),
        title: format!("record #{seed}"),
        description: format!("record description #{seed}"),
        minted_height: seed.wrapping_add(10),
        minted_time: seed.wrapping_add(20),
    }
}

fn json_array_len(len: usize, value: &str) -> String {
    let mut out = String::from("[");
    for n in 0..len {
        if n > 0 {
            out.push(',');
        }
        out.push_str(value);
    }
    out.push(']');
    out
}

#[test]
fn test_01_from_content_empty_bytes_matches_manual_blake3_xof() {
    let nft_id = hash_from_seed(1);
    let tx = NftMintTx::from_content_bytes(
        nft_id,
        "empty".to_string(),
        "empty content".to_string(),
        &[],
    );

    assert_eq!(tx.nft_id, nft_id);
    assert_eq!(tx.content_hash, manual_content_hash(&[]));
    assert_eq!(tx.title, "empty");
    assert_eq!(tx.description, "empty content");
}

#[test]
fn test_02_from_content_ascii_vector_matches_manual_blake3_xof() {
    let content = b"abc";
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(2),
        "abc".to_string(),
        "ascii".to_string(),
        content,
    );

    assert_eq!(tx.content_hash, manual_content_hash(content));
}

#[test]
fn test_03_from_content_single_byte_vector_matches_manual_blake3_xof() {
    let content = [255u8];
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(3),
        "single byte".to_string(),
        "binary".to_string(),
        &content,
    );

    assert_eq!(tx.content_hash, manual_content_hash(&content));
}

#[test]
fn test_04_from_content_zero_filled_binary_vector_matches_manual_blake3_xof() {
    let content = vec![0u8; 64];
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(4),
        "zeroes".to_string(),
        "zero content".to_string(),
        &content,
    );

    assert_eq!(tx.content_hash, manual_content_hash(&content));
}

#[test]
fn test_05_from_content_unicode_bytes_vector_matches_manual_blake3_xof() {
    let content = "Remzar NFT 🚀 post-quantum metadata".as_bytes();
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(5),
        "unicode".to_string(),
        "unicode metadata".to_string(),
        content,
    );

    assert_eq!(tx.content_hash, manual_content_hash(content));
}

#[test]
fn test_06_from_content_large_blob_load_vector_matches_manual_blake3_xof() {
    let mut rng = DeterministicRng::new(6);
    let content = rng.bytes(131_072);
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(6),
        "large".to_string(),
        "large blob".to_string(),
        &content,
    );

    assert_eq!(tx.content_hash, manual_content_hash(&content));
}

#[test]
fn test_07_nft_mint_json_roundtrip_preserves_all_fields() -> TestResult {
    let tx = make_mint(7, b"json mint roundtrip");
    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_08_nft_transfer_json_roundtrip_preserves_all_fields() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(8),
        new_owner_wallet: wallet_from_seed(80),
    };

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftTransferTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_09_nft_record_json_roundtrip_preserves_all_fields() -> TestResult {
    let record = make_record(9);
    let encoded = serde_json::to_vec(&record)?;
    let decoded: NftRecord = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.nft_id, record.nft_id);
    assert_eq!(decoded.creator_wallet, record.creator_wallet);
    assert_eq!(decoded.owner_wallet, record.owner_wallet);
    assert_eq!(decoded.content_hash, record.content_hash);
    assert_eq!(decoded.title, record.title);
    assert_eq!(decoded.description, record.description);
    assert_eq!(decoded.minted_height, record.minted_height);
    assert_eq!(decoded.minted_time, record.minted_time);
    Ok(())
}

#[test]
fn test_10_nft_record_pretty_json_roundtrip_preserves_all_fields() -> TestResult {
    let record = make_record(10);
    let encoded = serde_json::to_string_pretty(&record)?;
    let decoded: NftRecord = serde_json::from_str(&encoded)?;

    assert_eq!(decoded.nft_id, record.nft_id);
    assert_eq!(decoded.creator_wallet, record.creator_wallet);
    assert_eq!(decoded.owner_wallet, record.owner_wallet);
    assert_eq!(decoded.content_hash, record.content_hash);
    assert_eq!(decoded.title, record.title);
    assert_eq!(decoded.description, record.description);
    assert_eq!(decoded.minted_height, record.minted_height);
    assert_eq!(decoded.minted_time, record.minted_time);
    Ok(())
}

#[test]
fn test_11_nft_mint_postcard_roundtrip_preserves_all_fields() -> TestResult {
    let tx = make_mint(11, b"postcard mint roundtrip");
    let encoded = postcard::to_stdvec(&tx)?;
    let decoded: NftMintTx = postcard::from_bytes(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_12_deserialize_mint_rejects_short_nft_id_array() {
    let arr63 = json_array_len(63, "0");
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{"nft_id":{arr63},"content_hash":{arr64},"title":"bad","description":"short"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_13_deserialize_mint_rejects_long_content_hash_array() {
    let arr64 = json_array_len(64, "1");
    let arr65 = json_array_len(65, "2");
    let json = format!(
        r#"{{"nft_id":{arr64},"content_hash":{arr65},"title":"bad","description":"long"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_14_empty_title_and_empty_description_are_preserved() -> TestResult {
    let tx = NftMintTx::from_content_bytes(hash_from_seed(14), String::new(), String::new(), b"x");
    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.title, "");
    assert_eq!(decoded.description, "");
    assert_eq!(decoded.content_hash, manual_content_hash(b"x"));
    Ok(())
}

#[test]
fn test_15_long_title_and_long_description_are_preserved() -> TestResult {
    let title = "T".repeat(4_096);
    let description = "D".repeat(16_384);
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(15),
        title.clone(),
        description.clone(),
        b"long metadata fields",
    );

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.title, title);
    assert_eq!(decoded.description, description);
    Ok(())
}

#[test]
fn test_16_whitespace_title_and_description_are_preserved_exactly() -> TestResult {
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(16),
        "  title with whitespace  ".to_string(),
        "\n\t description with whitespace \t\n".to_string(),
        b"whitespace",
    );

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.title, "  title with whitespace  ");
    assert_eq!(decoded.description, "\n\t description with whitespace \t\n");
    Ok(())
}

#[test]
fn test_17_transfer_payload_preserves_noncanonical_wallet_string() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(17),
        new_owner_wallet: "not-a-wallet-but-payload-preserves-it".to_string(),
    };

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftTransferTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_18_zero_nft_id_is_serializable_payload_data() -> TestResult {
    let tx = NftMintTx::from_content_bytes(
        [0u8; 64],
        "zero id".to_string(),
        "allowed as payload data".to_string(),
        b"zero id content",
    );

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.nft_id, [0u8; 64]);
    assert_eq!(
        decoded.content_hash,
        manual_content_hash(b"zero id content")
    );
    Ok(())
}

#[test]
fn test_19_record_u64_max_height_and_time_roundtrip() -> TestResult {
    let record = NftRecord {
        nft_id: hash_from_seed(19),
        creator_wallet: wallet_from_seed(190),
        owner_wallet: wallet_from_seed(191),
        content_hash: hash_from_seed(192),
        title: "max u64".to_string(),
        description: "boundary fields".to_string(),
        minted_height: u64::MAX,
        minted_time: u64::MAX,
    };

    let encoded = serde_json::to_vec(&record)?;
    let decoded: NftRecord = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.minted_height, u64::MAX);
    assert_eq!(decoded.minted_time, u64::MAX);
    Ok(())
}

#[test]
fn test_20_record_creator_and_owner_can_differ_after_transfer_state() -> TestResult {
    let record = NftRecord {
        nft_id: hash_from_seed(20),
        creator_wallet: wallet_from_seed(200),
        owner_wallet: wallet_from_seed(201),
        content_hash: hash_from_seed(202),
        title: "transferred".to_string(),
        description: "creator is not owner".to_string(),
        minted_height: 1,
        minted_time: 2,
    };

    let encoded = serde_json::to_vec(&record)?;
    let decoded: NftRecord = serde_json::from_slice(&encoded)?;

    assert_ne!(decoded.creator_wallet, decoded.owner_wallet);
    assert_eq!(decoded.creator_wallet, wallet_from_seed(200));
    assert_eq!(decoded.owner_wallet, wallet_from_seed(201));
    Ok(())
}

#[test]
fn test_21_record_clone_is_independent_value_copy() {
    let original = make_record(21);
    let mut cloned = original.clone();
    cloned.owner_wallet = wallet_from_seed(2_121);

    assert_ne!(original.owner_wallet, cloned.owner_wallet);
    assert_eq!(original.nft_id, cloned.nft_id);
    assert_eq!(original.content_hash, cloned.content_hash);
}

#[test]
fn test_22_property_same_content_same_hash_across_repeated_builds() {
    for seed in 1u64..=64u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(512);
        let left = make_mint(seed, &content);
        let right = make_mint(seed.wrapping_add(1_000), &content);

        assert_eq!(left.content_hash, right.content_hash);
    }
}

#[test]
fn test_23_property_different_content_changes_hash_for_fixed_id() {
    let nft_id = hash_from_seed(23);
    let left = NftMintTx::from_content_bytes(
        nft_id,
        "left".to_string(),
        "left".to_string(),
        b"content-left",
    );
    let right = NftMintTx::from_content_bytes(
        nft_id,
        "right".to_string(),
        "right".to_string(),
        b"content-right",
    );

    assert_ne!(left.content_hash, right.content_hash);
    assert_eq!(left.nft_id, right.nft_id);
}

#[test]
fn test_24_property_same_content_different_nft_id_only_changes_nft_id() {
    let content = b"same content different nft id";
    let left = NftMintTx::from_content_bytes(
        hash_from_seed(24),
        "title".to_string(),
        "description".to_string(),
        content,
    );
    let right = NftMintTx::from_content_bytes(
        hash_from_seed(2_424),
        "title".to_string(),
        "description".to_string(),
        content,
    );

    assert_ne!(left.nft_id, right.nft_id);
    assert_eq!(left.content_hash, right.content_hash);
    assert_eq!(left.title, right.title);
    assert_eq!(left.description, right.description);
}

#[test]
fn test_25_property_title_and_description_do_not_affect_content_hash() {
    let content = b"title description independence";
    let left = NftMintTx::from_content_bytes(
        hash_from_seed(25),
        "A".to_string(),
        "B".to_string(),
        content,
    );
    let right = NftMintTx::from_content_bytes(
        hash_from_seed(25),
        "different title".to_string(),
        "different description".to_string(),
        content,
    );

    assert_eq!(left.nft_id, right.nft_id);
    assert_eq!(left.content_hash, right.content_hash);
    assert_ne!(left.title, right.title);
    assert_ne!(left.description, right.description);
}

#[test]
fn test_26_property_generated_hashes_are_always_64_bytes() {
    for seed in 26u64..=90u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(257);
        let tx = make_mint(seed, &content);

        assert_eq!(tx.nft_id.len(), 64);
        assert_eq!(tx.content_hash.len(), 64);
    }
}

#[test]
fn test_27_fuzz_mint_json_roundtrip_for_generated_payloads() -> TestResult {
    for seed in 100u64..200u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(300);
        let tx = make_mint(seed, &content);
        let encoded = serde_json::to_vec(&tx)?;
        let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, tx);
    }

    Ok(())
}

#[test]
fn test_28_fuzz_mint_postcard_roundtrip_for_generated_payloads() -> TestResult {
    for seed in 200u64..300u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(301);
        let tx = make_mint(seed, &content);
        let encoded = postcard::to_stdvec(&tx)?;
        let decoded: NftMintTx = postcard::from_bytes(&encoded)?;

        assert_eq!(decoded, tx);
    }

    Ok(())
}

#[test]
fn test_29_fuzz_record_json_roundtrip_for_generated_records() -> TestResult {
    for seed in 300u64..380u64 {
        let record = make_record(seed);
        let encoded = serde_json::to_vec(&record)?;
        let decoded: NftRecord = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded.nft_id, record.nft_id);
        assert_eq!(decoded.creator_wallet, record.creator_wallet);
        assert_eq!(decoded.owner_wallet, record.owner_wallet);
        assert_eq!(decoded.content_hash, record.content_hash);
        assert_eq!(decoded.title, record.title);
        assert_eq!(decoded.description, record.description);
        assert_eq!(decoded.minted_height, record.minted_height);
        assert_eq!(decoded.minted_time, record.minted_time);
    }

    Ok(())
}

#[test]
fn test_30_fuzz_transfer_json_roundtrip_for_generated_transfers() -> TestResult {
    for seed in 400u64..500u64 {
        let tx = NftTransferTx {
            nft_id: hash_from_seed(seed),
            new_owner_wallet: wallet_from_seed(seed.wrapping_add(9_000)),
        };

        let encoded = serde_json::to_vec(&tx)?;
        let decoded: NftTransferTx = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, tx);
    }

    Ok(())
}

#[test]
fn test_31_fuzz_nonempty_content_hashes_are_not_all_zero() {
    for seed in 500u64..560u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(128);
        let tx = make_mint(seed, &content);

        assert!(tx.content_hash.iter().any(|byte| *byte != 0));
    }
}

#[test]
fn test_32_adversarial_duplicate_mint_ids_are_detectable_before_db_apply() {
    let nft_id = hash_from_seed(32);
    let first = NftMintTx::from_content_bytes(
        nft_id,
        "first".to_string(),
        "first".to_string(),
        b"first content",
    );
    let second = NftMintTx::from_content_bytes(
        nft_id,
        "second".to_string(),
        "second".to_string(),
        b"second content",
    );

    let mut seen = BTreeSet::new();
    let inserted_first = seen.insert(first.nft_id);
    let inserted_second = seen.insert(second.nft_id);

    assert!(inserted_first);
    assert!(!inserted_second);
    assert_ne!(first.content_hash, second.content_hash);
}

#[test]
fn test_33_adversarial_duplicate_transfer_replay_serializes_identically() -> TestResult {
    let transfer = NftTransferTx {
        nft_id: hash_from_seed(33),
        new_owner_wallet: wallet_from_seed(3_333),
    };

    let first_wire = postcard::to_stdvec(&transfer)?;
    let second_wire = postcard::to_stdvec(&transfer)?;

    assert_eq!(first_wire, second_wire);
    Ok(())
}

#[test]
fn test_34_adversarial_truncated_mint_json_is_rejected() -> TestResult {
    let tx = make_mint(34, b"truncate me");
    let mut encoded = serde_json::to_string(&tx)?;
    let removed = encoded.pop();

    assert!(removed.is_some());
    assert!(serde_json::from_str::<NftMintTx>(&encoded).is_err());
    Ok(())
}

#[test]
fn test_35_adversarial_truncated_transfer_json_is_rejected() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(35),
        new_owner_wallet: wallet_from_seed(3_535),
    };

    let mut encoded = serde_json::to_string(&tx)?;
    let removed = encoded.pop();

    assert!(removed.is_some());
    assert!(serde_json::from_str::<NftTransferTx>(&encoded).is_err());
    Ok(())
}

#[test]
fn test_36_adversarial_mutated_content_hash_changes_mint_identity() {
    let original = make_mint(36, b"mutation target");
    let mut mutated = original.clone();

    if let Some(byte) = mutated.content_hash.first_mut() {
        *byte ^= 0b0000_0001;
    }

    assert_ne!(original, mutated);
    assert_eq!(original.nft_id, mutated.nft_id);
    assert_eq!(original.title, mutated.title);
    assert_eq!(original.description, mutated.description);
}

#[test]
fn test_37_adversarial_network_reordering_keeps_latest_simulated_owner() {
    let nft_id = hash_from_seed(37);
    let owner_a = wallet_from_seed(3_700);
    let owner_b = wallet_from_seed(3_701);
    let owner_c = wallet_from_seed(3_702);

    let transfers = vec![
        NftTransferTx {
            nft_id,
            new_owner_wallet: owner_b.clone(),
        },
        NftTransferTx {
            nft_id,
            new_owner_wallet: owner_c.clone(),
        },
    ];

    let mut simulated_owners = BTreeMap::new();
    simulated_owners.insert(nft_id, owner_a);

    for transfer in transfers {
        simulated_owners.insert(transfer.nft_id, transfer.new_owner_wallet);
    }

    assert_eq!(simulated_owners.get(&nft_id), Some(&owner_c));
}

#[test]
fn test_38_adversarial_large_description_payload_roundtrip() -> TestResult {
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(38),
        "large adversarial description".to_string(),
        "metadata ".repeat(32_768),
        b"large description payload",
    );

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_39_load_generate_two_thousand_mints_with_unique_ids() {
    let mut seen_ids = BTreeSet::new();

    for seed in 1_000u64..3_000u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(96);
        let tx = make_mint(seed, &content);
        let inserted = seen_ids.insert(tx.nft_id);

        assert!(inserted);
        assert_eq!(tx.content_hash, manual_content_hash(&content));
    }

    assert_eq!(seen_ids.len(), 2_000);
}

#[test]
fn test_40_load_one_thousand_json_roundtrips_for_mint_transfer_and_record() -> TestResult {
    for seed in 4_000u64..5_000u64 {
        let mut rng = DeterministicRng::new(seed);
        let content = rng.bytes(128);

        let mint = make_mint(seed, &content);
        let transfer = NftTransferTx {
            nft_id: mint.nft_id,
            new_owner_wallet: wallet_from_seed(seed.wrapping_add(10_000)),
        };
        let record = make_record(seed);

        let mint_encoded = serde_json::to_vec(&mint)?;
        let transfer_encoded = serde_json::to_vec(&transfer)?;
        let record_encoded = serde_json::to_vec(&record)?;

        let mint_decoded: NftMintTx = serde_json::from_slice(&mint_encoded)?;
        let transfer_decoded: NftTransferTx = serde_json::from_slice(&transfer_encoded)?;
        let record_decoded: NftRecord = serde_json::from_slice(&record_encoded)?;

        assert_eq!(mint_decoded, mint);
        assert_eq!(transfer_decoded, transfer);
        assert_eq!(record_decoded.nft_id, record.nft_id);
        assert_eq!(record_decoded.content_hash, record.content_hash);
    }

    Ok(())
}

#[test]
fn test_41_mint_json_contains_expected_top_level_fields() -> TestResult {
    let tx = make_mint(41, b"field check");
    let value: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&tx)?)?;
    let object = value
        .as_object()
        .ok_or_else(|| std::io::Error::other("mint json must be an object"))?;

    assert!(object.contains_key("nft_id"));
    assert!(object.contains_key("content_hash"));
    assert!(object.contains_key("title"));
    assert!(object.contains_key("description"));
    assert_eq!(object.len(), 4);
    Ok(())
}

#[test]
fn test_42_transfer_json_contains_expected_top_level_fields() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(42),
        new_owner_wallet: wallet_from_seed(4_242),
    };

    let value: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&tx)?)?;
    let object = value
        .as_object()
        .ok_or_else(|| std::io::Error::other("transfer json must be an object"))?;

    assert!(object.contains_key("nft_id"));
    assert!(object.contains_key("new_owner_wallet"));
    assert_eq!(object.len(), 2);
    Ok(())
}

#[test]
fn test_43_record_json_contains_expected_top_level_fields() -> TestResult {
    let record = make_record(43);
    let value: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&record)?)?;
    let object = value
        .as_object()
        .ok_or_else(|| std::io::Error::other("record json must be an object"))?;

    assert!(object.contains_key("nft_id"));
    assert!(object.contains_key("creator_wallet"));
    assert!(object.contains_key("owner_wallet"));
    assert!(object.contains_key("content_hash"));
    assert!(object.contains_key("title"));
    assert!(object.contains_key("description"));
    assert!(object.contains_key("minted_height"));
    assert!(object.contains_key("minted_time"));
    assert_eq!(object.len(), 8);
    Ok(())
}

#[test]
fn test_44_deserialize_mint_rejects_missing_title() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"content_hash":{arr64},"description":"missing title"}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_45_deserialize_mint_rejects_missing_nft_id() {
    let arr64 = json_array_len(64, "1");
    let json = format!(r#"{{"content_hash":{arr64},"title":"missing id","description":"bad"}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_46_deserialize_mint_rejects_missing_content_hash() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"title":"missing content hash","description":"bad"}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_47_deserialize_transfer_rejects_missing_new_owner_wallet() {
    let arr64 = json_array_len(64, "1");
    let json = format!(r#"{{"nft_id":{arr64}}}"#);

    let parsed = serde_json::from_str::<NftTransferTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_48_deserialize_record_rejects_missing_minted_time() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{arr64},
            "title":"bad record",
            "description":"missing minted time",
            "minted_height":1
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_49_deserialize_record_rejects_string_content_hash() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":"not-an-array",
            "title":"bad record",
            "description":"bad content hash",
            "minted_height":1,
            "minted_time":2
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_50_deserialize_record_rejects_hash_byte_above_u8_max() {
    let bad_arr = json_array_len(64, "256");
    let good_arr = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{bad_arr},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{good_arr},
            "title":"bad record",
            "description":"bad nft id byte",
            "minted_height":1,
            "minted_time":2
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_51_deserialize_mint_accepts_exactly_64_max_u8_hash_values() -> TestResult {
    let max_arr = json_array_len(64, "255");
    let json = format!(
        r#"{{"nft_id":{max_arr},"content_hash":{max_arr},"title":"max","description":"max bytes"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json)?;

    assert!(parsed.nft_id.iter().all(|byte| *byte == u8::MAX));
    assert!(parsed.content_hash.iter().all(|byte| *byte == u8::MAX));
    Ok(())
}

#[test]
fn test_52_hash_from_seed_is_deterministic_for_same_seed() {
    let left = hash_from_seed(52);
    let right = hash_from_seed(52);

    assert_eq!(left, right);
}

#[test]
fn test_53_hash_from_seed_differs_for_adjacent_seeds() {
    let left = hash_from_seed(53);
    let right = hash_from_seed(54);

    assert_ne!(left, right);
}

#[test]
fn test_54_single_bit_content_change_changes_content_hash() {
    let left = make_mint(54, b"bit flip target");
    let right = make_mint(54, b"cit flip target");

    assert_eq!(left.nft_id, right.nft_id);
    assert_ne!(left.content_hash, right.content_hash);
}

#[test]
fn test_55_appending_zero_byte_changes_content_hash() {
    let left = make_mint(55, b"append zero");
    let right = make_mint(55, b"append zero\0");

    assert_eq!(left.nft_id, right.nft_id);
    assert_ne!(left.content_hash, right.content_hash);
}

#[test]
fn test_56_binary_content_with_embedded_zeroes_hashes_correctly() {
    let content = [0u8, 1, 0, 2, 0, 3, 0, 4, 255, 0];
    let tx = make_mint(56, &content);

    assert_eq!(tx.content_hash, manual_content_hash(&content));
}

#[test]
fn test_57_transfer_owner_change_changes_serialized_json() -> TestResult {
    let nft_id = hash_from_seed(57);
    let first = NftTransferTx {
        nft_id,
        new_owner_wallet: wallet_from_seed(5_701),
    };
    let second = NftTransferTx {
        nft_id,
        new_owner_wallet: wallet_from_seed(5_702),
    };

    let first_json = serde_json::to_vec(&first)?;
    let second_json = serde_json::to_vec(&second)?;

    assert_ne!(first, second);
    assert_ne!(first_json, second_json);
    Ok(())
}

#[test]
fn test_58_empty_transfer_owner_wallet_roundtrips_as_payload_data() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(58),
        new_owner_wallet: String::new(),
    };

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftTransferTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded, tx);
    assert_eq!(decoded.new_owner_wallet, "");
    Ok(())
}

#[test]
fn test_59_transfer_owner_wallet_whitespace_is_preserved_exactly() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(59),
        new_owner_wallet: "  owner with spaces  ".to_string(),
    };

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftTransferTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.new_owner_wallet, "  owner with spaces  ");
    Ok(())
}

#[test]
fn test_60_record_zero_height_and_zero_time_roundtrip() -> TestResult {
    let record = NftRecord {
        nft_id: hash_from_seed(60),
        creator_wallet: wallet_from_seed(6_001),
        owner_wallet: wallet_from_seed(6_002),
        content_hash: hash_from_seed(6_003),
        title: "zero time".to_string(),
        description: "zero boundary".to_string(),
        minted_height: 0,
        minted_time: 0,
    };

    let encoded = serde_json::to_vec(&record)?;
    let decoded: NftRecord = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.minted_height, 0);
    assert_eq!(decoded.minted_time, 0);
    assert_eq!(decoded.nft_id, record.nft_id);
    Ok(())
}

#[test]
fn test_61_adversarial_simulated_owner_chain_accepts_current_owner_only() {
    let nft_id = hash_from_seed(61);
    let owner_a = wallet_from_seed(6_100);
    let owner_b = wallet_from_seed(6_101);
    let owner_c = wallet_from_seed(6_102);

    let mut current_owner = owner_a.clone();

    let signer_one = owner_a.clone();
    let transfer_one = NftTransferTx {
        nft_id,
        new_owner_wallet: owner_b.clone(),
    };

    if current_owner == signer_one && !transfer_one.new_owner_wallet.trim().is_empty() {
        current_owner = transfer_one.new_owner_wallet;
    }

    let signer_two = owner_b;
    let transfer_two = NftTransferTx {
        nft_id,
        new_owner_wallet: owner_c.clone(),
    };

    if current_owner == signer_two && !transfer_two.new_owner_wallet.trim().is_empty() {
        current_owner = transfer_two.new_owner_wallet;
    }

    assert_eq!(current_owner, owner_c);
}

#[test]
fn test_62_adversarial_simulated_stale_owner_transfer_is_denied() {
    let nft_id = hash_from_seed(62);
    let owner_a = wallet_from_seed(6_200);
    let owner_b = wallet_from_seed(6_201);
    let attacker = wallet_from_seed(6_202);

    let current_owner = owner_b.clone();
    let stale_signer = owner_a;
    let transfer = NftTransferTx {
        nft_id,
        new_owner_wallet: attacker,
    };

    let accepted = current_owner == stale_signer && !transfer.new_owner_wallet.trim().is_empty();

    assert!(!accepted);
    assert_eq!(current_owner, owner_b);
}

#[test]
fn test_63_adversarial_simulated_empty_owner_transfer_is_denied() {
    let nft_id = hash_from_seed(63);
    let owner = wallet_from_seed(6_300);
    let transfer = NftTransferTx {
        nft_id,
        new_owner_wallet: String::new(),
    };

    let accepted = owner == owner && !transfer.new_owner_wallet.trim().is_empty();

    assert!(!accepted);
}

#[test]
fn test_64_property_small_content_lengths_produce_unique_hashes() {
    let mut seen = BTreeSet::new();

    for len in 0usize..128usize {
        let content = vec![42u8; len];
        let tx = make_mint(64, &content);
        let inserted = seen.insert(tx.content_hash);

        assert!(inserted);
    }

    assert_eq!(seen.len(), 128);
}

#[test]
fn test_65_property_repeated_content_byte_values_produce_unique_hashes() {
    let mut seen = BTreeSet::new();

    for byte in u8::MIN..=u8::MAX {
        let content = vec![byte; 32];
        let tx = make_mint(u64::from(byte).wrapping_add(65), &content);
        let inserted = seen.insert(tx.content_hash);

        assert!(inserted);
    }

    assert_eq!(seen.len(), 256);
}

#[test]
fn test_66_postcard_transfer_roundtrip_preserves_all_fields() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(66),
        new_owner_wallet: wallet_from_seed(6_666),
    };

    let encoded = postcard::to_stdvec(&tx)?;
    let decoded: NftTransferTx = postcard::from_bytes(&encoded)?;

    assert_eq!(decoded, tx);
    Ok(())
}

#[test]
fn test_67_postcard_record_roundtrip_preserves_all_fields() -> TestResult {
    let record = make_record(67);
    let encoded = postcard::to_stdvec(&record)?;
    let decoded: NftRecord = postcard::from_bytes(&encoded)?;

    assert_eq!(decoded.nft_id, record.nft_id);
    assert_eq!(decoded.creator_wallet, record.creator_wallet);
    assert_eq!(decoded.owner_wallet, record.owner_wallet);
    assert_eq!(decoded.content_hash, record.content_hash);
    assert_eq!(decoded.title, record.title);
    assert_eq!(decoded.description, record.description);
    assert_eq!(decoded.minted_height, record.minted_height);
    assert_eq!(decoded.minted_time, record.minted_time);
    Ok(())
}

#[test]
fn test_68_postcard_truncated_mint_payload_is_rejected() -> TestResult {
    let tx = make_mint(68, b"postcard truncate");
    let mut encoded = postcard::to_stdvec(&tx)?;
    let removed = encoded.pop();

    assert!(removed.is_some());
    assert!(postcard::from_bytes::<NftMintTx>(&encoded).is_err());
    Ok(())
}

#[test]
fn test_69_postcard_truncated_transfer_payload_is_rejected() -> TestResult {
    let tx = NftTransferTx {
        nft_id: hash_from_seed(69),
        new_owner_wallet: wallet_from_seed(6_969),
    };

    let mut encoded = postcard::to_stdvec(&tx)?;
    let removed = encoded.pop();

    assert!(removed.is_some());
    assert!(postcard::from_bytes::<NftTransferTx>(&encoded).is_err());
    Ok(())
}

#[test]
fn test_70_deserialize_mint_rejects_number_title() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"content_hash":{arr64},"title":123,"description":"bad"}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_71_deserialize_mint_rejects_boolean_description() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"content_hash":{arr64},"title":"bad","description":true}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_72_deserialize_record_rejects_string_minted_height() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{arr64},
            "title":"bad record",
            "description":"bad height",
            "minted_height":"1",
            "minted_time":2
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);
    assert!(parsed.is_err());
}

#[test]
fn test_73_record_special_characters_roundtrip() -> TestResult {
    let record = NftRecord {
        nft_id: hash_from_seed(73),
        creator_wallet: wallet_from_seed(7_300),
        owner_wallet: wallet_from_seed(7_301),
        content_hash: hash_from_seed(7_302),
        title: "quotes \" slash \\ newline \n tab \t".to_string(),
        description: "emoji 🧪 unicode Καλημέρα null-like text \\u0000".to_string(),
        minted_height: 73,
        minted_time: 7_373,
    };

    let encoded = serde_json::to_vec(&record)?;
    let decoded: NftRecord = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.title, record.title);
    assert_eq!(decoded.description, record.description);
    Ok(())
}

#[test]
fn test_74_actual_null_character_in_strings_roundtrips() -> TestResult {
    let tx = NftMintTx::from_content_bytes(
        hash_from_seed(74),
        "title\0with\0nulls".to_string(),
        "description\0with\0nulls".to_string(),
        b"null char string payload",
    );

    let encoded = serde_json::to_vec(&tx)?;
    let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

    assert_eq!(decoded.title, "title\0with\0nulls");
    assert_eq!(decoded.description, "description\0with\0nulls");
    Ok(())
}

#[test]
fn test_75_load_one_mebibyte_content_hash_matches_manual_blake3_xof() {
    let mut rng = DeterministicRng::new(75);
    let content = rng.bytes(1_048_576);
    let tx = make_mint(75, &content);

    assert_eq!(tx.content_hash, manual_content_hash(&content));
}

#[test]
fn test_76_clone_mint_then_mutate_title_keeps_original_unchanged() {
    let original = make_mint(76, b"clone mint");
    let mut cloned = original.clone();
    cloned.title = "mutated title".to_string();

    assert_ne!(original.title, cloned.title);
    assert_eq!(original.nft_id, cloned.nft_id);
    assert_eq!(original.content_hash, cloned.content_hash);
    assert_eq!(original.description, cloned.description);
}

#[test]
fn test_77_clone_transfer_then_mutate_owner_keeps_original_unchanged() {
    let original = NftTransferTx {
        nft_id: hash_from_seed(77),
        new_owner_wallet: wallet_from_seed(7_700),
    };

    let mut cloned = original.clone();
    cloned.new_owner_wallet = wallet_from_seed(7_701);

    assert_ne!(original.new_owner_wallet, cloned.new_owner_wallet);
    assert_eq!(original.nft_id, cloned.nft_id);
}

#[test]
fn test_78_hashes_can_be_used_as_deterministic_btree_keys() {
    let mut map = BTreeMap::new();

    for seed in 7_800u64..7_900u64 {
        let key = hash_from_seed(seed);
        let previous = map.insert(key, seed);

        assert!(previous.is_none());
    }

    assert_eq!(map.len(), 100);
}

#[test]
fn test_79_adversarial_out_of_order_mints_are_detected_by_id_set() {
    let nft_a = hash_from_seed(79);
    let nft_b = hash_from_seed(80);

    let arrival_order = vec![
        NftMintTx::from_content_bytes(nft_b, "B".to_string(), "second first".to_string(), b"b"),
        NftMintTx::from_content_bytes(nft_a, "A".to_string(), "first second".to_string(), b"a"),
        NftMintTx::from_content_bytes(
            nft_b,
            "B replay".to_string(),
            "duplicate".to_string(),
            b"b2",
        ),
    ];

    let mut seen = BTreeSet::new();
    let mut duplicate_count = 0usize;

    for tx in arrival_order {
        if !seen.insert(tx.nft_id) {
            duplicate_count = duplicate_count.saturating_add(1);
        }
    }

    assert_eq!(seen.len(), 2);
    assert_eq!(duplicate_count, 1);
}

#[test]
fn test_80_concurrent_load_generates_unique_mint_ids() {
    let seen = std::sync::Arc::new(parking_lot::Mutex::new(BTreeSet::new()));
    let mut handles = Vec::new();

    for worker in 0u64..8u64 {
        let seen_clone = std::sync::Arc::clone(&seen);
        let handle = std::thread::spawn(move || {
            for offset in 0u64..128u64 {
                let seed = 80_000u64
                    .wrapping_add(worker.wrapping_mul(1_000))
                    .wrapping_add(offset);
                let mut rng = DeterministicRng::new(seed);
                let content = rng.bytes(64);
                let tx = make_mint(seed, &content);

                let mut guard = seen_clone.lock();
                let inserted = guard.insert(tx.nft_id);
                assert!(inserted);
                assert_eq!(tx.content_hash, manual_content_hash(&content));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
    }

    let guard = seen.lock();
    assert_eq!(guard.len(), 1_024);
}

#[test]
fn test_81_vector_empty_content_xof_first_32_matches_blake3_default_hash() {
    let content = b"";
    let tx = make_mint(81, content);
    let reference = blake3::hash(content);

    assert_eq!(
        tx.content_hash.get(..32),
        Some(reference.as_bytes().as_slice())
    );
}

#[test]
fn test_82_vector_abc_content_xof_first_32_matches_blake3_default_hash() {
    let content = b"abc";
    let tx = make_mint(82, content);
    let reference = blake3::hash(content);

    assert_eq!(
        tx.content_hash.get(..32),
        Some(reference.as_bytes().as_slice())
    );
}

#[test]
fn test_83_vector_sentence_content_xof_first_32_matches_blake3_default_hash() {
    let content = b"The quick brown fox jumps over the lazy dog";
    let tx = make_mint(83, content);
    let reference = blake3::hash(content);

    assert_eq!(
        tx.content_hash.get(..32),
        Some(reference.as_bytes().as_slice())
    );
}

#[test]
fn test_84_vector_empty_and_single_zero_byte_have_different_hashes() {
    let empty = make_mint(84, b"");
    let zero = make_mint(84, &[0u8]);

    assert_ne!(empty.content_hash, zero.content_hash);
}

#[test]
fn test_85_vector_binary_zero_and_ascii_zero_have_different_hashes() {
    let binary_zero = make_mint(85, &[0u8]);
    let ascii_zero = make_mint(85, b"0");

    assert_ne!(binary_zero.content_hash, ascii_zero.content_hash);
}

#[test]
fn test_86_vector_explicit_nft_ids_are_preserved_exactly() -> TestResult {
    let cases: Vec<(Hash, &str)> = vec![
        ([0u8; 64], "zero id"),
        ([u8::MAX; 64], "max id"),
        (hash_from_seed(8_600), "seeded id"),
    ];

    for (nft_id, title) in cases {
        let tx = NftMintTx::from_content_bytes(
            nft_id,
            title.to_string(),
            "explicit id vector".to_string(),
            b"explicit id content",
        );

        let encoded = serde_json::to_vec(&tx)?;
        let decoded: NftMintTx = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded.nft_id, nft_id);
        assert_eq!(decoded.title, title);
    }

    Ok(())
}

#[test]
fn test_87_edge_mint_json_with_unknown_extra_field_is_accepted_by_default_serde() -> TestResult {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "content_hash":{arr64},
            "title":"extra field",
            "description":"serde ignores unknown fields by default",
            "unexpected_field":"ignored"
        }}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json)?;

    assert_eq!(parsed.title, "extra field");
    assert_eq!(
        parsed.description,
        "serde ignores unknown fields by default"
    );
    Ok(())
}

#[test]
fn test_88_edge_record_json_with_unknown_extra_field_is_accepted_by_default_serde() -> TestResult {
    let arr64 = json_array_len(64, "2");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{arr64},
            "title":"record extra field",
            "description":"unknown field ignored",
            "minted_height":88,
            "minted_time":8800,
            "unexpected_record_field":123
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json)?;

    assert_eq!(parsed.title, "record extra field");
    assert_eq!(parsed.minted_height, 88);
    assert_eq!(parsed.minted_time, 8_800);
    Ok(())
}

#[test]
fn test_89_edge_mint_rejects_null_title() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"content_hash":{arr64},"title":null,"description":"bad"}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_90_edge_mint_rejects_null_description() {
    let arr64 = json_array_len(64, "1");
    let json =
        format!(r#"{{"nft_id":{arr64},"content_hash":{arr64},"title":"bad","description":null}}"#);

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_91_edge_transfer_rejects_null_new_owner_wallet() {
    let arr64 = json_array_len(64, "1");
    let json = format!(r#"{{"nft_id":{arr64},"new_owner_wallet":null}}"#);

    let parsed = serde_json::from_str::<NftTransferTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_92_edge_record_rejects_negative_minted_height() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{arr64},
            "title":"bad height",
            "description":"negative height",
            "minted_height":-1,
            "minted_time":1
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_93_edge_record_rejects_u64_overflow_minted_time() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "creator_wallet":"creator",
            "owner_wallet":"owner",
            "content_hash":{arr64},
            "title":"bad time",
            "description":"overflow time",
            "minted_height":1,
            "minted_time":18446744073709551616
        }}"#
    );

    let parsed = serde_json::from_str::<NftRecord>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_94_edge_mint_rejects_float_hash_bytes() {
    let float_arr = json_array_len(64, "1.5");
    let good_arr = json_array_len(64, "1");
    let json = format!(
        r#"{{"nft_id":{float_arr},"content_hash":{good_arr},"title":"bad","description":"float bytes"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_95_edge_mint_rejects_negative_hash_bytes() {
    let negative_arr = json_array_len(64, "-1");
    let good_arr = json_array_len(64, "1");
    let json = format!(
        r#"{{"nft_id":{negative_arr},"content_hash":{good_arr},"title":"bad","description":"negative bytes"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_96_edge_mint_rejects_empty_content_hash_array() {
    let good_arr = json_array_len(64, "1");
    let json = format!(
        r#"{{"nft_id":{good_arr},"content_hash":[],"title":"bad","description":"empty content hash"}}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_97_edge_unicode_normalization_is_not_changed_by_roundtrip() -> TestResult {
    let composed = "é".to_string();
    let decomposed = "e\u{301}".to_string();

    let first = NftMintTx::from_content_bytes(
        hash_from_seed(97),
        composed.clone(),
        "unicode composed".to_string(),
        b"same content",
    );
    let second = NftMintTx::from_content_bytes(
        hash_from_seed(97),
        decomposed.clone(),
        "unicode decomposed".to_string(),
        b"same content",
    );

    let first_decoded: NftMintTx = serde_json::from_slice(&serde_json::to_vec(&first)?)?;
    let second_decoded: NftMintTx = serde_json::from_slice(&serde_json::to_vec(&second)?)?;

    assert_ne!(composed, decomposed);
    assert_eq!(first_decoded.title, composed);
    assert_eq!(second_decoded.title, decomposed);
    assert_eq!(first_decoded.content_hash, second_decoded.content_hash);
    Ok(())
}

#[test]
fn test_98_edge_record_all_empty_strings_roundtrip_as_payload_data() -> TestResult {
    let record = NftRecord {
        nft_id: hash_from_seed(98),
        creator_wallet: String::new(),
        owner_wallet: String::new(),
        content_hash: hash_from_seed(9_800),
        title: String::new(),
        description: String::new(),
        minted_height: 0,
        minted_time: 0,
    };

    let decoded: NftRecord = serde_json::from_slice(&serde_json::to_vec(&record)?)?;

    assert_eq!(decoded.creator_wallet, "");
    assert_eq!(decoded.owner_wallet, "");
    assert_eq!(decoded.title, "");
    assert_eq!(decoded.description, "");
    assert_eq!(decoded.minted_height, 0);
    assert_eq!(decoded.minted_time, 0);
    Ok(())
}

#[test]
fn test_99_edge_mint_rejects_duplicate_title_field() {
    let arr64 = json_array_len(64, "1");
    let json = format!(
        r#"{{
            "nft_id":{arr64},
            "content_hash":{arr64},
            "title":"first",
            "title":"second",
            "description":"duplicate title"
        }}"#
    );

    let parsed = serde_json::from_str::<NftMintTx>(&json);

    assert!(parsed.is_err());
}

#[test]
fn test_100_vector_multiple_content_sizes_match_blake3_default_hash_prefix() {
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8],
        vec![1u8; 31],
        vec![2u8; 32],
        vec![3u8; 33],
        vec![4u8; 64],
        vec![5u8; 255],
        vec![6u8; 256],
        vec![7u8; 1_024],
    ];

    for content in cases {
        let tx = make_mint(100, &content);
        let reference = blake3::hash(&content);

        assert_eq!(
            tx.content_hash.get(..32),
            Some(reference.as_bytes().as_slice())
        );
        assert_eq!(tx.content_hash, manual_content_hash(&content));
    }
}
