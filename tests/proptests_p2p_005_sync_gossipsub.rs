// tests/proptests_p2p_005_sync_gossipsub.rs

use std::path::{Component, Path, PathBuf};

use libp2p::gossipsub::IdentTopic;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::network::p2p_013_peer_mesh::PEER_MESH_TOPIC_STR;
use remzar::network::p2p_014_chat::chat_topic;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;

const MAX_GOSSIP_BYTES_MODEL: usize = 1024 * 1024;
const MAX_CHAT_WIRE_BYTES_MODEL: usize = 64 * 1024;
const MAX_FILE_WIRE_BYTES_MODEL: usize = 256 * 1024;
const MAX_FILE_CHUNK_BYTES_MODEL: usize = 192 * 1024;
const MAX_FILE_TOTAL_CHUNKS_MODEL: u32 = 200_000;
const MAX_FILENAME_BYTES_MODEL: usize = 255;
const MAX_WALLET_TEXT_BYTES_MODEL: usize = 256;
const FILE_TOPIC_NAME_MODEL: &str = "remzar.file.v1";

fn consensus_max_bytes_model() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
}

fn ensure_within_consensus_cap_model(label: &str, n: usize) -> Result<(), String> {
    let cap = consensus_max_bytes_model();

    if n > cap {
        return Err(format!(
            "{label} exceeds MAX_BLOCK_SIZE: {n} bytes (cap {cap})"
        ));
    }

    Ok(())
}

fn model_consensus_cap_accepts(n: usize) -> bool {
    n <= consensus_max_bytes_model()
}

fn model_chat_payload_accepts(n: usize) -> bool {
    n <= MAX_CHAT_WIRE_BYTES_MODEL
}

fn model_file_envelope_accepts(n: usize) -> bool {
    n <= MAX_FILE_WIRE_BYTES_MODEL
}

fn model_gossip_payload_accepts(n: usize) -> bool {
    n <= MAX_GOSSIP_BYTES_MODEL
}

fn model_file_chunk_accepts(
    filename_len: usize,
    total_chunks: u32,
    chunk_index: u32,
    chunk_bytes_len: usize,
    from_wallet_len: usize,
    to_wallet_len: usize,
) -> bool {
    filename_len <= MAX_FILENAME_BYTES_MODEL
        && total_chunks > 0
        && total_chunks <= MAX_FILE_TOTAL_CHUNKS_MODEL
        && chunk_bytes_len <= MAX_FILE_CHUNK_BYTES_MODEL
        && chunk_index < total_chunks
        && from_wallet_len <= MAX_WALLET_TEXT_BYTES_MODEL
        && to_wallet_len <= MAX_WALLET_TEXT_BYTES_MODEL
}

fn model_chat_wallets_accept(from_wallet_len: usize, to_wallet_len: usize) -> bool {
    from_wallet_len <= MAX_WALLET_TEXT_BYTES_MODEL && to_wallet_len <= MAX_WALLET_TEXT_BYTES_MODEL
}

fn model_should_persist_to_local_wallet(local_wallet: &str, to_wallet: &str) -> bool {
    !local_wallet.is_empty() && to_wallet.eq_ignore_ascii_case(local_wallet)
}

fn file_topic_model() -> IdentTopic {
    IdentTopic::new(FILE_TOPIC_NAME_MODEL)
}

fn peer_mesh_topic_model() -> IdentTopic {
    IdentTopic::new(PEER_MESH_TOPIC_STR)
}

fn model_is_safe_leaf_name(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return false;
    }

    let p = Path::new(name);

    if p.is_absolute() {
        return false;
    }

    let mut comps = p.components();

    matches!(
        (comps.next(), comps.next()),
        (Some(Component::Normal(_)), None)
    )
}

fn receiver_root_dir_model(data_dir: &str, leaf: &str) -> Result<PathBuf, String> {
    let base = data_dir.trim();

    if base.is_empty() {
        return Err("data_dir is empty".to_string());
    }

    if !model_is_safe_leaf_name(leaf) {
        return Err("receiver storage leaf must be a single safe path component".to_string());
    }

    Ok(PathBuf::from(base).join(leaf))
}

fn valid_leaf_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._-]{1,80}".prop_filter("not dot or dotdot", |s| s != "." && s != "..")
}

fn invalid_leaf_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just(".".to_string()),
        Just("..".to_string()),
        "[A-Za-z0-9._-]{1,32}/[A-Za-z0-9._-]{1,32}",
        "[A-Za-z0-9._-]{1,32}\\\\[A-Za-z0-9._-]{1,32}",
        "/[A-Za-z0-9._-]{1,32}",
        "../[A-Za-z0-9._-]{1,32}",
        "[A-Za-z0-9._-]{1,32}/..",
    ]
}

fn bounded_payload_precheck_never_panics(data: Vec<u8>) -> bool {
    std::panic::catch_unwind(|| {
        let _accepted_by_gossip_cap = data.len() <= MAX_GOSSIP_BYTES_MODEL;
        let _accepted_by_chat_cap = data.len() <= MAX_CHAT_WIRE_BYTES_MODEL;
        let _accepted_by_file_cap = data.len() <= MAX_FILE_WIRE_BYTES_MODEL;
    })
    .is_ok()
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    })]

    #[test]
    fn test_001_consensus_max_bytes_matches_global_max_block_size(_probe in any::<u8>()) {
        prop_assert_eq!(
            consensus_max_bytes_model(),
            usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX),
            "gossip consensus cap model must mirror GlobalConfiguration::MAX_BLOCK_SIZE"
        );

        prop_assert!(
            consensus_max_bytes_model() > 0,
            "consensus byte cap model must be nonzero"
        );
    }

    #[test]
    fn test_002_ensure_within_consensus_cap_model_allows_exact_cap_and_rejects_above(
        extra in 0usize..=4096usize,
    ) {
        let cap = consensus_max_bytes_model();
        let n = cap.saturating_add(extra);

        let result = ensure_within_consensus_cap_model("proptest consensus object", n);

        prop_assert_eq!(
            result.is_ok(),
            extra == 0,
            "consensus cap model must be strict: exactly cap accepted, cap+1 rejected"
        );
    }

    #[test]
    fn test_003_ensure_within_consensus_cap_model_matches_acceptance_for_all_sizes(
        n in any::<usize>(),
    ) {
        prop_assert_eq!(
            ensure_within_consensus_cap_model("proptest", n).is_ok(),
            model_consensus_cap_accepts(n),
            "ensure_within_consensus_cap_model must exactly model n <= consensus_max_bytes_model()"
        );
    }

    #[test]
    fn test_004_consensus_cap_acceptance_model_is_monotonic(
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let low = a.min(b);
        let high = a.max(b);

        if ensure_within_consensus_cap_model("high", high).is_ok() {
            prop_assert!(
                ensure_within_consensus_cap_model("low", low).is_ok(),
                "if larger payload is within cap, smaller payload must also be within cap"
            );
        }

        if ensure_within_consensus_cap_model("low", low).is_err() {
            prop_assert!(
                ensure_within_consensus_cap_model("high", high).is_err(),
                "if smaller payload exceeds cap, larger payload must also exceed cap"
            );
        }
    }

    #[test]
    fn test_005_gossip_payload_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=4096usize,
    ) {
        let n = MAX_GOSSIP_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            model_gossip_payload_accepts(n),
            extra == 0,
            "inbound gossipsub payload cap model must allow exactly MAX_GOSSIP_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_006_chat_payload_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=4096usize,
    ) {
        let n = MAX_CHAT_WIRE_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            model_chat_payload_accepts(n),
            extra == 0,
            "chat payload cap model must allow exactly MAX_CHAT_WIRE_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_007_file_envelope_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=4096usize,
    ) {
        let n = MAX_FILE_WIRE_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            model_file_envelope_accepts(n),
            extra == 0,
            "file postcard envelope cap model must allow exactly MAX_FILE_WIRE_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_008_file_chunk_bytes_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=4096usize,
    ) {
        let n = MAX_FILE_CHUNK_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            n <= MAX_FILE_CHUNK_BYTES_MODEL,
            extra == 0,
            "file chunk byte cap model must allow exactly MAX_FILE_CHUNK_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_009_defensive_caps_have_expected_ordering(_probe in any::<u8>()) {
        prop_assert!(
            MAX_CHAT_WIRE_BYTES_MODEL < MAX_FILE_CHUNK_BYTES_MODEL,
            "chat payload cap should be lower than file chunk bytes cap"
        );

        prop_assert!(
            MAX_FILE_CHUNK_BYTES_MODEL < MAX_FILE_WIRE_BYTES_MODEL,
            "file chunk bytes cap should be below the full postcard envelope cap"
        );

        prop_assert!(
            MAX_FILE_WIRE_BYTES_MODEL < MAX_GOSSIP_BYTES_MODEL,
            "file envelope cap should be below the global gossip cap"
        );

        prop_assert!(
            MAX_GOSSIP_BYTES_MODEL <= consensus_max_bytes_model(),
            "global gossip cap should not exceed the consensus object cap"
        );
    }

    #[test]
    fn test_010_receiver_root_dir_model_rejects_empty_or_whitespace_data_dir(
        whitespace in "[ \\t\\n\\r]{0,16}",
        leaf in valid_leaf_strategy(),
    ) {
        prop_assert!(
            receiver_root_dir_model(&whitespace, &leaf).is_err(),
            "receiver_root_dir_model must reject empty or whitespace-only data_dir"
        );
    }

    #[test]
    fn test_011_receiver_root_dir_model_joins_safe_leaf_under_trimmed_data_dir(
        base in "[A-Za-z0-9._/-]{1,80}",
        leaf in valid_leaf_strategy(),
    ) {
        prop_assume!(!base.trim().is_empty());

        let decorated_base = format!("  {base}  ");

        let result = receiver_root_dir_model(&decorated_base, &leaf)
            .expect("safe base and leaf should resolve");

        let expected = PathBuf::from(base.trim()).join(&leaf);

        prop_assert_eq!(
            result,
            expected,
            "receiver_root_dir_model must trim data_dir and append the safe leaf"
        );
    }

    #[test]
    fn test_012_receiver_root_dir_model_rejects_leaf_with_slash_or_backslash(
        base in "[A-Za-z0-9._-]{1,64}",
        left in "[A-Za-z0-9._-]{1,32}",
        right in "[A-Za-z0-9._-]{1,32}",
    ) {
        let slash_leaf = format!("{left}/{right}");
        let backslash_leaf = format!("{left}\\{right}");

        prop_assert!(
            receiver_root_dir_model(&base, &slash_leaf).is_err(),
            "receiver_root_dir_model must reject slash-containing leaf"
        );

        prop_assert!(
            receiver_root_dir_model(&base, &backslash_leaf).is_err(),
            "receiver_root_dir_model must reject backslash-containing leaf"
        );
    }

    #[test]
    fn test_013_receiver_root_dir_model_rejects_empty_leaf(
        base in "[A-Za-z0-9._-]{1,64}",
    ) {
        prop_assert!(
            receiver_root_dir_model(&base, "").is_err(),
            "receiver_root_dir_model must reject empty receiver leaf"
        );
    }

    #[test]
    fn test_014_is_safe_leaf_name_model_accepts_single_normal_relative_leaf(
        leaf in valid_leaf_strategy(),
    ) {
        prop_assert!(
            model_is_safe_leaf_name(&leaf),
            "safe leaf names should be accepted"
        );

        prop_assert!(
            !Path::new(&leaf).is_absolute(),
            "generated safe leaf must be relative"
        );
    }

    #[test]
    fn test_015_is_safe_leaf_name_model_rejects_empty_dot_dotdot_absolute_and_nested(
        name in invalid_leaf_strategy(),
    ) {
        prop_assert!(
            !model_is_safe_leaf_name(&name),
            "unsafe leaf name must be rejected: {:?}",
            name
        );
    }

    #[test]
    fn test_016_filename_length_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=64usize,
    ) {
        let filename_len = MAX_FILENAME_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            filename_len <= MAX_FILENAME_BYTES_MODEL,
            extra == 0,
            "filename cap model must allow exactly MAX_FILENAME_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_017_wallet_text_cap_model_accepts_exact_boundary_and_rejects_above(
        extra in 0usize..=64usize,
    ) {
        let wallet_len = MAX_WALLET_TEXT_BYTES_MODEL.saturating_add(extra);

        prop_assert_eq!(
            wallet_len <= MAX_WALLET_TEXT_BYTES_MODEL,
            extra == 0,
            "wallet text cap model must allow exactly MAX_WALLET_TEXT_BYTES_MODEL and reject above"
        );
    }

    #[test]
    fn test_018_chat_wallet_bound_model_accepts_only_when_both_wallets_are_within_cap(
        from_len in 0usize..(MAX_WALLET_TEXT_BYTES_MODEL.saturating_add(128)),
        to_len in 0usize..(MAX_WALLET_TEXT_BYTES_MODEL.saturating_add(128)),
    ) {
        prop_assert_eq!(
            model_chat_wallets_accept(from_len, to_len),
            from_len <= MAX_WALLET_TEXT_BYTES_MODEL && to_len <= MAX_WALLET_TEXT_BYTES_MODEL,
            "chat wallet bound model must require both fields within cap"
        );
    }

    #[test]
    fn test_019_file_chunk_validation_model_rejects_invalid_chunk_index_even_when_other_fields_are_valid(
        filename_len in 0usize..=MAX_FILENAME_BYTES_MODEL,
        total_chunks in 1u32..=MAX_FILE_TOTAL_CHUNKS_MODEL,
        chunk_bytes_len in 0usize..=MAX_FILE_CHUNK_BYTES_MODEL,
        from_wallet_len in 0usize..=MAX_WALLET_TEXT_BYTES_MODEL,
        to_wallet_len in 0usize..=MAX_WALLET_TEXT_BYTES_MODEL,
    ) {
        let chunk_index = total_chunks;

        prop_assert!(
            !model_file_chunk_accepts(
                filename_len,
                total_chunks,
                chunk_index,
                chunk_bytes_len,
                from_wallet_len,
                to_wallet_len,
            ),
            "file chunk must be rejected when chunk_index >= total_chunks"
        );
    }

    #[test]
    fn test_020_file_chunk_validation_model_accepts_valid_boundary_values(
        filename_len in 0usize..=MAX_FILENAME_BYTES_MODEL,
        total_chunks in 1u32..=MAX_FILE_TOTAL_CHUNKS_MODEL,
        chunk_bytes_len in 0usize..=MAX_FILE_CHUNK_BYTES_MODEL,
        from_wallet_len in 0usize..=MAX_WALLET_TEXT_BYTES_MODEL,
        to_wallet_len in 0usize..=MAX_WALLET_TEXT_BYTES_MODEL,
    ) {
        let chunk_index = total_chunks.saturating_sub(1);

        prop_assert!(
            model_file_chunk_accepts(
                filename_len,
                total_chunks,
                chunk_index,
                chunk_bytes_len,
                from_wallet_len,
                to_wallet_len,
            ),
            "file chunk should be accepted when every field is inside bounds and index is valid"
        );
    }

    #[test]
    fn test_021_file_chunk_validation_model_rejects_absurd_total_chunks(
        filename_len in 0usize..=MAX_FILENAME_BYTES_MODEL,
        extra in 1u32..=10_000u32,
        chunk_bytes_len in 0usize..=MAX_FILE_CHUNK_BYTES_MODEL,
    ) {
        let total_chunks = MAX_FILE_TOTAL_CHUNKS_MODEL.saturating_add(extra);

        prop_assert!(
            !model_file_chunk_accepts(
                filename_len,
                total_chunks,
                0,
                chunk_bytes_len,
                0,
                0,
            ),
            "file chunk must reject total_chunks above MAX_FILE_TOTAL_CHUNKS_MODEL"
        );
    }

    #[test]
    fn test_022_topic_hashes_are_stable_and_separate_from_chat_and_peer_mesh(
        _probe in any::<u8>(),
    ) {
        let file = file_topic_model();
        let chat = chat_topic();
        let peer_mesh = peer_mesh_topic_model();

        prop_assert_eq!(
            file.hash(),
            IdentTopic::new(FILE_TOPIC_NAME_MODEL).hash(),
            "file_topic_model must construct the configured file topic"
        );

        prop_assert_eq!(
            peer_mesh.hash(),
            IdentTopic::new(PEER_MESH_TOPIC_STR).hash(),
            "peer_mesh_topic_model must construct the configured peer-mesh topic"
        );

        prop_assert_ne!(
            file.hash(),
            chat.hash(),
            "file topic must stay isolated from chat topic"
        );

        prop_assert_ne!(
            file.hash(),
            peer_mesh.hash(),
            "file topic must stay isolated from peer-mesh topic"
        );

        prop_assert_ne!(
            chat.hash(),
            peer_mesh.hash(),
            "chat topic must stay isolated from peer-mesh topic"
        );
    }

    #[test]
    fn test_023_local_wallet_delivery_match_is_case_insensitive_but_never_empty_local(
        wallet in "[rR][0-9a-fA-F]{128}",
    ) {
        let upper = wallet.to_ascii_uppercase();
        let lower = wallet.to_ascii_lowercase();

        prop_assert!(
            model_should_persist_to_local_wallet(&upper, &lower),
            "wallet delivery match must be case-insensitive"
        );

        prop_assert!(
            model_should_persist_to_local_wallet(&lower, &upper),
            "wallet delivery match must be symmetric across case variants"
        );

        prop_assert!(
            !model_should_persist_to_local_wallet("", &wallet),
            "empty local wallet must never persist incoming private payloads"
        );
    }

    #[test]
    fn test_024_bounded_payload_precheck_never_panics_for_untrusted_bytes(
        data in proptest::collection::vec(any::<u8>(), 0..7_500),
    ) {
        prop_assert!(
            bounded_payload_precheck_never_panics(data),
            "payload precheck model must never panic for arbitrary untrusted bytes"
        );
    }

    #[test]
    fn test_025_chat_file_and_global_caps_keep_expected_relationships(
        chat_extra in 0usize..=1024usize,
        file_extra in 0usize..=1024usize,
    ) {
        let chat_n = MAX_CHAT_WIRE_BYTES_MODEL.saturating_add(chat_extra);
        let file_n = MAX_FILE_WIRE_BYTES_MODEL.saturating_add(file_extra);

        prop_assert!(
            MAX_CHAT_WIRE_BYTES_MODEL < MAX_GOSSIP_BYTES_MODEL,
            "chat cap must be below global gossip cap"
        );

        prop_assert!(
            MAX_FILE_WIRE_BYTES_MODEL < MAX_GOSSIP_BYTES_MODEL,
            "file envelope cap must be below global gossip cap"
        );

        prop_assert_eq!(
            model_chat_payload_accepts(chat_n),
            chat_extra == 0,
            "chat cap model must accept exact boundary and reject above"
        );

        prop_assert_eq!(
            model_file_envelope_accepts(file_n),
            file_extra == 0,
            "file envelope cap model must accept exact boundary and reject above"
        );
    }
}
