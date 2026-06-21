#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{
    PeerId, Swarm,
    gossipsub::{Event as GossipsubEvent, IdentTopic, Message, MessageId},
    identity,
    swarm::Config as SwarmConfig,
};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    consensus::por_000_ephemeral_registration::RegistryData,
    network::{
        p2p_001_transport::build_transport, p2p_003_behaviour::RemzarBehaviour,
        p2p_008_broadcast::FILE_TOPIC_STR, p2p_011_peerbook::PeerBook, p2p_014_chat::chat_topic,
    },
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{
        p2p_001_sync_builders::P2pSync,
        p2p_005_sync_gossipsub::{handle_gossipsub, handle_gossipsub_checked},
        p2p_006_sync_runtime::NodeOpts,
    },
    storage::rocksdb_005_manager::RockDBManager,
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        alpha_003_detection_system::DetectionSystem, send_file::FileChunkMessage,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct GossipHarness {
    opts: NodeOpts,
    data_dir: PathBuf,
    db: Arc<RockDBManager>,
    mempool: Arc<MemPool>,
    chain: AccountModelTree,
    registry: RegistryData,
    sync: P2pSync,
    swarm: Swarm<RemzarBehaviour>,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn now_millis_for_test() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

fn unique_data_dir(test_name: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!(
        "remzar_p2p_005_sync_gossipsub_tests_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn file_topic() -> IdentTopic {
    IdentTopic::new(FILE_TOPIC_STR)
}

fn generic_topic() -> IdentTopic {
    IdentTopic::new("/remzar/test/gossipsub/1.0.0")
}

fn make_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let transport = build_transport(keypair.clone()).map_err(fmt_err)?;
    let mut behaviour = RemzarBehaviour::new(keypair).map_err(fmt_err)?;

    behaviour
        .gossipsub
        .subscribe(&IdentTopic::new("remzar.test.v1"))
        .map_err(fmt_err)?;

    Ok(Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    ))
}

fn build_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: "receiver-wallet".to_string(),
        founder: false,
    }
}

fn build_harness(test_name: &str) -> TestResult<GossipHarness> {
    let data_dir = unique_data_dir(test_name);
    fs::create_dir_all(&data_dir).map_err(fmt_err)?;

    let opts = build_node_opts(&data_dir);
    let blockchain_path = data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_text = blockchain_path.to_string_lossy().into_owned();

    let db = Arc::new(
        RockDBManager::new_blockchain(&opts, blockchain_path_text.as_str()).map_err(fmt_err)?,
    );

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let chain_for_sync = AccountModelTree::with_manager((*db).clone());
    let chain = AccountModelTree::with_manager((*db).clone());

    let peerlist_dir = data_dir.join(GlobalConfiguration::PEER_LIST_DIR);
    fs::create_dir_all(&peerlist_dir).map_err(fmt_err)?;
    PeerBook::configure_storage_dir(peerlist_dir.clone());
    let peerbook = Arc::new(Mutex::new(PeerBook::load_or_init()));

    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));
    let sync = P2pSync::new(
        chain_for_sync,
        Arc::clone(&db),
        Arc::clone(&mempool),
        peerbook,
        peerlist_dir,
        Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
        reorg_manager,
    );

    Ok(GossipHarness {
        opts,
        data_dir,
        db,
        mempool,
        chain,
        registry: RegistryData::new(),
        sync,
        swarm: make_swarm()?,
    })
}

fn make_message(topic: &IdentTopic, source: PeerId, data: Vec<u8>) -> Message {
    Message {
        source: Some(source),
        data,
        sequence_number: None,
        topic: topic.hash(),
    }
}

fn make_event(topic: &IdentTopic, source: PeerId, data: Vec<u8>) -> GossipsubEvent {
    let id = MESSAGE_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes();

    GossipsubEvent::Message {
        propagation_source: source,
        message_id: MessageId::from(id.to_vec()),
        message: make_message(topic, source, data),
    }
}

fn handle_checked(
    harness: &mut GossipHarness,
    topic: &IdentTopic,
    source: PeerId,
    data: Vec<u8>,
    local_wallet: &str,
) -> TestResult {
    let event = make_event(topic, source, data);

    handle_gossipsub_checked(
        event,
        source,
        &mut harness.swarm,
        &mut harness.chain,
        &harness.db,
        &harness.db,
        &harness.mempool,
        &mut harness.registry,
        &mut harness.sync,
        None,
        local_wallet,
        &harness.opts,
    )
    .map_err(fmt_err)
}

fn handle_unchecked(
    harness: &mut GossipHarness,
    topic: &IdentTopic,
    source: PeerId,
    data: Vec<u8>,
    local_wallet: &str,
) {
    let event = make_event(topic, source, data);

    handle_gossipsub(
        event,
        source,
        &mut harness.swarm,
        &mut harness.chain,
        &harness.db,
        &harness.db,
        &harness.mempool,
        &mut harness.registry,
        &mut harness.sync,
        None,
        local_wallet,
        &harness.opts,
    );
}

fn receiver_message_file(data_dir: &Path) -> PathBuf {
    data_dir
        .join("receiver.message")
        .join("received_chat.jsonl")
}

fn receiver_files_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("receiver.files")
}

fn file_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn file_id_hex(seed: u8) -> String {
    hex::encode(file_id(seed))
}

fn file_chunk_dir(data_dir: &Path, seed: u8) -> PathBuf {
    receiver_files_dir(data_dir).join(file_id_hex(seed))
}

fn chunk_path(data_dir: &Path, seed: u8, index: u32) -> PathBuf {
    file_chunk_dir(data_dir, seed).join(format!("chunk_{index:06}.bin"))
}

fn meta_path(data_dir: &Path, seed: u8) -> PathBuf {
    file_chunk_dir(data_dir, seed).join("meta.json")
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn file_chunk(
    seed: u8,
    filename: &str,
    from_wallet: &str,
    to_wallet: &str,
    chunk_index: u32,
    total_chunks: u32,
    chunk_bytes: Vec<u8>,
) -> FileChunkMessage {
    FileChunkMessage {
        file_id: file_id(seed),
        from_wallet: from_wallet.to_string(),
        to_wallet: to_wallet.to_string(),
        chunk_index,
        total_chunks,
        filename: filename.to_string(),
        file_size_bytes: u64::try_from(chunk_bytes.len()).unwrap_or(u64::MAX),
        content_hash_hex: blake3_hex(&chunk_bytes),
        chunk_bytes,
        timestamp_ms: now_ms(),
    }
}

fn encode_chunk(chunk: &FileChunkMessage) -> TestResult<Vec<u8>> {
    postcard::to_allocvec(chunk).map_err(fmt_err)
}

fn assert_no_receiver_files(data_dir: &Path) {
    assert!(!receiver_files_dir(data_dir).exists());
}

fn assert_initial_invariants(harness: &GossipHarness) -> TestResult {
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.chain.get_blocks().is_empty());
    assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn p2p_01_005_sync_gossipsub_constructs_real_harness() -> TestResult {
    let harness = build_harness("p2p_01")?;

    assert!(harness.data_dir.exists());
    assert!(!harness.swarm.local_peer_id().to_string().is_empty());
    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_02_005_sync_gossipsub_malformed_generic_message_returns_ok() -> TestResult {
    let mut harness = build_harness("p2p_02")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![1, 2, 3, 4],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_03_005_sync_gossipsub_empty_generic_message_returns_ok() -> TestResult {
    let mut harness = build_harness("p2p_03")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        Vec::new(),
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_04_005_sync_gossipsub_oversized_generic_message_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_04")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0xaa; (1024 * 1024) + 1],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_05_005_sync_gossipsub_self_echo_is_ignored_before_decoding() -> TestResult {
    let mut harness = build_harness("p2p_05")?;
    let local_peer = *harness.swarm.local_peer_id();

    handle_checked(
        &mut harness,
        &generic_topic(),
        local_peer,
        vec![0xbb; (1024 * 1024) + 1],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_06_005_sync_gossipsub_unchecked_wrapper_handles_malformed_message() -> TestResult {
    let mut harness = build_harness("p2p_06")?;

    handle_unchecked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![9, 8, 7, 6],
        "receiver-wallet",
    );

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_07_005_sync_gossipsub_invalid_chat_payload_does_not_persist_chat() -> TestResult {
    let mut harness = build_harness("p2p_07")?;

    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![1, 2, 3],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    Ok(())
}

#[test]
fn p2p_08_005_sync_gossipsub_empty_chat_payload_does_not_persist_chat() -> TestResult {
    let mut harness = build_harness("p2p_08")?;

    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        Vec::new(),
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    Ok(())
}

#[test]
fn p2p_09_005_sync_gossipsub_oversized_chat_payload_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_09")?;

    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![0xcc; (64 * 1024) + 1],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_10_005_sync_gossipsub_self_echo_chat_payload_does_not_persist() -> TestResult {
    let mut harness = build_harness("p2p_10")?;
    let local_peer = *harness.swarm.local_peer_id();

    handle_checked(
        &mut harness,
        &chat_topic(),
        local_peer,
        vec![0xdd; 32],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    Ok(())
}

#[test]
fn p2p_11_005_sync_gossipsub_invalid_file_payload_does_not_create_file_dir() -> TestResult {
    let mut harness = build_harness("p2p_11")?;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        vec![1, 2, 3, 4, 5],
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_12_005_sync_gossipsub_empty_file_payload_does_not_create_file_dir() -> TestResult {
    let mut harness = build_harness("p2p_12")?;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        Vec::new(),
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_13_005_sync_gossipsub_oversized_file_envelope_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_13")?;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        vec![0xee; (256 * 1024) + 1],
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_14_005_sync_gossipsub_valid_file_chunk_for_local_wallet_is_persisted() -> TestResult {
    let mut harness = build_harness("p2p_14")?;
    let chunk = file_chunk(
        14,
        "hello.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"hello remzar".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 14, 0)).map_err(fmt_err)?,
        b"hello remzar"
    );
    assert!(meta_path(&harness.data_dir, 14).exists());
    Ok(())
}

#[test]
fn p2p_15_005_sync_gossipsub_valid_file_chunk_for_other_wallet_is_not_persisted() -> TestResult {
    let mut harness = build_harness("p2p_15")?;
    let chunk = file_chunk(
        15,
        "other.txt",
        "sender-wallet",
        "someone-else",
        0,
        1,
        b"not mine".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_16_005_sync_gossipsub_file_recipient_match_is_case_insensitive() -> TestResult {
    let mut harness = build_harness("p2p_16")?;
    let chunk = file_chunk(
        16,
        "case.txt",
        "sender-wallet",
        "RECEIVER-WALLET",
        0,
        1,
        b"case match".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 16, 0)).map_err(fmt_err)?,
        b"case match"
    );
    Ok(())
}

#[test]
fn p2p_17_005_sync_gossipsub_empty_local_wallet_does_not_persist_file_chunk() -> TestResult {
    let mut harness = build_harness("p2p_17")?;
    let chunk = file_chunk(
        17,
        "empty-local.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"not persisted".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_18_005_sync_gossipsub_unsafe_file_name_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_18")?;
    let chunk = file_chunk(
        18,
        "../evil.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"safe bytes".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_19_005_sync_gossipsub_nested_file_name_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_19")?;
    let chunk = file_chunk(
        19,
        "nested/file.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"nested name".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_20_005_sync_gossipsub_dot_file_name_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_20")?;
    let chunk = file_chunk(
        20,
        ".",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"dot name".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_21_005_sync_gossipsub_filename_over_255_bytes_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_21")?;
    let long_name = "a".repeat(256);
    let chunk = file_chunk(
        21,
        &long_name,
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"too long name".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_22_005_sync_gossipsub_filename_exactly_255_bytes_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_22")?;
    let name = "a".repeat(255);
    let chunk = file_chunk(
        22,
        &name,
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"max safe filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 22)).map_err(fmt_err)?;
    assert!(meta.contains(&name));
    Ok(())
}

#[test]
fn p2p_23_005_sync_gossipsub_file_total_chunks_above_cap_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_23")?;
    let chunk = file_chunk(
        23,
        "too-many.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        200_001,
        b"too many chunks".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_24_005_sync_gossipsub_file_chunk_index_equal_total_chunks_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_24")?;
    let chunk = file_chunk(
        24,
        "bad-index.txt",
        "sender-wallet",
        "receiver-wallet",
        1,
        1,
        b"bad index".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_25_005_sync_gossipsub_file_chunk_index_greater_than_total_chunks_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_25")?;
    let chunk = file_chunk(
        25,
        "bad-index-2.txt",
        "sender-wallet",
        "receiver-wallet",
        9,
        2,
        b"bad index 2".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_26_005_sync_gossipsub_file_chunk_bytes_above_cap_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_26")?;
    let chunk = file_chunk(
        26,
        "oversized-chunk.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        vec![0x26; (192 * 1024) + 1],
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_27_005_sync_gossipsub_file_chunk_bytes_exact_cap_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_27")?;
    let chunk = file_chunk(
        27,
        "exact-cap.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        vec![0x27; 192 * 1024],
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::metadata(chunk_path(&harness.data_dir, 27, 0))
            .map_err(fmt_err)?
            .len(),
        u64::try_from(192 * 1024).map_err(fmt_err)?
    );
    Ok(())
}

#[test]
fn p2p_28_005_sync_gossipsub_from_wallet_over_256_bytes_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_28")?;
    let from_wallet = "f".repeat(257);
    let chunk = file_chunk(
        28,
        "from-too-long.txt",
        &from_wallet,
        "receiver-wallet",
        0,
        1,
        b"wallet too long".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_29_005_sync_gossipsub_to_wallet_over_256_bytes_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_29")?;
    let to_wallet = "t".repeat(257);
    let chunk = file_chunk(
        29,
        "to-too-long.txt",
        "sender-wallet",
        &to_wallet,
        0,
        1,
        b"wallet too long".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_30_005_sync_gossipsub_zero_length_file_chunk_is_persisted() -> TestResult {
    let mut harness = build_harness("p2p_30")?;
    let chunk = file_chunk(
        30,
        "empty.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        Vec::new(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::metadata(chunk_path(&harness.data_dir, 30, 0))
            .map_err(fmt_err)?
            .len(),
        0
    );
    Ok(())
}

#[test]
fn p2p_31_005_sync_gossipsub_second_file_chunk_is_written_with_padded_index() -> TestResult {
    let mut harness = build_harness("p2p_31")?;
    let chunk = file_chunk(
        31,
        "chunk-two.bin",
        "sender-wallet",
        "receiver-wallet",
        1,
        2,
        b"chunk one".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 31, 1)).map_err(fmt_err)?,
        b"chunk one"
    );
    Ok(())
}

#[test]
fn p2p_32_005_sync_gossipsub_multiple_chunks_same_file_are_written() -> TestResult {
    let mut harness = build_harness("p2p_32")?;
    let first = file_chunk(
        32,
        "multi.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        2,
        b"first".to_vec(),
    );
    let second = file_chunk(
        32,
        "multi.bin",
        "sender-wallet",
        "receiver-wallet",
        1,
        2,
        b"second".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&second)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 32, 0)).map_err(fmt_err)?,
        b"first"
    );
    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 32, 1)).map_err(fmt_err)?,
        b"second"
    );
    Ok(())
}

#[test]
fn p2p_33_005_sync_gossipsub_duplicate_chunk_keeps_first_chunk_file() -> TestResult {
    let mut harness = build_harness("p2p_33")?;
    let first = file_chunk(
        33,
        "dup.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"first-write".to_vec(),
    );
    let second = file_chunk(
        33,
        "dup.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"second-write".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&second)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 33, 0)).map_err(fmt_err)?,
        b"first-write"
    );
    Ok(())
}

#[test]
fn p2p_34_005_sync_gossipsub_file_meta_records_last_chunk_index() -> TestResult {
    let mut harness = build_harness("p2p_34")?;
    let chunk = file_chunk(
        34,
        "meta.bin",
        "sender-wallet",
        "receiver-wallet",
        7,
        8,
        b"meta bytes".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 34)).map_err(fmt_err)?;
    assert!(meta.contains("\"last_chunk_index\": 7"));
    assert!(meta.contains("\"total_chunks\": 8"));
    Ok(())
}

#[test]
fn p2p_35_005_sync_gossipsub_file_meta_records_wallets_and_hash() -> TestResult {
    let mut harness = build_harness("p2p_35")?;
    let chunk = file_chunk(
        35,
        "meta-wallet.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"hash me".to_vec(),
    );
    let expected_hash = chunk.content_hash_hex.clone();

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 35)).map_err(fmt_err)?;
    assert!(meta.contains("sender-wallet"));
    assert!(meta.contains("receiver-wallet"));
    assert!(meta.contains(&expected_hash));
    Ok(())
}

#[test]
fn p2p_36_005_sync_gossipsub_file_path_uses_hex_file_id_directory() -> TestResult {
    let mut harness = build_harness("p2p_36")?;
    let chunk = file_chunk(
        36,
        "hex-dir.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"hex dir".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(file_chunk_dir(&harness.data_dir, 36).exists());
    assert!(
        file_chunk_dir(&harness.data_dir, 36)
            .to_string_lossy()
            .contains(&file_id_hex(36))
    );
    Ok(())
}

#[test]
fn p2p_37_005_sync_gossipsub_file_topic_does_not_change_sync_percent() -> TestResult {
    let mut harness = build_harness("p2p_37")?;
    harness.sync.total_to_download = 400;
    harness.sync.downloaded = 100;

    let chunk = file_chunk(
        37,
        "sync-percent.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"sync unchanged".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    Ok(())
}

#[test]
fn p2p_38_005_sync_gossipsub_file_topic_does_not_create_blockchain_tip() -> TestResult {
    let mut harness = build_harness("p2p_38")?;
    let chunk = file_chunk(
        38,
        "no-tip.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"no chain".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);
    assert!(harness.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_39_005_sync_gossipsub_vector_many_valid_file_chunks_are_persisted() -> TestResult {
    let mut harness = build_harness("p2p_39")?;

    for index in 0u32..10u32 {
        let byte = u8::try_from(index).map_err(fmt_err)?;
        let chunk = file_chunk(
            39,
            "vector.bin",
            "sender-wallet",
            "receiver-wallet",
            index,
            10,
            vec![byte; 4],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    for index in 0u32..10u32 {
        assert!(chunk_path(&harness.data_dir, 39, index).exists());
    }

    Ok(())
}

#[test]
fn p2p_40_005_sync_gossipsub_end_to_end_mixed_drop_and_persist_invariants() -> TestResult {
    let mut harness = build_harness("p2p_40")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0xff; 32],
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![0xab; (64 * 1024) + 1],
        "receiver-wallet",
    )?;

    let dropped = file_chunk(
        40,
        "dropped.bin",
        "sender-wallet",
        "not-receiver",
        0,
        1,
        b"drop".to_vec(),
    );
    let kept = file_chunk(
        41,
        "kept.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"keep".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&dropped)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&kept)?,
        "receiver-wallet",
    )?;

    assert!(!file_chunk_dir(&harness.data_dir, 40).exists());
    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 41, 0)).map_err(fmt_err)?,
        b"keep"
    );
    assert!(!receiver_message_file(&harness.data_dir).exists());
    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_41_005_sync_gossipsub_file_total_chunks_exact_cap_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_41")?;
    let chunk = file_chunk(
        41,
        "total-cap.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        4_096,
        b"cap ok".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 41, 0)).map_err(fmt_err)?,
        b"cap ok"
    );
    Ok(())
}

#[test]
fn p2p_42_005_sync_gossipsub_file_total_chunks_zero_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_42")?;
    let chunk = file_chunk(
        42,
        "zero-total.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        0,
        b"drop".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_43_005_sync_gossipsub_file_last_valid_chunk_index_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_43")?;
    let chunk = file_chunk(
        43,
        "last-index.bin",
        "sender-wallet",
        "receiver-wallet",
        4,
        5,
        b"last valid".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 43, 4)).map_err(fmt_err)?,
        b"last valid"
    );
    Ok(())
}

#[test]
fn p2p_44_005_sync_gossipsub_empty_filename_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_44")?;
    let chunk = file_chunk(
        44,
        "",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"empty filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_45_005_sync_gossipsub_dotdot_filename_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_45")?;
    let chunk = file_chunk(
        45,
        "..",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"dotdot filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_46_005_sync_gossipsub_backslash_filename_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_46")?;
    let chunk = file_chunk(
        46,
        "nested\\evil.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"backslash filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_47_005_sync_gossipsub_absolute_windows_style_filename_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_47")?;
    let chunk = file_chunk(
        47,
        "C:\\evil.txt",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"absolute windows".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_48_005_sync_gossipsub_simple_filename_with_dash_and_dot_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_48")?;
    let chunk = file_chunk(
        48,
        "remzar-file-01.data",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"simple filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 48)).map_err(fmt_err)?;
    assert!(meta.contains("remzar-file-01.data"));
    Ok(())
}

#[test]
fn p2p_49_005_sync_gossipsub_unicode_filename_is_allowed_as_leaf() -> TestResult {
    let mut harness = build_harness("p2p_49")?;
    let chunk = file_chunk(
        49,
        "remzar-测试-🚀.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"unicode filename".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 49)).map_err(fmt_err)?;
    assert!(meta.contains("remzar-测试-🚀.bin"));
    Ok(())
}

#[test]
fn p2p_50_005_sync_gossipsub_exact_256_byte_from_wallet_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_50")?;
    let from_wallet = "f".repeat(256);
    let chunk = file_chunk(
        50,
        "from-exact.txt",
        &from_wallet,
        "receiver-wallet",
        0,
        1,
        b"from exact".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 50, 0)).map_err(fmt_err)?,
        b"from exact"
    );
    Ok(())
}

#[test]
fn p2p_51_005_sync_gossipsub_exact_256_byte_to_wallet_is_allowed_when_matching() -> TestResult {
    let mut harness = build_harness("p2p_51")?;
    let local_wallet = "r".repeat(256);
    let chunk = file_chunk(
        51,
        "to-exact.txt",
        "sender-wallet",
        &local_wallet,
        0,
        1,
        b"to exact".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        &local_wallet,
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 51, 0)).map_err(fmt_err)?,
        b"to exact"
    );
    Ok(())
}

#[test]
fn p2p_52_005_sync_gossipsub_257_byte_to_wallet_is_dropped_even_if_local_same() -> TestResult {
    let mut harness = build_harness("p2p_52")?;
    let local_wallet = "r".repeat(257);
    let chunk = file_chunk(
        52,
        "to-too-long-even-match.txt",
        "sender-wallet",
        &local_wallet,
        0,
        1,
        b"drop".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        &local_wallet,
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_53_005_sync_gossipsub_file_metadata_is_valid_json() -> TestResult {
    let mut harness = build_harness("p2p_53")?;
    let chunk = file_chunk(
        53,
        "valid-json.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"json".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 53)).map_err(fmt_err)?;
    let value: serde_json::Value = serde_json::from_str(&meta).map_err(fmt_err)?;

    assert_eq!(value["filename"], "valid-json.bin");
    assert_eq!(value["from_wallet"], "sender-wallet");
    assert_eq!(value["to_wallet"], "receiver-wallet");
    Ok(())
}

#[test]
fn p2p_54_005_sync_gossipsub_file_metadata_file_size_matches_chunk_bytes_len() -> TestResult {
    let mut harness = build_harness("p2p_54")?;
    let bytes = b"size check bytes".to_vec();
    let chunk = file_chunk(
        54,
        "size.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        bytes.clone(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 54)).map_err(fmt_err)?;
    let value: serde_json::Value = serde_json::from_str(&meta).map_err(fmt_err)?;

    assert_eq!(value["file_size_bytes"], bytes.len());
    Ok(())
}

#[test]
fn p2p_55_005_sync_gossipsub_file_metadata_file_id_hex_matches_directory() -> TestResult {
    let mut harness = build_harness("p2p_55")?;
    let chunk = file_chunk(
        55,
        "file-id.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"id check".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 55)).map_err(fmt_err)?;
    let value: serde_json::Value = serde_json::from_str(&meta).map_err(fmt_err)?;

    assert_eq!(value["file_id_hex"], file_id_hex(55));
    assert!(file_chunk_dir(&harness.data_dir, 55).exists());
    Ok(())
}

#[test]
fn p2p_56_005_sync_gossipsub_file_metadata_updates_on_later_chunk() -> TestResult {
    let mut harness = build_harness("p2p_56")?;
    let first = file_chunk(
        56,
        "meta-update.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        3,
        b"first".to_vec(),
    );
    let later = file_chunk(
        56,
        "meta-update.bin",
        "sender-wallet",
        "receiver-wallet",
        2,
        3,
        b"third".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&later)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 56)).map_err(fmt_err)?;
    let value: serde_json::Value = serde_json::from_str(&meta).map_err(fmt_err)?;

    assert_eq!(value["last_chunk_index"], 2);
    Ok(())
}

#[test]
fn p2p_57_005_sync_gossipsub_duplicate_chunk_keeps_original_meta_timestamp() -> TestResult {
    let mut harness = build_harness("p2p_57")?;
    let mut first = file_chunk(
        57,
        "timestamp.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"first timestamp".to_vec(),
    );
    let mut second = first.clone();
    first.timestamp_ms = 100;
    second.timestamp_ms = 200;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&second)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 57)).map_err(fmt_err)?;
    let value: serde_json::Value = serde_json::from_str(&meta).map_err(fmt_err)?;

    assert_eq!(value["last_timestamp_ms"], 100);
    Ok(())
}

#[test]
fn p2p_58_005_sync_gossipsub_file_chunk_with_invalid_hash_is_dropped() -> TestResult {
    let mut harness = build_harness("p2p_58")?;
    let mut chunk = file_chunk(
        58,
        "wrong-hash.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"wrong hash data".to_vec(),
    );
    chunk.content_hash_hex = "not-the-real-hash".to_string();

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_59_005_sync_gossipsub_file_chunk_same_id_different_filename_meta_uses_latest() -> TestResult
{
    let mut harness = build_harness("p2p_59")?;
    let first = file_chunk(
        59,
        "first-name.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        2,
        b"first".to_vec(),
    );
    let second = file_chunk(
        59,
        "second-name.bin",
        "sender-wallet",
        "receiver-wallet",
        1,
        2,
        b"second".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&second)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 59)).map_err(fmt_err)?;
    assert!(meta.contains("second-name.bin"));
    Ok(())
}

#[test]
fn p2p_60_005_sync_gossipsub_two_different_files_create_two_directories() -> TestResult {
    let mut harness = build_harness("p2p_60")?;
    let first = file_chunk(
        60,
        "first.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"first file".to_vec(),
    );
    let second = file_chunk(
        61,
        "second.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"second file".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&first)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&second)?,
        "receiver-wallet",
    )?;

    assert!(file_chunk_dir(&harness.data_dir, 60).exists());
    assert!(file_chunk_dir(&harness.data_dir, 61).exists());
    Ok(())
}

#[test]
fn p2p_61_005_sync_gossipsub_self_echo_valid_file_chunk_is_ignored() -> TestResult {
    let mut harness = build_harness("p2p_61")?;
    let local_peer = *harness.swarm.local_peer_id();
    let chunk = file_chunk(
        61,
        "self-echo.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"self echo".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        local_peer,
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_62_005_sync_gossipsub_self_echo_valid_file_chunk_with_wrapper_is_ignored() -> TestResult {
    let mut harness = build_harness("p2p_62")?;
    let local_peer = *harness.swarm.local_peer_id();
    let chunk = file_chunk(
        62,
        "self-wrapper.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"self wrapper".to_vec(),
    );

    handle_unchecked(
        &mut harness,
        &file_topic(),
        local_peer,
        encode_chunk(&chunk)?,
        "receiver-wallet",
    );

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_63_005_sync_gossipsub_unchecked_wrapper_persists_valid_file_chunk() -> TestResult {
    let mut harness = build_harness("p2p_63")?;
    let chunk = file_chunk(
        63,
        "wrapper-valid.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"wrapper valid".to_vec(),
    );

    handle_unchecked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    );

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 63, 0)).map_err(fmt_err)?,
        b"wrapper valid"
    );
    Ok(())
}

#[test]
fn p2p_64_005_sync_gossipsub_chunk_index_12_uses_six_digit_file_name() -> TestResult {
    let mut harness = build_harness("p2p_64")?;
    let chunk = file_chunk(
        64,
        "index12.bin",
        "sender-wallet",
        "receiver-wallet",
        12,
        20,
        b"index twelve".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(
        file_chunk_dir(&harness.data_dir, 64)
            .join("chunk_000012.bin")
            .exists()
    );
    Ok(())
}

#[test]
fn p2p_65_005_sync_gossipsub_chunk_index_4095_uses_six_digit_file_name() -> TestResult {
    let mut harness = build_harness("p2p_65")?;
    let chunk = file_chunk(
        65,
        "index4095.bin",
        "sender-wallet",
        "receiver-wallet",
        4_095,
        4_096,
        b"large index".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(
        file_chunk_dir(&harness.data_dir, 65)
            .join("chunk_004095.bin")
            .exists()
    );
    Ok(())
}

#[test]
fn p2p_66_005_sync_gossipsub_file_topic_payload_at_envelope_cap_with_garbage_is_safe() -> TestResult
{
    let mut harness = build_harness("p2p_66")?;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        vec![0x66; 256 * 1024],
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_67_005_sync_gossipsub_chat_topic_payload_at_cap_with_garbage_is_safe() -> TestResult {
    let mut harness = build_harness("p2p_67")?;

    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![0x67; 64 * 1024],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    Ok(())
}

#[test]
fn p2p_68_005_sync_gossipsub_generic_payload_at_cap_with_garbage_is_safe() -> TestResult {
    let mut harness = build_harness("p2p_68")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0x68; 1024 * 1024],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_69_005_sync_gossipsub_generic_payload_over_cap_with_garbage_is_safe() -> TestResult {
    let mut harness = build_harness("p2p_69")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0x69; (1024 * 1024) + 2],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_70_005_sync_gossipsub_file_chunk_with_empty_from_wallet_is_allowed() -> TestResult {
    let mut harness = build_harness("p2p_70")?;
    let chunk = file_chunk(
        70,
        "empty-from.bin",
        "",
        "receiver-wallet",
        0,
        1,
        b"empty from".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 70, 0)).map_err(fmt_err)?,
        b"empty from"
    );
    Ok(())
}

#[test]
fn p2p_71_005_sync_gossipsub_file_chunk_with_empty_to_wallet_is_not_persisted() -> TestResult {
    let mut harness = build_harness("p2p_71")?;
    let chunk = file_chunk(
        71,
        "empty-to.bin",
        "sender-wallet",
        "",
        0,
        1,
        b"empty to".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_72_005_sync_gossipsub_file_chunk_sender_case_is_preserved_in_meta() -> TestResult {
    let mut harness = build_harness("p2p_72")?;
    let chunk = file_chunk(
        72,
        "sender-case.bin",
        "Sender-Wallet-MIXED",
        "receiver-wallet",
        0,
        1,
        b"sender case".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 72)).map_err(fmt_err)?;
    assert!(meta.contains("Sender-Wallet-MIXED"));
    Ok(())
}

#[test]
fn p2p_73_005_sync_gossipsub_file_chunk_recipient_case_is_preserved_in_meta() -> TestResult {
    let mut harness = build_harness("p2p_73")?;
    let chunk = file_chunk(
        73,
        "recipient-case.bin",
        "sender-wallet",
        "RECEIVER-WALLET",
        0,
        1,
        b"recipient case".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 73)).map_err(fmt_err)?;
    assert!(meta.contains("RECEIVER-WALLET"));
    Ok(())
}

#[test]
fn p2p_74_005_sync_gossipsub_file_chunk_unicode_wallets_are_allowed_under_cap() -> TestResult {
    let mut harness = build_harness("p2p_74")?;
    let chunk = file_chunk(
        74,
        "unicode-wallets.bin",
        "sender-测试",
        "receiver-🚀",
        0,
        1,
        b"unicode wallets".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-🚀",
    )?;

    let meta = fs::read_to_string(meta_path(&harness.data_dir, 74)).map_err(fmt_err)?;
    assert!(meta.contains("sender-测试"));
    assert!(meta.contains("receiver-🚀"));
    Ok(())
}

#[test]
fn p2p_75_005_sync_gossipsub_malformed_generic_message_does_not_create_receiver_dirs() -> TestResult
{
    let mut harness = build_harness("p2p_75")?;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0x75; 128],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_76_005_sync_gossipsub_malformed_chat_does_not_create_receiver_files_dir() -> TestResult {
    let mut harness = build_harness("p2p_76")?;

    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![0x76; 128],
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_77_005_sync_gossipsub_malformed_file_does_not_create_receiver_message_file() -> TestResult {
    let mut harness = build_harness("p2p_77")?;

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        vec![0x77; 128],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    Ok(())
}

#[test]
fn p2p_78_005_sync_gossipsub_vector_valid_file_chunks_different_ids_are_all_persisted() -> TestResult
{
    let mut harness = build_harness("p2p_78")?;

    for seed in 78u8..88u8 {
        let chunk = file_chunk(
            seed,
            "vector-different.bin",
            "sender-wallet",
            "receiver-wallet",
            0,
            1,
            vec![seed; 3],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    for seed in 78u8..88u8 {
        assert_eq!(
            fs::read(chunk_path(&harness.data_dir, seed, 0)).map_err(fmt_err)?,
            vec![seed; 3]
        );
    }

    Ok(())
}

#[test]
fn p2p_79_005_sync_gossipsub_vector_invalid_chunk_indices_are_all_dropped() -> TestResult {
    let mut harness = build_harness("p2p_79")?;

    for seed in 79u8..89u8 {
        let chunk = file_chunk(
            seed,
            "invalid-index.bin",
            "sender-wallet",
            "receiver-wallet",
            5,
            5,
            vec![seed; 3],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_80_005_sync_gossipsub_vector_wrong_recipients_are_all_dropped() -> TestResult {
    let mut harness = build_harness("p2p_80")?;

    for seed in 80u8..90u8 {
        let chunk = file_chunk(
            seed,
            "wrong-recipient.bin",
            "sender-wallet",
            "not-me",
            0,
            1,
            vec![seed; 3],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_81_005_sync_gossipsub_load_20_small_file_chunks_same_file_are_persisted() -> TestResult {
    let mut harness = build_harness("p2p_81")?;

    for index in 0u32..20u32 {
        let byte = u8::try_from(index).map_err(fmt_err)?;
        let chunk = file_chunk(
            81,
            "load20.bin",
            "sender-wallet",
            "receiver-wallet",
            index,
            20,
            vec![byte; 2],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    for index in 0u32..20u32 {
        assert!(chunk_path(&harness.data_dir, 81, index).exists());
    }

    Ok(())
}

#[test]
fn p2p_82_005_sync_gossipsub_load_32_malformed_generic_messages_keep_state_clean() -> TestResult {
    let mut harness = build_harness("p2p_82")?;

    for index in 0u8..32u8 {
        handle_checked(
            &mut harness,
            &generic_topic(),
            test_peer_id(),
            vec![index; 16],
            "receiver-wallet",
        )?;
    }

    assert_initial_invariants(&harness)?;
    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_83_005_sync_gossipsub_load_32_malformed_chat_messages_keep_files_clean() -> TestResult {
    let mut harness = build_harness("p2p_83")?;

    for index in 0u8..32u8 {
        handle_checked(
            &mut harness,
            &chat_topic(),
            test_peer_id(),
            vec![index; 16],
            "receiver-wallet",
        )?;
    }

    assert!(!receiver_message_file(&harness.data_dir).exists());
    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_84_005_sync_gossipsub_load_32_malformed_file_messages_keep_files_clean() -> TestResult {
    let mut harness = build_harness("p2p_84")?;

    for index in 0u8..32u8 {
        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            vec![index; 16],
            "receiver-wallet",
        )?;
    }

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_85_005_sync_gossipsub_file_chunk_does_not_mutate_pending_sync_maps() -> TestResult {
    let mut harness = build_harness("p2p_85")?;
    let chunk = file_chunk(
        85,
        "pending-clean.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"pending clean".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    Ok(())
}

#[test]
fn p2p_86_005_sync_gossipsub_file_chunk_does_not_mutate_sync_queues() -> TestResult {
    let mut harness = build_harness("p2p_86")?;
    let chunk = file_chunk(
        86,
        "queue-clean.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"queue clean".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert!(!harness.sync.has_background_sync_work());
    Ok(())
}

#[test]
fn p2p_87_005_sync_gossipsub_file_chunk_preserves_manual_pq_ready_peer() -> TestResult {
    let mut harness = build_harness("p2p_87")?;
    let peer = test_peer_id();
    harness.sync.mark_pq_ready(peer);

    let chunk = file_chunk(
        87,
        "pq-ready.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"pq ready".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(harness.sync.is_pq_ready(&peer));
    Ok(())
}

#[test]
fn p2p_88_005_sync_gossipsub_file_chunk_preserves_manual_sync_percent() -> TestResult {
    let mut harness = build_harness("p2p_88")?;
    harness.sync.total_to_download = 800;
    harness.sync.downloaded = 200;

    let chunk = file_chunk(
        88,
        "percent.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"percent clean".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    Ok(())
}

#[test]
fn p2p_89_005_sync_gossipsub_malformed_generic_preserves_manual_sync_percent() -> TestResult {
    let mut harness = build_harness("p2p_89")?;
    harness.sync.total_to_download = 900;
    harness.sync.downloaded = 300;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0x89; 32],
        "receiver-wallet",
    )?;

    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "33.33");
    Ok(())
}

#[test]
fn p2p_90_005_sync_gossipsub_file_chunk_preserves_db_tip_height_zero() -> TestResult {
    let mut harness = build_harness("p2p_90")?;
    let chunk = file_chunk(
        90,
        "db-tip.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"db tip".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn p2p_91_005_sync_gossipsub_file_chunk_preserves_addr_index_height_zero() -> TestResult {
    let mut harness = build_harness("p2p_91")?;
    let chunk = file_chunk(
        91,
        "addr-index.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"addr index".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert_eq!(harness.db.get_addr_index_height().map_err(fmt_err)?, 0);
    Ok(())
}

#[test]
fn p2p_92_005_sync_gossipsub_file_chunk_preserves_chain_blocks_empty() -> TestResult {
    let mut harness = build_harness("p2p_92")?;
    let chunk = file_chunk(
        92,
        "chain-blocks.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"chain blocks".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(harness.chain.get_blocks().is_empty());
    Ok(())
}

#[test]
fn p2p_93_005_sync_gossipsub_file_chunk_preserves_chain_balances_empty() -> TestResult {
    let mut harness = build_harness("p2p_93")?;
    let chunk = file_chunk(
        93,
        "chain-balances.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"chain balances".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&chunk)?,
        "receiver-wallet",
    )?;

    assert!(harness.chain.get_balances().is_empty());
    Ok(())
}

#[test]
fn p2p_94_005_sync_gossipsub_self_echo_generic_keeps_state_clean() -> TestResult {
    let mut harness = build_harness("p2p_94")?;
    let local_peer = *harness.swarm.local_peer_id();

    handle_checked(
        &mut harness,
        &generic_topic(),
        local_peer,
        vec![0x94; 512],
        "receiver-wallet",
    )?;

    assert_initial_invariants(&harness)?;
    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_95_005_sync_gossipsub_self_echo_file_over_cap_is_ignored_before_drop_logic() -> TestResult {
    let mut harness = build_harness("p2p_95")?;
    let local_peer = *harness.swarm.local_peer_id();

    handle_checked(
        &mut harness,
        &file_topic(),
        local_peer,
        vec![0x95; (256 * 1024) + 128],
        "receiver-wallet",
    )?;

    assert_no_receiver_files(&harness.data_dir);
    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_96_005_sync_gossipsub_self_echo_chat_over_cap_is_ignored_before_drop_logic() -> TestResult {
    let mut harness = build_harness("p2p_96")?;
    let local_peer = *harness.swarm.local_peer_id();

    handle_checked(
        &mut harness,
        &chat_topic(),
        local_peer,
        vec![0x96; (64 * 1024) + 128],
        "receiver-wallet",
    )?;

    assert!(!receiver_message_file(&harness.data_dir).exists());
    assert_initial_invariants(&harness)?;
    Ok(())
}

#[test]
fn p2p_97_005_sync_gossipsub_load_50_tiny_valid_file_chunks_are_persisted() -> TestResult {
    let mut harness = build_harness("p2p_97")?;

    for index in 0u32..50u32 {
        let byte = u8::try_from(index).map_err(fmt_err)?;
        let chunk = file_chunk(
            97,
            "load50.bin",
            "sender-wallet",
            "receiver-wallet",
            index,
            50,
            vec![byte],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    let count = fs::read_dir(file_chunk_dir(&harness.data_dir, 97))
        .map_err(fmt_err)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("chunk_"))
        .count();

    assert_eq!(count, 50usize);
    Ok(())
}

#[test]
fn p2p_98_005_sync_gossipsub_load_50_wrong_recipient_chunks_are_dropped() -> TestResult {
    let mut harness = build_harness("p2p_98")?;

    for index in 0u32..50u32 {
        let byte = u8::try_from(index).map_err(fmt_err)?;
        let chunk = file_chunk(
            98,
            "drop50.bin",
            "sender-wallet",
            "not-receiver",
            index,
            50,
            vec![byte],
        );

        handle_checked(
            &mut harness,
            &file_topic(),
            test_peer_id(),
            encode_chunk(&chunk)?,
            "receiver-wallet",
        )?;
    }

    assert_no_receiver_files(&harness.data_dir);
    Ok(())
}

#[test]
fn p2p_99_005_sync_gossipsub_end_to_end_file_validation_mix() -> TestResult {
    let mut harness = build_harness("p2p_99")?;

    let valid = file_chunk(
        99,
        "valid99.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"valid99".to_vec(),
    );
    let invalid_index = file_chunk(
        98,
        "invalid-index99.bin",
        "sender-wallet",
        "receiver-wallet",
        2,
        2,
        b"drop99".to_vec(),
    );
    let wrong_recipient = file_chunk(
        97,
        "wrong-recipient99.bin",
        "sender-wallet",
        "wrong-wallet",
        0,
        1,
        b"wrong99".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&invalid_index)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&wrong_recipient)?,
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&valid)?,
        "receiver-wallet",
    )?;

    assert!(!file_chunk_dir(&harness.data_dir, 98).exists());
    assert!(!file_chunk_dir(&harness.data_dir, 97).exists());
    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 99, 0)).map_err(fmt_err)?,
        b"valid99"
    );
    Ok(())
}

#[test]
fn p2p_100_005_sync_gossipsub_final_mixed_gossip_state_invariants() -> TestResult {
    let mut harness = build_harness("p2p_100")?;
    harness.sync.total_to_download = 1_000;
    harness.sync.downloaded = 250;

    handle_checked(
        &mut harness,
        &generic_topic(),
        test_peer_id(),
        vec![0x10; 64],
        "receiver-wallet",
    )?;
    handle_checked(
        &mut harness,
        &chat_topic(),
        test_peer_id(),
        vec![0x20; 64],
        "receiver-wallet",
    )?;

    let kept = file_chunk(
        100,
        "final.bin",
        "sender-wallet",
        "receiver-wallet",
        0,
        1,
        b"final keep".to_vec(),
    );

    handle_checked(
        &mut harness,
        &file_topic(),
        test_peer_id(),
        encode_chunk(&kept)?,
        "receiver-wallet",
    )?;

    assert_eq!(
        fs::read(chunk_path(&harness.data_dir, 100, 0)).map_err(fmt_err)?,
        b"final keep"
    );
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());
    assert_eq!(harness.db.get_tip_height().map_err(fmt_err)?, 0);
    assert!(harness.chain.get_blocks().is_empty());
    assert!(harness.chain.get_balances().is_empty());
    Ok(())
}
