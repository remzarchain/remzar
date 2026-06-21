#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{
    PeerId,
    gossipsub::{
        Event as GossipsubEvent, IdentTopic, Message as GossipsubMessage, MessageId, TopicHash,
    },
    identity,
    swarm::Swarm,
};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    consensus::por_000_ephemeral_registration::RegistryData,
    network::{
        p2p_003_behaviour::RemzarBehaviour, p2p_011_peerbook::PeerBook, p2p_014_chat::chat_topic,
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep;

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_GOSSIP_BYTES_FOR_TEST: usize = 1024 * 1024;
const MAX_CHAT_WIRE_BYTES_FOR_TEST: usize = 64 * 1024;
const MAX_FILE_WIRE_BYTES_FOR_TEST: usize = 256 * 1024;
const MAX_FILE_CHUNK_BYTES_FOR_TEST: usize = 192 * 1024;
const MAX_FILE_TOTAL_CHUNKS_FOR_TEST: u32 = 200_000;
const MAX_FILENAME_BYTES_FOR_TEST: usize = 255;
const MAX_WALLET_TEXT_BYTES_FOR_TEST: usize = 256;

const FILE_TOPIC_NAME_FOR_TEST: &str = "remzar.file.v1";
const PEER_MESH_TOPIC_FOR_TEST: &str = "/remzar/peer_mesh/1.0.0";
const TX_TOPIC_FOR_TEST: &str = "/remzar/tx/1.0.0";
const TXBATCH_TOPIC_FOR_TEST: &str = "/remzar/tx_batch/1.0.0";
const REWARD_TOPIC_FOR_TEST: &str = "/remzar/reward/1.0.0";
const REGISTER_TOPIC_FOR_TEST: &str = "/remzar/register_node/1.0.0";
const BLOCK_TOPIC_FOR_TEST: &str = "/remzar/block/1.0.0";
const POR_TOPIC_FOR_TEST: &str = "/remzar/por/puzzle_proof/1.0.0";

struct GossipHarness {
    sync: P2pSync,
    swarm: Swarm<RemzarBehaviour>,
    chain: AccountModelTree,
    db: Arc<RockDBManager>,
    registry_db: Arc<RockDBManager>,
    mempool: Arc<MemPool>,
    registry_data: RegistryData,
    opts: NodeOpts,
    data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicGossipSnapshot {
    has_synced: bool,
    is_syncing: bool,
    sync_percent: String,
    total_to_download: u64,
    downloaded: u64,
    pending_versions_len: usize,
    pending_blocks_len: usize,
    pending_batches_len: usize,
    pending_pq_len: usize,
    block_queue_len: usize,
    batch_queue_len: usize,
    pq_ready_len: usize,
    registry_wallets_len: usize,
    has_background_sync_work: bool,
    expected_genesis_hash: Option<String>,
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

fn now_millis_u64_for_test() -> u64 {
    u64::try_from(now_millis_for_test()).unwrap_or(0)
}

fn unique_data_dir(test_name: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_e2e_p2p_005_sync_gossipsub_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn build_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_string(),
        founder: false,
    }
}

fn build_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let keypair = identity::Keypair::generate_ed25519();

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(fmt_err)?
        .with_behaviour(|key| {
            RemzarBehaviour::new(key.clone()).unwrap_or_else(|err| {
                panic!("failed to build RemzarBehaviour for e2e test swarm: {err}");
            })
        })
        .map_err(fmt_err)?
        .build();

    Ok(swarm)
}

fn build_gossip_harness(test_name: &str) -> TestResult<GossipHarness> {
    let data_dir = unique_data_dir(test_name);
    std::fs::create_dir_all(&data_dir).map_err(fmt_err)?;

    let opts = build_node_opts(&data_dir);
    let blockchain_path = data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_text = blockchain_path.to_string_lossy().into_owned();

    let db = Arc::new(
        RockDBManager::new_blockchain(&opts, blockchain_path_text.as_str()).map_err(fmt_err)?,
    );

    let sync_chain = AccountModelTree::with_manager((*db).clone());
    let handler_chain = AccountModelTree::with_manager((*db).clone());

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let peerbook = Arc::new(Mutex::new(PeerBook::default()));
    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));

    let sync = P2pSync::new(
        sync_chain,
        Arc::clone(&db),
        Arc::clone(&mempool),
        peerbook,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR),
        Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
        reorg_manager,
    );

    Ok(GossipHarness {
        sync,
        swarm: build_swarm()?,
        chain: handler_chain,
        db: Arc::clone(&db),
        registry_db: Arc::clone(&db),
        mempool,
        registry_data: RegistryData::default(),
        opts,
        data_dir,
    })
}

fn test_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn local_wallet() -> String {
    GlobalConfiguration::GENESIS_VALIDATOR.to_string()
}

fn other_wallet() -> String {
    format!("r{}", "2".repeat(128usize))
}

fn long_wallet(len: usize) -> String {
    "r".repeat(len)
}

fn snapshot(h: &GossipHarness) -> PublicGossipSnapshot {
    PublicGossipSnapshot {
        has_synced: h.sync.has_synced(),
        is_syncing: h.sync.is_syncing(),
        sync_percent: format!("{:.2}", h.sync.sync_percent()),
        total_to_download: h.sync.total_to_download,
        downloaded: h.sync.downloaded,
        pending_versions_len: h.sync.pending_versions.len(),
        pending_blocks_len: h.sync.pending_blocks.len(),
        pending_batches_len: h.sync.pending_batches.len(),
        pending_pq_len: h.sync.pending_pq.len(),
        block_queue_len: h.sync.block_queue.len(),
        batch_queue_len: h.sync.batch_queue.len(),
        pq_ready_len: h.sync.pq_ready_peers.len(),
        registry_wallets_len: h.registry_data.sorted_wallets().len(),
        has_background_sync_work: h.sync.has_background_sync_work(),
        expected_genesis_hash: h.sync.expected_genesis_hash.clone(),
    }
}

fn make_message_event_with_hash(
    propagation_source: PeerId,
    topic_hash: TopicHash,
    data: Vec<u8>,
    message_id_suffix: &str,
) -> GossipsubEvent {
    GossipsubEvent::Message {
        propagation_source,
        message_id: MessageId::from(format!("msg-{message_id_suffix}")),
        message: GossipsubMessage {
            source: Some(propagation_source),
            data,
            sequence_number: None,
            topic: topic_hash,
        },
    }
}

fn make_message_event(
    propagation_source: PeerId,
    topic: &str,
    data: Vec<u8>,
    message_id_suffix: &str,
) -> GossipsubEvent {
    make_message_event_with_hash(
        propagation_source,
        IdentTopic::new(topic).hash(),
        data,
        message_id_suffix,
    )
}

fn make_chat_message_event(
    propagation_source: PeerId,
    data: Vec<u8>,
    message_id_suffix: &str,
) -> GossipsubEvent {
    make_message_event_with_hash(
        propagation_source,
        chat_topic().hash(),
        data,
        message_id_suffix,
    )
}

fn subscribed_event(peer: PeerId, topic: &str) -> GossipsubEvent {
    let topic = IdentTopic::new(topic);
    GossipsubEvent::Subscribed {
        peer_id: peer,
        topic: topic.hash(),
    }
}

fn unsubscribed_event(peer: PeerId, topic: &str) -> GossipsubEvent {
    let topic = IdentTopic::new(topic);
    GossipsubEvent::Unsubscribed {
        peer_id: peer,
        topic: topic.hash(),
    }
}

fn handle_checked(
    h: &mut GossipHarness,
    event: GossipsubEvent,
    propagation_source: PeerId,
    local_wallet: &str,
) -> TestResult {
    handle_gossipsub_checked(
        event,
        propagation_source,
        &mut h.swarm,
        &mut h.chain,
        &h.db,
        &h.registry_db,
        &h.mempool,
        &mut h.registry_data,
        &mut h.sync,
        None,
        local_wallet,
        &h.opts,
    )
    .map_err(fmt_err)
}

fn handle_wrapper(
    h: &mut GossipHarness,
    event: GossipsubEvent,
    propagation_source: PeerId,
    local_wallet: &str,
) {
    handle_gossipsub(
        event,
        propagation_source,
        &mut h.swarm,
        &mut h.chain,
        &h.db,
        &h.registry_db,
        &h.mempool,
        &mut h.registry_data,
        &mut h.sync,
        None,
        local_wallet,
        &h.opts,
    );
}

fn receiver_chat_file(data_dir: &Path) -> PathBuf {
    data_dir
        .join("receiver.message")
        .join("received_chat.jsonl")
}

fn receiver_files_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("receiver.files")
}

fn file_chunk_dir(data_dir: &Path, chunk: &FileChunkMessage) -> PathBuf {
    receiver_files_dir(data_dir).join(hex::encode(chunk.file_id))
}

fn file_chunk_path(data_dir: &Path, chunk: &FileChunkMessage) -> PathBuf {
    file_chunk_dir(data_dir, chunk).join(format!("chunk_{:06}.bin", chunk.chunk_index))
}

fn file_meta_path(data_dir: &Path, chunk: &FileChunkMessage) -> PathBuf {
    file_chunk_dir(data_dir, chunk).join("meta.json")
}

fn assert_no_receiver_artifacts(h: &GossipHarness) {
    assert!(!receiver_chat_file(&h.data_dir).exists());
    assert!(!receiver_files_dir(&h.data_dir).exists());
}

fn hash_bytes(bytes: &[u8]) -> ([u8; 32], String) {
    let digest = blake3::hash(bytes);
    let mut file_id = [0u8; 32];
    file_id.copy_from_slice(digest.as_bytes());
    (file_id, hex::encode(file_id))
}

fn file_chunk(
    seed: u8,
    filename: &str,
    to_wallet: String,
    chunk_index: u32,
    total_chunks: u32,
    chunk_bytes: Vec<u8>,
) -> FileChunkMessage {
    let actual_bytes = if chunk_bytes.is_empty() {
        vec![seed]
    } else {
        chunk_bytes
    };

    let (file_id, content_hash_hex) = hash_bytes(&actual_bytes);

    FileChunkMessage {
        file_id,
        from_wallet: other_wallet(),
        to_wallet,
        chunk_index,
        total_chunks,
        filename: filename.to_string(),
        file_size_bytes: u64::try_from(actual_bytes.len()).unwrap_or(0),
        content_hash_hex,
        chunk_bytes: actual_bytes,
        timestamp_ms: now_millis_u64_for_test(),
    }
}

fn encoded_file_chunk(chunk: &FileChunkMessage) -> TestResult<Vec<u8>> {
    postcard::to_allocvec(chunk).map_err(fmt_err)
}

fn malformed_payload(seed: u8, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);

    for idx in 0..len {
        let i = u8::try_from(idx % 251usize).unwrap_or(0);
        out.push(seed.wrapping_add(i.rotate_left(u32::from(seed % 7))));
    }

    out
}

#[tokio::test]
async fn e2e_01_gossipsub_harness_boots_with_public_state_only() -> TestResult {
    let h = build_gossip_harness("e2e_01")?;

    assert!(h.data_dir.exists());
    assert_eq!(h.swarm.behaviour().gossipsub.all_peers().count(), 0);
    assert!(h.sync.pending_versions.is_empty());
    assert!(h.sync.pending_blocks.is_empty());
    assert!(h.sync.pending_batches.is_empty());
    assert_eq!(h.registry_data.sorted_wallets().len(), 0);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_02_non_message_subscribed_event_is_public_noop() -> TestResult {
    let mut h = build_gossip_harness("e2e_02")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    handle_checked(
        &mut h,
        subscribed_event(peer, TX_TOPIC_FOR_TEST),
        peer,
        &local_wallet(),
    )?;
    let after = snapshot(&h);

    assert_eq!(after, before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_03_non_message_unsubscribed_event_is_public_noop() -> TestResult {
    let mut h = build_gossip_harness("e2e_03")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    handle_checked(
        &mut h,
        unsubscribed_event(peer, TX_TOPIC_FOR_TEST),
        peer,
        &local_wallet(),
    )?;
    let after = snapshot(&h);

    assert_eq!(after, before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_04_self_echo_oversized_generic_message_is_ignored_before_decode() -> TestResult {
    let mut h = build_gossip_harness("e2e_04")?;
    let local_peer = *h.swarm.local_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        local_peer,
        TX_TOPIC_FOR_TEST,
        vec![0xabu8; MAX_GOSSIP_BYTES_FOR_TEST + 1],
        "04",
    );

    handle_checked(&mut h, event, local_peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_05_self_echo_valid_file_chunk_is_ignored_and_not_persisted() -> TestResult {
    let mut h = build_gossip_harness("e2e_05")?;
    let local_peer = *h.swarm.local_peer_id();

    let chunk = file_chunk(
        5,
        "self_echo.txt",
        local_wallet(),
        0,
        1,
        b"self echo".to_vec(),
    );
    let event = make_message_event(
        local_peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "05",
    );

    handle_checked(&mut h, event, local_peer, &local_wallet())?;

    assert!(!file_chunk_path(&h.data_dir, &chunk).exists());
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_06_oversized_generic_payload_is_dropped_without_state_change() -> TestResult {
    let mut h = build_gossip_harness("e2e_06")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        peer,
        TX_TOPIC_FOR_TEST,
        vec![0xcd; MAX_GOSSIP_BYTES_FOR_TEST + 1],
        "06",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_07_exact_max_generic_payload_is_handled_without_panic_or_state_change() -> TestResult {
    let mut h = build_gossip_harness("e2e_07")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        peer,
        BLOCK_TOPIC_FOR_TEST,
        malformed_payload(7, MAX_GOSSIP_BYTES_FOR_TEST),
        "07",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_08_small_malformed_generic_payload_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_08")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, TX_TOPIC_FOR_TEST, b"not-postcard".to_vec(), "08");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_09_empty_generic_payload_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_09")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, TX_TOPIC_FOR_TEST, Vec::new(), "09");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_10_truncated_random_generic_payload_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_10")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let mut data = malformed_payload(10, 128);
    data.truncate(17);

    let event = make_message_event(peer, TXBATCH_TOPIC_FOR_TEST, data, "10");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_11_malformed_chat_payload_creates_no_chat_file() -> TestResult {
    let mut h = build_gossip_harness("e2e_11")?;
    let peer = test_peer_id();

    let event = make_chat_message_event(peer, b"not-a-chat-envelope".to_vec(), "11");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_chat_file(&h.data_dir).exists());
    assert!(h.registry_data.sorted_wallets().is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_12_oversized_chat_payload_is_dropped_before_decode() -> TestResult {
    let mut h = build_gossip_harness("e2e_12")?;
    let peer = test_peer_id();

    let event = make_chat_message_event(peer, vec![0x11; MAX_CHAT_WIRE_BYTES_FOR_TEST + 1], "12");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_chat_file(&h.data_dir).exists());
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_13_exact_max_chat_random_payload_is_non_fatal_and_not_persisted() -> TestResult {
    let mut h = build_gossip_harness("e2e_13")?;
    let peer = test_peer_id();

    let event = make_chat_message_event(
        peer,
        malformed_payload(13, MAX_CHAT_WIRE_BYTES_FOR_TEST),
        "13",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_chat_file(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_14_chat_bytes_on_generic_topic_do_not_create_chat_file() -> TestResult {
    let mut h = build_gossip_harness("e2e_14")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        TX_TOPIC_FOR_TEST,
        br#"{"m":"wrong topic"}"#.to_vec(),
        "14",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_chat_file(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_15_malformed_file_payload_creates_no_receiver_files_dir() -> TestResult {
    let mut h = build_gossip_harness("e2e_15")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        b"not-a-file-chunk".to_vec(),
        "15",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_16_oversized_file_envelope_is_dropped_before_decode() -> TestResult {
    let mut h = build_gossip_harness("e2e_16")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        vec![0x16; MAX_FILE_WIRE_BYTES_FOR_TEST + 1],
        "16",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_17_valid_file_chunk_for_other_wallet_is_not_persisted() -> TestResult {
    let mut h = build_gossip_harness("e2e_17")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        17,
        "other.txt",
        other_wallet(),
        0,
        1,
        b"not for me".to_vec(),
    );
    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "17",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());
    assert!(!file_chunk_path(&h.data_dir, &chunk).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_18_valid_file_chunk_for_local_wallet_creates_receiver_files_dir() -> TestResult {
    let mut h = build_gossip_harness("e2e_18")?;
    let peer = test_peer_id();

    let chunk = file_chunk(18, "hello.txt", local_wallet(), 0, 1, b"hello".to_vec());
    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "18",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(receiver_files_dir(&h.data_dir).exists());
    assert!(file_chunk_dir(&h.data_dir, &chunk).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_19_valid_file_chunk_for_local_wallet_writes_chunk_file() -> TestResult {
    let mut h = build_gossip_harness("e2e_19")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        19,
        "chunk.txt",
        local_wallet(),
        0,
        1,
        b"chunk-data".to_vec(),
    );
    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "19",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(file_chunk_path(&h.data_dir, &chunk).exists());
    assert_eq!(
        fs::read(file_chunk_path(&h.data_dir, &chunk)).map_err(fmt_err)?,
        chunk.chunk_bytes
    );

    Ok(())
}

#[tokio::test]
async fn e2e_20_valid_file_chunk_for_local_wallet_writes_metadata() -> TestResult {
    let mut h = build_gossip_harness("e2e_20")?;
    let peer = test_peer_id();

    let chunk = file_chunk(20, "meta.txt", local_wallet(), 0, 1, b"metadata".to_vec());
    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "20",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    let meta = fs::read_to_string(file_meta_path(&h.data_dir, &chunk)).map_err(fmt_err)?;
    assert!(meta.contains("meta.txt"));
    assert!(meta.contains(&hex::encode(chunk.file_id)));

    Ok(())
}

#[tokio::test]
async fn e2e_21_unsafe_filename_is_replaced_in_file_metadata() -> TestResult {
    let mut h = build_gossip_harness("e2e_21")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        21,
        "../evil.txt",
        local_wallet(),
        0,
        1,
        b"unsafe-name".to_vec(),
    );

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "21",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!file_meta_path(&h.data_dir, &chunk).exists());
    assert!(!h.data_dir.join("receiver.files").exists());

    Ok(())
}

#[tokio::test]
async fn e2e_22_file_chunk_with_index_equal_total_chunks_is_dropped() -> TestResult {
    let mut h = build_gossip_harness("e2e_22")?;
    let peer = test_peer_id();

    let chunk = file_chunk(22, "bad-index.txt", local_wallet(), 1, 1, b"bad".to_vec());
    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "22",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_23_file_chunk_with_absurd_total_chunks_is_dropped() -> TestResult {
    let mut h = build_gossip_harness("e2e_23")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        23,
        "too-many.txt",
        local_wallet(),
        0,
        MAX_FILE_TOTAL_CHUNKS_FOR_TEST + 1,
        b"bad-total".to_vec(),
    );

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "23",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_24_oversized_file_chunk_bytes_are_dropped() -> TestResult {
    let mut h = build_gossip_harness("e2e_24")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        24,
        "oversized-chunk.bin",
        local_wallet(),
        0,
        1,
        vec![0x24; MAX_FILE_CHUNK_BYTES_FOR_TEST + 1],
    );

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "24",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_25_oversized_filename_is_dropped_before_disk_write() -> TestResult {
    let mut h = build_gossip_harness("e2e_25")?;
    let peer = test_peer_id();

    let filename = "a".repeat(MAX_FILENAME_BYTES_FOR_TEST + 1);
    let chunk = file_chunk(25, &filename, local_wallet(), 0, 1, b"bad-name".to_vec());

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "25",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_26_oversized_file_from_wallet_is_dropped_before_disk_write() -> TestResult {
    let mut h = build_gossip_harness("e2e_26")?;
    let peer = test_peer_id();

    let mut chunk = file_chunk(
        26,
        "from-long.txt",
        local_wallet(),
        0,
        1,
        b"bad-from".to_vec(),
    );
    chunk.from_wallet = long_wallet(MAX_WALLET_TEXT_BYTES_FOR_TEST + 1);

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "26",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_27_oversized_file_to_wallet_is_dropped_before_disk_write() -> TestResult {
    let mut h = build_gossip_harness("e2e_27")?;
    let peer = test_peer_id();

    let mut chunk = file_chunk(27, "to-long.txt", local_wallet(), 0, 1, b"bad-to".to_vec());
    chunk.to_wallet = long_wallet(MAX_WALLET_TEXT_BYTES_FOR_TEST + 1);

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "27",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_28_invalid_postcard_file_envelope_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_28")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        malformed_payload(28, 512),
        "28",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_29_repeated_malformed_file_messages_do_not_create_artifacts() -> TestResult {
    let mut h = build_gossip_harness("e2e_29")?;
    let peer = test_peer_id();

    for idx in 0usize..20usize {
        let event = make_message_event(
            peer,
            FILE_TOPIC_NAME_FOR_TEST,
            malformed_payload(29, 32usize + idx),
            &format!("29-{idx}"),
        );
        handle_checked(&mut h, event, peer, &local_wallet())?;
    }

    assert!(!receiver_files_dir(&h.data_dir).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_30_repeated_same_valid_file_chunk_is_idempotent_on_disk_path() -> TestResult {
    let mut h = build_gossip_harness("e2e_30")?;
    let peer = test_peer_id();

    let chunk = file_chunk(30, "repeat.txt", local_wallet(), 0, 1, b"repeat".to_vec());
    let bytes = encoded_file_chunk(&chunk)?;

    for idx in 0usize..5usize {
        let event = make_message_event(
            peer,
            FILE_TOPIC_NAME_FOR_TEST,
            bytes.clone(),
            &format!("30-{idx}"),
        );
        handle_checked(&mut h, event, peer, &local_wallet())?;
    }

    assert!(file_chunk_path(&h.data_dir, &chunk).exists());
    assert_eq!(
        fs::read(file_chunk_path(&h.data_dir, &chunk)).map_err(fmt_err)?,
        chunk.chunk_bytes
    );

    Ok(())
}

#[tokio::test]
async fn e2e_31_wrapper_handle_gossipsub_malformed_message_does_not_panic() -> TestResult {
    let mut h = build_gossip_harness("e2e_31")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, TX_TOPIC_FOR_TEST, malformed_payload(31, 64), "31");

    handle_wrapper(&mut h, event, peer, &local_wallet());

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_32_wrapper_handle_gossipsub_self_echo_has_no_effect() -> TestResult {
    let mut h = build_gossip_harness("e2e_32")?;
    let local_peer = *h.swarm.local_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        local_peer,
        TX_TOPIC_FOR_TEST,
        malformed_payload(32, 64),
        "32",
    );

    handle_wrapper(&mut h, event, local_peer, &local_wallet());

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_33_wrapper_handle_gossipsub_oversized_payload_has_no_effect() -> TestResult {
    let mut h = build_gossip_harness("e2e_33")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        peer,
        TX_TOPIC_FOR_TEST,
        vec![0x33; MAX_GOSSIP_BYTES_FOR_TEST + 1],
        "33",
    );

    handle_wrapper(&mut h, event, peer, &local_wallet());

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_34_malformed_peer_mesh_message_does_not_register_wallets() -> TestResult {
    let mut h = build_gossip_harness("e2e_34")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        PEER_MESH_TOPIC_FOR_TEST,
        malformed_payload(34, 48),
        "34",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(h.registry_data.sorted_wallets().len(), 0);

    Ok(())
}

#[tokio::test]
async fn e2e_35_malformed_tx_topic_message_does_not_create_sync_work() -> TestResult {
    let mut h = build_gossip_harness("e2e_35")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, TX_TOPIC_FOR_TEST, malformed_payload(35, 48), "35");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_36_malformed_block_topic_message_does_not_trigger_sync() -> TestResult {
    let mut h = build_gossip_harness("e2e_36")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, BLOCK_TOPIC_FOR_TEST, malformed_payload(36, 48), "36");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_37_malformed_register_topic_message_does_not_register_validator() -> TestResult {
    let mut h = build_gossip_harness("e2e_37")?;
    let peer = test_peer_id();

    let event = make_message_event(
        peer,
        REGISTER_TOPIC_FOR_TEST,
        malformed_payload(37, 48),
        "37",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(h.registry_data.sorted_wallets().is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_38_malformed_por_topic_message_is_ignored_without_builder() -> TestResult {
    let mut h = build_gossip_harness("e2e_38")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, POR_TOPIC_FOR_TEST, malformed_payload(38, 48), "38");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_39_malformed_reward_topic_message_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_39")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(peer, REWARD_TOPIC_FOR_TEST, malformed_payload(39, 48), "39");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_40_malformed_txbatch_topic_message_does_not_create_file_or_sync_artifacts()
-> TestResult {
    let mut h = build_gossip_harness("e2e_40")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        peer,
        TXBATCH_TOPIC_FOR_TEST,
        malformed_payload(40, 48),
        "40",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_41_unknown_topic_malformed_payload_is_non_fatal() -> TestResult {
    let mut h = build_gossip_harness("e2e_41")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        peer,
        "/remzar/unknown/1.0.0",
        malformed_payload(41, 48),
        "41",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_42_all_consensus_topics_reject_malformed_payloads_without_state_change() -> TestResult
{
    let mut h = build_gossip_harness("e2e_42")?;
    let peer = test_peer_id();

    let topics = [
        TX_TOPIC_FOR_TEST,
        TXBATCH_TOPIC_FOR_TEST,
        REWARD_TOPIC_FOR_TEST,
        REGISTER_TOPIC_FOR_TEST,
        BLOCK_TOPIC_FOR_TEST,
        POR_TOPIC_FOR_TEST,
        PEER_MESH_TOPIC_FOR_TEST,
    ];

    let before = snapshot(&h);

    for (idx, topic) in topics.iter().enumerate() {
        let event = make_message_event(
            peer,
            topic,
            malformed_payload(42, 16usize + idx),
            &format!("42-{idx}"),
        );
        handle_checked(&mut h, event, peer, &local_wallet())?;
    }

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_43_all_offchain_topics_reject_malformed_payloads_without_artifacts() -> TestResult {
    let mut h = build_gossip_harness("e2e_43")?;
    let peer = test_peer_id();

    let chat_event = make_chat_message_event(peer, malformed_payload(43, 32), "43-chat");
    handle_checked(&mut h, chat_event, peer, &local_wallet())?;

    let file_event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        malformed_payload(44, 33),
        "43-file",
    );
    handle_checked(&mut h, file_event, peer, &local_wallet())?;

    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_44_event_source_and_argument_source_mismatch_is_non_fatal_for_bad_payload()
-> TestResult {
    let mut h = build_gossip_harness("e2e_44")?;
    let event_peer = test_peer_id();
    let argument_peer = test_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        event_peer,
        TX_TOPIC_FOR_TEST,
        malformed_payload(44, 48),
        "44",
    );

    handle_checked(&mut h, event, argument_peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);

    Ok(())
}

#[tokio::test]
async fn e2e_45_argument_source_self_echo_ignores_remote_event_payload() -> TestResult {
    let mut h = build_gossip_harness("e2e_45")?;
    let event_peer = test_peer_id();
    let local_peer = *h.swarm.local_peer_id();

    let before = snapshot(&h);
    let event = make_message_event(
        event_peer,
        FILE_TOPIC_NAME_FOR_TEST,
        malformed_payload(45, 48),
        "45",
    );

    handle_checked(&mut h, event, local_peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_46_unsubscribed_file_topic_event_is_public_noop() -> TestResult {
    let mut h = build_gossip_harness("e2e_46")?;
    let peer = test_peer_id();

    let before = snapshot(&h);
    handle_checked(
        &mut h,
        unsubscribed_event(peer, FILE_TOPIC_NAME_FOR_TEST),
        peer,
        &local_wallet(),
    )?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    Ok(())
}

#[tokio::test]
async fn e2e_47_valid_file_chunk_on_wrong_topic_is_not_persisted_as_file() -> TestResult {
    let mut h = build_gossip_harness("e2e_47")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        47,
        "wrong-topic.txt",
        local_wallet(),
        0,
        1,
        b"wrong topic".to_vec(),
    );

    let event = make_message_event(peer, TX_TOPIC_FOR_TEST, encoded_file_chunk(&chunk)?, "47");

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(!receiver_files_dir(&h.data_dir).exists());
    assert!(!file_chunk_path(&h.data_dir, &chunk).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_48_file_chunk_to_wallet_is_case_insensitive_for_persistence_gate() -> TestResult {
    let mut h = build_gossip_harness("e2e_48")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        48,
        "case-insensitive.txt",
        local_wallet().to_ascii_uppercase(),
        0,
        1,
        b"case".to_vec(),
    );

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "48",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(file_chunk_path(&h.data_dir, &chunk).exists());

    Ok(())
}

#[tokio::test]
async fn e2e_49_max_allowed_file_chunk_bytes_can_be_persisted_for_local_wallet() -> TestResult {
    let mut h = build_gossip_harness("e2e_49")?;
    let peer = test_peer_id();

    let chunk = file_chunk(
        49,
        "max-chunk.bin",
        local_wallet(),
        0,
        1,
        vec![0x49; MAX_FILE_CHUNK_BYTES_FOR_TEST],
    );

    let event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "49",
    );

    handle_checked(&mut h, event, peer, &local_wallet())?;

    assert!(file_chunk_path(&h.data_dir, &chunk).exists());
    assert_eq!(
        fs::metadata(file_chunk_path(&h.data_dir, &chunk))
            .map_err(fmt_err)?
            .len(),
        u64::try_from(MAX_FILE_CHUNK_BYTES_FOR_TEST).unwrap_or(0)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_gossipsub_lifecycle_malformed_inputs_valid_file_and_self_echo_safety()
-> TestResult {
    let mut h = build_gossip_harness("e2e_50")?;
    let peer = test_peer_id();
    let local_peer = *h.swarm.local_peer_id();

    let before = snapshot(&h);

    let bad_generic =
        make_message_event(peer, TX_TOPIC_FOR_TEST, malformed_payload(50, 64), "50-a");
    handle_checked(&mut h, bad_generic, peer, &local_wallet())?;

    let bad_chat = make_chat_message_event(peer, malformed_payload(51, 64), "50-b");
    handle_checked(&mut h, bad_chat, peer, &local_wallet())?;

    assert_eq!(snapshot(&h), before);
    assert_no_receiver_artifacts(&h);

    let chunk = file_chunk(
        50,
        "full-life.txt",
        local_wallet(),
        0,
        1,
        b"full lifecycle".to_vec(),
    );
    let file_event = make_message_event(
        peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&chunk)?,
        "50-c",
    );
    handle_checked(&mut h, file_event, peer, &local_wallet())?;

    assert!(file_chunk_path(&h.data_dir, &chunk).exists());

    let self_echo_chunk = file_chunk(
        51,
        "self-echo-ignored.txt",
        local_wallet(),
        0,
        1,
        b"ignored".to_vec(),
    );

    let self_echo_event = make_message_event(
        local_peer,
        FILE_TOPIC_NAME_FOR_TEST,
        encoded_file_chunk(&self_echo_chunk)?,
        "50-d",
    );
    handle_checked(&mut h, self_echo_event, local_peer, &local_wallet())?;

    assert!(!file_chunk_path(&h.data_dir, &self_echo_chunk).exists());
    assert!(h.sync.pending_blocks.is_empty());
    assert!(h.sync.pending_batches.is_empty());
    assert!(h.registry_data.sorted_wallets().is_empty());

    sleep(Duration::from_millis(1)).await;

    Ok(())
}
