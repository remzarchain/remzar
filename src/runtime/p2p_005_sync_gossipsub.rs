// src/network/p2p_005_sync_gossipsub.rs

use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::{
    blockchain::{
        blockchain_001_builder::BlockchainBuilder, mempool::MemPool,
        transaction_005_tx_account_tree::AccountModelTree,
    },
    consensus::por_000_ephemeral_registration::RegistryData,
    network::{
        p2p_002_protocal::RemzarMessage,
        p2p_003_behaviour::RemzarBehaviour,
        p2p_014_chat::{ChatMessage, chat_topic, try_decode_incoming},
    },
    runtime::p2p_006_sync_runtime::NodeOpts,
    storage::rocksdb_005_manager::RockDBManager,
    utility::{send_file::FileChunkMessage, time_policy::TimePolicy},
};
use chrono::DateTime;
use libp2p::{
    PeerId,
    gossipsub::{Event as GossipsubEvent, IdentTopic},
    swarm::Swarm,
};
use postcard;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

// shared canonicalizer (single source of truth)
use crate::utility::helper::canon_wallet_id_checked;

/// ───────────── Defensive caps ─────────────
/// Hard cap for any inbound gossipsub message payload we will touch (bytes).
const MAX_GOSSIP_BYTES: usize = 2 * 1024 * 1024;

/// Chat payload cap (bytes). Chat is off-chain; keep it small to avoid stalling.
const MAX_CHAT_WIRE_BYTES: usize = 64 * 1024;

/// File-chunk postcard envelope cap (bytes). Prevent decode/alloc bombs.
const MAX_FILE_WIRE_BYTES: usize = 256 * 1024;

/// Maximum bytes allowed for chunk.chunk_bytes in a single message.
const MAX_FILE_CHUNK_BYTES: usize = 192 * 1024;

/// Cap number of chunks to prevent metadata causing stalls.
const MAX_FILE_TOTAL_CHUNKS: u32 = 4_096;

/// Cap a single advertised file transfer.
const MAX_FILE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

/// BLAKE3 hex is 64 chars; allow only that canonical content-hash shape.
const BLAKE3_HEX_LEN: usize = 64;

/// Cap filename length to avoid path/memory abuse.
const MAX_FILENAME_BYTES: usize = 255;

/// Cap wallet string lengths (best-effort input bounds; canonization is still used).
const MAX_WALLET_TEXT_BYTES: usize = 256;

/// Cap peer-mesh announce fanout from a single gossip message.
const MAX_PEER_MESH_ADDRS_PER_ANNOUNCE: usize = 64;

/// Cap serialized Multiaddr bytes accepted from peer-mesh gossip.
const MAX_PEER_MESH_MULTIADDR_BYTES: usize = 256;

/// Prevent a malicious block advertisement from setting sync_target to u64::MAX.
const MAX_GOSSIP_BLOCK_HEIGHT_ADVANCE: u64 = 1_000_000;

/// Runtime-only timestamp for gossip diagnostics/logs.
#[inline]
fn runtime_log_timestamp() -> String {
    match TimePolicy::now_unix_secs_runtime() {
        Ok(now_unix) => {
            let Some(now_i64) = i64::try_from(now_unix).ok() else {
                return format!("unix:{now_unix}");
            };

            DateTime::from_timestamp(now_i64, 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| format!("unix:{now_unix}"))
        }
        Err(..) => "time_unavailable".to_string(),
    }
}

#[inline]
fn short_wallet_for_log(wallet: &str) -> String {
    let w = wallet.trim();
    let chars: Vec<char> = w.chars().collect();

    if chars.len() <= 18 {
        w.to_string()
    } else {
        let prefix: String = chars.iter().take(8).collect();
        let mut suffix_chars: Vec<char> = chars.iter().rev().take(6).copied().collect();
        suffix_chars.reverse();
        let suffix: String = suffix_chars.into_iter().collect();
        format!("{prefix}...{suffix}")
    }
}

#[inline]
fn short_peer_for_log(peer: &str) -> String {
    let p = peer.trim();
    let chars: Vec<char> = p.chars().collect();

    if chars.len() <= 18 {
        p.to_string()
    } else {
        let prefix: String = chars.iter().take(10).collect();
        let mut suffix_chars: Vec<char> = chars.iter().rev().take(8).copied().collect();
        suffix_chars.reverse();
        let suffix: String = suffix_chars.into_iter().collect();
        format!("{prefix}...{suffix}")
    }
}

#[inline(always)]
fn consensus_max_bytes() -> usize {
    usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX)
}

/// Guard a serialized byte buffer against the consensus cap.
#[inline(always)]
fn ensure_within_consensus_cap(label: &str, n: usize) -> anyhow::Result<()> {
    let cap = consensus_max_bytes();
    if n > cap {
        return Err(anyhow::anyhow!(
            "{label} exceeds MAX_BLOCK_SIZE: {n} bytes (cap {cap})"
        ));
    }
    Ok(())
}

#[inline(always)]
fn is_ascii_hex(s: &str) -> bool {
    s.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

#[inline(always)]
fn local_tip_snapshot(chain: &AccountModelTree, blockchain_db: &Arc<RockDBManager>) -> u64 {
    blockchain_db
        .get_tip_height()
        .unwrap_or_else(|_| chain.latest_block_height() as u64)
}

#[inline(always)]
fn is_reasonable_gossip_peer_tip(local_tip: u64, peer_tip: u64) -> bool {
    if peer_tip <= local_tip {
        return false;
    }

    peer_tip.saturating_sub(local_tip) <= MAX_GOSSIP_BLOCK_HEIGHT_ADVANCE
}

fn validate_file_chunk_shape(chunk: &FileChunkMessage) -> bool {
    if chunk.filename.len() > MAX_FILENAME_BYTES || !is_safe_leaf_name(&chunk.filename) {
        return false;
    }

    if chunk.total_chunks == 0 || chunk.total_chunks > MAX_FILE_TOTAL_CHUNKS {
        return false;
    }

    if chunk.chunk_index >= chunk.total_chunks {
        return false;
    }

    if chunk.chunk_bytes.len() > MAX_FILE_CHUNK_BYTES {
        return false;
    }

    // Avoid zero-byte chunk spam except for an explicitly empty one-chunk file.
    if chunk.chunk_bytes.is_empty() && !(chunk.file_size_bytes == 0 && chunk.total_chunks == 1) {
        return false;
    }

    if chunk.file_size_bytes > MAX_FILE_TOTAL_BYTES {
        return false;
    }

    let declared_capacity = u64::from(chunk.total_chunks)
        .saturating_mul(u64::try_from(MAX_FILE_CHUNK_BYTES).unwrap_or(u64::MAX));
    if chunk.file_size_bytes > declared_capacity {
        return false;
    }

    if chunk.content_hash_hex.len() != BLAKE3_HEX_LEN || !is_ascii_hex(&chunk.content_hash_hex) {
        return false;
    }

    if chunk.from_wallet.len() > MAX_WALLET_TEXT_BYTES
        || chunk.to_wallet.len() > MAX_WALLET_TEXT_BYTES
    {
        return false;
    }

    true
}

#[inline(always)]
fn multiaddr_gossip_len_ok(addr: &libp2p::Multiaddr) -> bool {
    addr.to_vec().len() <= MAX_PEER_MESH_MULTIADDR_BYTES
}

/// Resolve a deterministic per-node receive directory under opts.data_dir.
fn receiver_root_dir(opts: &NodeOpts, leaf: &str) -> anyhow::Result<PathBuf> {
    let base = opts.data_dir.trim();
    if base.is_empty() {
        return Err(anyhow::anyhow!(
            "NodeOpts.data_dir is empty; cannot persist inbound p2p artifacts"
        ));
    }

    if leaf.is_empty() || leaf.contains('/') || leaf.contains('\\') {
        return Err(anyhow::anyhow!(
            "receiver storage leaf must be a single safe path component"
        ));
    }

    let mut dir = PathBuf::from(base);
    dir.push(leaf);
    Ok(dir)
}

/// Best-effort path hygiene check for operator-visible filenames.
fn is_safe_leaf_name(name: &str) -> bool {
    let p = Path::new(name);

    if name.is_empty() || p.is_absolute() {
        return false;
    }

    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => return false,
    }

    name != "." && name != ".."
}

/// Best-effort: append an incoming chat JSON line to
fn save_incoming_chat_json(chat: &ChatMessage, opts: &NodeOpts) {
    let dir = match receiver_root_dir(opts, "receiver.message") {
        Ok(d) => d,
        Err(..) => {
            return;
        }
    };

    if fs::create_dir_all(&dir).is_err() {
        return;
    }

    let file_path = dir.join("received_chat.jsonl");
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)
    {
        Ok(f) => f,
        Err(..) => {
            return;
        }
    };

    // Decode human text from chat.json bytes.
    let msg = match chat.plaintext() {
        Ok(m) => m,
        Err(..) => "<decode_failed>".to_string(),
    };

    let record = serde_json::json!({
        "from_wallet": chat.from_wallet,
        "message": msg,
        "timestamp_ms": chat.timestamp_ms,
        "to_wallet": chat.to_wallet,
    });

    // Pretty-print the JSON so it’s easy to read in receiver.message/received_chat.jsonl
    let line = serde_json::to_string_pretty(&record)
        .unwrap_or_else(|_| "{\"error\":\"serialize_failed\"}".to_string());

    if writeln!(file, "{}", line).is_err() {
        return;
    }

    drop(file.flush());
}

/// Gossipsub topic name for off-chain file transfer (chunks).
const FILE_TOPIC_NAME: &str = "remzar.file.v1";

/// Helper: construct the IdentTopic used for off-chain file chunks.
fn file_topic() -> IdentTopic {
    IdentTopic::new(FILE_TOPIC_NAME)
}

fn save_incoming_file_chunk(chunk: &FileChunkMessage, opts: &NodeOpts) {
    let mut dir = match receiver_root_dir(opts, "receiver.files") {
        Ok(d) => d,
        Err(..) => {
            return;
        }
    };

    if fs::create_dir_all(&dir).is_err() {
        return;
    }

    // Subdirectory per file_id (hex)
    let file_id_hex = hex::encode(chunk.file_id);
    dir.push(&file_id_hex);

    if fs::create_dir_all(&dir).is_err() {
        return;
    }

    // Write this chunk's bytes once. Duplicate chunk gossip should not cause
    // repeated disk overwrites. Also refuse symlink/non-file surprises.
    let chunk_path = dir.join(format!("chunk_{:06}.bin", chunk.chunk_index));

    if let Ok(meta) = fs::symlink_metadata(&chunk_path) {
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return;
        }

        // Existing regular chunk: duplicate gossip; ignore.
        return;
    }

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&chunk_path)
    {
        Ok(mut f) => {
            if f.write_all(&chunk.chunk_bytes).is_err() {
                drop(fs::remove_file(&chunk_path));
                return;
            }
            drop(f.flush());
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return,
        Err(..) => return,
    }

    // Maintain/update simple metadata for operator visibility
    let safe_filename = if is_safe_leaf_name(&chunk.filename) {
        chunk.filename.clone()
    } else {
        "unsafe_filename_replaced.bin".to_string()
    };

    let meta_path = dir.join("meta.json");
    let meta = serde_json::json!({
        "file_id_hex": file_id_hex,
        "from_wallet": chunk.from_wallet,
        "to_wallet": chunk.to_wallet,
        "filename": safe_filename,
        "file_size_bytes": chunk.file_size_bytes,
        "content_hash_hex": chunk.content_hash_hex,
        "total_chunks": chunk.total_chunks,
        "last_chunk_index": chunk.chunk_index,
        "last_timestamp_ms": chunk.timestamp_ms,
    });

    let meta_bytes = match serde_json::to_vec_pretty(&meta) {
        Ok(b) => b,
        Err(..) => {
            return;
        }
    };

    if let Ok(existing_meta) = fs::symlink_metadata(&meta_path)
        && (existing_meta.file_type().is_symlink() || !existing_meta.file_type().is_file())
    {
        return;
    }

    let meta_tmp_path = dir.join("meta.json.tmp");
    if fs::write(&meta_tmp_path, &meta_bytes).is_ok() {
        drop(fs::rename(&meta_tmp_path, &meta_path));
    }
}

/// Handles all Gossipsub events, with sync-triggering and strict no-double-apply rules.
#[allow(clippy::too_many_arguments)]
pub fn handle_gossipsub(
    event: GossipsubEvent,
    propagation_source: PeerId,
    swarm: &mut Swarm<RemzarBehaviour>,
    chain: &mut AccountModelTree,
    blockchain_db: &Arc<RockDBManager>,
    _registry_db: &Arc<RockDBManager>,
    mempool: &Arc<MemPool>,
    registry_data: &mut RegistryData,
    sync: &mut P2pSync,
    block_mint: Option<&mut BlockchainBuilder>,
    local_wallet: &str,
    opts: &NodeOpts,
) {
    // Keep internal handling best-effort.
    drop(handle_gossipsub_checked(
        event,
        propagation_source,
        swarm,
        chain,
        blockchain_db,
        _registry_db,
        mempool,
        registry_data,
        sync,
        block_mint,
        local_wallet,
        opts,
    ));
}

/// Checked variant: returns `anyhow::Result<()>` so the caller can log once cleanly.
#[allow(clippy::too_many_arguments)]
pub fn handle_gossipsub_checked(
    event: GossipsubEvent,
    propagation_source: PeerId,
    swarm: &mut Swarm<RemzarBehaviour>,
    chain: &mut AccountModelTree,
    blockchain_db: &Arc<RockDBManager>,
    _registry_db: &Arc<RockDBManager>,
    mempool: &Arc<MemPool>,
    registry_data: &mut RegistryData,
    sync: &mut P2pSync,
    mut block_mint: Option<&mut BlockchainBuilder>,
    local_wallet: &str,
    opts: &NodeOpts,
) -> anyhow::Result<()> {
    // Self-echo guard
    if &propagation_source == swarm.local_peer_id() {
        return Ok(());
    }

    if let GossipsubEvent::Message { message, .. } = event {
        // Fail-fast on obviously abusive payload sizes before any decode.
        if message.data.len() > MAX_GOSSIP_BYTES {
            return Ok(());
        }

        // ─────────────────────────────────────────────────────────────
        // Off-chain chat: detect CHAT_TOPIC and handle separately.
        // ─────────────────────────────────────────────────────────────
        if message.topic == chat_topic().hash() {
            let ts = runtime_log_timestamp();

            // Chat payload bounds: avoid feeding huge buffers into decode.
            if message.data.len() > MAX_CHAT_WIRE_BYTES {
                tracing::debug!(
                    "{} [GOSSIP][CHAT] DROP oversized payload bytes={} max={}",
                    ts,
                    message.data.len(),
                    MAX_CHAT_WIRE_BYTES
                );
                return Ok(());
            }

            let decoded_chat = catch_unwind(AssertUnwindSafe(|| try_decode_incoming(&message)));

            match decoded_chat {
                Ok(Ok(chat)) => {
                    // Best-effort wallet bounds (defensive; chat is off-chain).
                    if chat.from_wallet.len() > MAX_WALLET_TEXT_BYTES
                        || chat.to_wallet.len() > MAX_WALLET_TEXT_BYTES
                    {
                        return Ok(());
                    }

                    tracing::debug!(
                        "{} [GOSSIP][CHAT] incoming chat from={} to={} ts_ms={} json_len={}",
                        ts,
                        chat.from_wallet,
                        chat.to_wallet,
                        chat.timestamp_ms,
                        chat.json.len()
                    );

                    if !local_wallet.is_empty() && chat.to_wallet.eq_ignore_ascii_case(local_wallet)
                    {
                        save_incoming_chat_json(&chat, opts);
                    }

                    // (Optional future: forward to UI here)
                }
                Ok(Err(err)) => {
                    tracing::debug!(
                        "{} [GOSSIP][CHAT] ERROR decode incoming chat: {:?}",
                        ts,
                        err
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        "{} [GOSSIP][CHAT] ERROR decode panic from peer={}",
                        ts,
                        propagation_source
                    );
                }
            }

            return Ok(());
        }

        if message.topic == file_topic().hash() {
            let ts = runtime_log_timestamp();

            // File envelope bounds: avoid decode/alloc bombs.
            if message.data.len() > MAX_FILE_WIRE_BYTES {
                tracing::debug!(
                    "{} [GOSSIP][FILE] DROP oversized envelope bytes={} max={}",
                    ts,
                    message.data.len(),
                    MAX_FILE_WIRE_BYTES
                );
                return Ok(());
            }

            let decoded_file = catch_unwind(AssertUnwindSafe(|| {
                postcard::from_bytes::<FileChunkMessage>(&message.data)
            }));

            match decoded_file {
                Ok(Ok(chunk)) => {
                    // Defensive bounds before any disk writes / further processing.
                    if !validate_file_chunk_shape(&chunk) {
                        tracing::debug!(
                            "{} [GOSSIP][FILE] DROP invalid chunk shape from={} bytes={}",
                            ts,
                            propagation_source,
                            message.data.len()
                        );
                        return Ok(());
                    }

                    let file_id_hex = hex::encode(chunk.file_id);
                    tracing::debug!(
                        "{} [GOSSIP][FILE] incoming file chunk file_id={} idx={}/{} from={} to={} bytes={}",
                        ts,
                        file_id_hex,
                        chunk.chunk_index,
                        chunk.total_chunks,
                        chunk.from_wallet,
                        chunk.to_wallet,
                        chunk.chunk_bytes.len(),
                    );

                    // Only persist + assemble if *this* node is the intended recipient.
                    if !local_wallet.is_empty()
                        && chunk.to_wallet.eq_ignore_ascii_case(local_wallet)
                    {
                        // Keep existing per-chunk debug / operator-visible storage.
                        save_incoming_file_chunk(&chunk, opts);

                        // Wire into the high-level file assembler and verifier:
                        // - tracks chunks in memory
                        // - when complete, verifies BLAKE3 + size
                        // - writes final file under receiver.file/
                        // - appends JSON to received_files.jsonl
                        crate::network::p2p_016_file_store::handle_incoming_file_chunk(
                            chunk,
                            local_wallet,
                            opts,
                        );
                    }
                }
                Ok(Err(err)) => {
                    tracing::debug!(
                        "{} [GOSSIP][FILE] ERROR decode incoming file chunk: {:?}",
                        ts,
                        err
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        "{} [GOSSIP][FILE] ERROR decode panic from peer={}",
                        ts,
                        propagation_source
                    );
                }
            }

            // Do NOT decode as RemzarMessage; this is an off-chain file envelope.
            return Ok(());
        }

        // ─────────────────────────────────────────────────────────────
        // Non-chat, non-file topics: original RemzarMessage consensus wiring
        // ─────────────────────────────────────────────────────────────

        // Prefer bounded RemzarMessage decode helper if added it in p2p_002_protocal.
        // Fall back to postcard decode with the already-enforced MAX_GOSSIP_BYTES guard.
        let decoded = match catch_unwind(AssertUnwindSafe(|| {
            RemzarMessage::decode_from_wire(&message.data).or_else(|_| {
                postcard::from_bytes::<RemzarMessage>(&message.data).map_err(anyhow::Error::from)
            })
        })) {
            Ok(decoded) => decoded,
            Err(_) => {
                tracing::debug!(
                    "{} [GOSSIP] DROP RemzarMessage decode panic from={} bytes={}",
                    runtime_log_timestamp(),
                    propagation_source,
                    message.data.len()
                );
                return Ok(());
            }
        };

        match decoded {
            // 0) Generic TxKind → map into TxKind-aware mempool path.
            Ok(RemzarMessage::TxKind(kind)) => {
                let ts = runtime_log_timestamp();

                let add_result = catch_unwind(AssertUnwindSafe(|| mempool.add_tx_kind(&kind)));

                match add_result {
                    Ok(Ok(())) => {
                        tracing::debug!(
                            "{} [GOSSIP][TXKIND] mempool accepted TxKind tag={}",
                            ts,
                            kind.tag()
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "{} [GOSSIP][TXKIND] mempool add_tx_kind failed tag={} err={:?}",
                            ts,
                            kind.tag(),
                            e
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [GOSSIP][TXKIND] mempool add_tx_kind panic tag={}",
                            ts,
                            kind.tag()
                        );
                    }
                }
            }

            // 1) Plain tx → mempool only
            Ok(RemzarMessage::Transaction(tx)) => {
                let ts = runtime_log_timestamp();
                let add_result = catch_unwind(AssertUnwindSafe(|| mempool.add_transaction(&tx)));

                match add_result {
                    Ok(Ok(())) => {
                        tracing::debug!("{} [GOSSIP][TX] mempool accepted transaction", ts);
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("{} [GOSSIP][TX] mempool add failed: {:?}", ts, e);
                    }
                    Err(_) => {
                        tracing::debug!("{} [GOSSIP][TX] mempool add panic", ts);
                    }
                }
            }

            // 2) RegisterNode → EPHEMERAL registry heartbeat/insert + first_seen_tip write + in-memory identity map
            Ok(RemzarMessage::RegisterNode(reg_tx)) => {
                let ts = runtime_log_timestamp();

                // Decode incoming address as UTF-8 (RegisterNodeTx enforces "r"+64hex upstream)
                let wallet_in = String::from_utf8_lossy(&reg_tx.wallet_address).to_string();

                // Defensive bound: refuse absurdly large wallet text.
                if wallet_in.len() > MAX_WALLET_TEXT_BYTES {
                    return Ok(());
                }

                // STRICT: canonicalize/validate via shared helper.
                // - accepts canon-able inputs (e.g., mixed-case hex)
                // - outputs canonical "r"+lower-hex
                // - rejects malformed strings early (prevents weird metadata keys)
                let wallet_canon = match canon_wallet_id_checked(&wallet_in) {
                    Ok(c) => c,
                    Err(_) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] DROP invalid wallet peer_id={}",
                            ts,
                            short_peer_for_log(&propagation_source.to_base58())
                        );
                        return Ok(());
                    }
                };

                let wallet_lower = wallet_canon.to_ascii_lowercase();
                let peer_str = propagation_source.to_base58(); // base58 representation
                let wallet_id = short_wallet_for_log(&wallet_canon);
                let peer_id = short_peer_for_log(&peer_str);

                // Snapshot local tip HEIGHT (used for join-height)
                let tip_snapshot = blockchain_db
                    .get_tip_height()
                    .unwrap_or_else(|_| chain.latest_block_height() as u64);

                // REGISTER IN via heartbeat...
                let was_registered = registry_data.is_registered(&wallet_canon);
                let heartbeat_result = catch_unwind(AssertUnwindSafe(|| {
                    registry_data.note_heartbeat_round(&wallet_canon, tip_snapshot)
                }));

                match heartbeat_result {
                    Ok(Ok(_heartbeat_id)) => {}
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] ERROR note_heartbeat_round wallet_id={} err={:?}",
                            runtime_log_timestamp(),
                            wallet_id,
                            e
                        );

                        // Do NOT write first_seen_tip or identity map if we did not accept liveness.
                        return Ok(());
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] ERROR note_heartbeat_round panic wallet_id={}",
                            runtime_log_timestamp(),
                            wallet_id
                        );
                        return Ok(());
                    }
                }

                // Success logging (same behavior, now only on accept)
                if !was_registered {
                    tracing::debug!(
                        "{} [GOSSIP][REG] NEW validator wallet_id={} join_height={} (ts={})",
                        runtime_log_timestamp(),
                        wallet_id,
                        tip_snapshot,
                        reg_tx.timestamp
                    );
                }

                // first_seen_tip::<wallet_lower>...
                let fs_tip_key = format!("first_seen_tip::{}", wallet_lower);
                match blockchain_db.get_metadata(&fs_tip_key) {
                    Err(e) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] ERROR get_metadata kind=first_seen_tip wallet_id={} err={:?}",
                            runtime_log_timestamp(),
                            wallet_id,
                            e
                        );
                    }
                    Ok(Some(..)) => {}
                    Ok(None) => {
                        if let Err(e) =
                            blockchain_db.store_metadata(&fs_tip_key, &tip_snapshot.to_be_bytes())
                        {
                            tracing::debug!(
                                "{} [GOSSIP][REG] ERROR store_metadata kind=first_seen_tip wallet_id={} err={:?}",
                                runtime_log_timestamp(),
                                wallet_id,
                                e
                            );
                        } else {
                            tracing::debug!(
                                "{} [GOSSIP][REG] wrote first_seen_tip wallet_id={} value={}",
                                runtime_log_timestamp(),
                                wallet_id,
                                tip_snapshot
                            );
                        }
                    }
                }

                // In-memory identity map (no RocksDB registry writes)
                let assoc_result = catch_unwind(AssertUnwindSafe(|| {
                    registry_data.associate_identity(&peer_str, &wallet_canon)
                }));

                match assoc_result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] ERROR associate_identity peer_id={} wallet_id={} err={:?}",
                            runtime_log_timestamp(),
                            peer_id,
                            wallet_id,
                            e
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [GOSSIP][REG] ERROR associate_identity panic peer_id={} wallet_id={}",
                            runtime_log_timestamp(),
                            peer_id,
                            wallet_id
                        );
                    }
                }
            }

            // 3) Standalone reward → ignore (applies via batch/block)
            Ok(RemzarMessage::Reward(_)) => {
                tracing::debug!(
                    "{} [GOSSIP][REWARD] RewardTx gossip ignored (applied via batch/block)",
                    runtime_log_timestamp()
                );
            }

            // 4) TxBatch bytes only; commit via sync path
            Ok(RemzarMessage::TxBatch(batch)) => {
                let batch_serialized =
                    catch_unwind(AssertUnwindSafe(|| batch.serialize_for_storage()));

                if let Ok(Ok(batch_bytes)) = batch_serialized {
                    if let Err(e) = ensure_within_consensus_cap(
                        "gossip TransactionBatch (canonical)",
                        batch_bytes.len(),
                    ) {
                        tracing::debug!(
                            "{} [GOSSIP][BATCH] DROP oversized batch from={} err={:?}",
                            runtime_log_timestamp(),
                            propagation_source,
                            e
                        );
                        return Ok(());
                    }
                } else {
                    // If it can't serialize canonically, treat as invalid/poison and drop.
                    tracing::debug!(
                        "{} [GOSSIP][BATCH] DROP batch failing canonical serialization from={}",
                        runtime_log_timestamp(),
                        propagation_source
                    );
                    return Ok(());
                }

                match blockchain_db.open_db_blockchain() {
                    Err(e) => {
                        tracing::debug!(
                            "{} [GOSSIP][BATCH] ERROR open_db_blockchain() err={:?}",
                            runtime_log_timestamp(),
                            e
                        );
                    }
                    Ok(arc_db) => {
                        let rock_batch =
                            crate::storage::rocksdb_003_batches::RockBatch { db: arc_db };
                        let store_result =
                            catch_unwind(AssertUnwindSafe(|| batch.store_in_db(&rock_batch)));

                        match store_result {
                            Ok(Ok(())) => {
                                tracing::debug!(
                                    "{} [GOSSIP][BATCH] stored TransactionBatch bytes (no apply)",
                                    runtime_log_timestamp()
                                );
                            }
                            Ok(Err(e)) => {
                                tracing::debug!(
                                    "{} [GOSSIP][BATCH] ERROR store_in_db() err={:?}",
                                    runtime_log_timestamp(),
                                    e
                                );
                            }
                            Err(_) => {
                                tracing::debug!(
                                    "{} [GOSSIP][BATCH] ERROR store_in_db() panic",
                                    runtime_log_timestamp()
                                );
                            }
                        }
                    }
                }
            }

            // 5) Full block adv → trigger req/resp sync
            Ok(RemzarMessage::Block(block)) => {
                match catch_unwind(AssertUnwindSafe(|| block.serialize_for_storage())) {
                    Ok(Ok(block_bytes)) => {
                        if let Err(e) = ensure_within_consensus_cap(
                            "gossip Block (canonical)",
                            block_bytes.len(),
                        ) {
                            tracing::debug!(
                                "{} [GOSSIP][BLOCK] DROP oversized block adv from={} err={:?}",
                                runtime_log_timestamp(),
                                propagation_source,
                                e
                            );
                            return Ok(());
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            "{} [GOSSIP][BLOCK] DROP block adv failing canonical serialization from={} err={:?}",
                            runtime_log_timestamp(),
                            propagation_source,
                            e
                        );
                        return Ok(());
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} [GOSSIP][BLOCK] DROP block adv serialization panic from={}",
                            runtime_log_timestamp(),
                            propagation_source
                        );
                        return Ok(());
                    }
                }

                let peer_tip = block.metadata.index;
                let local_tip = local_tip_snapshot(chain, blockchain_db);

                if !is_reasonable_gossip_peer_tip(local_tip, peer_tip) {
                    tracing::debug!(
                        "{} [GOSSIP][BLOCK] DROP unreasonable block adv idx={} local_tip={} from={}",
                        runtime_log_timestamp(),
                        peer_tip,
                        local_tip,
                        propagation_source
                    );
                    return Ok(());
                }

                // Log-safe peer display only.
                let from_peer_id = {
                    let peer = propagation_source.to_base58();
                    let chars: Vec<char> = peer.chars().collect();

                    if chars.len() <= 18 {
                        peer
                    } else {
                        let prefix: String = chars.iter().take(10).collect();
                        let mut suffix_chars: Vec<char> =
                            chars.iter().rev().take(8).copied().collect();
                        suffix_chars.reverse();
                        let suffix: String = suffix_chars.into_iter().collect();

                        format!("{prefix}...{suffix}")
                    }
                };

                tracing::debug!(
                    "{} [GOSSIP][BLOCK] advertisement idx={} from_peer={} action=begin_sync_to_target",
                    runtime_log_timestamp(),
                    peer_tip,
                    from_peer_id
                );

                let begin_result = catch_unwind(AssertUnwindSafe(|| {
                    sync.begin_sync_to_target(swarm, propagation_source, peer_tip)
                }));

                if begin_result.is_err() {
                    tracing::debug!(
                        "{} [GOSSIP][BLOCK] begin_sync_to_target panic idx={} from={}",
                        runtime_log_timestamp(),
                        peer_tip,
                        propagation_source
                    );
                }
            }

            // 6) Por puzzle proof → deserialize, then feed into BlockchainBuilder::on_puzzle_proof.
            Ok(RemzarMessage::PorPuzzleProof(proof)) => {
                let ts = runtime_log_timestamp();

                if proof.validator.len() > MAX_WALLET_TEXT_BYTES {
                    tracing::debug!(
                        "{} [GOSSIP][Por] DROP proof with oversized validator field h={} from={}",
                        ts,
                        proof.height,
                        propagation_source
                    );
                    return Ok(());
                }

                // Log-safe validator display only.
                let validator_id = {
                    let validator = proof.validator.trim();
                    let chars: Vec<char> = validator.chars().collect();

                    if chars.len() <= 18 {
                        validator.to_string()
                    } else {
                        let prefix: String = chars.iter().take(10).collect();
                        let mut suffix_chars: Vec<char> =
                            chars.iter().rev().take(8).copied().collect();
                        suffix_chars.reverse();
                        let suffix: String = suffix_chars.into_iter().collect();

                        format!("{prefix}...{suffix}")
                    }
                };

                tracing::debug!(
                    "{} [GOSSIP][Por] puzzle proof received h={} validator_id={}",
                    ts,
                    proof.height,
                    validator_id
                );

                if let Some(m) = block_mint.as_mut() {
                    let accepted =
                        match catch_unwind(AssertUnwindSafe(|| m.on_puzzle_proof(&proof))) {
                            Ok(accepted) => accepted,
                            Err(_) => {
                                tracing::debug!(
                                    "{} [GOSSIP][Por] proof handler panic h={} validator_id={}",
                                    ts,
                                    proof.height,
                                    validator_id
                                );
                                return Ok(());
                            }
                        };

                    if accepted {
                        tracing::debug!(
                            "{} [GOSSIP][Por] proof accepted into local puzzle pool h={} validator_id={}",
                            ts,
                            proof.height,
                            validator_id
                        );
                    } else {
                        tracing::debug!(
                            "{} [GOSSIP][Por] proof rejected h={} validator_id={} reason=invalid_or_duplicate",
                            ts,
                            proof.height,
                            validator_id
                        );
                    }
                } else {
                    tracing::debug!(
                        "{} [GOSSIP][Por] proof ignored h={} validator_id={} reason=no_local_block_builder",
                        ts,
                        proof.height,
                        validator_id
                    );
                }
            }

            // 7) Runtime peer-mesh announce → normalize, ingest, map wallet identity, trigger autodial
            Ok(RemzarMessage::PeerMeshAnnounce(ann)) => {
                let norm = match catch_unwind(AssertUnwindSafe(|| ann.normalize())) {
                    Ok(Ok(n)) => n,
                    Ok(Err(..)) | Err(_) => {
                        return Ok(());
                    }
                };

                if norm.full_dial_addrs.len() > MAX_PEER_MESH_ADDRS_PER_ANNOUNCE
                    || norm.kad_base_addrs.len() > MAX_PEER_MESH_ADDRS_PER_ANNOUNCE
                    || !norm.full_dial_addrs.iter().all(multiaddr_gossip_len_ok)
                    || !norm.kad_base_addrs.iter().all(multiaddr_gossip_len_ok)
                {
                    tracing::debug!(
                        "{} [GOSSIP][MESH] DROP oversized peer-mesh announce from={}",
                        runtime_log_timestamp(),
                        propagation_source
                    );
                    return Ok(());
                }

                // Reject only pathological self-claims. Do NOT reject forwarded peer introductions.
                if norm.peer_id == *swarm.local_peer_id() {
                    return Ok(());
                }

                let is_direct_self_announcement = norm.peer_id == propagation_source;

                // Only trust the embedded wallet binding on direct self-announcements.
                // For forwarded peer intros, accept addresses for dialing/mesh expansion,
                // but do not let an intermediary rewrite identity bindings.
                if is_direct_self_announcement && let Some(wallet) = norm.wallet() {
                    let wallet_canon = canon_wallet_id_checked(wallet).unwrap_or_default();

                    if !wallet_canon.is_empty() {
                        drop(catch_unwind(AssertUnwindSafe(|| {
                            registry_data
                                .associate_identity(&norm.peer_id.to_base58(), &wallet_canon)
                        })));
                    }
                }

                // PeerBook gets FULL dialable addrs.
                if let Ok(mut pb) = sync.peerbook.lock() {
                    pb.upsert(&norm.peer_id, norm.full_dial_addrs.clone(), true);
                    _ = pb.save();
                }

                // Kademlia gets BASE transport addrs only.
                for a in &norm.kad_base_addrs {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&norm.peer_id, a.clone());
                }
                _ = swarm.behaviour_mut().kademlia.bootstrap();

                // Try healing / expanding the graph right away.
                sync.autodial_known_peers(swarm);
            }

            // Malformed message
            Err(..) => {}
        }
    }

    Ok(())
}
