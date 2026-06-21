// src/network/p2p_011_peerbook.rs

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs, io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::network::p2p_009_events::kad_ready_addrs;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;

const FILE_PATH: &str = "data/007.peerlist/peerlist.json";
const PEER_CAP: usize = 512;

/* ─────────────────────────────────────────────────────────────
Defensive caps (no crypto impact)
────────────────────────────────────────────────────────────── */

/// Hard cap on peerlist file size (bytes) we will read.
const PEERLIST_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Hard cap on number of addresses per peer we will persist/load.
const MAX_ADDRS_PER_PEER: usize = 32;

/// Hard cap on serialized Multiaddr size (bytes).
const MAX_MULTIADDR_BYTES: usize = 256;

/// Hard cap on tags per peer.
const MAX_TAGS_PER_PEER: usize = 16;

/// Hard cap on a single tag length (bytes).
const MAX_TAG_BYTES: usize = 64;

// Runtime-configurable peerbook directory (set once from DirectoryDB)
static PEERBOOK_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerListV1 {
    version: u32,
    updated_at_unix: u64,
    peers: Vec<PeerEntryV1>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PeerEntryV1 {
    peer_id: String,
    addrs: Vec<String>,
    score: i32,
    last_success_unix: Option<u64>,
    last_failure_unix: Option<u64>,
    tags: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct PeerEntry {
    pub addrs: BTreeSet<Multiaddr>,
    pub score: i32,
    pub last_success_unix: Option<u64>,
    pub last_failure_unix: Option<u64>,
    pub tags: BTreeSet<String>,
}

#[derive(Debug, Default, Clone)]
pub struct PeerBook {
    peers: HashMap<String, PeerEntry>,
}

// -------- Public API you’ll call --------

impl PeerBook {
    /// Call this once at startup (STEP 1) with DirectoryDB::peerlist_path.
    pub fn configure_storage_dir(peerlist_dir: impl Into<PathBuf>) {
        _ = PEERBOOK_DIR_OVERRIDE.set(peerlist_dir.into());
    }

    pub fn load_or_init() -> Self {
        let (file_path, tmp_path) = resolved_paths();

        // Try new schema first (resolved path)
        if let Ok(pb) = try_load_new(&file_path) {
            return pb;
        }
        // Try migrating OLD schema (resolved path)
        if let Ok(pb) = try_migrate_old(&file_path) {
            _ = save_atomic(&pb, &file_path, &tmp_path);
            return pb;
        }

        // Fallback migrate from legacy hardcoded path if different
        let legacy_file = Path::new(FILE_PATH);
        if legacy_file != file_path.as_path() {
            if let Ok(pb) = try_load_new(legacy_file) {
                _ = save_atomic(&pb, &file_path, &tmp_path);
                return pb;
            }
            if let Ok(pb) = try_migrate_old(legacy_file) {
                _ = save_atomic(&pb, &file_path, &tmp_path);
                return pb;
            }
        }

        // Fresh file
        let pb = PeerBook::default();
        _ = save_atomic(&pb, &file_path, &tmp_path);
        pb
    }

    /// Optional helper if you want explicit load location without global configure.
    pub fn load_or_init_in(peerlist_dir: impl AsRef<Path>) -> Self {
        let (file_path, tmp_path) = paths_in_dir(peerlist_dir.as_ref());

        if let Ok(pb) = try_load_new(&file_path) {
            return pb;
        }
        if let Ok(pb) = try_migrate_old(&file_path) {
            _ = save_atomic(&pb, &file_path, &tmp_path);
            return pb;
        }

        let pb = PeerBook::default();
        _ = save_atomic(&pb, &file_path, &tmp_path);
        pb
    }

    /// Merge addresses for a peer; if `mark_success`, bump score + timestamp.
    /// Addresses are normalized to Kad-ready base addrs (no trailing /p2p).
    pub fn upsert(
        &mut self,
        peer_id: &PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
        mark_success: bool,
    ) {
        let key = peer_id.to_string();
        let entry = self.peers.entry(key).or_default();

        // Normalize via shared helper (through a thin wrapper to keep tests/contracts intact).
        // Defensive: cap addresses per peer.
        for a in addrs.into_iter().map(strip_trailing_p2p) {
            if entry.addrs.len() >= MAX_ADDRS_PER_PEER {
                break;
            }
            if is_multiaddr_reasonable(&a) {
                entry.addrs.insert(a);
            }
        }

        if mark_success {
            entry.score = entry.score.saturating_add(10).min(120);
            entry.last_success_unix = Some(now_unix());
        } else {
            entry.score = entry.score.saturating_add(5).min(120);
        }
        self.enforce_cap();
    }

    /// Record a failure, but DO NOT immediately evict non-sticky peers.
    pub fn observe_failure(&mut self, peer_id: &PeerId) {
        let key = peer_id.to_string();

        if let Some(e) = self.peers.get_mut(&key) {
            e.last_failure_unix = Some(now_unix());
            e.score = e.score.saturating_sub(5).max(-120);
        }
    }

    /// Add a tag (e.g., "seed", "stable") to a peer.
    pub fn add_tag(&mut self, peer_id: &PeerId, tag: impl Into<String>) {
        let tag = tag.into();

        // Defensive: bound tag size.
        if tag.len() > MAX_TAG_BYTES {
            return;
        }

        let e = self.peers.entry(peer_id.to_string()).or_default();

        // Defensive: cap tags.
        if e.tags.len() >= MAX_TAGS_PER_PEER {
            return;
        }

        e.tags.insert(tag);
    }

    /// Remove a tag from a peer.
    pub fn remove_tag(&mut self, peer_id: &PeerId, tag: &str) {
        if let Some(e) = self.peers.get_mut(&peer_id.to_string()) {
            e.tags.remove(tag);
        }
    }

    /// Highest quality first.
    /// Order: sticky (seed/stable/static) first, then most recent success, then score.
    pub fn top_n(&self, n: usize) -> Vec<(String, Vec<Multiaddr>)> {
        let mut rows: Vec<(&String, &PeerEntry)> = self.peers.iter().collect();
        rows.sort_by(|a, b| {
            let asticky = Self::is_sticky(a.1);
            let bsticky = Self::is_sticky(b.1);
            let asu = a.1.last_success_unix.unwrap_or(0);
            let bsu = b.1.last_success_unix.unwrap_or(0);
            // sticky desc, last_success desc, score desc
            bsticky
                .cmp(&asticky)
                .then(bsu.cmp(&asu))
                .then(b.1.score.cmp(&a.1.score))
        });
        rows.into_iter()
            .take(n)
            .map(|(pid, e)| (pid.clone(), e.addrs.iter().cloned().collect()))
            .collect()
    }

    pub fn save(&self) -> io::Result<()> {
        let (file_path, tmp_path) = resolved_paths();
        save_atomic(self, &file_path, &tmp_path)
    }

    /// Optional helper you want explicit save location without global configure.
    pub fn save_in(&self, peerlist_dir: impl AsRef<Path>) -> io::Result<()> {
        let (file_path, tmp_path) = paths_in_dir(peerlist_dir.as_ref());
        save_atomic(self, &file_path, &tmp_path)
    }
}

// -------- Internals --------

fn resolved_peerlist_dir() -> PathBuf {
    // 1) explicit override (best: set from DirectoryDB::peerlist_path)
    if let Some(p) = PEERBOOK_DIR_OVERRIDE.get() {
        return p.clone();
    }

    // 2) environment override (matches DirectoryDB::base_data_dir contract)
    let base = std::env::var("REMZAR_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data"));

    // 3) consistent subdir name
    base.join(GlobalConfiguration::PEER_LIST_DIR)
}

fn paths_in_dir(peerlist_dir: &Path) -> (PathBuf, PathBuf) {
    let file_path = peerlist_dir.join("peerlist.json");
    let tmp_path = peerlist_dir.join("peerlist.json.tmp");
    (file_path, tmp_path)
}

fn resolved_paths() -> (PathBuf, PathBuf) {
    let dir = resolved_peerlist_dir();
    paths_in_dir(&dir)
}

fn check_file_size_bound(path: &Path) -> io::Result<()> {
    let meta = fs::metadata(path)?;
    if meta.len() > PEERLIST_MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "peerlist file too large: {} bytes (max {})",
                meta.len(),
                PEERLIST_MAX_FILE_BYTES
            ),
        ));
    }
    Ok(())
}

#[inline(always)]
fn is_multiaddr_reasonable(addr: &Multiaddr) -> bool {
    addr.to_vec().len() <= MAX_MULTIADDR_BYTES
}

fn try_load_new(path: &Path) -> io::Result<PeerBook> {
    check_file_size_bound(path)?;
    let bytes = fs::read(path)?;
    let file: PeerListV1 = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if file.version != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version"));
    }

    let mut pb = PeerBook::default();

    for e in file.peers {
        // Defensive: ignore absurd peer_id strings (should be base58 PeerId).
        if e.peer_id.len() > 128 {
            continue;
        }

        let mut entry = PeerEntry {
            score: e.score,
            last_success_unix: e.last_success_unix,
            last_failure_unix: e.last_failure_unix,
            tags: e
                .tags
                .into_iter()
                .filter(|t| t.len() <= MAX_TAG_BYTES)
                .take(MAX_TAGS_PER_PEER)
                .collect(),
            ..PeerEntry::default()
        };

        // Defensive: cap addresses per peer and skip oversized multiaddrs.
        for s in e.addrs.into_iter().take(MAX_ADDRS_PER_PEER) {
            // Defensive: skip absurd address strings before parse.
            if s.len() > (MAX_MULTIADDR_BYTES * 4) {
                continue;
            }
            if let Ok(ma) = s.parse::<Multiaddr>()
                && is_multiaddr_reasonable(&ma)
            {
                entry.addrs.insert(ma);
            }
        }

        // Keep even if empty addrs; caller may still treat tags/score as useful.
        pb.peers.insert(e.peer_id, entry);
    }

    // Defensive: enforce global cap after load.
    pb.enforce_cap();
    Ok(pb)
}

fn try_migrate_old(path: &Path) -> io::Result<PeerBook> {
    check_file_size_bound(path)?;
    let bytes = fs::read(path)?;
    // OLD: { "peer_id": "multiaddr", ... }
    let old: HashMap<String, String> = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut pb = PeerBook::default();
    for (pid, addr) in old.into_iter() {
        if pid.len() > 128 {
            continue;
        }
        if addr.len() > (MAX_MULTIADDR_BYTES * 4) {
            continue;
        }
        if let Ok(ma) = addr.parse::<Multiaddr>() {
            if !is_multiaddr_reasonable(&ma) {
                continue;
            }
            let mut entry = PeerEntry::default();
            entry.addrs.insert(ma);
            entry.score = 10;
            pb.peers.insert(pid, entry);
        }
    }
    pb.enforce_cap();
    Ok(pb)
}

fn save_atomic(pb: &PeerBook, path: &Path, tmp_path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    // Best-effort cleanup of stale tmp.
    _ = fs::remove_file(tmp_path);

    let now = now_unix();
    let mut peers = Vec::with_capacity(pb.peers.len().min(PEER_CAP));

    // Defensive: only persist up to PEER_CAP peers (should already be enforced).
    for (peer_id, e) in pb.peers.iter().take(PEER_CAP) {
        // Defensive: cap per-peer addrs/tags written.
        let addrs: Vec<String> = e
            .addrs
            .iter()
            .filter(|a| is_multiaddr_reasonable(a))
            .take(MAX_ADDRS_PER_PEER)
            .map(|a| a.to_string())
            .collect();

        let tags: Vec<String> = e
            .tags
            .iter()
            .filter(|t| t.len() <= MAX_TAG_BYTES)
            .take(MAX_TAGS_PER_PEER)
            .cloned()
            .collect();

        peers.push(PeerEntryV1 {
            peer_id: peer_id.clone(),
            addrs,
            score: e.score,
            last_success_unix: e.last_success_unix,
            last_failure_unix: e.last_failure_unix,
            tags,
        });
    }

    let file = PeerListV1 {
        version: 1,
        updated_at_unix: now,
        peers,
    };

    let json = serde_json::to_vec_pretty(&file)?;
    fs::write(tmp_path, &json)?;

    // Atomic on POSIX; on Windows, rename fails if destination exists.
    // We keep it best-effort and error-returning (caller logs once).
    match fs::rename(tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup so we don't accumulate tmp files.
            _ = fs::remove_file(tmp_path);
            Err(e)
        }
    }
}

/// Thin wrapper retained for API/test stability:
/// uses the centralized `kad_ready_addrs` logic for a single address.
fn strip_trailing_p2p(a: Multiaddr) -> Multiaddr {
    let v = [a.clone()];
    kad_ready_addrs(&v).into_iter().next().unwrap_or(a)
}

fn now_unix() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

impl PeerBook {
    #[inline]
    fn is_sticky(e: &PeerEntry) -> bool {
        // Protect these from eviction; adjust to policy.
        e.tags.contains("seed") || e.tags.contains("stable") || e.tags.contains("static")
    }

    fn enforce_cap(&mut self) {
        if self.peers.len() <= PEER_CAP {
            return;
        }
        // Prepare (key, sticky, score, last_success)
        let mut keys: Vec<(String, bool, i32, u64)> = self
            .peers
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    Self::is_sticky(v),
                    v.score,
                    v.last_success_unix.unwrap_or(0),
                )
            })
            .collect();

        // Worst first: oldest success, then lowest score
        keys.sort_by(|a, b| a.3.cmp(&b.3).then(a.2.cmp(&b.2)));

        let peers_len = self.peers.len();

        // Evict non-sticky first
        let mut to_remove: Vec<String> = Vec::new();
        for (k, sticky, _, _) in &keys {
            if peers_len.saturating_sub(to_remove.len()) <= PEER_CAP {
                break;
            }
            if !*sticky {
                to_remove.push(k.clone());
            }
        }
        // If still over cap (extreme edge), evict sticky last
        for (k, sticky, _, _) in &keys {
            if peers_len.saturating_sub(to_remove.len()) <= PEER_CAP {
                break;
            }
            if *sticky {
                to_remove.push(k.clone());
            }
        }

        for k in to_remove {
            self.peers.remove(&k);
        }
    }
}
