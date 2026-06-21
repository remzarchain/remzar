// p2p_012_janitor_peerbook.rs

use crate::network::p2p_011_peerbook::PeerBook;
use crate::utility::time_policy::TimePolicy;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const PEERLIST_PATH: &str = "data/007.peerlist/peerlist.json";
const PEERLIST_TMP_PATH: &str = "data/007.peerlist/peerlist.json.tmp";

/* ─────────────────────────────────────────────────────────────
Defensive caps (no crypto impact)
───────────────────────────────────────────────────────────── */

/// Hard cap on peerlist file size (bytes) we will read.
const PEERLIST_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Defensive cap: maximum number of peers we will process from disk.
/// Keep aligned with PeerBook's PEER_CAP (512) but tolerate small drift.
const MAX_PEERS_ON_DISK: usize = 512;

/// Defensive cap: maximum number of addresses per peer to process.
const MAX_ADDRS_PER_PEER: usize = 32;

/// Defensive cap: maximum number of tags per peer.
const MAX_TAGS_PER_PEER: usize = 16;

/// Defensive cap: maximum size of a single tag (bytes).
const MAX_TAG_BYTES: usize = 64;

/// Defensive cap: reject absurd PeerId strings (base58 PeerId should be small).
const MAX_PEER_ID_BYTES: usize = 128;

/// Defensive cap: reject absurd address strings before parsing.
const MAX_ADDR_STRING_BYTES: usize = 1024;

/// On-disk schema (duplicated from p2p_011_peerbook.rs).
/// This operates only at JSON level; it does not depend on PeerBook internals.
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

/// Configuration for how aggressively we clean peers.
#[derive(Debug, Clone)]
pub struct JanitorConfig {
    /// If a peer has a failure timestamp newer than its last success and
    /// `now - last_failure_unix >= failure_grace_secs`, we consider it dead.
    pub failure_grace_secs: u64,

    /// Optional max age of last_success_unix; if Some and exceeded, peer is removed.
    pub max_age_secs_since_success: Option<u64>,

    /// Optional minimum score; if Some and peer.score < min_score, peer is removed.
    pub min_score: Option<i32>,

    /// Tags that should NEVER be removed by the janitor (e.g., "seed", "stable").
    pub protected_tags: Vec<String>,
}

impl JanitorConfig {
    /// Very aggressive: remove any peer as soon as we see a failure that
    /// is more recent than its last success (unless it has a protected tag).
    pub fn aggressive() -> Self {
        Self {
            failure_grace_secs: 0,
            max_age_secs_since_success: None,
            min_score: None,
            protected_tags: vec!["seed".into(), "stable".into(), "static".into()],
        }
    }
}

impl Default for JanitorConfig {
    fn default() -> Self {
        Self {
            // e.g. allow 60s grace after last failure before pruning
            failure_grace_secs: 60,
            // e.g. drop peers that haven't succeeded in 24h
            max_age_secs_since_success: Some(24 * 60 * 60),
            // e.g. drop peers whose score is deeply negative
            min_score: Some(-80),
            protected_tags: vec!["seed".into(), "stable".into(), "static".into()],
        }
    }
}

/// The "janitor" for the PeerBook + peerlist.json.
pub struct JanitorBook {
    peerbook: Arc<Mutex<PeerBook>>,
    // if set, we read/write peerlist.json HERE (DirectoryDB::peerlist_path)
    peerlist_dir_override: Option<PathBuf>,
}

impl JanitorBook {
    /// Create a new janitor bound to the shared PeerBook (legacy path behaviour).
    pub fn new(peerbook: Arc<Mutex<PeerBook>>) -> Self {
        Self {
            peerbook,
            peerlist_dir_override: None,
        }
    }

    /// Create a janitor bound to a specific peerlist directory.
    pub fn new_with_dir(peerbook: Arc<Mutex<PeerBook>>, peerlist_dir: PathBuf) -> Self {
        // lock PeerBook onto the SAME dir the janitor will edit.
        PeerBook::configure_storage_dir(peerlist_dir.clone());

        Self {
            peerbook,
            peerlist_dir_override: Some(peerlist_dir),
        }
    }

    fn peerlist_paths(&self) -> (PathBuf, PathBuf) {
        if let Some(dir) = &self.peerlist_dir_override {
            (dir.join("peerlist.json"), dir.join("peerlist.json.tmp"))
        } else {
            (
                PathBuf::from(PEERLIST_PATH),
                PathBuf::from(PEERLIST_TMP_PATH),
            )
        }
    }

    /// Remove a single peer by its PeerId string.
    /// Returns Ok(true) if something was actually removed.
    pub fn remove_peer_by_id(&self, peer_id: &str) -> io::Result<bool> {
        let (file_path, tmp_path) = self.peerlist_paths();

        let mut list = match load_peerlist_from_disk_at(&file_path) {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // No peerlist file at all; nothing to remove.
                return Ok(false);
            }
            Err(e) => return Err(e),
        };

        let before = list.peers.len();
        list.peers.retain(|p| p.peer_id != peer_id);
        let after = list.peers.len();

        if after == before {
            // No change.
            return Ok(false);
        }

        list.updated_at_unix = now_unix()?;
        save_peerlist_to_disk_at(&file_path, &tmp_path, &list)?;

        // Reload in-memory PeerBook so the runtime stops autodialing this peer.
        reload_peerbook_in_place(&self.peerbook);

        tracing::debug!(
            "[JANITOR] Removed peer {} from peerlist.json ({} → {} entries) [{}]",
            peer_id,
            before,
            after,
            file_path.display()
        );

        Ok(true)
    }

    /// Clear ALL peers from peerlist.json (but keep the file + version header).
    pub fn clear_all_peers(&self) -> io::Result<()> {
        let (file_path, tmp_path) = self.peerlist_paths();

        let mut list = match load_peerlist_from_disk_at(&file_path) {
            Ok(list) => list,
            Err(e) if e.kind() == io::ErrorKind::NotFound => PeerListV1 {
                version: 1,
                updated_at_unix: now_unix()?,
                peers: Vec::new(),
            },
            Err(e) => return Err(e),
        };

        let before = list.peers.len();
        if before == 0 {
            return Ok(());
        }

        list.peers.clear();
        list.updated_at_unix = now_unix()?;
        save_peerlist_to_disk_at(&file_path, &tmp_path, &list)?;

        reload_peerbook_in_place(&self.peerbook);

        tracing::debug!(
            "[JANITOR] Cleared all {} peers from peerlist.json (now empty). [{}]",
            before,
            file_path.display()
        );

        Ok(())
    }

    /// Delete the peerlist.json file completely and reset the in-memory PeerBook.
    pub fn delete_peerlist_file(&self) -> io::Result<()> {
        let (file_path, tmp_path) = self.peerlist_paths();

        // delete resolved file
        if file_path.exists() {
            fs::remove_file(&file_path)?;
            tracing::debug!("[JANITOR] Deleted {} on request.", file_path.display());
        } else {
            tracing::debug!(
                "[JANITOR] delete_peerlist_file: {} does not exist; no-op.",
                file_path.display()
            );
        }

        // also delete tmp if present
        if tmp_path.exists() {
            _ = fs::remove_file(&tmp_path);
        }

        // if override is used and legacy file exists elsewhere, remove it too
        let legacy_file = Path::new(PEERLIST_PATH);
        if legacy_file != file_path.as_path() && legacy_file.exists() {
            _ = fs::remove_file(legacy_file);
            tracing::debug!(
                "[JANITOR] Also removed legacy peerlist path {} to avoid drift/confusion.",
                legacy_file.display()
            );
        }

        // Reset in-memory PeerBook to an empty default and re-persist.
        if let Ok(mut guard) = self.peerbook.lock() {
            *guard = PeerBook::default();
            _ = guard.save();
        }

        Ok(())
    }

    /// Sweep stale / offline peers according to the provided config.
    pub fn sweep_stale_peers(&self, cfg: &JanitorConfig) -> io::Result<usize> {
        let (file_path, tmp_path) = self.peerlist_paths();

        let mut list = match load_peerlist_from_disk_at(&file_path) {
            Ok(l) => l,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // No file → nothing to clean.
                return Ok(0);
            }
            Err(e) => return Err(e),
        };

        let now = now_unix()?;
        let before = list.peers.len();

        let protected: HashSet<String> = cfg
            .protected_tags
            .iter()
            .filter(|t| t.len() <= MAX_TAG_BYTES)
            .cloned()
            .collect();

        list.peers.retain(|p| {
            // 1) Never touch protected peers.
            if p.tags.iter().any(|t| protected.contains(t)) {
                return true;
            }

            // 2) If we have a "recent enough" failure that is newer than last_success,
            //    and we've passed the grace window, drop the peer.
            if let Some(fail_ts) = p.last_failure_unix {
                let last_success = p.last_success_unix.unwrap_or(0);
                if fail_ts >= last_success {
                    let age = now.saturating_sub(fail_ts);
                    if age >= cfg.failure_grace_secs {
                        return false; // remove
                    }
                }
            }

            // 3) Optional: prune peers whose last_success_unix is too old.
            if let Some(max_age) = cfg.max_age_secs_since_success
                && let Some(su) = p.last_success_unix
            {
                let age = now.saturating_sub(su);
                if age >= max_age {
                    return false;
                }
            }

            // 4) Optional: prune by score.
            if let Some(min_score) = cfg.min_score
                && p.score < min_score
            {
                return false;
            }

            true // keep
        });

        let removed = before.saturating_sub(list.peers.len());
        if removed == 0 {
            return Ok(0);
        }

        list.updated_at_unix = now;
        save_peerlist_to_disk_at(&file_path, &tmp_path, &list)?;

        reload_peerbook_in_place(&self.peerbook);

        tracing::debug!(
            "[JANITOR] sweep_stale_peers removed {} peer(s) ({} → {}). [{}]",
            removed,
            before,
            list.peers.len(),
            file_path.display()
        );

        Ok(removed)
    }
}

/* ──────────────────────────────
Helpers
────────────────────────────── */

fn now_unix() -> io::Result<u64> {
    TimePolicy::now_unix_secs_runtime()
        .map_err(|e| io::Error::other(format!("failed to derive runtime unix timestamp: {e:?}")))
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

fn sanitize_peerlist(mut list: PeerListV1) -> PeerListV1 {
    // Cap total peers processed (prevents memory blowups on malicious file).
    if list.peers.len() > MAX_PEERS_ON_DISK {
        list.peers.truncate(MAX_PEERS_ON_DISK);
    }

    // Sanitize each entry with caps.
    for p in &mut list.peers {
        if p.peer_id.len() > MAX_PEER_ID_BYTES {
            // Make it obviously invalid; caller may drop it later by policy.
            p.peer_id.clear();
        }

        if p.addrs.len() > MAX_ADDRS_PER_PEER {
            p.addrs.truncate(MAX_ADDRS_PER_PEER);
        }
        p.addrs.retain(|a| a.len() <= MAX_ADDR_STRING_BYTES);

        if p.tags.len() > MAX_TAGS_PER_PEER {
            p.tags.truncate(MAX_TAGS_PER_PEER);
        }
        p.tags.retain(|t| t.len() <= MAX_TAG_BYTES);
    }

    // Drop entries with empty peer_id after sanitization (bad/abusive records).
    list.peers.retain(|p| !p.peer_id.is_empty());

    list
}

// path-parameterized versions (DirectoryDB-compatible)
fn load_peerlist_from_disk_at(path: &Path) -> io::Result<PeerListV1> {
    check_file_size_bound(path)?;
    let bytes = fs::read(path)?;
    let list: PeerListV1 = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if list.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported peerlist.json version",
        ));
    }
    Ok(sanitize_peerlist(list))
}

fn save_peerlist_to_disk_at(path: &Path, tmp_path: &Path, list: &PeerListV1) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    // Best-effort cleanup of stale tmp (Windows rename can fail if tmp exists).
    _ = fs::remove_file(tmp_path);

    let json = serde_json::to_vec_pretty(list)?;
    fs::write(tmp_path, &json)?;

    // Atomic on POSIX; on Windows, rename may fail if destination exists.
    match fs::rename(tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup so we don't accumulate tmp files.
            _ = fs::remove_file(tmp_path);
            Err(e)
        }
    }
}

/// Replace the in-memory PeerBook with a fresh copy loaded from disk.
/// This ensures autodial/top_n() etc. use the cleaned state.
fn reload_peerbook_in_place(peerbook: &Arc<Mutex<PeerBook>>) {
    let new_pb = PeerBook::load_or_init();
    if let Ok(mut guard) = peerbook.lock() {
        *guard = new_pb;
    }
}
