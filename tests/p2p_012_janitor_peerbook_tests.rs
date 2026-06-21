#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use remzar::network::p2p_011_peerbook::PeerBook;
use remzar::network::p2p_012_janitor_peerbook::{JanitorBook, JanitorConfig};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> Result<MutexGuard<'static, ()>> {
    TEST_LOCK
        .lock()
        .map_err(|_| anyhow!("janitor peerbook test mutex poisoned"))
}

fn generated_peer_id() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

fn memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn fresh_dir(label: &str) -> Result<PathBuf> {
    let id = TEST_DIR_COUNTER.fetch_add(1_u64, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "remzar_janitor_peerbook_tests_{}_{}_{}",
        std::process::id(),
        label,
        id
    ));

    if dir.exists() {
        fs::remove_dir_all(&dir)
            .with_context(|| format!("failed to remove stale test dir: {}", dir.display()))?;
    }

    Ok(dir)
}

fn peerlist_file(dir: &Path) -> PathBuf {
    dir.join("peerlist.json")
}

fn peerlist_tmp_file(dir: &Path) -> PathBuf {
    dir.join("peerlist.json.tmp")
}

fn now_unix() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0_u64)
}

fn peer_entry(
    peer_id: String,
    addrs: Vec<String>,
    score: i32,
    last_success_unix: Option<u64>,
    last_failure_unix: Option<u64>,
    tags: Vec<String>,
) -> Value {
    json!({
        "peer_id": peer_id,
        "addrs": addrs,
        "score": score,
        "last_success_unix": last_success_unix,
        "last_failure_unix": last_failure_unix,
        "tags": tags
    })
}

fn write_peerlist(dir: &Path, peers: Vec<Value>, updated_at_unix: u64) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create peerlist dir: {}", dir.display()))?;

    let value = json!({
        "version": 1,
        "updated_at_unix": updated_at_unix,
        "peers": peers
    });

    fs::write(peerlist_file(dir), serde_json::to_vec_pretty(&value)?)
        .with_context(|| format!("failed to write peerlist file: {}", dir.display()))?;
    Ok(())
}

fn read_peerlist(dir: &Path) -> Result<Value> {
    let bytes = fs::read(peerlist_file(dir))
        .with_context(|| format!("failed to read peerlist file: {}", dir.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn read_peers(dir: &Path) -> Result<Vec<Value>> {
    let json = read_peerlist(dir)?;
    let peers = json["peers"]
        .as_array()
        .context("expected peers array")?
        .clone();
    Ok(peers)
}

fn peer_ids(dir: &Path) -> Result<Vec<String>> {
    let peers = read_peers(dir)?;
    let mut ids = Vec::new();

    for peer in peers {
        if let Some(peer_id) = peer["peer_id"].as_str() {
            ids.push(peer_id.to_owned());
        }
    }

    Ok(ids)
}

fn peer_count(dir: &Path) -> Result<usize> {
    Ok(read_peers(dir)?.len())
}

fn janitor_for_dir(dir: &Path) -> JanitorBook {
    let peerbook = Arc::new(Mutex::new(PeerBook::default()));
    JanitorBook::new_with_dir(peerbook, dir.to_path_buf())
}

fn sweep_cfg(
    failure_grace_secs: u64,
    max_age_secs_since_success: Option<u64>,
    min_score: Option<i32>,
    protected_tags: Vec<&str>,
) -> JanitorConfig {
    JanitorConfig {
        failure_grace_secs,
        max_age_secs_since_success,
        min_score,
        protected_tags: protected_tags
            .into_iter()
            .map(std::borrow::ToOwned::to_owned)
            .collect(),
    }
}

fn assert_invalid_data<T>(result: std::io::Result<T>, needle: &str) -> Result<()> {
    match result {
        Err(err) => {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            assert!(err.to_string().contains(needle));
            Ok(())
        }
        Ok(_) => Err(anyhow!("expected InvalidData error containing {needle}")),
    }
}

/* ───────────────────────── config and no-file behavior ─────────────────── */

#[test]
fn test_001_default_config_has_expected_policy() -> Result<()> {
    let _guard = test_lock()?;
    let cfg = JanitorConfig::default();

    assert_eq!(cfg.failure_grace_secs, 60_u64);
    assert_eq!(
        cfg.max_age_secs_since_success,
        Some(24_u64 * 60_u64 * 60_u64)
    );
    assert_eq!(cfg.min_score, Some(-80_i32));
    assert!(cfg.protected_tags.contains(&"seed".to_owned()));
    assert!(cfg.protected_tags.contains(&"stable".to_owned()));
    assert!(cfg.protected_tags.contains(&"static".to_owned()));
    Ok(())
}

#[test]
fn test_002_aggressive_config_has_zero_failure_grace_and_no_score_age_pruning() -> Result<()> {
    let _guard = test_lock()?;
    let cfg = JanitorConfig::aggressive();

    assert_eq!(cfg.failure_grace_secs, 0_u64);
    assert_eq!(cfg.max_age_secs_since_success, None);
    assert_eq!(cfg.min_score, None);
    assert!(cfg.protected_tags.contains(&"seed".to_owned()));
    Ok(())
}

#[test]
fn test_003_remove_missing_file_returns_false() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_missing")?;
    let janitor = janitor_for_dir(&dir);

    let removed = janitor.remove_peer_by_id("missing-peer")?;

    assert!(!removed);
    assert!(!peerlist_file(&dir).exists());
    Ok(())
}

#[test]
fn test_004_sweep_missing_file_returns_zero() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_missing")?;
    let janitor = janitor_for_dir(&dir);

    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert!(!peerlist_file(&dir).exists());
    Ok(())
}

#[test]
fn test_005_clear_missing_file_is_ok_and_does_not_create_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_missing")?;
    let janitor = janitor_for_dir(&dir);

    janitor.clear_all_peers()?;

    assert!(!peerlist_file(&dir).exists());
    Ok(())
}

/* ───────────────────────── remove / clear / delete paths ───────────────── */

#[test]
fn test_006_remove_absent_peer_returns_false_and_leaves_file_unchanged() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_absent")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(6_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id("not-present")?;

    assert!(!removed);
    assert_eq!(peer_ids(&dir)?, vec![peer.to_string()]);
    Ok(())
}

#[test]
fn test_007_remove_existing_peer_removes_only_that_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_existing")?;
    let target = generated_peer_id();
    let keep = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                target.to_string(),
                vec![memory_addr(7_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                keep.to_string(),
                vec![memory_addr(8_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&target.to_string())?;

    assert!(removed);
    assert_eq!(peer_ids(&dir)?, vec![keep.to_string()]);
    Ok(())
}

#[test]
fn test_008_remove_peer_id_removes_duplicate_entries_with_same_id() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_duplicates")?;
    let target = generated_peer_id();
    let keep = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                target.to_string(),
                vec![memory_addr(8_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                target.to_string(),
                vec![memory_addr(9_u64).to_string()],
                20_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                keep.to_string(),
                vec![memory_addr(10_u64).to_string()],
                30_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&target.to_string())?;

    assert!(removed);
    assert_eq!(peer_ids(&dir)?, vec![keep.to_string()]);
    Ok(())
}

#[test]
fn test_009_clear_all_peers_empties_existing_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_all")?;
    let first = generated_peer_id();
    let second = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                first.to_string(),
                vec![memory_addr(9_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                second.to_string(),
                vec![memory_addr(10_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_010_clear_empty_peerlist_keeps_empty_file() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_empty")?;

    write_peerlist(&dir, Vec::new(), 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_011_delete_peerlist_file_removes_or_recreates_empty_file_and_removes_tmp() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("delete_file")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(11_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;
    fs::write(peerlist_tmp_file(&dir), b"stale tmp")?;

    let janitor = janitor_for_dir(&dir);
    janitor.delete_peerlist_file()?;

    assert!(!peerlist_tmp_file(&dir).exists());

    if peerlist_file(&dir).exists() {
        assert_eq!(peer_count(&dir)?, 0_usize);
    }

    Ok(())
}

/* ───────────────────────── failure sweep behavior ──────────────────────── */

#[test]
fn test_012_aggressive_sweep_removes_failed_peer_without_success() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("aggressive_failed")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(12_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(1_u64)),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_013_aggressive_sweep_keeps_seed_protected_failed_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("aggressive_seed")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(13_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["seed".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_ids(&dir)?, vec![peer.to_string()]);
    Ok(())
}

#[test]
fn test_014_aggressive_sweep_keeps_stable_protected_failed_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("aggressive_stable")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(14_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["stable".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_015_aggressive_sweep_keeps_static_protected_failed_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("aggressive_static")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(15_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["static".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_016_custom_protected_tag_keeps_failed_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("custom_protected")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(16_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["bootstrap".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(0_u64, None, None, vec!["bootstrap"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_ids(&dir)?, vec![peer.to_string()]);
    Ok(())
}

#[test]
fn test_017_failure_under_grace_is_kept() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("under_grace")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(17_u64).to_string()],
            10_i32,
            None,
            Some(now),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_018_failure_past_grace_is_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("past_grace")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(18_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(61_u64)),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_019_failure_older_than_success_is_kept() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_older_than_success")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(19_u64).to_string()],
            10_i32,
            Some(now),
            Some(now.saturating_sub(10_u64)),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_020_failure_equal_to_success_is_removed_when_grace_elapsed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_equal_success")?;
    let peer = generated_peer_id();
    let ts = now_unix().saturating_sub(10_u64);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(20_u64).to_string()],
            10_i32,
            Some(ts),
            Some(ts),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

/* ───────────────────────── age / score sweep behavior ─────────────────── */

#[test]
fn test_021_max_age_removes_old_success() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("max_age_old_success")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(21_u64).to_string()],
            10_i32,
            Some(now.saturating_sub(101_u64)),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_022_max_age_none_keeps_old_success() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("max_age_none")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(22_u64).to_string()],
            10_i32,
            Some(1_u64),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_023_min_score_removes_below_threshold() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("min_score_below")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(23_u64).to_string()],
            -81_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_024_min_score_equal_threshold_is_kept() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("min_score_equal")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(24_u64).to_string()],
            -80_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_025_min_score_none_keeps_deep_negative_score() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("min_score_none")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(25_u64).to_string()],
            -120_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_026_default_config_removes_old_success() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("default_old_success")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(26_u64).to_string()],
            10_i32,
            Some(now.saturating_sub((24_u64 * 60_u64 * 60_u64) + 1_u64)),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::default())?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_027_default_config_removes_score_below_negative_80() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("default_low_score")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(27_u64).to_string()],
            -81_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::default())?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_028_sweep_mixed_policy_returns_exact_removed_count() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("mixed_removed_count")?;
    let keep = generated_peer_id();
    let fail = generated_peer_id();
    let old = generated_peer_id();
    let low = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                keep.to_string(),
                vec![memory_addr(28_u64).to_string()],
                10_i32,
                Some(now),
                None,
                Vec::new(),
            ),
            peer_entry(
                fail.to_string(),
                vec![memory_addr(29_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
            peer_entry(
                old.to_string(),
                vec![memory_addr(30_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(200_u64)),
                None,
                Vec::new(),
            ),
            peer_entry(
                low.to_string(),
                vec![memory_addr(31_u64).to_string()],
                -90_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 3_usize);
    assert_eq!(peer_ids(&dir)?, vec![keep.to_string()]);
    Ok(())
}

#[test]
fn test_029_sweep_no_removals_returns_zero() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("no_removals")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(29_u64).to_string()],
            10_i32,
            Some(now),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::default())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

/* ───────────────────────── invalid file behavior ──────────────────────── */

#[test]
fn test_030_remove_on_bad_version_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("bad_version_remove")?;
    fs::create_dir_all(&dir)?;
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&json!({
            "version": 999,
            "updated_at_unix": 1,
            "peers": []
        }))?,
    )?;

    let janitor = janitor_for_dir(&dir);

    assert_invalid_data(janitor.remove_peer_by_id("anything"), "unsupported")?;
    Ok(())
}

#[test]
fn test_031_sweep_on_malformed_json_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("malformed_json")?;
    fs::create_dir_all(&dir)?;
    fs::write(peerlist_file(&dir), b"{not valid json")?;

    let janitor = janitor_for_dir(&dir);

    assert_invalid_data(janitor.sweep_stale_peers(&JanitorConfig::default()), "")?;
    Ok(())
}

#[test]
fn test_032_sweep_on_oversized_peerlist_file_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("oversized_file")?;
    fs::create_dir_all(&dir)?;
    let huge = vec![b'0'; (4_usize * 1024_usize * 1024_usize) + 1_usize];
    fs::write(peerlist_file(&dir), huge)?;

    let janitor = janitor_for_dir(&dir);

    assert_invalid_data(
        janitor.sweep_stale_peers(&JanitorConfig::default()),
        "too large",
    )?;
    Ok(())
}

/* ───────────────────────── sanitize / cap behavior ────────────────────── */

#[test]
fn test_033_sanitize_caps_520_low_score_peers_to_512_processed_removals() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sanitize_peer_cap")?;
    let mut peers = Vec::new();

    for seed in 0_u64..520_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            -1_i32,
            None,
            None,
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(0_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 512_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_034_sanitize_drops_overlong_peer_id_when_rewriting_after_remove() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sanitize_long_peer_id")?;
    let good = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                "x".repeat(129_usize),
                vec![memory_addr(34_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                good.to_string(),
                vec![memory_addr(35_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&good.to_string())?;

    assert!(removed);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_035_sanitize_caps_addrs_per_peer_to_32_when_rewriting() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sanitize_addr_cap")?;
    let keep = generated_peer_id();
    let remove = generated_peer_id();
    let addrs = (0_u64..40_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();

    write_peerlist(
        &dir,
        vec![
            peer_entry(keep.to_string(), addrs, 10_i32, None, None, Vec::new()),
            peer_entry(
                remove.to_string(),
                vec![memory_addr(999_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&remove.to_string())?;

    assert!(removed);

    let peers = read_peers(&dir)?;
    let saved_addrs = peers[0_usize]["addrs"]
        .as_array()
        .context("expected addrs array")?;
    assert_eq!(saved_addrs.len(), 32_usize);
    Ok(())
}

#[test]
fn test_036_sanitize_removes_absurd_addr_string_when_rewriting() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sanitize_absurd_addr")?;
    let keep = generated_peer_id();
    let remove = generated_peer_id();
    let good_addr = memory_addr(36_u64).to_string();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                keep.to_string(),
                vec!["x".repeat(2000_usize), good_addr.clone()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                remove.to_string(),
                vec![memory_addr(37_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&remove.to_string())?;

    assert!(removed);

    let peers = read_peers(&dir)?;
    let saved_addrs = peers[0_usize]["addrs"]
        .as_array()
        .context("expected addrs array")?;
    assert_eq!(saved_addrs.len(), 1_usize);
    assert_eq!(saved_addrs[0_usize].as_str(), Some(good_addr.as_str()));
    Ok(())
}

#[test]
fn test_037_sanitize_caps_tags_to_16_and_removes_long_tags_when_rewriting() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sanitize_tags")?;
    let keep = generated_peer_id();
    let remove = generated_peer_id();

    let mut tags = (0_u8..20_u8)
        .map(|index| format!("tag-{index}"))
        .collect::<Vec<_>>();
    tags.push("x".repeat(65_usize));

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                keep.to_string(),
                vec![memory_addr(37_u64).to_string()],
                10_i32,
                None,
                None,
                tags,
            ),
            peer_entry(
                remove.to_string(),
                vec![memory_addr(38_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&remove.to_string())?;

    assert!(removed);

    let peers = read_peers(&dir)?;
    let saved_tags = peers[0_usize]["tags"]
        .as_array()
        .context("expected tags array")?;
    assert_eq!(saved_tags.len(), 16_usize);
    Ok(())
}

/* ───────────────────────── updated_at and combined paths ───────────────── */

#[test]
fn test_038_remove_peer_updates_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_updates_time")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(38_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&peer.to_string())?;

    assert!(removed);

    let json = read_peerlist(&dir)?;
    assert!(json["updated_at_unix"].as_u64().unwrap_or(0_u64) > 1_u64);
    Ok(())
}

#[test]
fn test_039_clear_all_updates_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_updates_time")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(39_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    let json = read_peerlist(&dir)?;
    assert!(json["updated_at_unix"].as_u64().unwrap_or(0_u64) > 1_u64);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_040_combined_adversarial_sweep_keeps_protected_and_removes_bad_peers() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_adversarial")?;
    let now = now_unix();

    let protected = generated_peer_id();
    let failed = generated_peer_id();
    let old_success = generated_peer_id();
    let low_score = generated_peer_id();
    let healthy = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                protected.to_string(),
                vec![memory_addr(40_u64).to_string()],
                -120_i32,
                Some(now.saturating_sub(1_000_000_u64)),
                Some(now.saturating_sub(999_999_u64)),
                vec!["seed".to_owned()],
            ),
            peer_entry(
                failed.to_string(),
                vec![memory_addr(41_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
            peer_entry(
                old_success.to_string(),
                vec![memory_addr(42_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(200_u64)),
                None,
                Vec::new(),
            ),
            peer_entry(
                low_score.to_string(),
                vec![memory_addr(43_u64).to_string()],
                -90_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                healthy.to_string(),
                vec![memory_addr(44_u64).to_string()],
                10_i32,
                Some(now),
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    let ids = peer_ids(&dir)?;

    assert_eq!(removed, 3_usize);
    assert_eq!(ids, vec![protected.to_string(), healthy.to_string()]);
    Ok(())
}

#[test]
fn test_041_remove_first_peer_preserves_remaining_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_first")?;
    let first = generated_peer_id();
    let second = generated_peer_id();
    let third = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                first.to_string(),
                vec![memory_addr(41_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                second.to_string(),
                vec![memory_addr(42_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                third.to_string(),
                vec![memory_addr(43_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(janitor.remove_peer_by_id(&first.to_string())?);

    assert_eq!(peer_ids(&dir)?, vec![second.to_string(), third.to_string()]);
    Ok(())
}

#[test]
fn test_042_remove_middle_peer_preserves_remaining_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_middle")?;
    let first = generated_peer_id();
    let second = generated_peer_id();
    let third = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                first.to_string(),
                vec![memory_addr(42_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                second.to_string(),
                vec![memory_addr(43_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                third.to_string(),
                vec![memory_addr(44_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(janitor.remove_peer_by_id(&second.to_string())?);

    assert_eq!(peer_ids(&dir)?, vec![first.to_string(), third.to_string()]);
    Ok(())
}

#[test]
fn test_043_remove_last_peer_preserves_remaining_order() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_last")?;
    let first = generated_peer_id();
    let second = generated_peer_id();
    let third = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                first.to_string(),
                vec![memory_addr(43_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                second.to_string(),
                vec![memory_addr(44_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                third.to_string(),
                vec![memory_addr(45_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(janitor.remove_peer_by_id(&third.to_string())?);

    assert_eq!(peer_ids(&dir)?, vec![first.to_string(), second.to_string()]);
    Ok(())
}

#[test]
fn test_044_remove_from_empty_peerlist_returns_false() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_empty_list")?;

    write_peerlist(&dir, Vec::new(), 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id("missing")?;

    assert!(!removed);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_045_remove_overlong_peer_id_target_is_safe_when_not_present() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_overlong_target")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(45_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id(&"x".repeat(1024_usize))?;

    assert!(!removed);
    assert_eq!(peer_ids(&dir)?, vec![peer.to_string()]);
    Ok(())
}

#[test]
fn test_046_remove_single_peer_leaves_empty_schema() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_single_peer")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(46_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(janitor.remove_peer_by_id(&peer.to_string())?);

    let json = read_peerlist(&dir)?;
    assert_eq!(json["version"].as_u64(), Some(1_u64));
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_047_clear_all_removes_duplicate_peer_entries() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_duplicates")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                peer.to_string(),
                vec![memory_addr(47_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                peer.to_string(),
                vec![memory_addr(48_u64).to_string()],
                20_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_048_clear_all_on_bad_version_is_ok_and_leaves_file_present() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_bad_version")?;
    fs::create_dir_all(&dir)?;
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&json!({
            "version": 999,
            "updated_at_unix": 1,
            "peers": []
        }))?,
    )?;

    let janitor = janitor_for_dir(&dir);

    assert_invalid_data(janitor.clear_all_peers(), "unsupported")?;
    assert!(peerlist_file(&dir).exists());

    Ok(())
}

#[test]
fn test_049_clear_all_on_malformed_json_is_ok_and_leaves_file_present() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_malformed_json")?;
    fs::create_dir_all(&dir)?;
    fs::write(peerlist_file(&dir), b"{bad json")?;

    let janitor = janitor_for_dir(&dir);

    assert_invalid_data(janitor.clear_all_peers(), "")?;
    assert!(peerlist_file(&dir).exists());

    Ok(())
}

#[test]
fn test_050_delete_missing_file_with_stale_tmp_removes_tmp() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("delete_missing_with_tmp")?;
    fs::create_dir_all(&dir)?;
    fs::write(peerlist_tmp_file(&dir), b"stale tmp")?;

    let janitor = janitor_for_dir(&dir);
    janitor.delete_peerlist_file()?;

    assert!(!peerlist_tmp_file(&dir).exists());
    Ok(())
}

/* ───────────────────────── failure grace boundaries ───────────────────── */

#[test]
fn test_051_failure_exactly_at_grace_boundary_is_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_exact_grace")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(51_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(60_u64)),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_052_failure_future_timestamp_with_grace_is_kept() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_future_with_grace")?;
    let peer = generated_peer_id();
    let future = now_unix().saturating_add(3600_u64);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(52_u64).to_string()],
            10_i32,
            None,
            Some(future),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_053_failure_future_timestamp_with_aggressive_zero_grace_is_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_future_aggressive")?;
    let peer = generated_peer_id();
    let future = now_unix().saturating_add(3600_u64);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(53_u64).to_string()],
            10_i32,
            None,
            Some(future),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_054_failure_without_success_and_zero_timestamp_removed_by_aggressive() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_zero_timestamp")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(54_u64).to_string()],
            10_i32,
            None,
            Some(0_u64),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_055_failure_lower_than_zero_success_comparison_keeps_when_success_newer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_before_success")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(55_u64).to_string()],
            10_i32,
            Some(100_u64),
            Some(99_u64),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

/* ───────────────────────── age and score boundaries ───────────────────── */

#[test]
fn test_056_success_exactly_at_max_age_boundary_is_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("success_exact_max_age")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(56_u64).to_string()],
            10_i32,
            Some(now.saturating_sub(100_u64)),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_057_future_success_timestamp_is_not_removed_by_age() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("future_success")?;
    let peer = generated_peer_id();
    let future = now_unix().saturating_add(3600_u64);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(57_u64).to_string()],
            10_i32,
            Some(future),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_058_min_score_one_below_threshold_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("min_score_one_below")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(58_u64).to_string()],
            -1_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(0_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_059_min_score_one_above_threshold_is_kept() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("min_score_one_above")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(59_u64).to_string()],
            1_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(0_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_060_protected_peer_ignores_age_failure_and_score_rules() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("protected_ignores_rules")?;
    let peer = generated_peer_id();
    let now = now_unix();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(60_u64).to_string()],
            -120_i32,
            Some(now.saturating_sub(1_000_000_u64)),
            Some(now.saturating_sub(999_999_u64)),
            vec!["seed".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(0_u64, Some(1_u64), Some(0_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

/* ───────────────────────── protected tag edge cases ───────────────────── */

#[test]
fn test_061_empty_protected_tag_list_allows_seed_peer_removal() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("empty_protected_list")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(61_u64).to_string()],
            -120_i32,
            None,
            None,
            vec!["seed".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), Vec::new());
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_062_protected_tag_matching_is_case_sensitive() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("case_sensitive_protected")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(62_u64).to_string()],
            -120_i32,
            None,
            None,
            vec!["Seed".to_owned()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_063_protected_tag_exactly_64_bytes_is_honored() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("protected_tag_exact_64")?;
    let peer = generated_peer_id();
    let tag = "x".repeat(64_usize);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(63_u64).to_string()],
            -120_i32,
            None,
            None,
            vec![tag.clone()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = JanitorConfig {
        failure_grace_secs: 60_u64,
        max_age_secs_since_success: None,
        min_score: Some(-80_i32),
        protected_tags: vec![tag],
    };
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_064_protected_tag_over_64_bytes_is_ignored() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("protected_tag_over_64")?;
    let peer = generated_peer_id();
    let tag = "x".repeat(65_usize);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(64_u64).to_string()],
            -120_i32,
            None,
            None,
            vec![tag.clone()],
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = JanitorConfig {
        failure_grace_secs: 60_u64,
        max_age_secs_since_success: None,
        min_score: Some(-80_i32),
        protected_tags: vec![tag],
    };
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_065_protected_seed_beyond_tag_cap_is_not_honored_after_sanitize() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("protected_beyond_tag_cap")?;
    let peer = generated_peer_id();

    let mut tags = (0_u8..16_u8)
        .map(|index| format!("tag-{index}"))
        .collect::<Vec<_>>();
    tags.push("seed".to_owned());

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(65_u64).to_string()],
            -120_i32,
            None,
            None,
            tags,
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

/* ───────────────────────── invalid file paths and schema errors ────────── */

#[test]
fn test_066_sweep_on_bad_version_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_bad_version")?;
    fs::create_dir_all(&dir)?;
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&json!({
            "version": 2,
            "updated_at_unix": 1,
            "peers": []
        }))?,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_invalid_data(
        janitor.sweep_stale_peers(&JanitorConfig::default()),
        "unsupported",
    )?;
    Ok(())
}

#[test]
fn test_067_remove_on_malformed_json_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_malformed_json")?;
    fs::create_dir_all(&dir)?;
    fs::write(peerlist_file(&dir), b"{not valid json")?;

    let janitor = janitor_for_dir(&dir);
    assert_invalid_data(janitor.remove_peer_by_id("anything"), "")?;
    Ok(())
}

#[test]
fn test_068_remove_on_oversized_peerlist_file_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_oversized_file")?;
    fs::create_dir_all(&dir)?;
    let huge = vec![b'0'; (4_usize * 1024_usize * 1024_usize) + 1_usize];
    fs::write(peerlist_file(&dir), huge)?;

    let janitor = janitor_for_dir(&dir);
    assert_invalid_data(janitor.remove_peer_by_id("anything"), "too large")?;
    Ok(())
}

#[test]
fn test_069_sweep_schema_missing_peers_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("missing_peers_field")?;
    fs::create_dir_all(&dir)?;
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "updated_at_unix": 1
        }))?,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_invalid_data(janitor.sweep_stale_peers(&JanitorConfig::default()), "")?;
    Ok(())
}

#[test]
fn test_070_sweep_schema_wrong_peers_type_returns_invalid_data() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("wrong_peers_type")?;
    fs::create_dir_all(&dir)?;
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "updated_at_unix": 1,
            "peers": "not-array"
        }))?,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_invalid_data(janitor.sweep_stale_peers(&JanitorConfig::default()), "")?;
    Ok(())
}

/* ───────────────────────── sanitization-on-rewrite tests ──────────────── */

#[test]
fn test_071_sweep_rewrite_sanitizes_addrs_and_tags_when_one_peer_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_rewrite_sanitizes")?;
    let keep = generated_peer_id();
    let remove = generated_peer_id();

    let addrs = (0_u64..40_u64)
        .map(|seed| memory_addr(seed).to_string())
        .chain(std::iter::once("x".repeat(2000_usize)))
        .collect::<Vec<_>>();

    let tags = (0_u8..20_u8)
        .map(|index| format!("tag-{index}"))
        .chain(std::iter::once("x".repeat(65_usize)))
        .collect::<Vec<_>>();

    write_peerlist(
        &dir,
        vec![
            peer_entry(keep.to_string(), addrs, 10_i32, None, None, tags),
            peer_entry(
                remove.to_string(),
                vec![memory_addr(999_u64).to_string()],
                -120_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);

    let peers = read_peers(&dir)?;
    let saved_addrs = peers[0_usize]["addrs"]
        .as_array()
        .context("expected addrs array")?;
    let saved_tags = peers[0_usize]["tags"]
        .as_array()
        .context("expected tags array")?;

    assert_eq!(saved_addrs.len(), 32_usize);
    assert_eq!(saved_tags.len(), 16_usize);
    Ok(())
}

#[test]
fn test_072_sanitize_truncates_to_first_512_peers_before_sweep() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("truncate_first_512")?;
    let mut peers = Vec::new();

    for seed in 0_u64..512_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            -1_i32,
            None,
            None,
            Vec::new(),
        ));
    }

    for seed in 512_u64..520_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            100_i32,
            None,
            None,
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(0_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 512_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_073_remove_no_change_does_not_rewrite_sanitized_peerlist() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_no_change_no_rewrite")?;
    let peer = generated_peer_id();
    let long_addr = "x".repeat(2000_usize);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![long_addr.clone()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.remove_peer_by_id("missing")?;

    assert!(!removed);

    let peers = read_peers(&dir)?;
    let addrs = peers[0_usize]["addrs"]
        .as_array()
        .context("expected addrs array")?;
    assert_eq!(addrs[0_usize].as_str(), Some(long_addr.as_str()));
    Ok(())
}

#[test]
fn test_074_sweep_no_removal_does_not_rewrite_sanitized_peerlist() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_no_removal_no_rewrite")?;
    let peer = generated_peer_id();
    let long_addr = "x".repeat(2000_usize);

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![long_addr.clone()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);

    let peers = read_peers(&dir)?;
    let addrs = peers[0_usize]["addrs"]
        .as_array()
        .context("expected addrs array")?;
    assert_eq!(addrs[0_usize].as_str(), Some(long_addr.as_str()));
    Ok(())
}

#[test]
fn test_075_sweep_rewrite_drops_empty_peer_id_after_sanitize() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("drop_empty_peer_id")?;
    let remove = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                String::new(),
                vec![memory_addr(75_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                "x".repeat(129_usize),
                vec![memory_addr(76_u64).to_string()],
                10_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                remove.to_string(),
                vec![memory_addr(77_u64).to_string()],
                -120_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

/* ───────────────────────── updated_at behavior ────────────────────────── */

#[test]
fn test_076_sweep_with_removal_updates_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_updates_time")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(76_u64).to_string()],
            -120_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);

    let json = read_peerlist(&dir)?;
    assert!(json["updated_at_unix"].as_u64().unwrap_or(0_u64) > 1_u64);
    Ok(())
}

#[test]
fn test_077_sweep_without_removal_does_not_update_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("sweep_no_update_without_removal")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(77_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);

    let json = read_peerlist(&dir)?;
    assert_eq!(json["updated_at_unix"].as_u64(), Some(1_u64));
    Ok(())
}

#[test]
fn test_078_remove_absent_peer_does_not_update_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_absent_no_update")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(78_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(!janitor.remove_peer_by_id("missing")?);

    let json = read_peerlist(&dir)?;
    assert_eq!(json["updated_at_unix"].as_u64(), Some(1_u64));
    Ok(())
}

#[test]
fn test_079_clear_empty_peerlist_does_not_update_updated_at_unix() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_empty_no_update")?;

    write_peerlist(&dir, Vec::new(), 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    let json = read_peerlist(&dir)?;
    assert_eq!(json["updated_at_unix"].as_u64(), Some(1_u64));
    Ok(())
}

#[test]
fn test_080_delete_existing_peerlist_file_removes_tmp_and_resets_explicit_file_if_recreated()
-> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("delete_existing_reset")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(80_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;
    fs::write(peerlist_tmp_file(&dir), b"stale")?;

    let janitor = janitor_for_dir(&dir);
    janitor.delete_peerlist_file()?;

    assert!(!peerlist_tmp_file(&dir).exists());

    if peerlist_file(&dir).exists() {
        assert_eq!(peer_count(&dir)?, 0_usize);
    }

    Ok(())
}

/* ───────────────────────── load and adversarial batches ───────────────── */

#[test]
fn test_081_load_64_failed_peers_aggressive_removes_all() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_64_failed")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..64_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 64_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_082_load_64_protected_failed_peers_aggressive_keeps_all() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_64_protected_failed")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..64_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["seed".to_owned()],
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 64_usize);
    Ok(())
}

#[test]
fn test_083_load_128_low_score_peers_removed_by_min_score() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_128_low_score")?;
    let mut peers = Vec::new();

    for seed in 0_u64..128_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            -100_i32,
            None,
            None,
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 128_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_084_load_128_healthy_peers_not_removed() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_128_healthy")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..128_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            Some(now),
            None,
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::default())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 128_usize);
    Ok(())
}

#[test]
fn test_085_mixed_failed_and_protected_removed_count_is_exact() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("mixed_failed_protected_count")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..32_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            Vec::new(),
        ));
    }

    for seed in 32_u64..64_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            vec!["stable".to_owned()],
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 32_usize);
    assert_eq!(peer_count(&dir)?, 32_usize);
    Ok(())
}

#[test]
fn test_086_mixed_age_score_failure_rules_remove_all_three_bad_categories() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("mixed_three_bad_categories")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..10_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            Vec::new(),
        ));
    }

    for seed in 10_u64..20_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            Some(now.saturating_sub(200_u64)),
            None,
            Vec::new(),
        ));
    }

    for seed in 20_u64..30_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            -100_i32,
            None,
            None,
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 30_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_087_mixed_healthy_and_bad_keeps_only_healthy_ids() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("mixed_keep_healthy_ids")?;
    let now = now_unix();
    let healthy_one = generated_peer_id();
    let healthy_two = generated_peer_id();
    let bad_one = generated_peer_id();
    let bad_two = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                healthy_one.to_string(),
                vec![memory_addr(87_u64).to_string()],
                10_i32,
                Some(now),
                None,
                Vec::new(),
            ),
            peer_entry(
                bad_one.to_string(),
                vec![memory_addr(88_u64).to_string()],
                -100_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                healthy_two.to_string(),
                vec![memory_addr(89_u64).to_string()],
                20_i32,
                Some(now),
                None,
                Vec::new(),
            ),
            peer_entry(
                bad_two.to_string(),
                vec![memory_addr(90_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 2_usize);
    assert_eq!(
        peer_ids(&dir)?,
        vec![healthy_one.to_string(), healthy_two.to_string()]
    );
    Ok(())
}

#[test]
fn test_088_remove_after_sweep_can_remove_remaining_protected_peer() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_after_sweep")?;
    let now = now_unix();
    let protected = generated_peer_id();
    let failed = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                protected.to_string(),
                vec![memory_addr(88_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                vec!["seed".to_owned()],
            ),
            peer_entry(
                failed.to_string(),
                vec![memory_addr(89_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_eq!(
        janitor.sweep_stale_peers(&JanitorConfig::aggressive())?,
        1_usize
    );
    assert!(janitor.remove_peer_by_id(&protected.to_string())?);

    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_089_clear_after_sweep_removes_remaining_peers() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_after_sweep")?;
    let now = now_unix();
    let protected = generated_peer_id();
    let failed = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                protected.to_string(),
                vec![memory_addr(89_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                vec!["seed".to_owned()],
            ),
            peer_entry(
                failed.to_string(),
                vec![memory_addr(90_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_eq!(
        janitor.sweep_stale_peers(&JanitorConfig::aggressive())?,
        1_usize
    );
    janitor.clear_all_peers()?;

    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_090_delete_after_sweep_removes_file_or_resets_to_empty() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("delete_after_sweep")?;
    let now = now_unix();
    let failed = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            failed.to_string(),
            vec![memory_addr(90_u64).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert_eq!(
        janitor.sweep_stale_peers(&JanitorConfig::aggressive())?,
        1_usize
    );
    janitor.delete_peerlist_file()?;

    if peerlist_file(&dir).exists() {
        assert_eq!(peer_count(&dir)?, 0_usize);
    }

    Ok(())
}

/* ───────────────────────── final combined vectors ─────────────────────── */

#[test]
fn test_091_custom_policy_only_score_pruning() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("only_score_pruning")?;
    let now = now_unix();
    let failed = generated_peer_id();
    let low_score = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                failed.to_string(),
                vec![memory_addr(91_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(1000_u64)),
                Vec::new(),
            ),
            peer_entry(
                low_score.to_string(),
                vec![memory_addr(92_u64).to_string()],
                -100_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(u64::MAX, None, Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_ids(&dir)?, vec![failed.to_string()]);
    Ok(())
}

#[test]
fn test_092_custom_policy_only_age_pruning() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("only_age_pruning")?;
    let now = now_unix();
    let old = generated_peer_id();
    let low_score = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                old.to_string(),
                vec![memory_addr(92_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(1000_u64)),
                None,
                Vec::new(),
            ),
            peer_entry(
                low_score.to_string(),
                vec![memory_addr(93_u64).to_string()],
                -120_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_ids(&dir)?, vec![low_score.to_string()]);
    Ok(())
}

#[test]
fn test_093_custom_policy_only_failure_pruning() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("only_failure_pruning")?;
    let now = now_unix();
    let failed = generated_peer_id();
    let old = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                failed.to_string(),
                vec![memory_addr(93_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(1000_u64)),
                Vec::new(),
            ),
            peer_entry(
                old.to_string(),
                vec![memory_addr(94_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(1000_u64)),
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    assert_eq!(peer_ids(&dir)?, vec![old.to_string()]);
    Ok(())
}

#[test]
fn test_094_all_pruning_disabled_keeps_bad_peers() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("all_pruning_disabled")?;
    let now = now_unix();
    let failed = generated_peer_id();
    let old = generated_peer_id();
    let low = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                failed.to_string(),
                vec![memory_addr(94_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(1000_u64)),
                Vec::new(),
            ),
            peer_entry(
                old.to_string(),
                vec![memory_addr(95_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(1000_u64)),
                None,
                Vec::new(),
            ),
            peer_entry(
                low.to_string(),
                vec![memory_addr(96_u64).to_string()],
                -120_i32,
                None,
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(u64::MAX, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 3_usize);
    Ok(())
}

#[test]
fn test_095_max_age_zero_removes_any_peer_with_last_success() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("max_age_zero")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(95_u64).to_string()],
            10_i32,
            Some(now_unix()),
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(0_u64), None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 1_usize);
    Ok(())
}

#[test]
fn test_096_failure_grace_max_keeps_old_failure() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("failure_grace_max")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(96_u64).to_string()],
            10_i32,
            None,
            Some(1_u64),
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(u64::MAX, None, None, vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 1_usize);
    Ok(())
}

#[test]
fn test_097_remove_then_sweep_empty_file_returns_zero() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("remove_then_sweep_empty")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(97_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    assert!(janitor.remove_peer_by_id(&peer.to_string())?);

    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 0_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_098_clear_then_remove_returns_false() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("clear_then_remove")?;
    let peer = generated_peer_id();

    write_peerlist(
        &dir,
        vec![peer_entry(
            peer.to_string(),
            vec![memory_addr(98_u64).to_string()],
            10_i32,
            None,
            None,
            Vec::new(),
        )],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    janitor.clear_all_peers()?;

    let removed = janitor.remove_peer_by_id(&peer.to_string())?;

    assert!(!removed);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_099_load_512_failed_peers_aggressive_removes_all() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("load_512_failed")?;
    let now = now_unix();
    let mut peers = Vec::new();

    for seed in 0_u64..512_u64 {
        peers.push(peer_entry(
            generated_peer_id().to_string(),
            vec![memory_addr(seed).to_string()],
            10_i32,
            None,
            Some(now.saturating_sub(100_u64)),
            Vec::new(),
        ));
    }

    write_peerlist(&dir, peers, 1_u64)?;

    let janitor = janitor_for_dir(&dir);
    let removed = janitor.sweep_stale_peers(&JanitorConfig::aggressive())?;

    assert_eq!(removed, 512_usize);
    assert_eq!(peer_count(&dir)?, 0_usize);
    Ok(())
}

#[test]
fn test_100_combined_adversarial_janitor_lifecycle_is_safe() -> Result<()> {
    let _guard = test_lock()?;
    let dir = fresh_dir("combined_lifecycle")?;
    let now = now_unix();

    let protected = generated_peer_id();
    let failed = generated_peer_id();
    let old = generated_peer_id();
    let low = generated_peer_id();
    let healthy = generated_peer_id();

    write_peerlist(
        &dir,
        vec![
            peer_entry(
                protected.to_string(),
                vec![memory_addr(100_u64).to_string(), "x".repeat(2000_usize)],
                -120_i32,
                Some(now.saturating_sub(1000_u64)),
                Some(now.saturating_sub(999_u64)),
                vec!["seed".to_owned(), "x".repeat(65_usize)],
            ),
            peer_entry(
                failed.to_string(),
                vec![memory_addr(101_u64).to_string()],
                10_i32,
                None,
                Some(now.saturating_sub(100_u64)),
                Vec::new(),
            ),
            peer_entry(
                old.to_string(),
                vec![memory_addr(102_u64).to_string()],
                10_i32,
                Some(now.saturating_sub(200_u64)),
                None,
                Vec::new(),
            ),
            peer_entry(
                low.to_string(),
                vec![memory_addr(103_u64).to_string()],
                -90_i32,
                None,
                None,
                Vec::new(),
            ),
            peer_entry(
                healthy.to_string(),
                vec![memory_addr(104_u64).to_string()],
                10_i32,
                Some(now),
                None,
                Vec::new(),
            ),
        ],
        1_u64,
    )?;

    let janitor = janitor_for_dir(&dir);
    let cfg = sweep_cfg(60_u64, Some(100_u64), Some(-80_i32), vec!["seed"]);
    let removed = janitor.sweep_stale_peers(&cfg)?;

    assert_eq!(removed, 3_usize);
    assert_eq!(
        peer_ids(&dir)?,
        vec![protected.to_string(), healthy.to_string()]
    );

    assert!(janitor.remove_peer_by_id(&healthy.to_string())?);
    assert_eq!(peer_ids(&dir)?, vec![protected.to_string()]);

    janitor.clear_all_peers()?;
    assert_eq!(peer_count(&dir)?, 0_usize);

    janitor.delete_peerlist_file()?;
    assert!(!peerlist_tmp_file(&dir).exists());

    Ok(())
}
