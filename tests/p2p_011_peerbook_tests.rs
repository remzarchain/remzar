#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use remzar::network::p2p_011_peerbook::PeerBook;
use serde_json::{Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn generated_peer_id() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

fn saved_peer_entry<'a>(json: &'a Value, peer: &PeerId) -> Result<&'a Value> {
    let peer_id = peer.to_string();
    let peers = json["peers"].as_array().context("expected peers array")?;

    peers
        .iter()
        .find(|entry| entry["peer_id"].as_str() == Some(peer_id.as_str()))
        .context("expected saved peer entry")
}

fn saved_score(dir: &Path, peer: &PeerId) -> Result<i64> {
    let json = read_json_file(dir)?;
    let entry = saved_peer_entry(&json, peer)?;
    entry["score"]
        .as_i64()
        .context("expected saved score field")
}

fn saved_addrs_len(dir: &Path, peer: &PeerId) -> Result<usize> {
    let json = read_json_file(dir)?;
    let entry = saved_peer_entry(&json, peer)?;
    let addrs = entry["addrs"]
        .as_array()
        .context("expected saved addrs array")?;
    Ok(addrs.len())
}

fn memory_addr(seed: u64) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    addr.push(Protocol::Memory(seed));
    addr
}

fn attach_peer(mut base: Multiaddr, peer: &PeerId) -> Multiaddr {
    base.push(Protocol::P2p(*peer));
    base
}

fn parse_addr(value: &str) -> Result<Multiaddr> {
    value
        .parse::<Multiaddr>()
        .with_context(|| format!("failed to parse multiaddr: {value}"))
}

fn fresh_dir(label: &str) -> Result<PathBuf> {
    let id = TEST_DIR_COUNTER.fetch_add(1_u64, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "remzar_peerbook_tests_{}_{}_{}",
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

fn write_json_file(dir: &Path, value: &Value) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create test dir: {}", dir.display()))?;
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(peerlist_file(dir), bytes)
        .with_context(|| format!("failed to write peerlist file in {}", dir.display()))?;
    Ok(())
}

fn read_json_file(dir: &Path) -> Result<Value> {
    let bytes = fs::read(peerlist_file(dir))
        .with_context(|| format!("failed to read peerlist file in {}", dir.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn oversized_multiaddr() -> Multiaddr {
    let mut addr = Multiaddr::empty();
    let mut seed = 1_u64;

    while addr.to_vec().len() <= 256_usize {
        addr.push(Protocol::Memory(seed));
        seed = seed.saturating_add(1_u64);
    }

    addr
}

fn top_peer_ids(pb: &PeerBook, n: usize) -> Vec<String> {
    pb.top_n(n)
        .into_iter()
        .map(|(peer_id, _addrs)| peer_id)
        .collect()
}

fn top_addr_count(pb: &PeerBook, peer: &PeerId) -> usize {
    pb.top_n(1024_usize)
        .into_iter()
        .find_map(|(peer_id, addrs)| {
            if peer_id == peer.to_string() {
                Some(addrs.len())
            } else {
                None
            }
        })
        .unwrap_or(0_usize)
}

/* ───────────────────────── fresh init / basic upsert ───────────────────── */

#[test]
fn test_001_default_peerbook_top_n_is_empty() -> Result<()> {
    let pb = PeerBook::default();

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_002_load_or_init_in_fresh_dir_creates_empty_peerbook_and_file() -> Result<()> {
    let dir = fresh_dir("fresh_init")?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    assert!(peerlist_file(&dir).exists());
    Ok(())
}

#[test]
fn test_003_upsert_base_addr_adds_peer_to_top_n() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addr = memory_addr(3_u64);

    pb.upsert(&peer, [addr.clone()], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert_eq!(rows[0].1, vec![addr]);
    Ok(())
}

#[test]
fn test_004_upsert_full_p2p_addr_strips_peer_suffix_for_storage() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let base = memory_addr(4_u64);
    let full = attach_peer(base.clone(), &peer);

    pb.upsert(&peer, [full], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].1, vec![base]);
    Ok(())
}

#[test]
fn test_005_upsert_multiple_duplicate_addrs_dedupes() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addr = memory_addr(5_u64);

    pb.upsert(&peer, [addr.clone(), addr.clone(), addr.clone()], false);

    assert_eq!(top_addr_count(&pb, &peer), 1_usize);
    Ok(())
}

#[test]
fn test_006_upsert_base_and_full_same_addr_dedupes_to_one_base() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let base = memory_addr(6_u64);
    let full = attach_peer(base.clone(), &peer);

    pb.upsert(&peer, [base.clone(), full], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows[0].1, vec![base]);
    Ok(())
}

#[test]
fn test_007_upsert_empty_addr_is_persisted_by_public_contract() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [Multiaddr::empty()], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].1, vec![Multiaddr::empty()]);
    Ok(())
}

#[test]
fn test_008_upsert_p2p_only_addr_is_retained_by_strip_fallback() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let p2p_only = attach_peer(Multiaddr::empty(), &peer);

    pb.upsert(&peer, [p2p_only.clone()], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].1, vec![p2p_only]);
    Ok(())
}

/* ───────────────────────── score / failure / top_n ordering ────────────── */

#[test]
fn test_009_mark_success_peer_ranks_above_non_success_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let success_peer = generated_peer_id();
    let normal_peer = generated_peer_id();

    pb.upsert(&normal_peer, [memory_addr(9_u64)], false);
    pb.upsert(&success_peer, [memory_addr(10_u64)], true);

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&success_peer.to_string()));
    Ok(())
}

#[test]
fn test_010_repeated_non_success_upserts_increase_score_and_rank() -> Result<()> {
    let mut pb = PeerBook::default();
    let high_score_peer = generated_peer_id();
    let low_score_peer = generated_peer_id();

    pb.upsert(&low_score_peer, [memory_addr(10_u64)], false);
    for seed in 11_u64..16_u64 {
        pb.upsert(&high_score_peer, [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&high_score_peer.to_string()));
    Ok(())
}

#[test]
fn test_011_observe_failure_lowers_score_without_removing_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let failed_peer = generated_peer_id();
    let other_peer = generated_peer_id();

    pb.upsert(&failed_peer, [memory_addr(11_u64)], false);
    pb.upsert(&other_peer, [memory_addr(12_u64)], false);
    pb.observe_failure(&failed_peer);

    let rows = pb.top_n(2_usize);
    assert_eq!(rows.len(), 2_usize);
    assert!(
        rows.iter()
            .any(|(peer_id, _)| peer_id == &failed_peer.to_string())
    );

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&other_peer.to_string()));
    Ok(())
}

#[test]
fn test_012_observe_failure_missing_peer_does_not_create_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let missing_peer = generated_peer_id();

    pb.observe_failure(&missing_peer);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_013_top_n_zero_returns_empty_even_with_peers() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(13_u64)], false);

    assert!(pb.top_n(0_usize).is_empty());
    Ok(())
}

#[test]
fn test_014_top_n_larger_than_peer_count_returns_all_peers() -> Result<()> {
    let mut pb = PeerBook::default();

    for seed in 14_u64..17_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    assert_eq!(pb.top_n(100_usize).len(), 3_usize);
    Ok(())
}

/* ───────────────────────── tags / sticky ordering / caps ───────────────── */

#[test]
fn test_015_add_tag_creates_peer_even_without_addr() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.add_tag(&peer, "seed");

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert!(rows[0].1.is_empty());
    Ok(())
}

#[test]
fn test_016_sticky_seed_peer_ranks_above_higher_score_non_sticky_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let sticky_peer = generated_peer_id();
    let high_score_peer = generated_peer_id();

    pb.upsert(&sticky_peer, [memory_addr(16_u64)], false);
    pb.add_tag(&sticky_peer, "seed");

    for seed in 17_u64..30_u64 {
        pb.upsert(&high_score_peer, [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&sticky_peer.to_string()));
    Ok(())
}

#[test]
fn test_017_sticky_stable_peer_ranks_first() -> Result<()> {
    let mut pb = PeerBook::default();
    let stable_peer = generated_peer_id();
    let normal_peer = generated_peer_id();

    pb.upsert(&normal_peer, [memory_addr(17_u64)], true);
    pb.upsert(&stable_peer, [memory_addr(18_u64)], false);
    pb.add_tag(&stable_peer, "stable");

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&stable_peer.to_string()));
    Ok(())
}

#[test]
fn test_018_sticky_static_peer_ranks_first() -> Result<()> {
    let mut pb = PeerBook::default();
    let static_peer = generated_peer_id();
    let normal_peer = generated_peer_id();

    pb.upsert(&normal_peer, [memory_addr(18_u64)], true);
    pb.upsert(&static_peer, [memory_addr(19_u64)], false);
    pb.add_tag(&static_peer, "static");

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&static_peer.to_string()));
    Ok(())
}

#[test]
fn test_019_remove_tag_removes_sticky_priority() -> Result<()> {
    let mut pb = PeerBook::default();
    let former_sticky = generated_peer_id();
    let high_score = generated_peer_id();

    pb.upsert(&former_sticky, [memory_addr(19_u64)], false);
    pb.add_tag(&former_sticky, "seed");
    pb.remove_tag(&former_sticky, "seed");

    for seed in 20_u64..40_u64 {
        pb.upsert(&high_score, [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&high_score.to_string()));
    Ok(())
}

#[test]
fn test_020_remove_missing_tag_is_safe() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(20_u64)], false);
    pb.remove_tag(&peer, "missing");

    assert_eq!(pb.top_n(1_usize).len(), 1_usize);
    Ok(())
}

#[test]
fn test_021_long_tag_over_64_bytes_is_ignored_and_peer_is_not_created() -> Result<()> {
    let dir = fresh_dir("long_tag_ignored")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let long_tag = "x".repeat(65_usize);

    pb.add_tag(&peer, long_tag);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let peers = json["peers"].as_array().context("expected peers array")?;

    assert!(peers.is_empty());
    assert!(pb.top_n(1_usize).is_empty());
    Ok(())
}

#[test]
fn test_022_tags_are_capped_at_16_per_peer_on_add() -> Result<()> {
    let dir = fresh_dir("tag_cap")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    for index in 0_u8..20_u8 {
        pb.add_tag(&peer, format!("tag-{index}"));
    }

    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let tags = json["peers"][0_usize]["tags"]
        .as_array()
        .context("expected tags array")?;
    assert_eq!(tags.len(), 16_usize);
    Ok(())
}

/* ───────────────────────── address / peer caps ─────────────────────────── */

#[test]
fn test_023_addresses_per_peer_are_capped_at_32() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addrs = (0_u64..40_u64).map(memory_addr).collect::<Vec<_>>();

    pb.upsert(&peer, addrs, false);

    assert_eq!(top_addr_count(&pb, &peer), 32_usize);
    Ok(())
}

#[test]
fn test_024_upsert_skips_oversized_multiaddr() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let good = memory_addr(24_u64);
    let bad = oversized_multiaddr();

    assert!(bad.to_vec().len() > 256_usize);

    pb.upsert(&peer, [bad, good.clone()], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows[0].1, vec![good]);
    Ok(())
}

#[test]
fn test_025_peer_cap_enforced_at_512() -> Result<()> {
    let mut pb = PeerBook::default();

    for seed in 0_u64..520_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    assert_eq!(pb.top_n(600_usize).len(), 512_usize);
    Ok(())
}

#[test]
fn test_026_sticky_peer_survives_peer_cap_pressure() -> Result<()> {
    let mut pb = PeerBook::default();
    let sticky_peer = generated_peer_id();

    pb.upsert(&sticky_peer, [memory_addr(26_u64)], false);
    pb.add_tag(&sticky_peer, "seed");

    for seed in 1000_u64..1530_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 600_usize);
    assert!(
        ids.iter()
            .any(|peer_id| peer_id == &sticky_peer.to_string())
    );
    assert_eq!(ids.len(), 512_usize);
    Ok(())
}

/* ───────────────────────── save / load new schema ──────────────────────── */

#[test]
fn test_027_save_in_then_load_or_init_in_round_trips_peer() -> Result<()> {
    let dir = fresh_dir("save_load_roundtrip")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addr = memory_addr(27_u64);

    pb.upsert(&peer, [addr.clone()], true);
    pb.add_tag(&peer, "seed");
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let rows = loaded.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert_eq!(rows[0].1, vec![addr]);
    Ok(())
}

#[test]
fn test_028_saved_file_has_version_one_and_updated_timestamp() -> Result<()> {
    let dir = fresh_dir("saved_file_schema")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(28_u64)], false);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    assert_eq!(json["version"].as_u64(), Some(1_u64));
    assert!(json["updated_at_unix"].as_u64().unwrap_or(0_u64) > 0_u64);
    assert_eq!(
        json["peers"]
            .as_array()
            .context("expected peers array")?
            .len(),
        1_usize
    );
    Ok(())
}

#[test]
fn test_029_load_new_schema_accepts_empty_addrs_peer() -> Result<()> {
    let dir = fresh_dir("load_empty_addrs_peer")?;
    let peer = generated_peer_id();
    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [],
            "score": 42,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": ["seed"]
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert!(rows[0].1.is_empty());
    Ok(())
}

#[test]
fn test_030_load_new_schema_skips_overlong_peer_id() -> Result<()> {
    let dir = fresh_dir("load_skip_long_pid")?;
    let long_peer_id = "x".repeat(129_usize);
    let valid_peer = generated_peer_id();
    let valid_addr = memory_addr(30_u64);
    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": long_peer_id,
                "addrs": [valid_addr.to_string()],
                "score": 100,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            },
            {
                "peer_id": valid_peer.to_string(),
                "addrs": [valid_addr.to_string()],
                "score": 10,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 10_usize);

    assert_eq!(ids, vec![valid_peer.to_string()]);
    Ok(())
}

#[test]
fn test_031_load_new_schema_caps_addresses_per_peer_at_32() -> Result<()> {
    let dir = fresh_dir("load_addr_cap")?;
    let peer = generated_peer_id();
    let addrs = (0_u64..40_u64)
        .map(|seed| memory_addr(seed).to_string())
        .collect::<Vec<_>>();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": addrs,
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert_eq!(top_addr_count(&pb, &peer), 32_usize);
    Ok(())
}

#[test]
fn test_032_load_new_schema_caps_tags_per_peer_at_16_and_skips_long_tags() -> Result<()> {
    let dir = fresh_dir("load_tag_cap")?;
    let peer = generated_peer_id();
    let tags = (0_u8..20_u8)
        .map(|index| format!("tag-{index}"))
        .chain(std::iter::once("x".repeat(65_usize)))
        .collect::<Vec<_>>();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [memory_addr(32_u64).to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": tags
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    Ok(())
}

/* ───────────────────────── invalid / migration files ───────────────────── */

#[test]
fn test_033_load_bad_version_falls_back_to_default() -> Result<()> {
    let dir = fresh_dir("bad_version")?;
    let json = serde_json::json!({
        "version": 999,
        "updated_at_unix": 1,
        "peers": []
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_034_load_malformed_json_falls_back_to_default() -> Result<()> {
    let dir = fresh_dir("malformed_json")?;
    fs::create_dir_all(&dir)?;
    fs::write(peerlist_file(&dir), b"{not valid json")?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_035_load_oversized_peerlist_file_falls_back_to_default() -> Result<()> {
    let dir = fresh_dir("oversized_file")?;
    fs::create_dir_all(&dir)?;
    let huge = vec![b' '; (4_usize * 1024_usize * 1024_usize) + 1_usize];
    fs::write(peerlist_file(&dir), huge)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_036_migrate_old_schema_loads_peer_addr() -> Result<()> {
    let dir = fresh_dir("old_schema")?;
    fs::create_dir_all(&dir)?;

    let peer = generated_peer_id();
    let addr = memory_addr(36_u64);
    let mut map = Map::new();
    map.insert(peer.to_string(), Value::String(addr.to_string()));
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert_eq!(rows[0].1, vec![addr]);
    Ok(())
}

#[test]
fn test_037_migrate_old_schema_skips_oversized_addr_string() -> Result<()> {
    let dir = fresh_dir("old_schema_oversized_addr")?;
    fs::create_dir_all(&dir)?;

    let peer = generated_peer_id();
    let mut map = Map::new();
    map.insert(peer.to_string(), Value::String("x".repeat(2000_usize)));
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_038_migrate_old_schema_skips_overlong_peer_id() -> Result<()> {
    let dir = fresh_dir("old_schema_overlong_pid")?;
    fs::create_dir_all(&dir)?;

    let mut map = Map::new();
    map.insert(
        "x".repeat(129_usize),
        Value::String(memory_addr(38_u64).to_string()),
    );
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

/* ───────────────────────── vector / adversarial paths ──────────────────── */

#[test]
fn test_039_vector_multiple_transport_addrs_round_trip_save_load() -> Result<()> {
    let dir = fresh_dir("transport_vectors")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/36213")?;
    let ip6 = parse_addr("/ip6/::1/tcp/36214")?;
    let quic = parse_addr("/ip4/127.0.0.1/udp/36215/quic-v1")?;

    pb.upsert(&peer, [ip4.clone(), ip6.clone(), quic.clone()], true);
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let rows = loaded.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0].0, peer.to_string());
    assert_eq!(rows[0].1.len(), 3_usize);
    assert!(rows[0].1.contains(&ip4));
    assert!(rows[0].1.contains(&ip6));
    assert!(rows[0].1.contains(&quic));
    Ok(())
}

#[test]
fn test_040_combined_adversarial_peerbook_path_is_safe() -> Result<()> {
    let dir = fresh_dir("combined_adversarial")?;
    let mut pb = PeerBook::default();

    let sticky_peer = generated_peer_id();
    let normal_peer = generated_peer_id();

    let sticky_base = memory_addr(40_u64);
    let sticky_full = attach_peer(sticky_base.clone(), &sticky_peer);

    pb.upsert(
        &sticky_peer,
        [
            Multiaddr::empty(),
            sticky_full,
            oversized_multiaddr(),
            sticky_base.clone(),
        ],
        true,
    );
    pb.add_tag(&sticky_peer, "seed");

    for seed in 100_u64..150_u64 {
        pb.upsert(&normal_peer, [memory_addr(seed)], false);
    }
    pb.observe_failure(&normal_peer);

    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let rows = loaded.top_n(2_usize);

    assert_eq!(rows.len(), 2_usize);
    assert_eq!(rows[0].0, sticky_peer.to_string());
    assert!(rows[0].1.contains(&sticky_base));
    assert!(rows[0].1.len() <= 32_usize);
    Ok(())
}

#[test]
fn test_041_mark_success_score_caps_at_120() -> Result<()> {
    let dir = fresh_dir("success_score_cap")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    for seed in 0_u64..20_u64 {
        pb.upsert(&peer, [memory_addr(seed)], true);
    }

    pb.save_in(&dir)?;

    assert_eq!(saved_score(&dir, &peer)?, 120_i64);
    Ok(())
}

#[test]
fn test_042_non_success_score_caps_at_120() -> Result<()> {
    let dir = fresh_dir("non_success_score_cap")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    for seed in 0_u64..40_u64 {
        pb.upsert(&peer, [memory_addr(seed)], false);
    }

    pb.save_in(&dir)?;

    assert_eq!(saved_score(&dir, &peer)?, 120_i64);
    Ok(())
}

#[test]
fn test_043_observe_failure_score_floors_at_negative_120() -> Result<()> {
    let dir = fresh_dir("failure_score_floor")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(43_u64)], false);

    for _round in 0_u8..64_u8 {
        pb.observe_failure(&peer);
    }

    pb.save_in(&dir)?;

    assert_eq!(saved_score(&dir, &peer)?, -120_i64);
    Ok(())
}

#[test]
fn test_044_mark_success_sets_last_success_timestamp() -> Result<()> {
    let dir = fresh_dir("last_success_set")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(44_u64)], true);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    assert!(entry["last_success_unix"].as_u64().unwrap_or(0_u64) > 0_u64);
    assert!(entry["last_failure_unix"].is_null());
    Ok(())
}

#[test]
fn test_045_non_success_upsert_does_not_set_last_success() -> Result<()> {
    let dir = fresh_dir("last_success_not_set")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(45_u64)], false);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    assert!(entry["last_success_unix"].is_null());
    Ok(())
}

#[test]
fn test_046_observe_failure_sets_last_failure_timestamp() -> Result<()> {
    let dir = fresh_dir("last_failure_set")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(46_u64)], false);
    pb.observe_failure(&peer);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    assert!(entry["last_failure_unix"].as_u64().unwrap_or(0_u64) > 0_u64);
    Ok(())
}

#[test]
fn test_047_success_then_failure_keeps_peer_with_both_timestamps() -> Result<()> {
    let dir = fresh_dir("success_then_failure")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(47_u64)], true);
    pb.observe_failure(&peer);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;

    assert!(entry["last_success_unix"].as_u64().unwrap_or(0_u64) > 0_u64);
    assert!(entry["last_failure_unix"].as_u64().unwrap_or(0_u64) > 0_u64);
    Ok(())
}

/* ───────────────────────── tag boundaries and persistence ─────────────── */

#[test]
fn test_048_remove_existing_tag_persists_empty_tags() -> Result<()> {
    let dir = fresh_dir("remove_existing_tag")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(48_u64)], false);
    pb.add_tag(&peer, "seed");
    pb.remove_tag(&peer, "seed");
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let tags = entry["tags"].as_array().context("expected tags array")?;

    assert!(tags.is_empty());
    Ok(())
}

#[test]
fn test_049_duplicate_tags_are_deduped() -> Result<()> {
    let dir = fresh_dir("duplicate_tags")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.add_tag(&peer, "seed");
    pb.add_tag(&peer, "seed");
    pb.add_tag(&peer, "seed");
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let tags = entry["tags"].as_array().context("expected tags array")?;

    assert_eq!(tags.len(), 1_usize);
    assert_eq!(tags[0_usize].as_str(), Some("seed"));
    Ok(())
}

#[test]
fn test_050_tag_exactly_64_bytes_is_accepted() -> Result<()> {
    let dir = fresh_dir("tag_exact_64")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let tag = "x".repeat(64_usize);

    pb.add_tag(&peer, tag.clone());
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let tags = entry["tags"].as_array().context("expected tags array")?;

    assert_eq!(tags.len(), 1_usize);
    assert_eq!(tags[0_usize].as_str(), Some(tag.as_str()));
    Ok(())
}

#[test]
fn test_051_long_tag_on_existing_peer_is_ignored() -> Result<()> {
    let dir = fresh_dir("long_tag_existing_peer")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(51_u64)], false);
    pb.add_tag(&peer, "x".repeat(65_usize));
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let tags = entry["tags"].as_array().context("expected tags array")?;

    assert!(tags.is_empty());
    Ok(())
}

#[test]
fn test_052_tag_cap_prevents_seventeenth_tag() -> Result<()> {
    let dir = fresh_dir("tag_cap_prevents_17")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    for index in 0_u8..16_u8 {
        pb.add_tag(&peer, format!("tag-{index}"));
    }
    pb.add_tag(&peer, "seed");

    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let tags = entry["tags"].as_array().context("expected tags array")?;

    assert_eq!(tags.len(), 16_usize);
    assert!(!tags.iter().any(|tag| tag.as_str() == Some("seed")));
    Ok(())
}

#[test]
fn test_053_uppercase_seed_tag_is_not_sticky() -> Result<()> {
    let mut pb = PeerBook::default();
    let uppercase_seed_peer = generated_peer_id();
    let high_score_peer = generated_peer_id();

    pb.upsert(&uppercase_seed_peer, [memory_addr(53_u64)], false);
    pb.add_tag(&uppercase_seed_peer, "Seed");

    for seed in 100_u64..130_u64 {
        pb.upsert(&high_score_peer, [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 2_usize);
    assert_eq!(ids.first(), Some(&high_score_peer.to_string()));
    Ok(())
}

#[test]
fn test_054_seed_tag_sticky_priority_survives_save_load() -> Result<()> {
    let dir = fresh_dir("sticky_survives_load")?;
    let mut pb = PeerBook::default();
    let sticky_peer = generated_peer_id();
    let high_score_peer = generated_peer_id();

    pb.upsert(&sticky_peer, [memory_addr(54_u64)], false);
    pb.add_tag(&sticky_peer, "seed");

    for seed in 200_u64..230_u64 {
        pb.upsert(&high_score_peer, [memory_addr(seed)], false);
    }

    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&loaded, 2_usize);

    assert_eq!(ids.first(), Some(&sticky_peer.to_string()));
    Ok(())
}

/* ───────────────────────── save shape / address persistence ───────────── */

#[test]
fn test_055_upsert_full_p2p_saves_base_addr_without_p2p_suffix() -> Result<()> {
    let dir = fresh_dir("save_strips_p2p")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let base = memory_addr(55_u64);
    let full = attach_peer(base.clone(), &peer);

    pb.upsert(&peer, [full], false);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let addrs = entry["addrs"].as_array().context("expected addrs array")?;

    assert_eq!(addrs.len(), 1_usize);
    assert_eq!(addrs[0_usize].as_str(), Some(base.to_string().as_str()));
    Ok(())
}

#[test]
fn test_056_p2p_only_addr_saves_as_one_addr() -> Result<()> {
    let dir = fresh_dir("p2p_only_saved")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let p2p_only = attach_peer(Multiaddr::empty(), &peer);

    pb.upsert(&peer, [p2p_only.clone()], false);
    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let entry = saved_peer_entry(&json, &peer)?;
    let addrs = entry["addrs"].as_array().context("expected addrs array")?;

    assert_eq!(addrs.len(), 1_usize);
    assert_eq!(addrs[0_usize].as_str(), Some(p2p_only.to_string().as_str()));
    Ok(())
}

#[test]
fn test_057_empty_addr_saves_as_one_addr() -> Result<()> {
    let dir = fresh_dir("empty_addr_saved")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [Multiaddr::empty()], false);
    pb.save_in(&dir)?;

    assert_eq!(saved_addrs_len(&dir, &peer)?, 1_usize);
    Ok(())
}

#[test]
fn test_058_save_in_creates_nested_directory() -> Result<()> {
    let root = fresh_dir("nested_save_root")?;
    let dir = root.join("a").join("b").join("c");
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.upsert(&peer, [memory_addr(58_u64)], false);
    pb.save_in(&dir)?;

    assert!(peerlist_file(&dir).exists());
    Ok(())
}

#[test]
fn test_059_saved_addrs_are_capped_at_32() -> Result<()> {
    let dir = fresh_dir("saved_addr_cap")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addrs = (0_u64..100_u64).map(memory_addr).collect::<Vec<_>>();

    pb.upsert(&peer, addrs, false);
    pb.save_in(&dir)?;

    assert_eq!(saved_addrs_len(&dir, &peer)?, 32_usize);
    Ok(())
}

#[test]
fn test_060_saved_peers_are_capped_at_512() -> Result<()> {
    let dir = fresh_dir("saved_peer_cap")?;
    let mut pb = PeerBook::default();

    for seed in 0_u64..700_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    let peers = json["peers"].as_array().context("expected peers array")?;
    assert_eq!(peers.len(), 512_usize);
    Ok(())
}

/* ───────────────────────── load new schema edge cases ─────────────────── */

#[test]
fn test_061_load_new_schema_skips_invalid_addr_but_keeps_peer() -> Result<()> {
    let dir = fresh_dir("load_invalid_addr")?;
    let peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": ["not-a-multiaddr"],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize].0, peer.to_string());
    assert!(rows[0_usize].1.is_empty());
    Ok(())
}

#[test]
fn test_062_load_new_schema_skips_oversized_addr_and_keeps_good_addr() -> Result<()> {
    let dir = fresh_dir("load_oversized_addr_keep_good")?;
    let peer = generated_peer_id();
    let good = memory_addr(62_u64);

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [oversized_multiaddr().to_string(), good.to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows[0_usize].1, vec![good]);
    Ok(())
}

#[test]
fn test_063_load_new_schema_skips_absurd_addr_string_before_parse() -> Result<()> {
    let dir = fresh_dir("load_absurd_addr_string")?;
    let peer = generated_peer_id();
    let good = memory_addr(63_u64);

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": ["x".repeat(2000_usize), good.to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows[0_usize].1, vec![good]);
    Ok(())
}

#[test]
fn test_064_load_new_schema_preserves_score_ordering() -> Result<()> {
    let dir = fresh_dir("load_score_ordering")?;
    let low_peer = generated_peer_id();
    let high_peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": low_peer.to_string(),
                "addrs": [memory_addr(64_u64).to_string()],
                "score": 1,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            },
            {
                "peer_id": high_peer.to_string(),
                "addrs": [memory_addr(65_u64).to_string()],
                "score": 100,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 2_usize);

    assert_eq!(ids.first(), Some(&high_peer.to_string()));
    Ok(())
}

#[test]
fn test_065_load_new_schema_last_success_orders_before_score() -> Result<()> {
    let dir = fresh_dir("load_last_success_ordering")?;
    let recent_peer = generated_peer_id();
    let high_score_peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": high_score_peer.to_string(),
                "addrs": [memory_addr(65_u64).to_string()],
                "score": 120,
                "last_success_unix": 1,
                "last_failure_unix": null,
                "tags": []
            },
            {
                "peer_id": recent_peer.to_string(),
                "addrs": [memory_addr(66_u64).to_string()],
                "score": 1,
                "last_success_unix": 999999,
                "last_failure_unix": null,
                "tags": []
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 2_usize);

    assert_eq!(ids.first(), Some(&recent_peer.to_string()));
    Ok(())
}

#[test]
fn test_066_load_new_schema_sticky_tag_orders_before_recent_success() -> Result<()> {
    let dir = fresh_dir("load_sticky_ordering")?;
    let sticky_peer = generated_peer_id();
    let recent_peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": recent_peer.to_string(),
                "addrs": [memory_addr(66_u64).to_string()],
                "score": 120,
                "last_success_unix": 999999,
                "last_failure_unix": null,
                "tags": []
            },
            {
                "peer_id": sticky_peer.to_string(),
                "addrs": [memory_addr(67_u64).to_string()],
                "score": 1,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": ["stable"]
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 2_usize);

    assert_eq!(ids.first(), Some(&sticky_peer.to_string()));
    Ok(())
}

#[test]
fn test_067_load_new_schema_non_sticky_unknown_tag_does_not_get_priority() -> Result<()> {
    let dir = fresh_dir("load_nonsticky_unknown_tag")?;
    let tagged_peer = generated_peer_id();
    let high_score_peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": tagged_peer.to_string(),
                "addrs": [memory_addr(67_u64).to_string()],
                "score": 1,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": ["bootstrap"]
            },
            {
                "peer_id": high_score_peer.to_string(),
                "addrs": [memory_addr(68_u64).to_string()],
                "score": 120,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 2_usize);

    assert_eq!(ids.first(), Some(&high_score_peer.to_string()));
    Ok(())
}

#[test]
fn test_068_load_new_schema_caps_peer_count_at_512() -> Result<()> {
    let dir = fresh_dir("load_peer_cap")?;
    let mut peers = Vec::new();

    for seed in 0_u64..520_u64 {
        let peer = generated_peer_id();
        peers.push(serde_json::json!({
            "peer_id": peer.to_string(),
            "addrs": [memory_addr(seed).to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }));
    }

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": peers
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert_eq!(pb.top_n(600_usize).len(), 512_usize);
    Ok(())
}

#[test]
fn test_069_load_new_schema_caps_all_sticky_peer_count_at_512() -> Result<()> {
    let dir = fresh_dir("load_all_sticky_peer_cap")?;
    let mut peers = Vec::new();

    for seed in 0_u64..520_u64 {
        let peer = generated_peer_id();
        peers.push(serde_json::json!({
            "peer_id": peer.to_string(),
            "addrs": [memory_addr(seed).to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": ["seed"]
        }));
    }

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": peers
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert_eq!(pb.top_n(600_usize).len(), 512_usize);
    Ok(())
}

/* ───────────────────────── old-schema migration vectors ───────────────── */

#[test]
fn test_070_migrate_old_schema_preserves_full_p2p_addr() -> Result<()> {
    let dir = fresh_dir("old_schema_full_p2p")?;
    fs::create_dir_all(&dir)?;

    let peer = generated_peer_id();
    let base = memory_addr(70_u64);
    let full = attach_peer(base, &peer);

    let mut map = Map::new();
    map.insert(peer.to_string(), Value::String(full.to_string()));
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize].1, vec![full]);
    Ok(())
}

#[test]
fn test_071_migrate_old_schema_skips_invalid_addr_string() -> Result<()> {
    let dir = fresh_dir("old_schema_invalid_addr")?;
    fs::create_dir_all(&dir)?;

    let peer = generated_peer_id();
    let mut map = Map::new();
    map.insert(
        peer.to_string(),
        Value::String("not-a-multiaddr".to_owned()),
    );
    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_072_migrate_old_schema_caps_peer_count_at_512() -> Result<()> {
    let dir = fresh_dir("old_schema_peer_cap")?;
    fs::create_dir_all(&dir)?;

    let mut map = Map::new();
    for seed in 0_u64..520_u64 {
        map.insert(
            generated_peer_id().to_string(),
            Value::String(memory_addr(seed).to_string()),
        );
    }

    fs::write(
        peerlist_file(&dir),
        serde_json::to_vec_pretty(&Value::Object(map))?,
    )?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert_eq!(pb.top_n(600_usize).len(), 512_usize);
    Ok(())
}

#[test]
fn test_073_migrate_old_schema_empty_map_returns_empty_peerbook() -> Result<()> {
    let dir = fresh_dir("old_schema_empty_map")?;
    fs::create_dir_all(&dir)?;

    fs::write(peerlist_file(&dir), b"{}")?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

/* ───────────────────────── malformed schema / file cases ──────────────── */

#[test]
fn test_074_load_new_schema_accepts_128_byte_peer_id_string() -> Result<()> {
    let dir = fresh_dir("load_pid_len_128")?;
    let peer_id = "p".repeat(128_usize);

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer_id,
            "addrs": [memory_addr(74_u64).to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    assert_eq!(pb.top_n(1_usize).len(), 1_usize);
    Ok(())
}

#[test]
fn test_075_remove_tag_missing_peer_does_not_create_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    pb.remove_tag(&peer, "seed");

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_076_observe_failure_then_upsert_missing_peer_creates_normal_peer() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let addr = memory_addr(76_u64);

    pb.observe_failure(&peer);
    pb.upsert(&peer, [addr.clone()], false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize].1, vec![addr]);
    Ok(())
}

#[test]
fn test_077_load_schema_missing_updated_at_falls_back_to_default() -> Result<()> {
    let dir = fresh_dir("missing_updated_at")?;
    let json = serde_json::json!({
        "version": 1,
        "peers": []
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_078_load_schema_extra_fields_are_ignored() -> Result<()> {
    let dir = fresh_dir("extra_fields")?;
    let peer = generated_peer_id();
    let addr = memory_addr(78_u64);

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "extra_root": true,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [addr.to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": [],
            "extra_peer_field": "ignored"
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize].1, vec![addr]);
    Ok(())
}

#[test]
fn test_079_load_or_init_in_missing_file_creates_file() -> Result<()> {
    let dir = fresh_dir("missing_file")?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    assert!(peerlist_file(&dir).exists());
    Ok(())
}

#[test]
fn test_080_save_in_removes_stale_tmp_file_on_success() -> Result<()> {
    let dir = fresh_dir("stale_tmp_cleanup")?;
    fs::create_dir_all(&dir)?;
    let tmp = dir.join("peerlist.json.tmp");
    fs::write(&tmp, b"stale")?;

    let mut pb = PeerBook::default();
    pb.upsert(&generated_peer_id(), [memory_addr(80_u64)], false);
    pb.save_in(&dir)?;

    assert!(!tmp.exists());
    assert!(peerlist_file(&dir).exists());
    Ok(())
}

/* ───────────────────────── cap and ordering pressure ──────────────────── */

#[test]
fn test_081_peer_cap_removes_nonsticky_before_sticky() -> Result<()> {
    let mut pb = PeerBook::default();
    let sticky_peer = generated_peer_id();

    pb.upsert(&sticky_peer, [memory_addr(81_u64)], false);
    pb.add_tag(&sticky_peer, "seed");

    for seed in 1000_u64..1512_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    let ids = top_peer_ids(&pb, 600_usize);

    assert_eq!(ids.len(), 512_usize);
    assert!(
        ids.iter()
            .any(|peer_id| peer_id == &sticky_peer.to_string())
    );
    Ok(())
}

#[test]
fn test_082_peer_cap_with_all_sticky_peers_still_caps_to_512_when_upsert_enforces() -> Result<()> {
    let mut pb = PeerBook::default();

    for seed in 0_u64..520_u64 {
        let peer = generated_peer_id();
        pb.add_tag(&peer, "seed");
        pb.upsert(&peer, [memory_addr(seed)], false);
    }

    assert_eq!(pb.top_n(600_usize).len(), 512_usize);
    Ok(())
}

#[test]
fn test_083_adding_new_unique_addr_after_32_cap_does_not_increase_addr_count() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    let first_batch = (0_u64..32_u64).map(memory_addr).collect::<Vec<_>>();
    pb.upsert(&peer, first_batch, false);

    pb.upsert(&peer, [memory_addr(999_u64)], false);

    assert_eq!(top_addr_count(&pb, &peer), 32_usize);
    Ok(())
}

#[test]
fn test_084_duplicate_addrs_do_not_block_later_unique_addrs_before_cap() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let duplicate = memory_addr(84_u64);
    let unique = memory_addr(85_u64);

    let mut addrs = Vec::new();
    for _round in 0_u8..40_u8 {
        addrs.push(duplicate.clone());
    }
    addrs.push(unique.clone());

    pb.upsert(&peer, addrs, false);

    let rows = pb.top_n(1_usize);
    assert_eq!(rows.len(), 1_usize);
    assert!(rows[0_usize].1.contains(&duplicate));
    assert!(rows[0_usize].1.contains(&unique));
    Ok(())
}

#[test]
fn test_085_top_n_returns_requested_subset_size() -> Result<()> {
    let mut pb = PeerBook::default();

    for seed in 0_u64..10_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    assert_eq!(pb.top_n(5_usize).len(), 5_usize);
    Ok(())
}

/* ───────────────────────── load / fuzz style tests ────────────────────── */

#[test]
fn test_086_load_64_saved_peers_round_trip() -> Result<()> {
    let dir = fresh_dir("load_64_saved_peers")?;
    let mut pb = PeerBook::default();

    for seed in 0_u64..64_u64 {
        pb.upsert(&generated_peer_id(), [memory_addr(seed)], false);
    }

    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);

    assert_eq!(loaded.top_n(100_usize).len(), 64_usize);
    Ok(())
}

#[test]
fn test_087_load_saved_single_peer_with_100_addrs_still_has_32() -> Result<()> {
    let dir = fresh_dir("load_saved_single_peer_100_addrs")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    let addrs = (0_u64..100_u64).map(memory_addr).collect::<Vec<_>>();
    pb.upsert(&peer, addrs, false);
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);

    assert_eq!(top_addr_count(&loaded, &peer), 32_usize);
    Ok(())
}

#[test]
fn test_088_adversarial_mixed_duplicate_full_and_oversized_addrs_stays_bounded() -> Result<()> {
    let dir = fresh_dir("mixed_duplicate_full_oversized")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();
    let base = memory_addr(88_u64);
    let full = attach_peer(base.clone(), &peer);

    let mut addrs = Vec::new();
    for _round in 0_u8..20_u8 {
        addrs.push(full.clone());
        addrs.push(base.clone());
        addrs.push(oversized_multiaddr());
    }

    pb.upsert(&peer, addrs, true);
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let rows = loaded.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert!(rows[0_usize].1.contains(&base));
    assert!(rows[0_usize].1.len() <= 32_usize);
    Ok(())
}

#[test]
fn test_089_repeated_success_and_failure_path_remains_bounded() -> Result<()> {
    let dir = fresh_dir("success_failure_bounded")?;
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    for seed in 0_u64..64_u64 {
        pb.upsert(&peer, [memory_addr(seed)], true);
        pb.observe_failure(&peer);
    }

    pb.save_in(&dir)?;

    let score = saved_score(&dir, &peer)?;
    assert!((-120_i64..=120_i64).contains(&score));
    assert_eq!(saved_addrs_len(&dir, &peer)?, 32_usize);
    Ok(())
}

#[test]
fn test_090_load_new_schema_negative_score_orders_below_positive_score() -> Result<()> {
    let dir = fresh_dir("negative_score_order")?;
    let negative_peer = generated_peer_id();
    let positive_peer = generated_peer_id();

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [
            {
                "peer_id": negative_peer.to_string(),
                "addrs": [memory_addr(90_u64).to_string()],
                "score": -120,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            },
            {
                "peer_id": positive_peer.to_string(),
                "addrs": [memory_addr(91_u64).to_string()],
                "score": 1,
                "last_success_unix": null,
                "last_failure_unix": null,
                "tags": []
            }
        ]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&pb, 2_usize);

    assert_eq!(ids.first(), Some(&positive_peer.to_string()));
    Ok(())
}

/* ───────────────────────── transport / schema vectors ─────────────────── */

#[test]
fn test_091_transport_vector_full_addrs_are_normalized_to_bases() -> Result<()> {
    let mut pb = PeerBook::default();
    let peer = generated_peer_id();

    let ip4 = parse_addr("/ip4/127.0.0.1/tcp/0")?;
    let ip6 = parse_addr("/ip6/::1/tcp/65535")?;
    let quic = parse_addr("/ip4/127.0.0.1/udp/65535/quic-v1")?;

    pb.upsert(
        &peer,
        [
            attach_peer(ip4.clone(), &peer),
            attach_peer(ip6.clone(), &peer),
            attach_peer(quic.clone(), &peer),
        ],
        false,
    );

    let rows = pb.top_n(1_usize);

    assert_eq!(rows[0_usize].1.len(), 3_usize);
    assert!(rows[0_usize].1.contains(&ip4));
    assert!(rows[0_usize].1.contains(&ip6));
    assert!(rows[0_usize].1.contains(&quic));
    Ok(())
}

#[test]
fn test_092_load_new_schema_preserves_p2p_only_addr_from_file() -> Result<()> {
    let dir = fresh_dir("load_p2p_only_addr")?;
    let peer = generated_peer_id();
    let p2p_only = attach_peer(Multiaddr::empty(), &peer);

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [p2p_only.to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": []
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows[0_usize].1, vec![p2p_only]);
    Ok(())
}

#[test]
fn test_093_empty_new_schema_file_loads_empty_peerbook() -> Result<()> {
    let dir = fresh_dir("empty_new_schema")?;
    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": []
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_094_save_empty_peerbook_writes_valid_schema() -> Result<()> {
    let dir = fresh_dir("save_empty_schema")?;
    let pb = PeerBook::default();

    pb.save_in(&dir)?;

    let json = read_json_file(&dir)?;
    assert_eq!(json["version"].as_u64(), Some(1_u64));
    assert!(
        json["peers"]
            .as_array()
            .context("expected peers array")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn test_095_loaded_long_tags_are_skipped_before_tag_cap() -> Result<()> {
    let dir = fresh_dir("load_long_tags_skipped")?;
    let peer = generated_peer_id();
    let mut tags = vec!["x".repeat(65_usize)];
    for index in 0_u8..16_u8 {
        tags.push(format!("ok-{index}"));
    }

    let json = serde_json::json!({
        "version": 1,
        "updated_at_unix": 1,
        "peers": [{
            "peer_id": peer.to_string(),
            "addrs": [memory_addr(95_u64).to_string()],
            "score": 10,
            "last_success_unix": null,
            "last_failure_unix": null,
            "tags": tags
        }]
    });

    write_json_file(&dir, &json)?;

    let pb = PeerBook::load_or_init_in(&dir);
    let rows = pb.top_n(1_usize);

    assert_eq!(rows.len(), 1_usize);
    assert_eq!(rows[0_usize].0, peer.to_string());
    Ok(())
}

#[test]
fn test_096_score_order_survives_save_load() -> Result<()> {
    let dir = fresh_dir("score_order_save_load")?;
    let high_peer = generated_peer_id();
    let low_peer = generated_peer_id();
    let mut pb = PeerBook::default();

    pb.upsert(&low_peer, [memory_addr(96_u64)], false);
    for seed in 100_u64..130_u64 {
        pb.upsert(&high_peer, [memory_addr(seed)], false);
    }

    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&loaded, 2_usize);

    assert_eq!(ids.first(), Some(&high_peer.to_string()));
    Ok(())
}

#[test]
fn test_097_failure_order_survives_save_load() -> Result<()> {
    let dir = fresh_dir("failure_order_save_load")?;
    let failed_peer = generated_peer_id();
    let healthy_peer = generated_peer_id();
    let mut pb = PeerBook::default();

    pb.upsert(&failed_peer, [memory_addr(97_u64)], false);
    pb.upsert(&healthy_peer, [memory_addr(98_u64)], false);
    pb.observe_failure(&failed_peer);
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let ids = top_peer_ids(&loaded, 2_usize);

    assert_eq!(ids.first(), Some(&healthy_peer.to_string()));
    Ok(())
}

#[test]
fn test_098_combined_load_bad_file_then_save_fresh_peerbook_in_new_dir() -> Result<()> {
    let bad_dir = fresh_dir("bad_then_fresh_bad")?;
    fs::create_dir_all(&bad_dir)?;
    fs::write(peerlist_file(&bad_dir), b"{bad json")?;

    let bad_loaded = PeerBook::load_or_init_in(&bad_dir);
    assert!(bad_loaded.top_n(10_usize).is_empty());

    let fresh_dir = fresh_dir("bad_then_fresh_good")?;
    let mut fresh = PeerBook::default();
    let peer = generated_peer_id();
    let addr = memory_addr(98_u64);

    fresh.upsert(&peer, [addr.clone()], true);
    fresh.save_in(&fresh_dir)?;

    let loaded = PeerBook::load_or_init_in(&fresh_dir);
    let rows = loaded.top_n(1_usize);

    assert_eq!(rows[0_usize].0, peer.to_string());
    assert_eq!(rows[0_usize].1, vec![addr]);
    Ok(())
}

#[test]
fn test_099_combined_load_large_file_then_default_is_safe() -> Result<()> {
    let dir = fresh_dir("combined_large_file")?;
    fs::create_dir_all(&dir)?;
    let huge = vec![b'0'; (4_usize * 1024_usize * 1024_usize) + 1_usize];
    fs::write(peerlist_file(&dir), huge)?;

    let pb = PeerBook::load_or_init_in(&dir);

    assert!(pb.top_n(10_usize).is_empty());
    Ok(())
}

#[test]
fn test_100_combined_adversarial_load_save_peerbook_path_is_safe() -> Result<()> {
    let dir = fresh_dir("combined_final")?;
    let mut pb = PeerBook::default();

    let seed_peer = generated_peer_id();
    let normal_peer = generated_peer_id();

    let seed_base = memory_addr(100_u64);
    let seed_full = attach_peer(seed_base.clone(), &seed_peer);

    pb.upsert(
        &seed_peer,
        [
            Multiaddr::empty(),
            seed_full,
            seed_base.clone(),
            oversized_multiaddr(),
        ],
        true,
    );
    pb.add_tag(&seed_peer, "seed");

    for seed in 1000_u64..1064_u64 {
        pb.upsert(&normal_peer, [memory_addr(seed)], false);
    }

    for _round in 0_u8..32_u8 {
        pb.observe_failure(&normal_peer);
    }

    pb.add_tag(&normal_peer, "x".repeat(65_usize));
    pb.save_in(&dir)?;

    let loaded = PeerBook::load_or_init_in(&dir);
    let rows = loaded.top_n(2_usize);

    assert_eq!(rows.len(), 2_usize);
    assert_eq!(rows[0_usize].0, seed_peer.to_string());
    assert!(rows[0_usize].1.contains(&seed_base));
    assert!(rows[0_usize].1.len() <= 32_usize);
    assert!(rows[1_usize].1.len() <= 32_usize);
    Ok(())
}
