//! p2p_006_sync_runtime.rs

use crate::blockchain::blockchain_004_orchestration_run::{
    OrchestrationLoop, OrchestrationLoopArgs,
};
use crate::blockchain::genesis_002_file::GenesisFile;
use crate::consensus::por_005_time_management::{TimeConfig, TimeManager};
use crate::reorganization::reorg_006_manager::ReorgManager;
use crate::runtime::p2p_001_sync_builders::P2pSync;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{
        p2p_001_transport::build_transport,
        p2p_003_behaviour::RemzarBehaviour,
        p2p_004_peerdiscovery::{add_peerdiscovery_peers, kick_off_peerdiscovery},
        p2p_008_broadcast::Broadcaster,
        p2p_010_netcmd::NetCmd,
        p2p_011_peerbook::PeerBook,
        p2p_012_janitor_peerbook::{JanitorBook, JanitorConfig},
    },
    storage::rocksdb_005_manager::RockDBManager,
};

use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
use crate::consensus::por_000_ephemeral_registration::NodeEphemeral;
use crate::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;

use clap::Parser;
use libp2p::identity;
use libp2p::{Multiaddr, PeerId, gossipsub::IdentTopic, multiaddr::Protocol};
use std::{
    error::Error,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/* ─────────────────────────────────────────────────────────────
Defensive caps (no crypto impact)
───────────────────────────────────────────────────────────── */

/// Reject absurd multiaddr sizes (serialized bytes).
const MAX_MULTIADDR_BYTES: usize = 256;

/// Cap number of CLI bootstrap addrs we will accept/process.
const MAX_CLI_BOOTSTRAPS: usize = 256;

/// Cap how many total unique addrs we will dial once at startup.
const MAX_STARTUP_DIALS: usize = 256;

/// Cap how many Kad seeds we will add at startup (CLI + PeerBook).
const MAX_KAD_SEEDS: usize = 2048;

/// Hardcoded seed list.
const HARDCODED_SEEDS: &[(&str, &str)] = &[];

/// Options for `remzar node`.
#[derive(Parser, Debug, Clone)]
pub struct NodeOpts {
    #[clap(long, default_value = "identity.key")]
    pub identity_file: String,

    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/36213")]
    pub listen: String,

    /// One or more multiaddrs. Prefer full form with /p2p/<PeerId>.
    #[clap(long)]
    pub bootstrap: Vec<String>,

    #[clap(long, default_value = "info")]
    pub log: String,

    #[clap(long, default_value = "data")]
    pub data_dir: String,

    /// Wallet address (used as the “miner” string in Block::new)
    #[clap(long)]
    pub wallet_address: String,

    /// Founder mode (CLI). Alias: --is-founder
    #[clap(long, alias = "is-founder")]
    pub founder: bool,
}

/* ────────────────────────────────────────────────
Small helpers
──────────────────────────────────────────────── */

/// Parse env var truthiness: 1/true/yes/y/on (case-insensitive).
#[inline(always)]
fn env_true(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("y")
                || v.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

fn reexec_if_founder_cli_needs_env() -> Result<(), Box<dyn Error>> {
    // guard to prevent loops
    const REEXEC_GUARD: &str = "REMZAR_FOUNDER_REEXEC_GUARD";

    let cli_founder = std::env::args().any(|a| a == "--founder" || a == "--is-founder");
    let env_founder = env_true("REMZAR_IS_FOUNDER");
    let already_reexeced = env_true(REEXEC_GUARD);

    if cli_founder && !env_founder && !already_reexeced {
        let exe = std::env::current_exe()?;
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();

        // Best-effort message even if tracing isn't initialized yet.
        tracing::debug!(
            "[STARTUP] --founder detected but REMZAR_IS_FOUNDER not set; re-execing with REMZAR_IS_FOUNDER=1"
        );

        let status = Command::new(exe)
            .args(args)
            .env("REMZAR_IS_FOUNDER", "1")
            .env(REEXEC_GUARD, "1")
            .status()?;

        let code = status.code().unwrap_or(1);
        return Err(format!(
            "re-execed with REMZAR_IS_FOUNDER=1; parent process should terminate (child exit code: {code})"
        )
        .into());
    }

    Ok(())
}

/// Load or create Ed25519 key on disk.
pub(crate) fn load_or_generate_identity(path: &Path) -> Result<identity::Keypair, Box<dyn Error>> {
    // Paranoia 1: Refuse symlink as identity file
    if path.exists() && std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err("❌ Refusing to use symlink as identity file (security risk)".into());
    }

    // Refuse weak permissions (unix only)
    #[cfg(unix)]
    if path.exists() {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(path)?.permissions().mode();
        if perms & 0o077 != 0 {
            return Err(
                "❌ Identity file is world-readable or writable (chmod 600 recommended)".into(),
            );
        }
    }

    if path.exists() {
        Ok(identity::Keypair::from_protobuf_encoding(&std::fs::read(
            path,
        )?)?)
    } else {
        let kp = identity::Keypair::generate_ed25519();
        std::fs::write(path, kp.to_protobuf_encoding()?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(kp)
    }
}

/// Seed the PeerBook with sticky seeds and persist.
fn seed_peerbook_sticky(peerbook: &Arc<Mutex<PeerBook>>, pairs: Vec<(PeerId, Multiaddr)>) {
    if pairs.is_empty() {
        return;
    }
    if let Ok(mut pb) = peerbook.lock() {
        for (pid, addr) in pairs {
            pb.upsert(&pid, std::iter::once(addr), /*success=*/ false);
            pb.add_tag(&pid, "seed");
        }
        _ = pb.save();
    }
}

use fips204::ml_dsa_65;

type SigningKey = ml_dsa_65::PrivateKey;

const VALIDATOR_SIGNING_KEY_BYTES: usize = MlDsa65Keypair::SECRET_LEN;
const VALIDATOR_SIGNING_KEY_FILE_BYTES: u64 = MlDsa65Keypair::SECRET_LEN as u64;

#[inline(always)]
fn reject_signing_key_symlink(path: &Path) -> Result<(), Box<dyn Error>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("❌ Refusing to use symlink as signing key file (security risk)".into())
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

fn validate_signing_key_file_metadata(path: &Path) -> Result<(), Box<dyn Error>> {
    reject_signing_key_symlink(path)?;

    let meta = std::fs::metadata(path)?;
    if !meta.file_type().is_file() {
        return Err("❌ Signing key path exists but is not a regular file".into());
    }

    if meta.len() != VALIDATOR_SIGNING_KEY_FILE_BYTES {
        return Err(format!(
            "signing key file has wrong length: expected {} bytes, got {} bytes",
            VALIDATOR_SIGNING_KEY_BYTES,
            meta.len()
        )
        .into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = meta.permissions().mode();
        if perms & 0o077 != 0 {
            warn!(
                "[STARTUP] validator signing key permissions are too broad; attempting chmod 600"
            );
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

            let repaired = std::fs::metadata(path)?.permissions().mode();
            if repaired & 0o077 != 0 {
                return Err(
                    "❌ Signing key file is world/group-readable or writable (chmod 600 recommended)"
                        .into(),
                );
            }
        }
    }

    Ok(())
}

fn read_validator_signing_key_bytes(
    path: &Path,
) -> Result<[u8; VALIDATOR_SIGNING_KEY_BYTES], Box<dyn Error>> {
    validate_signing_key_file_metadata(path)?;

    let mut bytes = std::fs::read(path)?;
    if bytes.len() != VALIDATOR_SIGNING_KEY_BYTES {
        bytes.fill(0);
        return Err(format!(
            "signing key file has wrong length after read: expected {} bytes, got {} bytes",
            VALIDATOR_SIGNING_KEY_BYTES,
            bytes.len()
        )
        .into());
    }

    let mut out = [0u8; VALIDATOR_SIGNING_KEY_BYTES];
    out.copy_from_slice(&bytes);
    bytes.fill(0);

    Ok(out)
}

fn decode_validator_signing_key_hardened(
    secret_bytes: &[u8; VALIDATOR_SIGNING_KEY_BYTES],
    context: &'static str,
) -> Result<SigningKey, Box<dyn Error>> {
    // Critical hardening:
    // Do NOT call fips204::ml_dsa_65::PrivateKey::try_from_bytes directly here.
    // Route through MlDsa65Keypair so validator key loading inherits the same
    // fail-fast parse/derive timeout guards that fixed the ML-DSA fuzz stall.
    let keypair = MlDsa65Keypair::from_secret(*secret_bytes).map_err(|e| {
        format!("{context}: hardened ML-DSA-65 validator signing key import failed: {e:?}")
    })?;

    keypair.validate_self().map_err(|e| {
        format!("{context}: hardened ML-DSA-65 validator signing key invariant check failed: {e:?}")
    })?;

    keypair.get_signing_key().map_err(|e| {
        format!("{context}: hardened ML-DSA-65 validator signing key extraction failed: {e:?}")
            .into()
    })
}

fn write_validator_signing_key_atomically(
    path: &Path,
    secret_bytes: &[u8; VALIDATOR_SIGNING_KEY_BYTES],
) -> Result<(), Box<dyn Error>> {
    reject_signing_key_symlink(path)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension("tmp");

    if tmp.exists() {
        if std::fs::symlink_metadata(&tmp)?.file_type().is_symlink() {
            return Err("❌ Refusing to overwrite symlink temp signing key file".into());
        }

        let meta = std::fs::metadata(&tmp)?;
        if !meta.file_type().is_file() {
            return Err("❌ Temp signing key path exists but is not a regular file".into());
        }

        std::fs::remove_file(&tmp)?;
    }

    std::fs::write(&tmp, secret_bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn load_or_generate_validator_signing_key(path: &Path) -> Result<SigningKey, Box<dyn Error>> {
    reject_signing_key_symlink(path)?;

    if path.exists() {
        let existing_secret_bytes = read_validator_signing_key_bytes(path)?;
        return decode_validator_signing_key_hardened(
            &existing_secret_bytes,
            "existing validator signing key",
        );
    }

    let generated = MlDsa65Keypair::generate()
        .map_err(|e| format!("failed to generate hardened ML-DSA-65 validator keypair: {e:?}"))?;

    generated.validate_self().map_err(|e| {
        format!("generated ML-DSA-65 validator keypair failed invariant check: {e:?}")
    })?;

    let mut generated_secret_bytes = generated.to_bytes();
    write_validator_signing_key_atomically(path, &generated_secret_bytes)?;
    generated_secret_bytes.fill(0);
    drop(generated);

    let persisted_secret_bytes = read_validator_signing_key_bytes(path)?;
    decode_validator_signing_key_hardened(&persisted_secret_bytes, "new validator signing key")
}

/* ────────────────────────────────────────────────
Defensive helpers (pure wiring)
──────────────────────────────────────────────── */

#[inline(always)]
fn multiaddr_within_bounds(a: &Multiaddr) -> bool {
    a.to_vec().len() <= MAX_MULTIADDR_BYTES
}

#[inline(always)]
fn filter_multiaddrs_within_bounds(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs.into_iter().filter(multiaddr_within_bounds).collect()
}

/// Main entry: start the node.
pub async fn run_node(opts: NodeOpts) -> Result<(), Box<dyn Error>> {
    reexec_if_founder_cli_needs_env()?;

    /* logging */
    _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&opts.log))
        .try_init();

    // Visibility: show founder mode from both sources (CLI + env)
    let founder_env = env_true("REMZAR_IS_FOUNDER");
    let is_founder_mode = opts.founder || founder_env;
    info!(
        "[STARTUP] founder_mode(cli_or_env)={} (cli={}, env={})",
        is_founder_mode, opts.founder, founder_env
    );

    // =========================================================
    // RUNTIME STEP 0A — Resolve DirectoryDB ONCE
    // =========================================================
    let dir =
        DirectoryDB::from_node_opts(&opts).map_err(|e| format!("DirectoryDB init failed: {e}"))?;

    // Ensure key directories exist (safe; idempotent)
    _ = dir.create_peerlist_directory();
    _ = dir.create_blockchain_directory();

    // =========================================================
    // RUNTIME STEP 0B — Configure PeerBook to use DirectoryDB path
    // =========================================================
    PeerBook::configure_storage_dir(dir.peerlist_path.clone());

    /* identity */
    let id_keys = load_or_generate_identity(Path::new(&opts.identity_file))?;
    let peer_id = PeerId::from(id_keys.public());
    info!("▶ Local PeerId: {peer_id}");

    // load versioned, sticky PeerBook (auto-migrates old peerlist)
    // Wrap in Arc<Mutex<..>> to pass into P2pSync and share with runtime
    let peerbook: Arc<Mutex<PeerBook>> = Arc::new(Mutex::new(PeerBook::load_or_init()));

    // Janitor for PeerBook + peerlist.json (wired to DirectoryDB::peerlist_path)
    let janitor = JanitorBook::new_with_dir(Arc::clone(&peerbook), dir.peerlist_path.clone());

    // one-shot startup sweep so we don't dial obviously-dead peers.
    if let Err(e) = janitor.sweep_stale_peers(&JanitorConfig::default()) {
        warn!("[JANITOR] startup sweep failed: {:?}", e);
    } else {
        info!("[JANITOR] startup sweep completed.");
    }

    // background janitor task — periodically cleans stale peers.
    {
        let janitor_book = janitor;
        tokio::spawn(async move {
            let cfg = JanitorConfig::default();
            loop {
                // e.g. every 5 minutes; tune as you like.
                tokio::time::sleep(Duration::from_secs(300)).await;
                match janitor_book.sweep_stale_peers(&cfg) {
                    Ok(removed) => {
                        if removed > 0 {
                            info!("[JANITOR] periodic sweep removed {} peer(s).", removed);
                        }
                    }
                    Err(e) => {
                        warn!("[JANITOR] periodic sweep failed: {:?}", e);
                    }
                }
            }
        });
    }

    /* behaviour */
    let mut behaviour = RemzarBehaviour::new(id_keys.clone())?;
    behaviour.gossipsub.subscribe(&IdentTopic::new("remzar"))?;

    /* swarm setup */
    let custom_transport = build_transport(id_keys.clone())?;
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_other_transport(move |_| custom_transport)?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(20)))
        .build();

    // Listen
    swarm.listen_on(
        opts.listen
            .parse()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Bad listen address: {e}"),
                tx_id: None,
            })?,
    )?;
    info!("▶ Listening on {}", opts.listen);

    let detection = Arc::new(DetectionSystem::new());

    /* bootstrap (CLI + PeerBook) */
    // Collect CLI bootstraps (as Multiaddrs)
    let cli_bootstrap_addrs: Vec<Multiaddr> = opts
        .bootstrap
        .iter()
        .take(MAX_CLI_BOOTSTRAPS) // ✅ defensive: cap untrusted CLI input volume
        .filter_map(|s| match s.parse::<Multiaddr>() {
            Ok(a) => {
                if multiaddr_within_bounds(&a) {
                    Some(a)
                } else {
                    warn!(
                        "[BOOTSTRAP] ignoring oversized multiaddr (>{} bytes): {}",
                        MAX_MULTIADDR_BYTES, s
                    );
                    None
                }
            }
            Err(_) => {
                warn!("[BOOTSTRAP] ignoring invalid multiaddr string: {}", s);
                None
            }
        })
        .collect();

    // mark *all* explicit CLI bootstraps as sticky "seed" in PeerBook
    let cli_seed_pairs: Vec<(PeerId, Multiaddr)> = cli_bootstrap_addrs
        .iter()
        .filter_map(|a| {
            let comps: Vec<_> = a.iter().collect();
            match comps.last().cloned() {
                Some(Protocol::P2p(pid)) => Some((pid, a.clone())),
                _ => None,
            }
        })
        .collect();
    seed_peerbook_sticky(&peerbook, cli_seed_pairs);

    // also mark any HARDCODED_SEEDS as sticky in PeerBook (if provided)
    let hardcoded_pairs: Vec<(PeerId, Multiaddr)> = HARDCODED_SEEDS
        .iter()
        .filter_map(|(pid_str, addr_str)| {
            let pid = pid_str.parse::<PeerId>().ok()?;
            let addr = addr_str.parse::<Multiaddr>().ok()?;
            if !multiaddr_within_bounds(&addr) {
                warn!(
                    "[BOOTSTRAP] ignoring oversized hardcoded seed addr (>{} bytes): {}",
                    MAX_MULTIADDR_BYTES, addr_str
                );
                return None;
            }
            Some((pid, addr))
        })
        .collect();
    seed_peerbook_sticky(&peerbook, hardcoded_pairs);

    // After seeding, collect top-N from PeerBook **with peer ids** so we can seed Kad
    let peerbook_top: Vec<(PeerId, Vec<Multiaddr>)> = {
        let pb = peerbook.lock().map_err(|_| "peerbook mutex poisoned")?;
        pb.top_n(64)
            .into_iter()
            .filter_map(|(pid_str, addrs)| {
                if let Ok(pid) = pid_str.parse::<PeerId>() {
                    Some((pid, filter_multiaddrs_within_bounds(addrs)))
                } else {
                    None
                }
            })
            .collect()
    };

    // Build a flat address list for one-shot dialing (Identify will fill more info)
    let mut all_addrs: Vec<Multiaddr> = Vec::new();
    let mut seen_addr_strings = std::collections::HashSet::<String>::new();

    for a in &cli_bootstrap_addrs {
        let key = a.to_string();
        if seen_addr_strings.insert(key) {
            all_addrs.push(a.clone());
        }
    }
    for (_pid, addrs) in &peerbook_top {
        for a in addrs {
            let key = a.to_string();
            if seen_addr_strings.insert(key) {
                all_addrs.push(a.clone());
            }
        }
    }

    // cap total dials we will attempt at startup (unique addrs)
    if all_addrs.len() > MAX_STARTUP_DIALS {
        warn!(
            "[BOOTSTRAP] capping startup dial list: {} → {}",
            all_addrs.len(),
            MAX_STARTUP_DIALS
        );
        all_addrs.truncate(MAX_STARTUP_DIALS);
    }

    // Seed peer discovery helpers
    add_peerdiscovery_peers(swarm.behaviour_mut(), &all_addrs, &detection).map_err(|e| {
        error!("Failed to add peer discovery peers: {}", e);
        e
    })?;

    // Seed **Kademlia** from CLI multiaddrs that include /p2p/<PeerId>
    let mut kad_seeds = 0usize;

    for a in &cli_bootstrap_addrs {
        if kad_seeds >= MAX_KAD_SEEDS {
            break;
        }

        // If addr has a trailing /p2p/<PeerId>, split it for Kad
        let mut comps: Vec<_> = a.iter().collect();
        if let Some(Protocol::P2p(pid)) = comps.last().cloned() {
            comps.pop(); // strip /p2p/<PeerId>
            let base_addr: Multiaddr = comps.into_iter().collect();
            if !multiaddr_within_bounds(&base_addr) {
                continue;
            }
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&pid, base_addr.clone());
            kad_seeds = kad_seeds.saturating_add(1);
            info!("▶ Kad seed (CLI): {} via {}", pid, base_addr);
        }
    }

    // Seed **Kademlia** from PeerBook (peer_id + each stored address)
    for (pid, addrs) in &peerbook_top {
        for a in addrs {
            if kad_seeds >= MAX_KAD_SEEDS {
                break;
            }
            if !multiaddr_within_bounds(a) {
                continue;
            }
            swarm.behaviour_mut().kademlia.add_address(pid, a.clone());
            kad_seeds = kad_seeds.saturating_add(1);
        }
        if !addrs.is_empty() {
            info!("▶ Kad seed (PeerBook): {} via {} addr(s)", pid, addrs.len());
        }
        if kad_seeds >= MAX_KAD_SEEDS {
            break;
        }
    }

    // Dial all known bootstraps once (so Identify flows; Kad learns more addrs)
    for a in &all_addrs {
        match swarm.dial(a.clone()) {
            Ok(_) => info!("▶ Dialling bootstrap {}", a),
            Err(e) => error!("✖ Dial {a}: {e}"),
        }
    }

    // Kick initial DHT bootstrap if we seeded any peers
    if kad_seeds > 0 {
        _ = swarm.behaviour_mut().kademlia.bootstrap();
        info!("▶ Kad bootstrap started over {kad_seeds} seed(s)");
    }

    // Keep existing helper kick (if it sets up other discovery)
    kick_off_peerdiscovery(swarm.behaviour_mut())?;

    // =========================================================
    // RUNTIME STEP 6 — Open blockchain DB using DirectoryDB path
    // =========================================================
    let blockchain_db_dir_str = dir.blockchain_path.to_string_lossy().to_string();

    let db = Arc::new(RockDBManager::new_blockchain(
        &opts,
        &blockchain_db_dir_str,
    )?);

    let mut chain = match AccountModelTree::load_state((*db).clone()) {
        Ok(tree) => tree,
        Err(e) => {
            println!(
                "⚠️ Failed to load AccountModelTree from DB: {}. Starting with empty tree.",
                e
            );
            AccountModelTree::with_manager((*db).clone())
        }
    };
    chain.reload_from_db();

    // ----------- STARTUP LOGGING ------------
    let genesis_path = std::env::var("REMZAR_GENESIS_PATH")
        .unwrap_or_else(|_| format!("{}/genesis.json", opts.data_dir));

    match GenesisFile::from_json_file(&genesis_path) {
        Ok(genesis) => {
            info!("[STARTUP] Chain ID: {}", genesis.chain_id);
            info!(
                "[STARTUP] Description: {:?}",
                genesis.description.as_deref().unwrap_or("None")
            );
            info!(
                "[STARTUP] Version: {:?}",
                genesis.version.as_deref().unwrap_or("None")
            );
        }
        Err(e) => {
            warn!(
                "[STARTUP] Failed to load genesis file for chain info: {:?}",
                e
            );
        }
    }

    match chain.get_block_by_index(0) {
        Ok(genesis_block) => {
            info!(
                "[STARTUP] Genesis block found at index 0, hash = {:x?}",
                genesis_block.block_hash
            );
        }
        Err(e) => {
            warn!("[STARTUP] No genesis block at index 0: {:?}", e);
        }
    }

    info!("[STARTUP] opts.data_dir (base): {}", opts.data_dir);
    info!(
        "[STARTUP] blockchain DB path: {}",
        dir.blockchain_path.display()
    );
    info!("[STARTUP] peerlist path: {}", dir.peerlist_path.display());

    // -------------------------------------------------
    // load or generate validator signing key ONCE (persisted in blockchain dir)
    // -------------------------------------------------
    let signing_key_path = dir.blockchain_path.join("validator_signing_key.bin");
    let signing_key: Arc<SigningKey> =
        Arc::new(load_or_generate_validator_signing_key(&signing_key_path)?);
    info!(
        "[STARTUP] validator signing key ready (path={})",
        signing_key_path.display()
    );

    // -------------------------------------------------
    // MEMPOOL + SYNC ENGINE (TokioMutex)
    // -------------------------------------------------
    let detection_system = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection_system));

    // Build a fresh AccountModelTree for the sync engine’s in-memory view
    let mut chain_for_sync = AccountModelTree::with_manager((*db).clone());
    chain_for_sync.reload_from_db();

    // REORG MANAGER FOR SYNC ENGINE (PART 3 – used by P2pSync)
    let reorg_manager_for_sync = ReorgManager::mainnet_default(Arc::clone(&db));

    // SINGLE sync engine; wrap in Arc<TokioMutex<…>>
    let sync_engine: Arc<TokioMutex<P2pSync>> = Arc::new(TokioMutex::new(P2pSync::new(
        chain_for_sync,
        Arc::clone(&db),
        Arc::clone(&mempool),
        Arc::clone(&peerbook),
        dir.peerlist_path.clone(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
        reorg_manager_for_sync,
    )));

    // seed Kad from PeerBook via P2pSync, before orchestration
    {
        let mut sync = sync_engine.lock().await;
        sync.seed_kad_from_peerbook(&mut swarm);
    }

    // Join gossip topics before handing off to orchestration
    {
        let mut b = Broadcaster::new(&mut swarm);
        b.join_all_topics()?;
    }

    // -------------------------------------------------
    // EPHEMERAL REGISTRY (PoR; NO RocksDB FOR REGISTRY)
    // -------------------------------------------------
    let my_wallet = opts.wallet_address.clone();
    if my_wallet.is_empty() {
        return Err("wallet_address is required (use --wallet-address)".into());
    }

    // PoR-era registry wrapper: no Pacemaker, in-memory only.
    let node_ephemeral = NodeEphemeral::new();

    // Seed founder (join_height=0) if block #0 exists; also add local wallet
    if let Ok(Some(block0)) = db.get_block_by_index(0) {
        let founder_wallet = block0.miner_wallet().to_string();
        // founder
        _ = node_ephemeral.register_wallet_strict(&founder_wallet, 0);
        _ = node_ephemeral.set_join_height(&founder_wallet, 0);
    }

    // local wallet (join at current tip)
    let join_height_local = db.get_tip_height().unwrap_or(0);
    _ = node_ephemeral.register_wallet_strict(&my_wallet, join_height_local);

    // -------------------------------------------------
    // REORG MANAGER (PART 3 – validator-aware reorg orchestration for mint path)
    // -------------------------------------------------
    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));

    let console_bus_for_loop = ConsoleBus::new();

    // -------------------------------------------------
    // UNIFIED ORCHESTRATION LOOP (drives swarm + minting)
    // -------------------------------------------------
    let ol = OrchestrationLoop::new(OrchestrationLoopArgs {
        db: Arc::clone(&db),
        node_ephemeral: node_ephemeral.clone(),
        mempool: Arc::clone(&mempool),
        sync_engine: Arc::clone(&sync_engine),

        // pass the validator signing key through to OrchestrationLoop/BlockMint
        signing_key: Arc::clone(&signing_key),

        tm: Arc::clone(&tm_from_genesis_or_block0(&genesis_path, &db)),
        reorg_manager,
        local_wallet: my_wallet,
        console_bus: console_bus_for_loop,
    });

    info!("▶ Handing off to OrchestrationLoop (Ctrl-C to exit)...");
    // run_until_ctrl_c expects an Option<mpsc::Receiver<NetCmd>> plus &NodeOpts.
    ol.run_until_ctrl_c(
        &mut chain,
        &mut swarm,
        None::<mpsc::Receiver<NetCmd>>,
        &opts,
    )
    .await?;
    info!("▶ Node shut down.");

    Ok(())
}

/// Build TimeManager (prefer genesis.json; fall back to block #0; else now)
fn tm_from_genesis_or_block0(genesis_path: &str, db: &Arc<RockDBManager>) -> Arc<TimeManager> {
    let tm = match TimeManager::new_from_genesis_file(genesis_path) {
        Ok(tm) => tm,
        Err(_) => {
            // Try block #0 in DB
            if let Ok(Some(block0)) = db.get_block_by_index(0) {
                TimeManager::new(TimeConfig::from_genesis_ts(block0.metadata.timestamp))
            } else {
                TimeManager::new(TimeConfig::from_genesis_ts(TimeManager::now_unix()))
            }
        }
    };
    // Ensure seconds-first derivation matches the const
    tm.assert_activation_delay_consistent();
    Arc::new(tm)
}

impl Default for NodeOpts {
    fn default() -> Self {
        NodeOpts {
            identity_file: "identity.key".into(),
            listen: "/ip4/0.0.0.0/tcp/36213".into(),
            bootstrap: vec![],
            log: "info".into(),
            data_dir: "data".into(),
            wallet_address: "".into(),
            founder: false,
        }
    }
}
