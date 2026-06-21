//! src/commandline/s_07_view_status.rs
//! 7. View Participant Status
//!
//! This module isolates the participant-status flow into its own struct + impl,
//! while keeping private CommandManager access inside the manager wrapper.

use crate::consensus::por_000_ephemeral_registration::{NodeEphemeral, RegistryData};
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use colored::Colorize;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub struct S07ViewStatus;

impl S07ViewStatus {
    pub fn new() -> Self {
        Self
    }

    fn load_identity_if_exists(path: &Path) -> Option<libp2p::identity::Keypair> {
        if !path.exists() {
            return None;
        }

        let bytes = fs::read(path).ok()?;
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes).ok()
    }

    // ─────────────────────────────────────────────────────────────────────
    // 7) VIEW PARTICIPANT STATUS (Prefers persistent; DB-gated leader calc)
    // ─────────────────────────────────────────────────────────────────────
    pub fn view_status(
        &mut self,
        node_ephemeral: Option<&NodeEphemeral>,
        db_manager: Arc<RockDBManager>,
        local_wallet: &str,
        identity_path: &Path,
    ) -> Result<(), ErrorDetection> {
        use crate::utility::helper::canon_wallet_id_checked;

        println!("{}", "🔹 Viewing Wallet Registry Status...".green());

        // EPHEMERAL-only snapshot
        let view: RegistryData = if let Some(ne) = node_ephemeral {
            let eph = ne.ephemeral();
            let mut rd = RegistryData::new();

            if let Ok(e) = eph.lock() {
                for w in e.sorted_wallets() {
                    rd.wallets.insert(w);
                }
                rd.identity_map = e.identity_map.clone();
                rd.join_heights = e.join_heights.clone();
            } else {
                println!(
                    "{}",
                    "⚠️ Could not lock ephemeral registry (poisoned?)".yellow()
                );
            }

            rd
        } else {
            RegistryData::new()
        };

        println!("{}", "memory-only; wiped on restart".yellow());

        let total_count = view.wallets.len();
        let max_participants =
            usize::try_from(GlobalConfiguration::MAX_ZAR_PARTICIPANTS).unwrap_or(usize::MAX);

        println!(
            "{}: {}/{}",
            "👥 Participants".cyan(),
            total_count.to_string().green(),
            max_participants.to_string().green()
        );

        let (tip, have_tip) = match db_manager.get_tip_height() {
            Ok(h) => (h, true),
            Err(_) => (0, false),
        };

        let mut wallets_sorted: Vec<String> = view.wallets.iter().cloned().collect();
        wallets_sorted.sort_unstable_by(|a: &String, b: &String| {
            let al = a.to_ascii_lowercase();
            let bl = b.to_ascii_lowercase();
            match al.cmp(&bl) {
                std::cmp::Ordering::Equal => a.cmp(b),
                o => o,
            }
        });

        if wallets_sorted.is_empty() {
            println!(
                "{}",
                "⚠️ No registered validators; schedule is empty.".yellow()
            );
        } else {
            let label = |h: u64, tag: &str| -> Option<(String, u64, String)> {
                if wallets_sorted.is_empty() {
                    None
                } else {
                    let h_usize = usize::try_from(h).unwrap_or(usize::MAX);
                    let len = wallets_sorted.len();
                    let idx = h_usize.checked_rem(len).unwrap_or(0);
                    wallets_sorted
                        .get(idx)
                        .cloned()
                        .map(|w| (tag.to_string(), h, w))
                }
            };

            if have_tip && tip > 0 {
                if let Some((tag, h, who)) = label(tip.saturating_sub(1), "📤 Last leader") {
                    println!("{} {} (height #{})", tag.magenta().bold(), who.yellow(), h);
                }
            } else {
                println!("{} {}", "📤 Last leader:".magenta().bold(), "n/a".yellow());
            }

            if have_tip {
                if let Some((tag, h, who)) = label(tip, "✅ Current leader") {
                    println!("{} {} (height #{})", tag.magenta().bold(), who.yellow(), h);
                }
            } else {
                println!(
                    "{} {}",
                    "✅ Current leader:".magenta().bold(),
                    "unknown".yellow()
                );
            }

            if let Some((tag, h, who)) = label(tip.saturating_add(1), "📥 Next leader") {
                println!("{} {} (height #{})", tag.magenta().bold(), who.yellow(), h);
            }
        }

        if !view.wallets.is_empty() {
            println!("{}", "📜 Registered Wallets:".cyan());
            for w in &wallets_sorted {
                println!("  - 🏦 {}", w.green());
            }
        } else {
            println!("{}", "❌ No registered wallets right now.".red());
        }

        if !view.identity_map.is_empty() {
            println!("\n{}", "🔗 Node Identity Mappings:".cyan());
            for (peer_id, wallet) in &view.identity_map {
                println!("  - 🆔 {} → 🏦 {}", peer_id.green(), wallet.green());
            }
        }

        let peer_id_str = match Self::load_identity_if_exists(identity_path) {
            Some(keys) => libp2p::PeerId::from(keys.public()).to_string(),
            None => "<unknown>".to_string(),
        };

        println!("🔗 This node PeerId: {}", peer_id_str);

        if !local_wallet.is_empty() {
            let display_wallet = match canon_wallet_id_checked(local_wallet) {
                Ok(c) => c,
                Err(_) => local_wallet.to_string(),
            };
            println!("PeerID/bootstrap: {} = {}", peer_id_str, display_wallet);
        }

        Ok(())
    }
}

impl Default for S07ViewStatus {
    fn default() -> Self {
        Self::new()
    }
}
