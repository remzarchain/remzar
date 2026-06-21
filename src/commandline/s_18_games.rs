//! src/commandline/s_18_games.rs

use crate::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::tokens::game_slot_machine::{SlotMachineContext, SlotMachineGame};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use rust_rocksdb::DB;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

/// Section 18: Games.
pub struct S18Games;

impl S18Games {
    pub fn new() -> Self {
        Self
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 18.  Games
    // ─────────────────────────────────────────────────────────────────────────────
    pub fn play_slot_machine(
        &mut self,
        opts: &NodeOpts,
        db: &Arc<DB>,
        db_manager: Arc<RockDBManager>,
        net_tx: Sender<NetCmd>,
        mut chain_opt: Option<&mut AccountModelTree>,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        // Callback: send to background broadcaster (non-blocking)
        let mut send_cb = move |cmd: NetCmd| -> Result<(), ErrorDetection> {
            net_tx.try_send(cmd).map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => ErrorDetection::ProtocolError {
                    message: "Too many pending broadcasts; please wait".into(),
                },
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    ErrorDetection::ProtocolError {
                        message: "Network thread has shut down".into(),
                    }
                }
            })
        };

        // Callback: canonical balance lookup (state snapshot preferred; chain fallback)
        let mut bal_cb = move |addr: &str| -> u64 {
            match db_manager.load_state() {
                Ok(state_tree) => state_tree.get_balance(addr),
                Err(e) => {
                    let msg = format!("Slot: load_state failed; falling back to chain: {e:?}");
                    json_logger
                        .log_error_event("slot", "LoadStateFailed", &msg)
                        .ok();

                    if let Some(chain) = chain_opt.as_mut() {
                        (*chain).reload_from_db();
                        (*chain).get_balance(addr)
                    } else {
                        0
                    }
                }
            }
        };

        // Build the context the standalone game module needs
        let mut ctx = SlotMachineContext {
            opts,
            db,
            json_logger,
            send_net_cmd: &mut send_cb,
            get_balance_micro: &mut bal_cb,
        };

        // Run the interactive play
        let game = SlotMachineGame::default();

        // Menu suppresses errors on-screen; print ONE line so user knows what happened.
        match game.play_once_interactive(&mut ctx) {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                println!("❌ Game aborted: {msg}");
                json_logger.log_error_event("slot", "PlayFailed", &msg).ok();
                Ok(())
            }
        }
    }
}

impl Default for S18Games {
    fn default() -> Self {
        Self::new()
    }
}
