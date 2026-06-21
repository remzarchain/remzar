//! Orchestration display helpers extracted from the unified orchestration loop.

use std::sync::Arc;

use crate::blockchain::{
    halving_schedule::RewardHalving, transaction_005_tx_account_tree::AccountModelTree,
    transaction_005_tx_batch::TransactionBatch,
};
use crate::commandline::s_04_view_blockchain_console::ConsoleBus;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration, helper, time_policy::TimePolicy,
};
use chrono::DateTime;
use colored::Colorize;

pub struct OrchestrationDisplay {
    db: Arc<RockDBManager>,
    console_bus: ConsoleBus,
    pub log_sequence: bool,
}

impl OrchestrationDisplay {
    pub fn new(db: Arc<RockDBManager>, console_bus: ConsoleBus) -> Self {
        Self {
            db,
            console_bus,
            log_sequence: true,
        }
    }

    /// Runtime-only display timestamp.
    fn runtime_display_timestamp() -> String {
        match TimePolicy::now_unix_secs_runtime() {
            Ok(now_unix) => {
                let Some(now_i64) = i64::try_from(now_unix).ok() else {
                    return format!("unix:{now_unix}");
                };

                DateTime::from_timestamp(now_i64, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| format!("unix:{now_unix}"))
            }
            Err(_) => "time_unavailable".to_string(),
        }
    }

    pub fn print_new_blocks_since(
        &self,
        _tree: &AccountModelTree,
        last_logged_tip: &mut u64,
        last_minted_height: &mut Option<u64>,
    ) {
        let should_print_terminal = self.log_sequence;
        let should_publish_live_console = self.console_bus.live_chain_tx.receiver_count() > 0;

        if !should_print_terminal && !should_publish_live_console {
            if let Ok(tip_now) = self.db.get_tip_height()
                && tip_now > *last_logged_tip
            {
                *last_logged_tip = tip_now;
                *last_minted_height = None;
            }
            return;
        }

        if let Ok(tip_now) = self.db.get_tip_height()
            && tip_now > *last_logged_tip
        {
            const HASH_HEAD: usize = 32;
            const HASH_TAIL: usize = 32;

            let start_h = (*last_logged_tip).saturating_add(1);
            for h in start_h..=tip_now {
                if let Ok(Some(block)) = self.db.get_block_by_index(h) {
                    let tx_count = {
                        let key = format!("tx_batch_{:010}", h);
                        self.db
                            .read(
                                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                                key.as_bytes(),
                            )
                            .ok()
                            .flatten()
                            .and_then(|bytes| {
                                TransactionBatch::deserialize(&bytes)
                                    .ok()
                                    .map(|b| b.transactions.len())
                            })
                            .unwrap_or(0)
                    };

                    let reward_display = {
                        let reward_micro = RewardHalving::get_block_reward(h);
                        helper::format_remzar_trim(reward_micro)
                    };

                    let reward_left = {
                        let remaining_micro =
                            RewardHalving::remaining_reward_supply_micro_after_block(h);
                        let remaining_u64 = u64::try_from(remaining_micro).unwrap_or(u64::MAX);
                        helper::format_remzar_trim_one_decimal(remaining_u64)
                    };

                    let hash_full = hex::encode(block.block_hash);
                    let hash_print =
                        helper::ellipsize_middle_ascii(&hash_full, HASH_HEAD, HASH_TAIL);

                    let minted_locally = *last_minted_height == Some(h);
                    let ts = Self::runtime_display_timestamp();

                    if minted_locally {
                        let line = format!(
                            "{}  minted:    {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                            ts,
                            ">",
                            h,
                            tx_count,
                            reward_display.as_str(),
                            reward_left.as_str(),
                            hash_print,
                        );

                        if should_print_terminal {
                            println!(
                                "{}  minted:    {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                                ts,
                                ">".green(),
                                h.to_string().green(),
                                tx_count.to_string().green(),
                                reward_display.as_str().green(),
                                reward_left.as_str().green(),
                                hash_print.green()
                            );
                        }

                        if should_publish_live_console {
                            self.console_bus.publish_live_chain_line(line);
                        }
                    } else {
                        let line = format!(
                            "{}  accepted:  {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                            ts,
                            "<",
                            h,
                            tx_count,
                            reward_display.as_str(),
                            reward_left.as_str(),
                            hash_print,
                        );

                        if should_print_terminal {
                            println!(
                                "{}  accepted:  {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                                ts,
                                "<".cyan(),
                                h.to_string().cyan(),
                                tx_count.to_string().cyan(),
                                reward_display.as_str().cyan(),
                                reward_left.as_str().cyan(),
                                hash_print.cyan()
                            );
                        }

                        if should_publish_live_console {
                            self.console_bus.publish_live_chain_line(line);
                        }
                    }
                } else if should_print_terminal {
                    println!(
                        "{}  accepted <  | block: {} | [header missing in DB?]",
                        Self::runtime_display_timestamp(),
                        h
                    );
                }
            }

            *last_logged_tip = tip_now;
            *last_minted_height = None;
        }
    }
}
