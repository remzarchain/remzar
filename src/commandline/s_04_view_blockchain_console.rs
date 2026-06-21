//! src/commandline/s_04_view_blockchain_console.rs
//!
//! Blockchain Console (Menu #4):
//! - (1) Live chain view: subscribe to the live block feed and print as blocks arrive.
//! - (2) Display latest block as one compact summary line. pressing 2, on fresh start up; delay is expected.
//! - (3) Display last 50 blocks as compact summary lines.
//! - (4) Display genesis block as one compact cached summary line.
//! - (5) Search a compact block range with a 100-block request limit.

use colored::Colorize;
use rust_rocksdb::{ColumnFamily, DB, IteratorMode};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

use crate::blockchain::block_002_blocks::Block;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::{
    alpha_001_global_configuration::GlobalConfiguration,
    alpha_002_error_detection_system::ErrorDetection,
};

/// Central console bus (Option B).
/// The node/orchestration loop publishes formatted lines.
/// The console subscribes while user is in "Live view".
#[derive(Clone)]
pub struct ConsoleBus {
    pub live_chain_tx: broadcast::Sender<String>,
    recent_live_lines: Arc<RwLock<VecDeque<String>>>,
}

impl ConsoleBus {
    const RECENT_LIVE_LINES_CAP: usize = 200;
    const MAX_CACHED_LIVE_LINE_CHARS: usize = 4096;

    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<String>(1024);
        Self {
            live_chain_tx: tx,
            recent_live_lines: Arc::new(RwLock::new(VecDeque::with_capacity(
                Self::RECENT_LIVE_LINES_CAP,
            ))),
        }
    }

    pub fn subscribe_live_chain(&self) -> broadcast::Receiver<String> {
        self.live_chain_tx.subscribe()
    }

    /// Latest cached live line, if this process has observed one.
    pub fn latest_live_chain_line(&self) -> Option<String> {
        self.recent_live_lines
            .read()
            .ok()
            .and_then(|lines| lines.back().cloned())
    }

    /// Last cached live lines, newest-last, capped by `limit`.
    pub fn recent_live_chain_lines(&self, limit: usize) -> Vec<String> {
        self.recent_live_lines
            .read()
            .map(|lines| {
                let keep = limit.min(lines.len());
                lines
                    .iter()
                    .skip(lines.len().saturating_sub(keep))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return cached live lines for a complete inclusive block range.
    pub fn cached_live_lines_for_block_range(&self, start: u64, end: u64) -> Option<Vec<String>> {
        if end < start {
            return None;
        }

        let requested = end.checked_sub(start)?.checked_add(1)?;
        let requested_usize = usize::try_from(requested).ok()?;

        let lines = self.recent_live_lines.read().ok()?;
        if requested_usize > lines.len() {
            return None;
        }

        let mut out = Vec::with_capacity(requested_usize);
        for idx in start..=end {
            let found = lines
                .iter()
                .rev()
                .find(|line| Self::extract_block_index_from_live_line(line) == Some(idx))
                .cloned()?;
            out.push(found);
        }

        Some(out)
    }

    /// Parse the `| block: N |` section from a live summary line.
    fn extract_block_index_from_live_line(line: &str) -> Option<u64> {
        for part in line.split('|') {
            let trimmed = part.trim();
            if let Some(v) = trimmed.strip_prefix("block:") {
                return v.trim().parse::<u64>().ok();
            }
        }
        None
    }

    fn truncate_live_line_for_cache(s: &str) -> String {
        let mut out = String::new();

        for (i, ch) in s.chars().enumerate() {
            if i >= Self::MAX_CACHED_LIVE_LINE_CHARS {
                out.push_str("…[truncated]");
                return out;
            }
            out.push(ch);
        }

        out
    }

    /// Node-side helper. Call this when a new block is minted/accepted.
    pub fn publish_live_chain_line(&self, line: String) {
        if let Ok(mut lines) = self.recent_live_lines.write() {
            let cached_line = Self::truncate_live_line_for_cache(&line);
            lines.push_back(cached_line);

            while lines.len() > Self::RECENT_LIVE_LINES_CAP {
                lines.pop_front();
            }
        }

        // Ignore error if no subscribers.
        drop(self.live_chain_tx.send(line));
    }
}

impl Default for ConsoleBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Callable blockchain console component.
pub struct BlockchainConsoleView {
    bus: ConsoleBus,
    secondary_db: Option<DB>,

    // Compact display cache only. These strings are not consensus data.
    genesis_cache: Option<String>,
    db_block_compact_summary_cache: HashMap<u64, String>,
    db_block_compact_summary_order: VecDeque<u64>,
}

impl BlockchainConsoleView {
    // ─────────────── Lightweight CLI guards ───────────────
    const MAX_MENU_INPUT_LEN: usize = 16;
    const MAX_INDEX_INPUT_LEN: usize = 32;
    const MAX_RANGE: u64 = 100;
    const MAX_LAST_N: usize = 50;
    const GENESIS_BLOCK_INDEX: u64 = 0;

    const MAX_DB_COMPACT_SUMMARY_CACHE_BLOCKS: usize = 512;

    // Compact range output guardrails. Option 5 can print up to 100 rows, so
    // each row must stay short and predictable.
    const COMPACT_HASH_HEAD: usize = 16;
    const COMPACT_HASH_TAIL: usize = 16;
    const MAX_COMPACT_SUMMARY_CHARS: usize = 512;

    // Live line guard: prevents accidental giant terminal output.
    const MAX_LIVE_LINE_CHARS: usize = 4096;

    // Secondary RocksDB open guardrails.
    const MAX_SECONDARY_OPEN_ATTEMPTS: usize = 5;
    const SECONDARY_OPEN_RETRY_MS: u64 = 750;
    // ───────────────────────────────────────────────────────

    pub fn new(bus: ConsoleBus) -> Self {
        Self {
            bus,
            secondary_db: None,
            genesis_cache: None,
            db_block_compact_summary_cache: HashMap::new(),
            db_block_compact_summary_order: VecDeque::new(),
        }
    }

    // re-render with the exact spacing we want ("minted:  {}   |" vs "accepted:  {}  |").
    fn render_live_line_colored(line: &str) -> Option<String> {
        // Expected shape (plain bus line):
        // "{ts}  minted:    >  | block: {h} | txs: {txs} | reward: {r}/{left} | hash: {hex}"
        // "{ts}  accepted:  <  | block: {h} | txs: {txs} | reward: {r}/{left} | hash: {hex}"

        let (ts, rest) = line.split_once("  ")?;

        let is_minted = rest.contains("minted:");
        let is_accepted = rest.contains("accepted:");
        if !is_minted && !is_accepted {
            return None;
        }

        // Split on pipes: head | block | txs | reward | hash
        let mut parts = rest.split('|').map(|s| s.trim());

        let _head = parts.next()?;
        let block_p = parts.next()?;
        let txs_p = parts.next()?;
        let reward_p = parts.next()?;
        let hash_p = parts.next()?;

        let h = block_p.strip_prefix("block:")?.trim();
        let txs = txs_p.strip_prefix("txs:")?.trim();

        let reward_vals = reward_p.strip_prefix("reward:")?.trim();
        let (reward_a, reward_b) = reward_vals.split_once('/')?;
        let reward_a = reward_a.trim();
        let reward_b = reward_b.trim();

        let hash = hash_p.strip_prefix("hash:")?.trim();

        if is_minted {
            Some(format!(
                "{}  minted:    {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                ts,
                ">".green(),
                h.green(),
                txs.green(),
                reward_a.green(),
                reward_b.green(),
                hash.green()
            ))
        } else {
            Some(format!(
                "{}  accepted:  {}  | block: {} | txs: {} | reward: {}/{} | hash: {}",
                ts,
                "<".cyan(),
                h.cyan(),
                txs.cyan(),
                reward_a.cyan(),
                reward_b.cyan(),
                hash.cyan()
            ))
        }
    }

    /// Shorten huge strings for console output only.
    #[inline]
    fn ellipsize_middle(s: &str, head: usize, tail: usize) -> String {
        if head == 0 || tail == 0 {
            return s.to_string();
        }

        let bytes = s.as_bytes();

        if bytes.len() <= head.saturating_add(tail).saturating_add(3) {
            return s.to_string();
        }

        let start_tail = bytes.len().saturating_sub(tail);

        // Hex strings are ASCII, so this is safe and preserves identical output for valid hex.
        let head_str = bytes
            .get(..head)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or(s);

        let tail_str = bytes
            .get(start_tail..)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or(s);

        format!("{head_str}...{tail_str}")
    }

    /// Truncate arbitrary console lines by char count, preserving UTF-8 validity.
    fn truncate_for_console(s: &str, max_chars: usize) -> String {
        let mut out = String::new();

        for (i, ch) in s.chars().enumerate() {
            if i >= max_chars {
                out.push_str("…[truncated]");
                return out;
            }
            out.push(ch);
        }

        out
    }

    /// Run console in blocking mode (current CommandManager function can call it).
    pub fn run_blocking(&mut self, node_opts: &NodeOpts) -> Result<(), ErrorDetection> {
        println!("{}", "🔹 Connecting to Live Blockchain Console...".cyan());
        println!("{}", "Commands:".yellow());

        println!("  {} Live Chain View (real-time)", "1)".yellow());
        println!("  {} Display Latest Block", "2)".yellow());
        println!("  {} Display Last 50 Blocks", "3)".yellow());
        println!("  {} Display Genesis Block", "4)".yellow());
        println!("  {} Search Block Range (100 compact limit)", "5)".yellow());
        println!("  {} Exit to Menu", "6)".yellow());

        // Resolve correct DB path only. Do NOT open RocksDB here.
        // Live mode must be able to start even while the running node owns the primary DB lock.
        let directory =
            DirectoryDB::from_node_opts(node_opts).map_err(|e| ErrorDetection::StorageError {
                message: format!("Failed to initialize directories: {}", e),
            })?;
        let db_path = &directory.blockchain_path;

        // CF name needed only by DB-reading options.
        let cf_names: [&'static str; 1] = [GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME];

        loop {
            let input = match Self::read_line_capped(
                "\n⏳ Enter choice (1–6, press 6 to exit): ",
                Self::MAX_MENU_INPUT_LEN,
            ) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("⚠️ {}", e).yellow());
                    continue;
                }
            };

            match input.as_str() {
                // Live mode is bus-only. It does not open RocksDB.
                "1" => self.live_chain_view_blocking()?,

                // Hot cache first for latest/last-N; DB fallback uses cached secondary reader.
                "2" => self.display_latest_block(db_path, &cf_names)?,
                "3" => self.display_last_blocks(db_path, &cf_names, Self::MAX_LAST_N)?,

                // DB modes reuse one secondary reader while this console menu is open.
                "4" => self.display_genesis_block(db_path, &cf_names)?,
                "5" => self.display_block_range(db_path, &cf_names)?,

                "6" => {
                    println!(
                        "{}",
                        "🚪 Exiting Blockchain Console and returning to menu...".red()
                    );
                    break;
                }

                other => println!(
                    "{}",
                    format!("⚠️ Invalid choice: {}. Please enter 1–6.", other).yellow()
                ),
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // DB query menu actions
    // ─────────────────────────────────────────────────────────────────────

    fn display_latest_block(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
    ) -> Result<(), ErrorDetection> {
        // Guardrail: the live bus is fast, but it is not authoritative if the
        // publisher stopped feeding it. Always compare it to the DB tip before
        // showing it as "latest".
        let live_line = self.bus.latest_live_chain_line();
        let live_index = live_line.as_deref().and_then(Self::live_line_block_index);

        let mut loaded_summary: Option<(u64, String)> = None;

        let db_read = self.with_cached_secondary_db(db_path, cf_names, true, |db, cf_data| {
            match db.iterator_cf(cf_data, IteratorMode::End).next() {
                Some(Ok((_k, bytes))) => {
                    let (block, _actual, stored) = Block::deserialize_with_sizes(&bytes)?;
                    let idx = block.metadata.index;
                    let summary = Self::format_block_range_compact_summary(&block, stored);
                    loaded_summary = Some((idx, summary));
                }
                Some(Err(e)) => {
                    return Err(ErrorDetection::DatabaseError {
                        details: format!("Failed while reading latest blockchain DB block: {}", e),
                    });
                }
                None => {}
            }

            Ok(())
        });

        if let Err(e) = db_read {
            if let Some(line) = live_line.as_ref() {
                println!(
                    "{}",
                    "⚠️ Could not verify latest block against RocksDB; showing live cache fallback."
                        .to_string()
                    .yellow()
                );
                println!(
                    "{}",
                    "📌 Latest live block summary (compact, unverified):".green()
                );
                Self::print_live_line_compact(line);
                return Ok(());
            }

            return Err(e);
        }

        match loaded_summary {
            Some((db_index, summary)) => {
                if let (Some(line), Some(live_idx)) = (live_line.as_ref(), live_index) {
                    if live_idx >= db_index {
                        if live_idx > db_index {
                            println!(
                                "{}",
                                format!(
                                    "⚠️ Live cache is ahead of the secondary DB snapshot (live {}, DB {}). Showing live cache.",
                                    live_idx, db_index
                                )
                                .yellow()
                            );
                        }

                        println!("{}", "📌 Latest live block summary (compact):".green());
                        Self::print_live_line_compact(line);
                        return Ok(());
                    }

                    println!(
                        "{}",
                        format!(
                            "⚠️ Live cache is stale at block {}; showing latest DB block {}.",
                            live_idx, db_index
                        )
                        .yellow()
                    );
                } else if live_line.is_some() {
                    println!(
                        "{}",
                        "⚠️ Latest live cache line could not be parsed; showing latest DB block."
                            .yellow()
                    );
                }

                println!("{}", "📌 Latest DB block summary (compact):".green());
                Self::print_compact_summary_guarded(&summary);
                self.cache_db_compact_summary(db_index, summary);
            }
            None => {
                if let Some(line) = live_line.as_ref() {
                    println!(
                        "{}",
                        "⚠️ No DB blocks found in secondary snapshot; showing live cache fallback."
                            .yellow()
                    );
                    println!(
                        "{}",
                        "📌 Latest live block summary (compact, unverified):".green()
                    );
                    Self::print_live_line_compact(line);
                } else {
                    println!("{}", "⚠️ No blocks found yet.".yellow());
                }
            }
        }

        Ok(())
    }

    fn display_last_blocks(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
        max_last_n: usize,
    ) -> Result<(), ErrorDetection> {
        // Guardrail: use live cache only when it is complete enough and current
        // against the DB tip. Otherwise DB is the source of truth for option 3.
        let cached_lines = self.bus.recent_live_chain_lines(max_last_n);
        let cached_latest_index = cached_lines
            .last()
            .and_then(|line| Self::live_line_block_index(line));

        let mut db_latest_index: Option<u64> = None;

        let latest_probe = self.with_cached_secondary_db(db_path, cf_names, true, |db, cf_data| {
            match db.iterator_cf(cf_data, IteratorMode::End).next() {
                Some(Ok((_k, bytes))) => {
                    let (block, _actual, _stored) = Block::deserialize_with_sizes(&bytes)?;
                    db_latest_index = Some(block.metadata.index);
                }
                Some(Err(e)) => {
                    return Err(ErrorDetection::DatabaseError {
                        details: format!("Failed while probing latest blockchain DB block: {}", e),
                    });
                }
                None => {}
            }

            Ok(())
        });

        if let Err(e) = latest_probe {
            if !cached_lines.is_empty() {
                println!(
                    "{}",
                    "⚠️ Could not verify last blocks against RocksDB; showing live cache fallback."
                        .to_string()
                        .yellow()
                );
                println!(
                    "{}",
                    format!(
                        "Displaying last {} live compact block summaries (unverified):",
                        cached_lines.len()
                    )
                    .green()
                );
                Self::print_live_lines_compact(cached_lines);
                return Ok(());
            }

            return Err(e);
        }

        if let (Some(db_tip), Some(cache_tip)) = (db_latest_index, cached_latest_index) {
            if cached_lines.len() >= max_last_n && cache_tip >= db_tip {
                if cache_tip > db_tip {
                    println!(
                        "{}",
                        format!(
                            "⚠️ Live cache is ahead of the secondary DB snapshot (live {}, DB {}). Showing live cache.",
                            cache_tip, db_tip
                        )
                        .yellow()
                    );
                }

                println!(
                    "{}",
                    format!(
                        "Displaying last {} live compact block summaries:",
                        cached_lines.len()
                    )
                    .green()
                );

                Self::print_live_lines_compact(cached_lines);
                return Ok(());
            }

            if !cached_lines.is_empty() {
                let reason = if cache_tip < db_tip {
                    "stale"
                } else {
                    "incomplete"
                };

                println!(
                    "{}",
                    format!(
                        "⚠️ Live cache is {} (cached latest {}, DB latest {}, cached {}/{}). Falling back to compact DB view.",
                        reason,
                        cache_tip,
                        db_tip,
                        cached_lines.len(),
                        max_last_n
                    )
                    .yellow()
                );
            }
        } else if !cached_lines.is_empty() {
            println!(
                "{}",
                "⚠️ Live cache exists but DB/latest index could not be established; falling back to compact DB view."
                    .yellow()
            );
        }

        let mut loaded_summaries: Vec<(u64, String)> = Vec::with_capacity(max_last_n);

        let db_read = self.with_cached_secondary_db(db_path, cf_names, false, |db, cf_data| {
            let mut iter = db.iterator_cf(cf_data, IteratorMode::End);
            for _ in 0..max_last_n {
                match iter.next() {
                    Some(Ok((_k, bytes))) => {
                        let (block, _actual, stored) = Block::deserialize_with_sizes(&bytes)?;
                        let idx = block.metadata.index;

                        let summary = Self::format_block_range_compact_summary(&block, stored);
                        loaded_summaries.push((idx, summary));
                    }
                    Some(Err(e)) => {
                        return Err(ErrorDetection::DatabaseError {
                            details: format!("Failed while iterating blockchain DB: {}", e),
                        });
                    }
                    None => break,
                }
            }

            Ok(())
        });

        if let Err(e) = db_read {
            if !cached_lines.is_empty() {
                println!(
                    "{}",
                    "⚠️ DB fallback failed; showing stale live cache as emergency fallback."
                        .to_string()
                        .yellow()
                );
                Self::print_live_lines_compact(cached_lines);
                return Ok(());
            }

            return Err(e);
        }

        if loaded_summaries.is_empty() {
            println!("{}", "⚠️ No blocks found yet.".yellow());
            return Ok(());
        }

        println!(
            "{}",
            format!(
                "Displaying last {} DB compact block summaries (requested up to {}):",
                loaded_summaries.len(),
                max_last_n
            )
            .green()
        );

        for (idx, summary) in loaded_summaries {
            Self::print_compact_summary_guarded(&summary);
            self.cache_db_compact_summary(idx, summary);
        }

        Ok(())
    }

    fn display_genesis_block(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
    ) -> Result<(), ErrorDetection> {
        if let Some(summary) = self.genesis_cache.as_ref() {
            println!(
                "{}",
                "📜 Displaying cached genesis block summary (compact):".green()
            );
            Self::print_compact_summary_guarded(summary);
            return Ok(());
        }

        if let Some(summary) = self.cached_db_compact_summary(Self::GENESIS_BLOCK_INDEX) {
            println!(
                "{}",
                "📜 Displaying cached genesis block summary (compact):".green()
            );
            Self::print_compact_summary_guarded(&summary);
            self.genesis_cache = Some(summary);
            return Ok(());
        }

        let mut loaded: Option<String> = None;

        self.with_cached_secondary_db(db_path, cf_names, false, |db, cf_data| {
            let key = Self::block_key(Self::GENESIS_BLOCK_INDEX);
            match db.get_pinned_cf(cf_data, key.as_bytes()).map_err(|e| {
                ErrorDetection::StorageError {
                    message: e.to_string(),
                }
            })? {
                Some(bytes) => {
                    let (block, _actual, stored) = Block::deserialize_with_sizes(bytes.as_ref())?;
                    loaded = Some(Self::format_block_range_compact_summary(&block, stored));
                }
                None => println!("{}", "⚠️ No genesis block found.".yellow()),
            }

            Ok(())
        })?;

        if let Some(summary) = loaded {
            println!(
                "{}",
                "📜 Displaying genesis block summary (compact):".green()
            );
            Self::print_compact_summary_guarded(&summary);
            self.genesis_cache = Some(summary.clone());
            self.cache_db_compact_summary(Self::GENESIS_BLOCK_INDEX, summary);
        }

        Ok(())
    }

    fn display_block_range(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
    ) -> Result<(), ErrorDetection> {
        let start_s =
            match Self::read_line_capped("Enter start block index: ", Self::MAX_INDEX_INPUT_LEN) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("⚠️ {}", e).yellow());
                    return Ok(());
                }
            };
        let start: u64 = match start_s.parse() {
            Ok(v) => v,
            Err(_) => {
                println!("{}", "⚠️ Invalid start index".yellow());
                return Ok(());
            }
        };

        let end_s =
            match Self::read_line_capped("Enter end block index: ", Self::MAX_INDEX_INPUT_LEN) {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", format!("⚠️ {}", e).yellow());
                    return Ok(());
                }
            };
        let end: u64 = match end_s.parse() {
            Ok(v) => v,
            Err(_) => {
                println!("{}", "⚠️ Invalid end index".yellow());
                return Ok(());
            }
        };

        if end < start {
            println!("{}", "⚠️ End index must be >= start index.".yellow());
            return Ok(());
        }

        let requested = end.saturating_sub(start).saturating_add(1);
        if requested > Self::MAX_RANGE {
            println!(
                "{}",
                format!(
                    "⚠️ Please limit your search to {} blocks or fewer (you requested {}).",
                    Self::MAX_RANGE,
                    requested
                )
                .yellow()
            );
            return Ok(());
        }

        // Fastest path: answer recent ranges from the live cache without touching RocksDB.
        if let Some(lines) = self.bus.cached_live_lines_for_block_range(start, end) {
            println!(
                "{}",
                format!("Displaying cached live block summaries {}..{}:", start, end).green()
            );
            Self::print_live_lines_compact(lines);
            return Ok(());
        }

        // Second-fastest path: answer repeated DB queries from this menu's compact display cache.
        let mut missing = Vec::new();
        for idx in start..=end {
            if self.cached_db_compact_summary(idx).is_none() {
                missing.push(idx);
            }
        }

        if !missing.is_empty() {
            let mut loaded_summaries: Vec<(u64, String)> = Vec::with_capacity(missing.len());

            self.with_cached_secondary_db(db_path, cf_names, false, |db, cf_data| {
                for idx in &missing {
                    let key = Self::block_key(*idx);

                    match db.get_pinned_cf(cf_data, key.as_bytes()).map_err(|e| {
                        ErrorDetection::StorageError {
                            message: e.to_string(),
                        }
                    })? {
                        Some(bytes) => {
                            let (block, _actual, stored) =
                                Block::deserialize_with_sizes(bytes.as_ref())?;
                            let summary = Self::format_block_range_compact_summary(&block, stored);
                            loaded_summaries.push((*idx, summary));
                        }
                        None => loaded_summaries.push((
                            *idx,
                            format!("⚠️ Block {} not found\n", idx).yellow().to_string(),
                        )),
                    }
                }

                Ok(())
            })?;

            for (idx, summary) in loaded_summaries {
                self.cache_db_compact_summary(idx, summary);
            }
        }

        println!(
            "{}",
            format!(
                "Displaying compact DB block summaries {}..{} ({} max):",
                start,
                end,
                Self::MAX_RANGE
            )
            .green()
        );

        for idx in start..=end {
            if let Some(summary) = self.cached_db_compact_summary(idx) {
                Self::print_compact_summary_guarded(&summary);
            } else {
                println!("{}", format!("⚠️ Block {} unavailable", idx).yellow());
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Live chain view (Option B)
    // ─────────────────────────────────────────────────────────────────────

    fn live_chain_view_blocking(&self) -> Result<(), ErrorDetection> {
        if tokio::runtime::Handle::try_current().is_ok() {
            let bus = self.bus.clone();

            let join = std::thread::spawn(move || -> Result<(), ErrorDetection> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| ErrorDetection::IoError {
                        message: format!("Failed to build tokio runtime: {}", e),
                        code: None,
                        source: None,
                    })?;

                rt.block_on(Self::live_chain_view_async_inner(bus))
            });

            match join.join() {
                Ok(r) => r,
                Err(_) => Err(ErrorDetection::ProtocolError {
                    message: "Live chain view thread panicked".to_string(),
                }),
            }
        } else {
            // No runtime active: safe to create one locally and block.
            let bus = self.bus.clone();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to build tokio runtime: {}", e),
                    code: None,
                    source: None,
                })?;
            rt.block_on(Self::live_chain_view_async_inner(bus))
        }
    }

    // Inner async live view (takes ConsoleBus by value so it can run on another thread)
    async fn live_chain_view_async_inner(bus: ConsoleBus) -> Result<(), ErrorDetection> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        println!();
        println!("{}", "📡 Live Chain View (real-time)".cyan().bold());
        println!("{}", "Streaming minted/accepted blocks…".bright_black());
        println!("{}", "Type 'q' then Enter to exit.\n".bright_black());

        let mut rx = bus.subscribe_live_chain();

        // Shared stop flag so the input thread can terminate cleanly when view ends.
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_input = Arc::clone(&stop_flag);

        // Input watcher: blocks waiting for input, but will exit once stop_flag is set.
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::task::spawn_blocking(move || {
            use std::io::{self, Write};

            while !stop_flag_input.load(Ordering::Relaxed) {
                print!("Type 'q' then Enter to menu: ");
                if io::stdout().flush().is_err() {
                    // If we can't flush, attempt to stop the async loop and exit.
                    match stop_tx.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    break;
                }

                let mut s = String::new();
                if io::stdin().read_line(&mut s).is_err() {
                    match stop_tx.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    break;
                }

                if s.trim().eq_ignore_ascii_case("q") {
                    match stop_tx.send(()) {
                        Ok(()) | Err(()) => {}
                    }
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                _ = &mut stop_rx => {
                    println!("\n{}", "Leaving Live Chain View…".bright_black());
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(line) => {
                            // Guardrail: never let one bus message flood the terminal.
                            let printable = Self::truncate_for_console(
                                &line,
                                Self::MAX_LIVE_LINE_CHARS,
                            );

                            // Parse and render minted/accepted lines with proper per-field coloring
                            // and the exact spacing you want around the arrows.
                            if let Some(colored_line) = Self::render_live_line_colored(&printable) {
                                println!("{colored_line}");
                            } else {
                                // fallback: leave other lines neutral/dim
                                println!("{}", printable.bright_black());
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            println!("{}", format!("(console lagged; skipped {n} lines)").yellow());
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            println!("{}", "(live chain stream closed)".yellow());
                            break;
                        }
                    }
                }
            }
        }

        stop_flag.store(true, Ordering::Relaxed);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // RocksDB secondary open helpers
    // ─────────────────────────────────────────────────────────────────────
    fn with_cached_secondary_db<T, F>(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
        catch_up: bool,
        action: F,
    ) -> Result<T, ErrorDetection>
    where
        F: FnOnce(&DB, &ColumnFamily) -> Result<T, ErrorDetection>,
    {
        if self.secondary_db.is_none() {
            self.secondary_db = Some(Self::open_secondary_db_with_retry(db_path, cf_names)?);
        }

        if catch_up {
            self.catch_up_or_reopen_secondary(db_path, cf_names)?;
        }

        let db = self
            .secondary_db
            .as_ref()
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: "Secondary DB handle unavailable after open".to_string(),
            })?;

        let cf_data = db
            .cf_handle(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)
            .ok_or_else(|| ErrorDetection::DatabaseError {
                details: format!(
                    "Column '{}' not found",
                    GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
                ),
            })?;

        action(db, cf_data)
    }

    fn catch_up_or_reopen_secondary(
        &mut self,
        db_path: &Path,
        cf_names: &[&'static str],
    ) -> Result<(), ErrorDetection> {
        let Some(db) = self.secondary_db.as_ref() else {
            self.secondary_db = Some(Self::open_secondary_db_with_retry(db_path, cf_names)?);
            return Ok(());
        };

        match db.try_catch_up_with_primary() {
            Ok(()) => Ok(()),
            Err(e) if Self::is_retryable_db_error(&e) => {
                println!(
                    "{}",
                    "⚠️  Cached secondary DB catch-up busy; reopening secondary reader…".yellow()
                );

                self.secondary_db = None;
                self.secondary_db = Some(Self::open_secondary_db_with_retry(db_path, cf_names)?);
                Ok(())
            }
            Err(e) => Err(ErrorDetection::DatabaseError {
                details: format!("Cached secondary DB failed to catch up with primary: {}", e),
            }),
        }
    }

    /// Build a stable per-process secondary path next to the primary DB.
    fn secondary_db_path(primary_db_path: &Path) -> PathBuf {
        let parent = primary_db_path.parent().unwrap_or_else(|| Path::new("."));

        parent.join(format!(
            "003.blockchain_db_console_secondary_{}",
            std::process::id()
        ))
    }

    /// Open the blockchain DB as a RocksDB secondary reader.
    fn open_secondary_db_with_retry(
        db_path: &Path,
        cf_names: &[&'static str],
    ) -> Result<DB, ErrorDetection> {
        if !db_path.exists() {
            return Err(ErrorDetection::DatabaseError {
                details: format!("Blockchain DB path does not exist: {}", db_path.display()),
            });
        }

        if !db_path.is_dir() {
            return Err(ErrorDetection::DatabaseError {
                details: format!(
                    "Blockchain DB path is not a directory: {}",
                    db_path.display()
                ),
            });
        }

        let secondary_path = Self::secondary_db_path(db_path);

        std::fs::create_dir_all(&secondary_path).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to create DB secondary directory '{}': {}",
                secondary_path.display(),
                e
            ),
            code: None,
            source: None,
        })?;

        let mut rocksdb_opts = rust_rocksdb::Options::default();

        // Secondary instances are commonly opened with unlimited open files so the
        // secondary can inspect/catch up across the primary's files without running
        // into a low max-open-files ceiling.
        rocksdb_opts.set_max_open_files(-1);

        let mut last_err: Option<rust_rocksdb::Error> = None;

        for attempt in 1..=Self::MAX_SECONDARY_OPEN_ATTEMPTS {
            match DB::open_cf_as_secondary(
                &rocksdb_opts,
                db_path,
                secondary_path.as_path(),
                cf_names,
            ) {
                Ok(db) => return Ok(db),
                Err(e)
                    if attempt < Self::MAX_SECONDARY_OPEN_ATTEMPTS
                        && Self::is_retryable_db_error(&e) =>
                {
                    println!(
                        "{}",
                        format!(
                            "⚠️  Secondary DB open busy, retrying in {}ms (attempt {}/{})…",
                            Self::SECONDARY_OPEN_RETRY_MS,
                            attempt,
                            Self::MAX_SECONDARY_OPEN_ATTEMPTS
                        )
                        .yellow()
                    );

                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(
                        Self::SECONDARY_OPEN_RETRY_MS,
                    ));
                }
                Err(e) => {
                    return Err(ErrorDetection::DatabaseError {
                        details: format!("Failed to open blockchain DB as secondary reader: {}", e),
                    });
                }
            }
        }

        Err(ErrorDetection::DatabaseError {
            details: format!(
                "Failed to open blockchain DB as secondary reader after {} attempts: {}",
                Self::MAX_SECONDARY_OPEN_ATTEMPTS,
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string())
            ),
        })
    }

    fn is_retryable_db_error(e: &rust_rocksdb::Error) -> bool {
        let s = e.to_string().to_lowercase();

        s.contains("lock file")
            || s.contains("failed to lock")
            || s.contains("io error: lock")
            || s.contains("lock held")
            || s.contains("lock hold")
            || s.contains("busy")
            || s.contains("in use")
            || s.contains("try again")
            || s.contains("temporarily unavailable")
            || s.contains("resource temporarily unavailable")
            || s.contains("database is locked")
    }

    // ──────────────────────────────────────────────────────────────
    // Safe input helper
    // ──────────────────────────────────────────────────────────────

    fn read_line_capped(prompt: &str, cap: usize) -> Result<String, ErrorDetection> {
        use std::io::{self, Write};

        print!("{prompt}");
        io::stdout().flush().map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to flush stdout: {}", e),
            code: None,
            source: None,
        })?;

        let mut s = String::new();
        io::stdin()
            .read_line(&mut s)
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read input: {}", e),
                code: None,
                source: None,
            })?;

        if s.len() > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!("Input too long (max {} chars)", cap),
                tx_id: None,
            });
        }

        Ok(s.trim().to_string())
    }

    // ──────────────────────────────────────────────────────────────
    // Console summary formatting + bounded cache helpers
    // ──────────────────────────────────────────────────────────────

    fn block_key(index: u64) -> String {
        format!("block_{:010}", index)
    }

    fn cached_db_compact_summary(&self, index: u64) -> Option<String> {
        self.db_block_compact_summary_cache.get(&index).cloned()
    }

    fn cache_db_compact_summary(&mut self, index: u64, summary: String) {
        if !self.db_block_compact_summary_cache.contains_key(&index) {
            self.db_block_compact_summary_order.push_back(index);
        }

        self.db_block_compact_summary_cache.insert(index, summary);

        while self.db_block_compact_summary_order.len() > Self::MAX_DB_COMPACT_SUMMARY_CACHE_BLOCKS
        {
            if let Some(oldest) = self.db_block_compact_summary_order.pop_front() {
                self.db_block_compact_summary_cache.remove(&oldest);
            }
        }
    }

    fn print_live_line_compact(line: &str) {
        let compact = Self::format_live_line_compact(line);
        Self::print_compact_summary_guarded(&compact);
    }

    fn print_live_lines_compact(lines: Vec<String>) {
        for line in lines {
            let compact = Self::format_live_line_compact(&line);
            Self::print_compact_summary_guarded(&compact);
        }
    }

    fn format_live_line_compact(line: &str) -> String {
        let block = Self::extract_pipe_field(line, "block").unwrap_or_else(|| "?".to_string());
        let txs = Self::extract_pipe_field(line, "txs").unwrap_or_else(|| "?".to_string());
        let reward = Self::extract_pipe_field(line, "reward").unwrap_or_else(|| "?".to_string());
        let hash = Self::extract_pipe_field(line, "hash")
            .map(|h| Self::ellipsize_middle(&h, Self::COMPACT_HASH_HEAD, Self::COMPACT_HASH_TAIL))
            .unwrap_or_else(|| "?".to_string());

        let ts = line
            .split_once("  ")
            .map(|(head, _)| head.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        format!("Block #{block} | time: {ts} | txs: {txs} | reward: {reward} | hash: {hash}\n")
    }

    fn extract_pipe_field(line: &str, field: &str) -> Option<String> {
        let prefix = format!("{field}:");
        for part in line.split('|') {
            let trimmed = part.trim();
            if let Some(v) = trimmed.strip_prefix(&prefix) {
                return Some(v.trim().to_string());
            }
        }
        None
    }

    fn live_line_block_index(line: &str) -> Option<u64> {
        Self::extract_pipe_field(line, "block")?.parse::<u64>().ok()
    }

    fn print_compact_summary_guarded(summary: &str) {
        let printable = Self::truncate_for_console(summary, Self::MAX_COMPACT_SUMMARY_CHARS);
        print!("{printable}");
        if !printable.ends_with('\n') {
            println!();
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Compact block summary formatting
    // ──────────────────────────────────────────────────────────────

    fn format_block_range_compact_summary(block: &Block, stored_block: usize) -> String {
        let curr_hash_hex = hex::encode(block.block_hash);
        let curr_hash_print = Self::ellipsize_middle(
            &curr_hash_hex,
            Self::COMPACT_HASH_HEAD,
            Self::COMPACT_HASH_TAIL,
        );

        let batch_text = match block.batch_key.as_deref() {
            Some(s) if !s.is_empty() => "yes",
            _ => "no",
        };
        format!(
            "Block #{} | ts: {} | reward: {} | stored: {} B | batch: {} | hash: {}\n",
            block.metadata.index,
            block.metadata.timestamp,
            block.reward,
            stored_block,
            batch_text,
            curr_hash_print
        )
    }
}
