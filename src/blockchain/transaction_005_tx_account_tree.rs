// src/blockchain/transaction_005_tx_account_tree.rs

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::halving_schedule::RewardHalving;
use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::blockchain::transaction_006_tx_account_tree_guards::{
    AccountGuard, ApplyContext, ApplyMode,
};
use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::tokens::nft_001::{apply_nft_mint, apply_nft_transfer, load_nft_record};
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::STATE_KEY;
pub use crate::utility::helper::{from_micro_units, to_micro_units};
use parking_lot::RwLock;
use postcard::{take_from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use tracing::{debug, info, warn};

/// **AccountModelTree**
#[derive(Debug, Clone)]
pub struct AccountModelTree {
    inner: Arc<RwLock<InnerTree>>,
    db_manager: RockDBManager,
    pending_blocks: Arc<RwLock<HashMap<u64, Block>>>,
}

/// Canonical zero hash helper for 64-byte Blake3-512 fields.
#[inline]
fn zero_hash() -> Hash {
    [0u8; 64]
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct InnerTree {
    pub balances: HashMap<String, u64>,

    #[serde(default)]
    pub tip_height: u64,

    #[serde(default = "zero_hash", with = "BigArray")]
    pub tip_hash: Hash,

    #[serde(default = "zero_hash", with = "BigArray")]
    pub prev_tip_hash: Hash,

    #[serde(default)]
    pub has_tip: bool,

    #[serde(default, skip_serializing, skip_deserializing)]
    pub blocks: Vec<Block>,

    // ─────────────────────────────────────────────────────────────
    // SUPPLY / ISSUANCE COUNTERS (persisted in STATE_KEY)
    // ─────────────────────────────────────────────────────────────
    #[serde(default)]
    pub total_issued_micro: u64,

    #[serde(default)]
    pub rewards_issued_micro: u64,

    #[serde(default)]
    pub reserved_issued_micro: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
struct AccountStateSnapshot {
    version: u64,
    balances: HashMap<String, u64>,

    #[serde(default)]
    tip_height: u64,

    #[serde(default = "zero_hash", with = "BigArray")]
    tip_hash: Hash,

    #[serde(default = "zero_hash", with = "BigArray")]
    prev_tip_hash: Hash,

    #[serde(default)]
    has_tip: bool,

    #[serde(default)]
    total_issued_micro: u64,

    #[serde(default)]
    rewards_issued_micro: u64,

    #[serde(default)]
    reserved_issued_micro: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct LegacyInnerTree {
    pub balances: HashMap<String, u64>,
    pub blocks: Vec<Block>,

    #[serde(default)]
    pub total_issued_micro: u64,

    #[serde(default)]
    pub rewards_issued_micro: u64,

    #[serde(default)]
    pub reserved_issued_micro: u64,
}

const ACCOUNT_STATE_SNAPSHOT_VERSION: u64 = 2;
const MAX_RECENT_BLOCKS_IN_RAM: usize = 512;
const MAX_PENDING_BLOCKS: usize = 4_096;
const MAX_PENDING_BLOCK_DISTANCE: u64 = 1_024;
const MAX_ACCOUNT_STATE_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
const RSS_WARN_MB: u64 = 512;
const RSS_CRITICAL_MB: u64 = 1_024;
const RSS_EMERGENCY_MB: u64 = 2_048;

impl InnerTree {
    pub(crate) fn empty() -> Self {
        Self {
            balances: HashMap::new(),
            tip_height: 0,
            tip_hash: [0u8; 64],
            prev_tip_hash: [0u8; 64],
            has_tip: false,
            blocks: Vec::new(),
            total_issued_micro: 0,
            rewards_issued_micro: 0,
            reserved_issued_micro: 0,
        }
    }

    #[inline]
    pub(crate) fn expected_next_height(&self) -> u64 {
        if self.has_tip {
            self.tip_height.saturating_add(1)
        } else {
            0
        }
    }

    #[inline]
    pub(crate) fn current_tip_hash(&self) -> Option<Hash> {
        self.has_tip.then_some(self.tip_hash)
    }

    #[inline]
    pub(crate) fn current_prev_tip_hash(&self) -> Option<Hash> {
        self.has_tip.then_some(self.prev_tip_hash)
    }
}

impl AccountModelTree {
    // ─────────────────────────────────────────────────────────────
    // (A) Constructors / Basics
    // ─────────────────────────────────────────────────────────────

    pub fn with_manager(db_manager: RockDBManager) -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerTree::empty())),
            db_manager,
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn decode_inner_state_strict(data: &[u8]) -> Result<InnerTree, ErrorDetection> {
        if let Ok((snapshot, remaining)) = take_from_bytes::<AccountStateSnapshot>(data)
            && remaining.is_empty()
            && snapshot.version == ACCOUNT_STATE_SNAPSHOT_VERSION
        {
            let mut inner = Self::inner_from_snapshot(snapshot);
            Self::backfill_total_issued_if_missing(&mut inner)?;
            Self::verify_compact_state_invariants(&inner, None, None, None)?;

            return Ok(inner);
        }

        let (legacy, remaining): (LegacyInnerTree, &[u8]) =
            take_from_bytes(data).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Deserialize account state failed as compact or legacy: {e}"),
            })?;

        if !remaining.is_empty() {
            return Err(ErrorDetection::SerializationError {
                details: "Deserialize legacy account state failed: trailing bytes rejected"
                    .to_string(),
            });
        }

        let mut inner = Self::inner_from_legacy(legacy);
        Self::backfill_total_issued_if_missing(&mut inner)?;
        Self::verify_compact_state_invariants(&inner, None, None, None)?;

        warn!(
            "[STATE][MIGRATION] loaded legacy STATE_KEY containing block history; compact rewrite will remove serialized blocks"
        );

        Ok(inner)
    }

    fn inner_from_snapshot(snapshot: AccountStateSnapshot) -> InnerTree {
        InnerTree {
            balances: snapshot.balances,
            tip_height: snapshot.tip_height,
            tip_hash: snapshot.tip_hash,
            prev_tip_hash: snapshot.prev_tip_hash,
            has_tip: snapshot.has_tip,
            blocks: Vec::new(),
            total_issued_micro: snapshot.total_issued_micro,
            rewards_issued_micro: snapshot.rewards_issued_micro,
            reserved_issued_micro: snapshot.reserved_issued_micro,
        }
    }

    fn snapshot_from_inner(inner: &InnerTree) -> AccountStateSnapshot {
        AccountStateSnapshot {
            version: ACCOUNT_STATE_SNAPSHOT_VERSION,
            balances: inner.balances.clone(),
            tip_height: inner.tip_height,
            tip_hash: inner.tip_hash,
            prev_tip_hash: inner.prev_tip_hash,
            has_tip: inner.has_tip,
            total_issued_micro: inner.total_issued_micro,
            rewards_issued_micro: inner.rewards_issued_micro,
            reserved_issued_micro: inner.reserved_issued_micro,
        }
    }

    fn inner_from_legacy(mut legacy: LegacyInnerTree) -> InnerTree {
        let (has_tip, tip_height, tip_hash, prev_tip_hash) =
            match (legacy.blocks.last(), legacy.blocks.iter().rev().nth(1)) {
                (Some(tip), prev) => (
                    true,
                    tip.metadata.index,
                    tip.block_hash,
                    prev.map(|b| b.block_hash)
                        .unwrap_or(tip.metadata.previous_hash),
                ),
                (None, _) => (false, 0, [0u8; 64], [0u8; 64]),
            };

        if legacy.blocks.len() > MAX_RECENT_BLOCKS_IN_RAM {
            let drain_to = legacy.blocks.len().saturating_sub(MAX_RECENT_BLOCKS_IN_RAM);
            legacy.blocks.drain(0..drain_to);
        }

        InnerTree {
            balances: legacy.balances,
            tip_height,
            tip_hash,
            prev_tip_hash,
            has_tip,
            blocks: legacy.blocks,
            total_issued_micro: legacy.total_issued_micro,
            rewards_issued_micro: legacy.rewards_issued_micro,
            reserved_issued_micro: legacy.reserved_issued_micro,
        }
    }

    fn remember_recent_block(inner: &mut InnerTree, block: Block) {
        inner.prev_tip_hash = if inner.has_tip {
            inner.tip_hash
        } else {
            block.metadata.previous_hash
        };

        inner.tip_height = block.metadata.index;
        inner.tip_hash = block.block_hash;
        inner.has_tip = true;

        inner.blocks.push(block);

        if inner.blocks.len() > MAX_RECENT_BLOCKS_IN_RAM {
            let excess = inner.blocks.len().saturating_sub(MAX_RECENT_BLOCKS_IN_RAM);
            inner.blocks.drain(0..excess);
        }
    }

    fn validate_next_block_link(inner: &InnerTree, block: &Block) -> Result<(), ErrorDetection> {
        let expected = inner.expected_next_height();

        if block.metadata.index != expected {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block height mismatch: expected next {}, got {}",
                    expected, block.metadata.index
                ),
                tx_id: None,
            });
        }

        if inner.has_tip && block.metadata.previous_hash != inner.tip_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block {} has invalid previous_hash: expected {}, got {}",
                    block.metadata.index,
                    hex::encode(inner.tip_hash),
                    hex::encode(block.metadata.previous_hash)
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn verify_compact_state_invariants(
        inner: &InnerTree,
        expected_tip_height: Option<u64>,
        expected_tip_hash: Option<Hash>,
        expected_prev_hash: Option<Hash>,
    ) -> Result<(), ErrorDetection> {
        if inner.blocks.len() > MAX_RECENT_BLOCKS_IN_RAM {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Recent block cache exceeded bound: len={} max={}",
                    inner.blocks.len(),
                    MAX_RECENT_BLOCKS_IN_RAM
                ),
                tx_id: None,
            });
        }

        if let Some(expected) = expected_tip_height {
            if !inner.has_tip {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Expected tip height {expected}, but compact state has no tip"
                    ),
                    tx_id: None,
                });
            }

            if inner.tip_height != expected {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Tip height mismatch: expected {}, got {}",
                        expected, inner.tip_height
                    ),
                    tx_id: None,
                });
            }
        }

        if let Some(expected) = expected_tip_hash
            && (!inner.has_tip || inner.tip_hash != expected)
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Tip hash mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(inner.tip_hash)
                ),
                tx_id: None,
            });
        }

        if let Some(expected) = expected_prev_hash
            && (!inner.has_tip || inner.prev_tip_hash != expected)
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Previous tip hash mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(inner.prev_tip_hash)
                ),
                tx_id: None,
            });
        }

        for pair in inner.blocks.windows(2) {
            let [prev, next] = pair else {
                return Err(ErrorDetection::ValidationError {
                    message: "Recent block cache window length was not 2".to_string(),
                    tx_id: None,
                });
            };

            if next.metadata.index != prev.metadata.index.saturating_add(1) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Recent block cache is not contiguous: {} then {}",
                        prev.metadata.index, next.metadata.index
                    ),
                    tx_id: None,
                });
            }

            if next.metadata.previous_hash != prev.block_hash {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Recent block cache linkage failed at height {}",
                        next.metadata.index
                    ),
                    tx_id: None,
                });
            }
        }

        if let Some(last) = inner.blocks.last()
            && (!inner.has_tip
                || last.metadata.index != inner.tip_height
                || last.block_hash != inner.tip_hash)
        {
            return Err(ErrorDetection::ValidationError {
                message: "Recent block cache tip does not match compact tip metadata".to_string(),
                tx_id: None,
            });
        }

        let balance_sum: u64 = inner
            .balances
            .values()
            .copied()
            .try_fold(0u64, |acc, value| acc.checked_add(value))
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Overflow while summing account balances".to_string(),
                tx_id: None,
            })?;

        if balance_sum > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Balance sum exceeds MAX_SUPPLY: {} > {}",
                    balance_sum,
                    GlobalConfiguration::MAX_SUPPLY
                ),
                tx_id: None,
            });
        }

        if inner.total_issued_micro > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "total_issued_micro exceeds MAX_SUPPLY: {} > {}",
                    inner.total_issued_micro,
                    GlobalConfiguration::MAX_SUPPLY
                ),
                tx_id: None,
            });
        }

        if inner.rewards_issued_micro > GlobalConfiguration::MAX_REWARD_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "rewards_issued_micro exceeds MAX_REWARD_SUPPLY: {} > {}",
                    inner.rewards_issued_micro,
                    GlobalConfiguration::MAX_REWARD_SUPPLY
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn trace_state_resource_usage(&self, block_height: u64) {
        let inner = self.inner.read();
        let balances_len = inner.balances.len();
        let recent_blocks_len = inner.blocks.len();
        let tip_height = inner.tip_height;
        let has_tip = inner.has_tip;
        drop(inner);

        let pending_len = self.pending_blocks.read().len();

        tracing::debug!(
            "[RESOURCE][STATE] block={} balances={} recent_blocks={} recent_blocks_cap={} pending_blocks={} pending_blocks_cap={} tip_height={} has_tip={} state_serializes_blocks=false",
            block_height,
            balances_len,
            recent_blocks_len,
            MAX_RECENT_BLOCKS_IN_RAM,
            pending_len,
            MAX_PENDING_BLOCKS,
            tip_height,
            has_tip
        );
    }

    fn trace_rss_threshold_guard(block_height: u64, rss_mb: Option<u64>) {
        use std::sync::{Mutex, OnceLock};

        static LAST_RSS_SEVERITY: OnceLock<Mutex<Option<&'static str>>> = OnceLock::new();

        let Some(rss_mb) = rss_mb else {
            return;
        };

        let severity = if rss_mb >= RSS_EMERGENCY_MB {
            "emergency"
        } else if rss_mb >= RSS_CRITICAL_MB {
            "critical"
        } else if rss_mb >= RSS_WARN_MB {
            "warning"
        } else {
            let lock = LAST_RSS_SEVERITY.get_or_init(|| Mutex::new(None));
            let mut previous = match lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };

            *previous = None;
            return;
        };

        let lock = LAST_RSS_SEVERITY.get_or_init(|| Mutex::new(None));
        let mut previous = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if *previous == Some(severity) {
            return;
        }

        *previous = Some(severity);

        match severity {
            "warning" => warn!(
                "[RESOURCE][MEMORY][RSS_GUARD] severity=warning block={} rss_mb={} threshold_mb={} action=observe_only",
                block_height, rss_mb, RSS_WARN_MB
            ),
            "critical" => tracing::error!(
                "[RESOURCE][MEMORY][RSS_GUARD] severity=critical block={} rss_mb={} threshold_mb={} action=observe_only",
                block_height,
                rss_mb,
                RSS_CRITICAL_MB
            ),
            "emergency" => tracing::error!(
                "[RESOURCE][MEMORY][RSS_GUARD] severity=emergency block={} rss_mb={} threshold_mb={} action=observe_only",
                block_height,
                rss_mb,
                RSS_EMERGENCY_MB
            ),
            _ => {}
        }
    }

    fn format_resource_percent(value: Option<f64>, fallback: &'static str) -> String {
        value
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| fallback.to_string())
    }

    fn format_resource_u64(value: Option<u64>, fallback: &'static str) -> String {
        value
            .map(|value| value.to_string())
            .unwrap_or_else(|| fallback.to_string())
    }

    #[cfg(target_os = "linux")]
    fn read_proc_file(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    #[cfg(target_os = "linux")]
    fn current_rss_mb() -> Option<u64> {
        let status = Self::read_proc_file("/proc/self/status")?;

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())?;

                return Some(kb / 1024);
            }
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn memory_used_percent() -> Option<f64> {
        let meminfo = Self::read_proc_file("/proc/meminfo")?;

        let mut mem_total_kb = None;
        let mut mem_available_kb = None;

        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                mem_total_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok());
            }

            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                mem_available_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok());
            }
        }

        let total = mem_total_kb?;
        let available = mem_available_kb?;

        if total == 0 || available > total {
            return None;
        }

        let used = total.saturating_sub(available);
        Some((used as f64 / total as f64) * 100.0)
    }

    #[cfg(target_os = "linux")]
    fn disk_used_percent() -> Option<f64> {
        let output = std::process::Command::new("df")
            .arg("-P")
            .arg(".")
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8(output.stdout).ok()?;
        let line = stdout.lines().nth(1)?;

        line.split_whitespace()
            .nth(4)?
            .trim_end_matches('%')
            .parse::<f64>()
            .ok()
    }

    #[cfg(target_os = "linux")]
    fn cpu_used_percent_snapshot() -> Option<f64> {
        use std::sync::{Mutex, OnceLock};

        static LAST_CPU_SAMPLE: OnceLock<Mutex<Option<(u64, u64)>>> = OnceLock::new();

        let stat = Self::read_proc_file("/proc/stat")?;
        let cpu_line = stat.lines().find(|line| line.starts_with("cpu "))?;

        let values: Vec<u64> = cpu_line
            .split_whitespace()
            .skip(1)
            .filter_map(|value| value.parse::<u64>().ok())
            .collect();

        if values.len() < 4 {
            return None;
        }

        let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
        let total = values.iter().copied().sum::<u64>();

        let sample_lock = LAST_CPU_SAMPLE.get_or_init(|| Mutex::new(None));
        let mut previous = match sample_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let Some((previous_total, previous_idle)) = *previous else {
            *previous = Some((total, idle));
            return None;
        };

        *previous = Some((total, idle));

        let total_delta = total.saturating_sub(previous_total);
        let idle_delta = idle.saturating_sub(previous_idle);

        if total_delta == 0 || idle_delta > total_delta {
            return None;
        }

        Some(((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0)
    }

    #[cfg(target_os = "windows")]
    fn run_powershell_scalar(command: &str) -> Option<String> {
        let output = std::process::Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(command)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8(output.stdout).ok()?;
        let value = stdout.trim();

        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_powershell_f64(command: &str) -> Option<f64> {
        Self::run_powershell_scalar(command)?.parse::<f64>().ok()
    }

    #[cfg(target_os = "windows")]
    fn parse_powershell_u64(command: &str) -> Option<u64> {
        Self::run_powershell_scalar(command)?.parse::<u64>().ok()
    }

    #[cfg(target_os = "windows")]
    fn current_rss_mb() -> Option<u64> {
        let pid = std::process::id();

        let command = format!(
            r#"$p = Get-Process -Id {pid}; [Console]::WriteLine([UInt64][Math]::Floor($p.WorkingSet64 / 1MB))"#
        );

        Self::parse_powershell_u64(&command)
    }

    #[cfg(target_os = "windows")]
    fn memory_used_percent() -> Option<f64> {
        Self::parse_powershell_f64(
            r#"$os = Get-CimInstance Win32_OperatingSystem; $used = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100; [Console]::WriteLine(([double]$used).ToString([Globalization.CultureInfo]::InvariantCulture))"#,
        )
    }

    #[cfg(target_os = "windows")]
    fn disk_used_percent() -> Option<f64> {
        Self::parse_powershell_f64(
            r#"$drive = [System.IO.Path]::GetPathRoot((Get-Location).Path).TrimEnd('\'); $disk = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $drive }; if ($null -eq $disk -or $disk.Size -eq 0) { exit 1 }; $used = (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100; [Console]::WriteLine(([double]$used).ToString([Globalization.CultureInfo]::InvariantCulture))"#,
        )
    }

    #[cfg(target_os = "windows")]
    fn cpu_used_percent_snapshot() -> Option<f64> {
        Self::parse_powershell_f64(
            r#"$cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average; [Console]::WriteLine(([double]$cpu.Average).ToString([Globalization.CultureInfo]::InvariantCulture))"#,
        )
    }

    #[cfg(target_os = "macos")]
    fn command_stdout(command: &str, args: &[&str]) -> Option<String> {
        let output = std::process::Command::new(command)
            .args(args)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        String::from_utf8(output.stdout).ok()
    }

    #[cfg(target_os = "macos")]
    fn current_rss_mb() -> Option<u64> {
        let pid = std::process::id().to_string();
        let output = Self::command_stdout("ps", &["-o", "rss=", "-p", pid.as_str()])?;
        let kb = output.trim().parse::<u64>().ok()?;

        Some(kb / 1024)
    }

    #[cfg(target_os = "macos")]
    fn memory_used_percent() -> Option<f64> {
        let memsize = Self::command_stdout("sysctl", &["-n", "hw.memsize"])?
            .trim()
            .parse::<u64>()
            .ok()?;

        let vm_stat = Self::command_stdout("vm_stat", &[])?;

        let mut page_size = 4096_u64;
        let mut free_pages = 0_u64;
        let mut inactive_pages = 0_u64;
        let mut speculative_pages = 0_u64;

        for line in vm_stat.lines() {
            if let Some(start) = line.find("page size of ") {
                let after = &line[start + "page size of ".len()..];
                if let Some(value) = after.split_whitespace().next() {
                    if let Ok(parsed) = value.parse::<u64>() {
                        page_size = parsed;
                    }
                }
            }

            let parse_pages = |prefix: &str, line: &str| -> Option<u64> {
                let rest = line.strip_prefix(prefix)?;
                rest.trim()
                    .trim_end_matches('.')
                    .replace('.', "")
                    .parse::<u64>()
                    .ok()
            };

            if let Some(value) = parse_pages("Pages free:", line) {
                free_pages = value;
            } else if let Some(value) = parse_pages("Pages inactive:", line) {
                inactive_pages = value;
            } else if let Some(value) = parse_pages("Pages speculative:", line) {
                speculative_pages = value;
            }
        }

        if memsize == 0 {
            return None;
        }

        let available_bytes = free_pages
            .saturating_add(inactive_pages)
            .saturating_add(speculative_pages)
            .saturating_mul(page_size);

        let used_bytes = memsize.saturating_sub(available_bytes.min(memsize));
        Some((used_bytes as f64 / memsize as f64) * 100.0)
    }

    #[cfg(target_os = "macos")]
    fn disk_used_percent() -> Option<f64> {
        let output = Self::command_stdout("df", &["-Pk", "."])?;
        let line = output.lines().nth(1)?;

        line.split_whitespace()
            .nth(4)?
            .trim_end_matches('%')
            .parse::<f64>()
            .ok()
    }

    #[cfg(target_os = "macos")]
    fn cpu_used_percent_snapshot() -> Option<f64> {
        let output = Self::command_stdout("top", &["-l", "1", "-n", "0"])?;
        let line = output.lines().find(|line| line.contains("CPU usage:"))?;

        let mut percent_values = Vec::new();

        for part in line.split_whitespace() {
            if let Some(raw) = part.strip_suffix('%') {
                if let Ok(value) = raw.parse::<f64>() {
                    percent_values.push(value);
                }
            }
        }

        let user = *percent_values.first()?;
        let system = *percent_values.get(1).unwrap_or(&0.0);

        Some(user + system)
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    fn trace_block_resource_usage(block_height: u64) {
        let cpu_fallback = if cfg!(target_os = "linux") {
            "warming_up"
        } else {
            "unavailable"
        };

        let cpu_percent =
            Self::format_resource_percent(Self::cpu_used_percent_snapshot(), cpu_fallback);

        let memory_percent =
            Self::format_resource_percent(Self::memory_used_percent(), "unavailable");

        let rss_mb_value = Self::current_rss_mb();
        let rss_mb = Self::format_resource_u64(rss_mb_value, "unavailable");

        let disk_percent = Self::format_resource_percent(Self::disk_used_percent(), "unavailable");

        tracing::debug!(
            "[RESOURCE][CPU] block={} cpu_percent={}",
            block_height,
            cpu_percent
        );

        tracing::debug!(
            "[RESOURCE][MEMORY] block={} memory_percent={} rss_mb={}",
            block_height,
            memory_percent,
            rss_mb
        );

        Self::trace_rss_threshold_guard(block_height, rss_mb_value);

        tracing::debug!(
            "[RESOURCE][DISK] block={} disk_percent={}",
            block_height,
            disk_percent
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    fn trace_block_resource_usage(block_height: u64) {
        tracing::debug!(
            "[RESOURCE][CPU] block={} cpu_percent=unavailable",
            block_height
        );

        tracing::debug!(
            "[RESOURCE][MEMORY] block={} memory_percent=unavailable rss_mb=unavailable",
            block_height
        );

        tracing::debug!(
            "[RESOURCE][DISK] block={} disk_percent=unavailable",
            block_height
        );
    }

    pub fn latest_block_height_u64(&self) -> u64 {
        let g = self.inner.read();

        if g.has_tip { g.tip_height } else { 0 }
    }

    pub fn latest_block_height(&self) -> usize {
        usize::try_from(self.latest_block_height_u64()).unwrap_or(usize::MAX)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Block, ErrorDetection> {
        if let Some(block) = self
            .inner
            .read()
            .blocks
            .iter()
            .find(|block| block.metadata.index == height)
            .cloned()
        {
            return Ok(block);
        }

        self.db_manager
            .get_block_by_index(height)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("Block {height} not found in recent cache or RocksDB"),
            })
    }

    pub fn get_block_by_index(&self, idx: usize) -> Result<Block, ErrorDetection> {
        let height = u64::try_from(idx).map_err(|_| ErrorDetection::ValidationError {
            message: format!("Block index {idx} cannot fit u64"),
            tx_id: None,
        })?;

        self.get_block_by_height(height)
    }

    fn process_pending_blocks(&mut self) {
        loop {
            let next_height = self.inner.read().expected_next_height();

            let maybe_block = self.pending_blocks.write().remove(&next_height);
            match maybe_block {
                Some(block) => {
                    info!(
                        "🔄 Processing previously queued block #{}.",
                        block.metadata.index
                    );
                    if let Err(e) = self.add_block(block) {
                        tracing::error!("Failed to process queued block: {:?}", e);
                        break;
                    }
                }
                None => break,
            }
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), ErrorDetection> {
        let expected_index = self.inner.read().expected_next_height();
        let block_index = block.metadata.index;

        if block_index == expected_index {
            {
                let inner = self.inner.read();
                Self::validate_next_block_link(&inner, &block)?;
            }

            {
                let mut inner = self.inner.write();
                Self::remember_recent_block(&mut inner, block);
                Self::verify_compact_state_invariants(
                    &inner,
                    Some(expected_index),
                    Some(inner.tip_hash),
                    None,
                )?;
            }

            let new_tip_present = self.inner.read().has_tip;

            if !new_tip_present {
                return Err(ErrorDetection::ValidationError {
                    message: "Invariant violated: compact tip missing right after add_block()"
                        .to_string(),
                    tx_id: None,
                });
            }

            tracing::debug!(
                "[CHAIN] block_accepted=true h={} new_tip_present={} recent_blocks={}",
                expected_index,
                new_tip_present,
                self.inner.read().blocks.len()
            );

            if tracing::enabled!(tracing::Level::DEBUG) {
                Self::trace_block_resource_usage(expected_index);
                self.trace_state_resource_usage(expected_index);
            }

            self.process_pending_blocks();
            Ok(())
        } else if block_index > expected_index {
            let distance = block_index.saturating_sub(expected_index);

            if distance > MAX_PENDING_BLOCK_DISTANCE {
                tracing::debug!(
                    "Dropping far-future block #{}; expected_next={} distance={} max={}",
                    block.metadata.index,
                    expected_index,
                    distance,
                    MAX_PENDING_BLOCK_DISTANCE
                );
                return Ok(());
            }

            let mut pending = self.pending_blocks.write();

            if pending.len() >= MAX_PENDING_BLOCKS {
                tracing::debug!(
                    "Dropping future block #{} because pending queue is full len={} max={}",
                    block.metadata.index,
                    pending.len(),
                    MAX_PENDING_BLOCKS
                );
                return Ok(());
            }

            tracing::debug!(
                "Block #{} received before parent. Queued for later processing. Expected next: {} pending_len_after={}",
                block.metadata.index,
                expected_index,
                pending.len().saturating_add(1)
            );
            pending.insert(block_index, block);
            Ok(())
        } else {
            let tip_height = self.inner.read().tip_height;
            tracing::debug!(
                "Duplicate or old block #{} received (current tip: {}). Ignoring.",
                block.metadata.index,
                tip_height
            );
            Ok(())
        }
    }

    pub fn reload_from_db(&mut self) {
        let tip = self.db_manager.get_latest_block_index().unwrap_or(0);
        if let Err(e) = self.reload_from_db_to_height(tip) {
            tracing::debug!("reload_from_db (to {}) failed: {:?}", tip, e);
        }
    }

    pub fn reload_from_db_to_height(&mut self, height: u64) -> Result<(), ErrorDetection> {
        let guard = AccountGuard::new();

        let mut new_inner = InnerTree::empty();

        for idx in 0..=height {
            let block = self.db_manager.get_block_by_index(idx)?.ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: format!("Canonical replay missing block at height {}", idx),
                    tx_id: None,
                }
            })?;

            Self::validate_next_block_link(&new_inner, &block)?;

            let previous_hash_for_ctx = new_inner
                .current_tip_hash()
                .unwrap_or(block.metadata.previous_hash);

            Self::remember_recent_block(&mut new_inner, block.clone());

            let maybe_batch_bytes = self.db_manager.get_batch_bytes_by_index(idx)?;

            match maybe_batch_bytes {
                Some(bytes) => {
                    let batch = TransactionBatch::deserialize(&bytes).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: format!(
                                "Failed to deserialize replay batch at height {}: {:?}",
                                idx, e
                            ),
                        }
                    })?;

                    if batch.index != idx {
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Replay batch index {} does not match block height {}",
                                batch.index, idx
                            ),
                            tx_id: None,
                        });
                    }

                    let ctx = ApplyContext {
                        mode: ApplyMode::Replay,
                        block_height: idx,
                        block_hash: block.block_hash,
                        previous_hash: previous_hash_for_ctx,
                        allow_duplicate_reward_in_batch: false,
                    };

                    let _outcome = guard.apply_batch_to_state(&mut new_inner, &batch, &ctx)?;

                    let signer_wallet = block.miner_wallet().to_string();
                    let block_height = block.metadata.index;
                    let block_ts = block.metadata.timestamp;
                    let db_arc = Arc::new(self.db_manager.clone());

                    for kind in &batch.transactions {
                        match kind {
                            TxKind::NftMint(mint) => {
                                debug!(
                                    "Replay saw NftMint at height {} (rebuilding NFT metadata).",
                                    idx
                                );

                                if load_nft_record(&db_arc, &mint.nft_id)?.is_some() {
                                    continue;
                                }

                                apply_nft_mint(
                                    &db_arc,
                                    mint,
                                    &signer_wallet,
                                    block_height,
                                    block_ts,
                                )?;
                            }

                            TxKind::NftTransfer(transfer) => {
                                debug!(
                                    "Replay saw NftTransfer at height {} (rebuilding NFT ownership).",
                                    idx
                                );

                                if let Err(e) = apply_nft_transfer(
                                    &db_arc,
                                    transfer,
                                    &signer_wallet,
                                    block_height,
                                    block_ts,
                                ) {
                                    match &e {
                                        ErrorDetection::ValidationError { message, .. }
                                            if message
                                                .starts_with("NFT transfer denied: signer ") =>
                                        {
                                            debug!(
                                                "Replay skipping invalid NftTransfer at height {}: {}",
                                                idx, message
                                            );
                                        }
                                        _ => return Err(e),
                                    }
                                }
                            }

                            _ => {}
                        }
                    }
                }

                None => {
                    if idx > 0 {
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Canonical replay missing batch bytes at height {}",
                                idx
                            ),
                            tx_id: None,
                        });
                    }

                    Self::verify_compact_state_invariants(
                        &new_inner,
                        Some(idx),
                        Some(block.block_hash),
                        Some(previous_hash_for_ctx),
                    )?;
                }
            }
        }

        let expected_tip_hash = new_inner.current_tip_hash();
        let expected_prev_hash = new_inner.current_prev_tip_hash();

        Self::verify_compact_state_invariants(
            &new_inner,
            Some(height),
            expected_tip_hash,
            expected_prev_hash,
        )?;

        *self.inner.write() = new_inner;
        self.pending_blocks
            .write()
            .retain(|pending_height, _| *pending_height > height);

        Ok(())
    }

    pub fn get_balances(&self) -> HashMap<String, u64> {
        self.inner.read().balances.clone()
    }

    /// Compatibility/debug accessor.
    ///
    /// This no longer returns every canonical block. It returns only the bounded
    /// recent-block cache. Use `get_block_by_index()` for historical reads.
    pub fn get_blocks(&self) -> Vec<Block> {
        self.inner.read().blocks.clone()
    }

    // ─────────────────────────────────────────────────────────────
    // (B) Transaction application
    // ─────────────────────────────────────────────────────────────

    pub fn apply_transaction(&mut self, transaction: &Transaction) -> Result<(), ErrorDetection> {
        let sender = String::from_utf8_lossy(&transaction.sender).to_string();
        let receiver = String::from_utf8_lossy(&transaction.receiver).to_string();

        if transaction.amount == 0 {
            return Err(ErrorDetection::ValidationError {
                message: "Transaction amount must be non-zero".to_string(),
                tx_id: None,
            });
        }

        if sender == receiver {
            return Err(ErrorDetection::ValidationError {
                message: "Sender and receiver cannot be the same".to_string(),
                tx_id: None,
            });
        }

        if transaction.amount > GlobalConfiguration::MAX_TX_AMOUNT {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Transaction amount {} exceeds the allowed maximum {}",
                    transaction.amount,
                    GlobalConfiguration::MAX_TX_AMOUNT
                ),
                tx_id: None,
            });
        }

        let sender_balance = self.get_balance(&sender);
        if sender_balance < transaction.amount {
            return Err(ErrorDetection::ValidationError {
                message: "Insufficient balance".to_string(),
                tx_id: None,
            });
        }

        self.decrement_balance(&sender, transaction.amount)?;
        self.increment_balance(&receiver, transaction.amount)?;
        self.commit()?;

        Ok(())
    }

    pub fn apply_batch(&mut self, batch: &TransactionBatch) -> Result<(), ErrorDetection> {
        let guard = AccountGuard::new();
        let mut next_state = self.inner.read().clone();

        let block_hash: Hash = next_state.current_tip_hash().unwrap_or_else(zero_hash);
        let previous_hash: Hash = next_state.current_prev_tip_hash().unwrap_or_else(zero_hash);

        let ctx = ApplyContext {
            mode: ApplyMode::Live,
            block_height: batch.index,
            block_hash,
            previous_hash,
            allow_duplicate_reward_in_batch: false,
        };

        if next_state.has_tip && block_hash != zero_hash() {
            let _outcome = guard.apply_batch_to_state(&mut next_state, batch, &ctx)?;
        } else {
            guard.validate_batch_structure(batch)?;

            if batch.index != ctx.block_height {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Batch index {} does not match context block height {}",
                        batch.index, ctx.block_height
                    ),
                    tx_id: None,
                });
            }

            let mut touched_accounts = BTreeSet::new();

            for kind in &batch.transactions {
                guard.apply_txkind_to_state(&mut next_state, kind, &ctx, &mut touched_accounts)?;
            }

            guard.verify_state_invariants(&next_state, None, None, None)?;
        }

        *self.inner.write() = next_state;

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // (C) Balance helpers
    // ─────────────────────────────────────────────────────────────

    pub fn get_balance(&self, acct: &str) -> u64 {
        *self.inner.read().balances.get(acct).unwrap_or(&0)
    }

    pub fn set_balance(&mut self, acct: &str, bal: u64) {
        self.inner.write().balances.insert(acct.into(), bal);
    }

    pub fn increment_balance(&mut self, acct: &str, amt: u64) -> Result<(), ErrorDetection> {
        let mut g = self.inner.write();

        let current_balance = g.balances.get(acct).copied().unwrap_or(0);

        let new_balance =
            current_balance
                .checked_add(amt)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("Overflow on {acct} when adding {amt}"),
                    tx_id: None,
                })?;

        if new_balance > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!("Account {} would exceed total supply limit", acct),
                tx_id: None,
            });
        }

        g.balances.insert(acct.into(), new_balance);
        Ok(())
    }

    pub fn decrement_balance(&mut self, acct: &str, amt: u64) -> Result<(), ErrorDetection> {
        let mut g = self.inner.write();
        let entry = g
            .balances
            .get_mut(acct)
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!("Account {acct} not found"),
            })?;
        *entry = entry
            .checked_sub(amt)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("Underflow on {acct}: need {amt}"),
                tx_id: None,
            })?;
        Ok(())
    }

    pub fn update_balance(&mut self, acct: &str, amt: u64) -> Result<(), ErrorDetection> {
        let mut g = self.inner.write();
        let entry = g.balances.entry(acct.into()).or_insert(0);

        let new_balance =
            entry
                .checked_add(amt)
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: format!("Overflow on account {} when adding {}", acct, amt),
                    tx_id: None,
                })?;

        if new_balance > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!("Account {} would exceed total supply limit", acct),
                tx_id: None,
            });
        }

        *entry = new_balance;

        Ok(())
    }

    pub fn get_balance_decimal(&self, acct: &str) -> f64 {
        crate::utility::helper::from_micro_units(self.get_balance(acct))
    }

    // ─────────────────────────────────────────────────────────────
    // (D) Persistence
    // ─────────────────────────────────────────────────────────────

    pub fn commit(&self) -> Result<(), ErrorDetection> {
        let inner = self.inner.read();
        self.commit_inner_state(&inner)
    }

    fn commit_inner_state(&self, inner: &InnerTree) -> Result<(), ErrorDetection> {
        Self::verify_compact_state_invariants(inner, None, None, None)?;

        let snapshot = Self::snapshot_from_inner(inner);
        let bytes = to_allocvec(&snapshot).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        if bytes.len() > MAX_ACCOUNT_STATE_SNAPSHOT_BYTES {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Refusing to write oversized account STATE_KEY snapshot: {} bytes > {} bytes. \
                     This prevents accidental reintroduction of unbounded serialized state.",
                    bytes.len(),
                    MAX_ACCOUNT_STATE_SNAPSHOT_BYTES
                ),
            });
        }

        self.db_manager
            .write(GlobalConfiguration::STATE_COLUMN_NAME, STATE_KEY, &bytes)
            .map_err(|e| ErrorDetection::StorageError {
                message: e.to_string(),
            })
    }

    fn backfill_total_issued_if_missing(inner: &mut InnerTree) -> Result<(), ErrorDetection> {
        if inner.total_issued_micro == 0 && !inner.balances.is_empty() {
            let total_supply: u64 = inner
                .balances
                .values()
                .copied()
                .try_fold(0u64, |acc, v| acc.checked_add(v))
                .ok_or_else(|| ErrorDetection::ValidationError {
                    message: "Overflow while backfilling total_issued_micro".into(),
                    tx_id: None,
                })?;

            inner.total_issued_micro = total_supply;
        }

        if inner.rewards_issued_micro == 0 && inner.total_issued_micro > 0 {
            inner.rewards_issued_micro = inner.total_issued_micro;
        }

        Ok(())
    }

    pub fn load_state(db: RockDBManager) -> Result<Self, ErrorDetection> {
        let bytes = db
            .read(GlobalConfiguration::STATE_COLUMN_NAME, STATE_KEY)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: "Account state".into(),
            })?;

        let inner = Self::decode_inner_state_strict(&bytes)?;

        let tree = Self {
            inner: Arc::new(RwLock::new(inner)),
            db_manager: db,
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
        };

        // Always rewrite as compact v2 snapshot. If the input was already v2,
        // this is idempotent. If it was legacy, this removes serialized blocks
        // from STATE_KEY immediately.
        tree.commit()?;

        Ok(tree)
    }

    // ─────────────────────────────────────────────────────────────
    // (E) Flush Balance helpers
    // ─────────────────────────────────────────────────────────────

    pub fn flush_balances(&self) -> Result<(), ErrorDetection> {
        let g = self.inner.read();
        g.balances
            .iter()
            .try_for_each(|(addr, bal)| -> Result<(), ErrorDetection> {
                self.db_manager.write(
                    GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                    addr.as_bytes(),
                    &postcard::to_allocvec(bal).map_err(|e| {
                        ErrorDetection::SerializationError {
                            details: e.to_string(),
                        }
                    })?,
                )?;
                Ok(())
            })?;
        Ok(())
    }

    pub fn flush_balances_for_batch(&self, batch: &TransactionBatch) -> Result<(), String> {
        use std::collections::HashSet;

        let mut addrs: HashSet<String> = HashSet::new();
        for kind in &batch.transactions {
            for addr in kind.touched_addresses() {
                addrs.insert(addr);
            }
        }
        self.flush_addresses(addrs)
    }

    pub fn flush_addresses<I>(&self, addrs: I) -> Result<(), String>
    where
        I: IntoIterator<Item = String>,
    {
        for addr in addrs {
            let bal_u64 = self.get_balance(&addr);

            self.db_manager
                .write(
                    GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                    addr.as_bytes(),
                    &postcard::to_allocvec(&bal_u64)
                        .map_err(|e| format!("serialize balance for {addr}: {e}"))?,
                )
                .map_err(|e| format!("write ACCOUNT for {addr}: {e:?}"))?;
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // (F) Manual (de)serialization helpers
    // ─────────────────────────────────────────────────────────────

    pub fn serialize_state(&self) -> Result<Vec<u8>, ErrorDetection> {
        let inner = self.inner.read();
        Self::verify_compact_state_invariants(&inner, None, None, None)?;

        let snapshot = Self::snapshot_from_inner(&inner);
        let bytes = to_allocvec(&snapshot).map_err(|e| ErrorDetection::SerializationError {
            details: e.to_string(),
        })?;

        if bytes.len() > MAX_ACCOUNT_STATE_SNAPSHOT_BYTES {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Refusing to serialize oversized account state snapshot: {} bytes > {} bytes",
                    bytes.len(),
                    MAX_ACCOUNT_STATE_SNAPSHOT_BYTES
                ),
            });
        }

        Ok(bytes)
    }

    pub fn deserialize_state(data: &[u8], db: RockDBManager) -> Result<Self, ErrorDetection> {
        let inner = Self::decode_inner_state_strict(data)?;

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            db_manager: db,
            pending_blocks: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    // ─────────────────────────────────────────────────────────────
    // (G) NFT application helper (wiring into apply_block)
    // ─────────────────────────────────────────────────────────────

    fn apply_nft_mints_for_block(
        &self,
        block: &Block,
        batch: &TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        let height = block.metadata.index;
        let ts = block.metadata.timestamp;
        let signer_wallet = block.miner_wallet().to_string();
        let db_arc = Arc::new(self.db_manager.clone());

        for kind in &batch.transactions {
            if let TxKind::NftMint(mint_tx) = kind {
                apply_nft_mint(&db_arc, mint_tx, &signer_wallet, height, ts)?;
            }
        }

        Ok(())
    }

    fn apply_nft_transfers_for_block(
        &self,
        block: &Block,
        batch: &TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        let height = block.metadata.index;
        let ts = block.metadata.timestamp;
        let signer_wallet = block.miner_wallet().to_string();
        let db_arc = Arc::new(self.db_manager.clone());

        for kind in &batch.transactions {
            if let TxKind::NftTransfer(transfer_tx) = kind
                && let Err(e) = apply_nft_transfer(&db_arc, transfer_tx, &signer_wallet, height, ts)
            {
                match &e {
                    ErrorDetection::ValidationError { message, .. }
                        if message.starts_with("NFT transfer denied: signer ") =>
                    {
                        debug!(
                            "Gracefully skipping invalid NftTransfer in live apply at height {}: {}",
                            height, message
                        );
                    }
                    _ => return Err(e),
                }
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // (H) Supply helpers (read-only)
    // ─────────────────────────────────────────────────────────────

    pub fn total_issued_micro(&self) -> u64 {
        self.inner.read().total_issued_micro
    }

    pub fn rewards_issued_micro(&self) -> u64 {
        self.inner.read().rewards_issued_micro
    }

    pub fn remaining_supply_micro(&self) -> u64 {
        GlobalConfiguration::MAX_SUPPLY.saturating_sub(self.inner.read().total_issued_micro)
    }

    pub fn total_issued_aos(&self) -> f64 {
        from_micro_units(self.total_issued_micro())
    }

    pub fn remaining_supply_aos(&self) -> f64 {
        from_micro_units(self.remaining_supply_micro())
    }

    pub fn remaining_reward_supply_micro(&self) -> u64 {
        GlobalConfiguration::MAX_REWARD_SUPPLY.saturating_sub(self.rewards_issued_micro())
    }

    pub fn remaining_reward_supply_aos(&self) -> f64 {
        from_micro_units(self.remaining_reward_supply_micro())
    }

    pub fn rewards_issued_aos(&self) -> f64 {
        from_micro_units(self.rewards_issued_micro())
    }

    pub fn remaining_reward_supply_micro_after_height_scheduled(&self, height: u64) -> u64 {
        let remaining_u128 = RewardHalving::remaining_reward_supply_micro_after_block(height);
        u64::try_from(remaining_u128.min(u64::MAX as u128)).unwrap_or(u64::MAX)
    }

    pub fn remaining_reward_supply_aos_after_height_scheduled(&self, height: u64) -> f64 {
        from_micro_units(self.remaining_reward_supply_micro_after_height_scheduled(height))
    }

    pub fn remaining_reward_supply_micro_scheduled_now(&self) -> u64 {
        let tip_usize = self.latest_block_height();
        let tip_u64: u64 = u64::try_from(tip_usize).unwrap_or(u64::MAX);

        self.remaining_reward_supply_micro_after_height_scheduled(tip_u64)
    }

    pub fn remaining_reward_supply_aos_scheduled_now(&self) -> f64 {
        from_micro_units(self.remaining_reward_supply_micro_scheduled_now())
    }
}

// ─────────────────────────────────────────────────────────────────
// Consolidated in utility::helper
// ─────────────────────────────────────────────────────────────────

pub trait ChainLogic {
    fn rollback_to(&mut self, ancestor: Hash) -> Result<(), String>;
    fn apply_block(&mut self, block: &Block) -> Result<(), String>;
}

impl ChainLogic for AccountModelTree {
    fn rollback_to(&mut self, ancestor: Hash) -> Result<(), String> {
        let current_tip = self.inner.read().tip_height;

        let ancestor_height = if let Some(block) = self
            .inner
            .read()
            .blocks
            .iter()
            .find(|block| block.block_hash == ancestor)
            .cloned()
        {
            Some(block.metadata.index)
        } else {
            let mut found = None;

            for height in (0..=current_tip).rev() {
                let maybe_block = self.db_manager.get_block_by_index(height).map_err(|e| {
                    format!("Failed to read block {height} during rollback: {:?}", e)
                })?;

                if let Some(block) = maybe_block
                    && block.block_hash == ancestor
                {
                    found = Some(height);
                    break;
                }
            }

            found
        };

        let Some(height) = ancestor_height else {
            return Err(format!(
                "Ancestor block hash {} not found for rollback",
                hex::encode(ancestor)
            ));
        };

        self.reload_from_db_to_height(height).map_err(|e| {
            format!(
                "Failed to reload compact state to rollback height {height}: {:?}",
                e
            )
        })?;

        self.pending_blocks
            .write()
            .retain(|pending_height, _| *pending_height > height);

        Ok(())
    }

    fn apply_block(&mut self, block: &Block) -> Result<(), String> {
        let guard = AccountGuard::new();

        // Rollback snapshots for anything that mutates live state/queues later.
        let snapshot_inner = self.inner.read().clone();
        let snapshot_pending = self.pending_blocks.read().clone();

        let out = (|| -> Result<(), String> {
            block
                .validate(None)
                .map_err(|e| format!("Block validation failed: {:?}", e))?;

            {
                let inner = self.inner.read();

                if inner.has_tip
                    && block.metadata.index <= inner.tip_height
                    && guard
                        .check_canonical_idempotency(&inner, block)
                        .map_err(|e| format!("Canonical idempotency check failed: {:?}", e))?
                {
                    debug!(
                        "apply_block: block #{} already canonical or older than tip; skipping re-apply.",
                        block.metadata.index
                    );
                    return Ok(());
                }

                Self::validate_next_block_link(&inner, block)
                    .map_err(|e| format!("Block linkage failed: {:?}", e))?;
            }

            let batch_key = block
                .batch_key
                .as_ref()
                .ok_or_else(|| "Block missing batch_key".to_string())?;

            let batch_bytes = self
                .db_manager
                .read(
                    GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                    batch_key.as_bytes(),
                )
                .map_err(|e| format!("Failed to read batch bytes: {:?}", e))?
                .ok_or_else(|| format!("Batch bytes missing for key: {}", batch_key))?;

            let batch = TransactionBatch::deserialize(&batch_bytes)
                .map_err(|e| format!("Failed to deserialize batch: {:?}", e))?;

            if batch.index != block.metadata.index {
                return Err(format!(
                    "Batch index {} does not match block height {}",
                    batch.index, block.metadata.index
                ));
            }

            // One isolated clone of live state.
            let tentative_state = self.inner.read().clone();

            let (tentative_state, outcome) = guard
                .dry_run_block_and_batch(tentative_state, block, &batch)
                .map_err(|e| format!("Dry-run block+batch failed: {:?}", e))?;

            self.apply_nft_mints_for_block(block, &batch)
                .map_err(|e| format!("Failed to apply NFT mints: {:?}", e))?;

            self.apply_nft_transfers_for_block(block, &batch)
                .map_err(|e| format!("Failed to apply NFT transfers: {:?}", e))?;

            self.commit_inner_state(&tentative_state)
                .map_err(|e| format!("Failed to commit compact next state: {:?}", e))?;

            // Commit the already-verified tentative state into live memory.
            *self.inner.write() = tentative_state;

            self.flush_addresses(outcome.touched_accounts.iter().cloned())
                .map_err(|e| format!("Failed to flush touched balances: {:?}", e))?;

            guard
                .verify_account_cf_matches_state(
                    &self.db_manager,
                    &self.inner.read(),
                    &outcome.touched_accounts,
                )
                .map_err(|e| format!("ACCOUNT CF verification failed: {:?}", e))?;

            if tracing::enabled!(tracing::Level::DEBUG) {
                Self::trace_block_resource_usage(block.metadata.index);
                self.trace_state_resource_usage(block.metadata.index);
            }

            Ok(())
        })();

        if out.is_err() {
            *self.inner.write() = snapshot_inner;
            *self.pending_blocks.write() = snapshot_pending;
        }

        out
    }
}
