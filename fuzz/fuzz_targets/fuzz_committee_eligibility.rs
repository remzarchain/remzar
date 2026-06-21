#![no_main]

use libfuzzer_sys::fuzz_target;

/* ─────────────────────────────────────────────────────────────
   Minimal utility shims needed by por_006_committee_eligibility.rs
   ───────────────────────────────────────────────────────────── */

mod utility {
    pub mod alpha_001_global_configuration {
        pub struct GlobalConfiguration;

        impl GlobalConfiguration {
            pub const MAX_VALIDATORS: usize = 10_000;
        }
    }

    pub mod alpha_002_error_detection_system {
        use core::fmt;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum ErrorDetection {
            ValidationError {
                message: String,
                tx_id: Option<String>,
            },
        }

        impl fmt::Display for ErrorDetection {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ValidationError { message, tx_id } => {
                        write!(f, "ValidationError(message={message}, tx_id={tx_id:?})")
                    }
                }
            }
        }

        impl std::error::Error for ErrorDetection {}
    }

    pub mod helper {
        use crate::utility::alpha_002_error_detection_system::ErrorDetection;

        pub const REMZAR_WALLET_LEN: usize = 129;
        pub const REMZAR_WALLET_BODY_LEN: usize = 128;
        pub const REMZAR_WALLET_PREFIX: u8 = b'r';

        /*
            Minimal canonical wallet checker aligned with helper.rs:

            - trim whitespace
            - accept r or R
            - require 129 chars total
            - require 128 hex chars after prefix
            - return canonical r + lowercase hex
        */
        #[inline]
        pub fn canon_wallet_id_checked(id: &str) -> Result<String, ErrorDetection> {
            let s = id.trim();

            if s.len() != REMZAR_WALLET_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let lower = s.to_ascii_lowercase();
            let b = lower.as_bytes();

            if b.first() != Some(&REMZAR_WALLET_PREFIX) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            let Some(body) = b.get(1..) else {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            };

            if body.len() != REMZAR_WALLET_BODY_LEN {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            if !body.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(ErrorDetection::ValidationError {
                    message: "Wallet address is invalid or incomplete".to_string(),
                    tx_id: None,
                });
            }

            Ok(lower)
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Pull in the real production file.
   Do NOT use include!().
   ───────────────────────────────────────────────────────────── */

#[path = "../../src/consensus/por_006_committee_eligibility.rs"]
pub mod por_006_committee_eligibility;

/* ─────────────────────────────────────────────────────────────
   Imports
   ───────────────────────────────────────────────────────────── */

use crate::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig, CommitteeMemberStatus,
    CommitteeStatusUpdate, IneligibilityReason,
};
use crate::utility::helper::canon_wallet_id_checked;

/* ─────────────────────────────────────────────────────────────
   Main fuzz entry
   ───────────────────────────────────────────────────────────── */

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] % 9;
    let body = &data[1..];

    match mode {
        0 => fuzz_config_validation(body),
        1 => fuzz_status_update_invariants(body),
        2 => fuzz_member_status_invariants(body),
        3 => fuzz_live_wallet_management(body),
        4 => fuzz_status_upsert_and_lookup(body),
        5 => fuzz_solo_rule(body),
        6 => fuzz_multi_node_reasons(body),
        7 => fuzz_candidate_filters(body),
        _ => fuzz_state_machine(body),
    }
});

/* ─────────────────────────────────────────────────────────────
   Fuzz cases
   ───────────────────────────────────────────────────────────── */

fn fuzz_config_validation(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let cfg = make_config(&mut r);
    let result = cfg.validate();

    if cfg.min_connected_wallet_peers > cfg.min_peers_connected {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
    }

    let default_cfg = CommitteeEligibilityConfig::default();
    assert!(default_cfg.validate().is_ok());

    let globals_cfg = CommitteeEligibilityConfig::from_globals();
    assert!(globals_cfg.validate().is_ok());

    let mut eligibility = CommitteeEligibility::new(cfg.clone());
    assert_eq!(eligibility.config(), &cfg);
    let _ = eligibility.validate_config();

    let new_cfg = make_valid_config(&mut r);
    *eligibility.config_mut() = new_cfg.clone();
    assert_eq!(eligibility.config(), &new_cfg);
    assert!(eligibility.validate_config().is_ok());
}

fn fuzz_status_update_invariants(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let update = make_status_update(&mut r);
    let result = update.validate_invariants();

    if update.connected_wallet_peers > update.peers_connected {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
        assert_eq!(update.is_isolated(), update.connected_wallet_peers == 0);
    }
}

fn fuzz_member_status_invariants(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let wallet = make_wallet_or_invalid(&mut r);
    let status = make_member_status_for_wallet(&mut r, wallet.clone());

    let result = status.validate_invariants();

    let wallet_ok = canon_wallet_id_checked(&wallet).is_ok();
    let peers_ok = status.connected_wallet_peers <= status.peers_connected;
    let isolation_ok = !(status.is_isolated && status.connected_wallet_peers > 0);

    if wallet_ok && peers_ok && isolation_ok {
        assert!(result.is_ok());
    }

    assert_eq!(
        status.tip_lag(),
        status.network_tip.saturating_sub(status.local_tip)
    );

    assert_eq!(status.canonical_wallet(), status.wallet.as_str());
}

fn fuzz_live_wallet_management(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let mut eligibility = CommitteeEligibility::new(make_valid_config(&mut r));

    assert!(eligibility.is_empty());
    assert_eq!(eligibility.len(), 0);

    let wallets = make_wallet_list(&mut r, 8);

    let replace_result = eligibility.replace_live_wallets(wallets.clone());

    if replace_result.is_ok() {
        let live = eligibility.live_wallets();

        assert!(live.windows(2).all(|w| w[0] <= w[1]));

        for w in &live {
            assert_eq!(canon_wallet_id_checked(w).ok().as_deref(), Some(w.as_str()));
            assert!(eligibility.is_wallet_live(w));
        }

        for original in wallets {
            if let Ok(can) = canon_wallet_id_checked(&original) {
                assert!(eligibility.is_wallet_live(&can));
            }
        }
    }

    let wallet = make_valid_wallet(&mut r);

    assert!(eligibility.mark_wallet_live(&wallet, true).is_ok());
    assert!(eligibility.is_wallet_live(&wallet));

    assert!(eligibility.mark_wallet_live(&wallet, false).is_ok());
    assert!(!eligibility.is_wallet_live(&wallet));

    eligibility.clear();
    assert!(eligibility.is_empty());
    assert!(eligibility.live_wallets().is_empty());
}

fn fuzz_status_upsert_and_lookup(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let mut eligibility = CommitteeEligibility::new(make_valid_config(&mut r));

    let wallet = make_valid_wallet(&mut r);
    let update = make_valid_status_update(&mut r);

    let result = match r.next_u8() % 3 {
        0 => eligibility.update_local_status(&wallet, update),
        1 => eligibility.update_remote_status(&wallet, update),
        _ => {
            let status = CommitteeMemberStatus {
                wallet: wallet.clone(),
                is_live: update.is_live,
                has_synced: update.has_synced,
                local_tip: update.local_tip,
                network_tip: update.network_tip,
                peers_connected: update.peers_connected,
                connected_wallet_peers: update.connected_wallet_peers,
                is_isolated: update.is_isolated(),
            };

            eligibility.upsert_status(status)
        }
    };

    assert!(result.is_ok());

    let can = canon_wallet_id_checked(&wallet).unwrap();

    assert_eq!(eligibility.is_wallet_live(&wallet), update.is_live);

    let status = eligibility.get_status(&wallet).expect("status should exist");
    assert_eq!(status.wallet, can);
    assert_eq!(status.is_live, update.is_live);
    assert_eq!(status.has_synced, update.has_synced);
    assert_eq!(status.local_tip, update.local_tip);
    assert_eq!(status.network_tip, update.network_tip);
    assert_eq!(status.peers_connected, update.peers_connected);
    assert_eq!(status.connected_wallet_peers, update.connected_wallet_peers);
    assert_eq!(status.is_isolated, update.is_isolated());

    assert_eq!(eligibility.len(), 1);

    let removed = eligibility.remove_wallet(&wallet);
    assert!(removed);
    assert!(eligibility.get_status(&wallet).is_none());
    assert!(!eligibility.is_wallet_live(&wallet));
}

fn fuzz_solo_rule(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let cfg = CommitteeEligibilityConfig {
        max_tip_lag_blocks: 0,
        min_peers_connected: 8,
        min_connected_wallet_peers: 4,
        require_non_isolated: true,
        require_synced: true,
    };

    assert!(cfg.validate().is_ok());

    let mut eligibility = CommitteeEligibility::new(cfg);

    let wallet = make_valid_wallet(&mut r);

    let status = CommitteeMemberStatus {
        wallet: wallet.clone(),
        is_live: true,
        has_synced: true,
        local_tip: 100,
        network_tip: 100,
        peers_connected: 0,
        connected_wallet_peers: 0,
        is_isolated: true,
    };

    assert!(eligibility.upsert_status(status).is_ok());

    let decision = eligibility.decide_wallet(&wallet);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
    assert!(decision.is_runtime_ready());
    assert!(eligibility.is_wallet_eligible(&wallet));
    assert!(eligibility.is_wallet_runtime_ready(&wallet));
}

fn fuzz_multi_node_reasons(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let cfg = CommitteeEligibilityConfig {
        max_tip_lag_blocks: 2,
        min_peers_connected: 2,
        min_connected_wallet_peers: 1,
        require_non_isolated: true,
        require_synced: true,
    };

    assert!(cfg.validate().is_ok());

    let mut eligibility = CommitteeEligibility::new(cfg);

    let wallet_a = make_valid_wallet(&mut r);
    let wallet_b = make_different_valid_wallet(&wallet_a);

    let status_a = CommitteeMemberStatus {
        wallet: wallet_a.clone(),
        is_live: true,
        has_synced: false,
        local_tip: 10,
        network_tip: 100,
        peers_connected: 0,
        connected_wallet_peers: 0,
        is_isolated: true,
    };

    let status_b = CommitteeMemberStatus {
        wallet: wallet_b.clone(),
        is_live: true,
        has_synced: true,
        local_tip: 100,
        network_tip: 100,
        peers_connected: 2,
        connected_wallet_peers: 1,
        is_isolated: false,
    };

    assert!(eligibility.upsert_status(status_a).is_ok());
    assert!(eligibility.upsert_status(status_b).is_ok());

    let decision = eligibility.decide_wallet(&wallet_a);

    assert!(!decision.eligible);
    assert!(!decision.reasons.is_empty());

    assert!(
        decision
            .reasons
            .iter()
            .any(|r| matches!(r, IneligibilityReason::NotSynced))
    );

    assert!(
        decision
            .reasons
            .iter()
            .any(|r| matches!(r, IneligibilityReason::TooFarBehind { .. }))
    );

    assert!(
        decision
            .reasons
            .iter()
            .any(|r| matches!(r, IneligibilityReason::NotEnoughPeers { .. }))
    );

    assert!(
        decision
            .reasons
            .iter()
            .any(|r| matches!(r, IneligibilityReason::NotEnoughWalletPeers { .. }))
    );

    assert!(
        decision
            .reasons
            .iter()
            .any(|r| matches!(r, IneligibilityReason::Isolated))
    );

    let decision_b = eligibility.decide_wallet(&wallet_b);
    assert!(decision_b.eligible);
    assert!(decision_b.reasons.is_empty());
}

fn fuzz_candidate_filters(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let mut eligibility = CommitteeEligibility::new(make_valid_config(&mut r));

    let live_count = 1 + r.next_usize(8);
    let mut live_wallets = Vec::with_capacity(live_count);

    for _ in 0..live_count {
        let w = make_valid_wallet(&mut r);
        assert!(eligibility.mark_wallet_live(&w, true).is_ok());
        live_wallets.push(w);
    }

    let mut candidates = live_wallets.clone();

    for _ in 0..r.next_usize(8) {
        candidates.push(make_wallet_or_invalid(&mut r));
    }

    let kept = eligibility.filter_candidates(candidates.clone());
    let (kept2, decisions) = eligibility.filter_candidates_with_decisions(candidates.clone());

    assert_eq!(kept, kept2);
    assert_eq!(decisions.len(), candidates.len());

    for (candidate, decision) in candidates.iter().zip(decisions.iter()) {
        assert_eq!(decision.eligible, eligibility.is_wallet_eligible(candidate));

        if decision.eligible {
            assert!(kept.contains(candidate));
        }
    }

    let all = eligibility.all_runtime_decisions();

    for d in all {
        assert!(canon_wallet_id_checked(&d.wallet).is_ok());
    }
}

fn fuzz_state_machine(data: &[u8]) {
    let mut r = FuzzBytes::new(data);

    let mut eligibility = CommitteeEligibility::new(make_config(&mut r));

    let steps = 1 + r.next_usize(64);

    for _ in 0..steps {
        match r.next_u8() % 11 {
            0 => {
                let wallets = make_wallet_list(&mut r, 8);
                let _ = eligibility.replace_live_wallets(wallets);
            }
            1 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let is_live = r.next_bool();
                let _ = eligibility.mark_wallet_live(&wallet, is_live);
            }
            2 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let update = make_status_update(&mut r);
                let _ = eligibility.update_local_status(&wallet, update);
            }
            3 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let update = make_status_update(&mut r);
                let _ = eligibility.update_remote_status(&wallet, update);
            }
            4 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let status = make_member_status_for_wallet(&mut r, wallet);
                let _ = eligibility.upsert_status(status);
            }
            5 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let d = eligibility.decide_wallet(&wallet);
                assert_eq!(d.eligible, d.is_runtime_ready());
                assert_eq!(d.eligible, eligibility.is_wallet_eligible(&wallet));
                assert_eq!(d.eligible, eligibility.is_wallet_runtime_ready(&wallet));
            }
            6 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let _ = eligibility.get_status(&wallet);
                let _ = eligibility.is_wallet_live(&wallet);
            }
            7 => {
                let wallet = make_wallet_or_invalid(&mut r);
                let _ = eligibility.remove_wallet(&wallet);
            }
            8 => {
                let candidates = make_wallet_list(&mut r, 12);
                let kept = eligibility.filter_candidates(candidates.clone());
                let (kept2, decisions) = eligibility.filter_candidates_with_decisions(candidates);
                assert_eq!(kept, kept2);
                assert_eq!(kept.len(), decisions.iter().filter(|d| d.eligible).count());
            }
            9 => {
                let decisions = eligibility.all_runtime_decisions();
                assert!(decisions.windows(2).all(|w| w[0].wallet <= w[1].wallet));
            }
            _ => {
                eligibility.clear();
                assert!(eligibility.is_empty());
                assert_eq!(eligibility.len(), 0);
                assert!(eligibility.live_wallets().is_empty());
            }
        }

        let live = eligibility.live_wallets();
        assert!(live.windows(2).all(|w| w[0] <= w[1]));

        for w in live {
            assert!(canon_wallet_id_checked(&w).is_ok());
        }
    }
}

/* ─────────────────────────────────────────────────────────────
   Construction helpers
   ───────────────────────────────────────────────────────────── */

fn make_config(r: &mut FuzzBytes<'_>) -> CommitteeEligibilityConfig {
    let min_peers_connected = match r.next_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 8,
        4 => 64,
        _ => r.next_usize(32),
    };

    let min_connected_wallet_peers = match r.next_u8() % 8 {
        0 => 0,
        1 => 1,
        2 => min_peers_connected,
        3 => min_peers_connected.saturating_add(1),
        4 => 64,
        _ => r.next_usize(32),
    };

    CommitteeEligibilityConfig {
        max_tip_lag_blocks: match r.next_u8() % 8 {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 10,
            4 => u64::MAX,
            _ => r.next_u64(),
        },
        min_peers_connected,
        min_connected_wallet_peers,
        require_non_isolated: r.next_bool(),
        require_synced: r.next_bool(),
    }
}

fn make_valid_config(r: &mut FuzzBytes<'_>) -> CommitteeEligibilityConfig {
    let min_peers_connected = r.next_usize(8);
    let min_connected_wallet_peers = r.next_usize(min_peers_connected.saturating_add(1));

    let cfg = CommitteeEligibilityConfig {
        max_tip_lag_blocks: r.next_u64() % 16,
        min_peers_connected,
        min_connected_wallet_peers,
        require_non_isolated: r.next_bool(),
        require_synced: r.next_bool(),
    };

    assert!(cfg.validate().is_ok());
    cfg
}

fn make_status_update(r: &mut FuzzBytes<'_>) -> CommitteeStatusUpdate {
    let peers_connected = r.next_usize(16);

    let connected_wallet_peers = match r.next_u8() % 5 {
        0 => 0,
        1 => peers_connected,
        2 => peers_connected.saturating_add(1),
        3 => r.next_usize(16),
        _ => usize::MAX,
    };

    CommitteeStatusUpdate {
        is_live: r.next_bool(),
        has_synced: r.next_bool(),
        local_tip: r.next_u64(),
        network_tip: r.next_u64(),
        peers_connected,
        connected_wallet_peers,
    }
}

fn make_valid_status_update(r: &mut FuzzBytes<'_>) -> CommitteeStatusUpdate {
    let peers_connected = r.next_usize(16);
    let connected_wallet_peers = r.next_usize(peers_connected.saturating_add(1));

    let update = CommitteeStatusUpdate {
        is_live: r.next_bool(),
        has_synced: r.next_bool(),
        local_tip: r.next_u64() % 1_000_000,
        network_tip: r.next_u64() % 1_000_000,
        peers_connected,
        connected_wallet_peers,
    };

    assert!(update.validate_invariants().is_ok());
    update
}

fn make_member_status_for_wallet(r: &mut FuzzBytes<'_>, wallet: String) -> CommitteeMemberStatus {
    let peers_connected = r.next_usize(16);

    let connected_wallet_peers = match r.next_u8() % 5 {
        0 => 0,
        1 => peers_connected,
        2 => peers_connected.saturating_add(1),
        3 => r.next_usize(16),
        _ => usize::MAX,
    };

    let is_isolated = match r.next_u8() % 3 {
        0 => connected_wallet_peers == 0,
        1 => true,
        _ => false,
    };

    CommitteeMemberStatus {
        wallet,
        is_live: r.next_bool(),
        has_synced: r.next_bool(),
        local_tip: r.next_u64(),
        network_tip: r.next_u64(),
        peers_connected,
        connected_wallet_peers,
        is_isolated,
    }
}

fn make_wallet_list(r: &mut FuzzBytes<'_>, max_len: usize) -> Vec<String> {
    let count = r.next_usize(max_len.saturating_add(1));
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        out.push(make_wallet_or_invalid(r));
    }

    out
}

fn make_wallet_or_invalid(r: &mut FuzzBytes<'_>) -> String {
    match r.next_u8() % 9 {
        0 => make_valid_wallet(r),
        1 => make_uppercase_wallet(r),
        2 => String::new(),
        3 => make_fuzzy_string(r, 256),
        4 => {
            let mut s = make_valid_wallet(r);
            s.push('x');
            s
        }
        5 => {
            let mut s = make_valid_wallet(r);
            s.replace_range(1..2, "z");
            s
        }
        6 => format!(" {} ", make_valid_wallet(r)),
        7 => "r".repeat(300),
        _ => "not-a-wallet".to_string(),
    }
}

fn make_valid_wallet(r: &mut FuzzBytes<'_>) -> String {
    let mut s = String::with_capacity(129);
    s.push('r');

    for _ in 0..128 {
        let n = r.next_u8() % 16;
        let c = match n {
            0..=9 => char::from(b'0' + n),
            _ => char::from(b'a' + (n - 10)),
        };
        s.push(c);
    }

    s
}

fn make_uppercase_wallet(r: &mut FuzzBytes<'_>) -> String {
    let s = make_valid_wallet(r);

    match r.next_u8() % 3 {
        0 => s.to_ascii_uppercase(),
        1 => {
            let mut out = s;
            out.replace_range(0..1, "R");
            out
        }
        _ => {
            let mut out = s;
            if out.len() == 129 {
                out.replace_range(1..2, "A");
            }
            out
        }
    }
}

fn make_different_valid_wallet(existing: &str) -> String {
    if existing.len() != 129 {
        return format!("r{}", "2".repeat(128));
    }

    let mut s = existing.to_string();
    let last = s.pop().unwrap_or('0');

    let replacement = match last {
        '0' => '1',
        '1' => '2',
        '2' => '3',
        '3' => '4',
        '4' => '5',
        '5' => '6',
        '6' => '7',
        '7' => '8',
        '8' => '9',
        '9' => 'a',
        'a' => 'b',
        'b' => 'c',
        'c' => 'd',
        'd' => 'e',
        'e' => 'f',
        _ => '0',
    };

    s.push(replacement);
    s
}

fn make_fuzzy_string(r: &mut FuzzBytes<'_>, max_chars: usize) -> String {
    let len = r.next_usize(max_chars.saturating_add(1));

    let mut s = String::new();

    for _ in 0..len {
        let b = r.next_u8();

        match b % 10 {
            0 => s.push(char::from(b'a' + (b % 26))),
            1 => s.push(char::from(b'A' + (b % 26))),
            2 => s.push(char::from(b'0' + (b % 10))),
            3 => s.push('r'),
            4 => s.push('R'),
            5 => s.push('_'),
            6 => s.push('-'),
            7 => s.push('é'),
            8 => s.push('雪'),
            _ => s.push('🚀'),
        }
    }

    s
}

/* ─────────────────────────────────────────────────────────────
   Deterministic byte reader
   ───────────────────────────────────────────────────────────── */

struct FuzzBytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FuzzBytes<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }

        let b = self.data[self.pos % self.data.len()];
        self.pos = self.pos.wrapping_add(1);
        b
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];

        for b in &mut out {
            *b = self.next_u8();
        }

        u64::from_le_bytes(out)
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive == 0 {
            return 0;
        }

        (self.next_u64() as usize) % max_exclusive
    }
}