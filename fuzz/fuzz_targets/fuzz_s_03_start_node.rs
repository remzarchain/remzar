// fuzz/fuzz_targets/fuzz_s_03_start_node.rs

#![no_main]

use libfuzzer_sys::fuzz_target;

use libp2p::{
    identity,
    multiaddr::Protocol,
    Multiaddr,
    PeerId,
};

use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet};

const MAX_ATTEMPTS_MODEL: usize = 8;
const MAX_INPUT_BYTES_MODEL: usize = 4096;
const MAX_GENESIS_JSON_BYTES_MODEL: u64 = 4 * 1024 * 1024;
const MAX_BOOTSTRAP_LINES_MODEL: usize = 256;
const MAX_PEERBOOK_PEERS_MODEL: usize = 64;
const MAX_ADDRS_PER_PEER_MODEL: usize = 8;
const MAX_STARTUP_DIALS_MODEL: usize = 256;
const MAX_MODEL_OPS: usize = 512;
const MAX_WIRE_BYTES: usize = 2048;
const REMZAR_WALLET_LEN: usize = 129;
const REMZAR_WALLET_HEX_LEN: usize = 128;
const FOUNDER_KEY_HEX_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum StartupOp {
    AlreadyRunningGuard,
    FounderStartGate,
    FounderKeyCheck,
    YesNoPrompt,
    GenesisMetadata,
    GenesisStartDecision,
    WalletCanonicalize,
    WalletBinding,
    WalletProof,
    ListenAddress,
    BootstrapInputCollection,
    BootstrapLine,
    BootstrapBatch,
    PeerbookExpansion,
    ColdReboot,
    MiningIntent,
    DialSummary,
    TcpEndpoint,
    WireRoundtrip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireStartScenario {
    op: StartupOp,
    is_founder: bool,
    founder_authenticated: bool,
    chain_already_exists: bool,
    force: bool,
    bootstrap_count: u16,
    online_count: u16,
    accepted_dials: u16,
    failed_dials: u16,
    p2p_running: bool,
    needs_genesis: bool,
    genesis_exists: bool,
    identity_registered: bool,
    founder_bc_start_yes: bool,
    input: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YesNo {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FounderStartGate {
    Continue {
        is_founder: bool,
        founder_authenticated: bool,
    },
    ReturnToMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenesisStartDecision {
    ResumeExistingChain,
    FounderInitializesGenesis,
    FounderMissingGenesisFile,
    NonFounderSyncOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletProofDecision {
    ObserverMode,
    AcceptedAndCached,
    RejectInvalidWallet,
    RejectWalletFileMissing,
    RejectWalletReadFailed,
    RejectDecryptFailed,
    RejectSecretLengthMismatch,
    RejectPubkeyMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiningIntentDecision {
    FounderMining,
    FounderObserver,
    NonFounderMining,
    NonFounderObserver,
    BlockedNonFounderColdReboot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingDecision {
    Observer,
    FounderBypass,
    WriteNewBinding,
    AcceptExistingBinding,
    RejectInvalidWallet,
    RejectInvalidExistingBinding,
    RejectMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapReject {
    InvalidMultiaddr,
    MissingPeerId,
    SelfPeer,
}

#[derive(Debug, Clone)]
struct BootstrapOutcome {
    accepted: Vec<(PeerId, Multiaddr)>,
    rejected_invalid: usize,
    rejected_missing_peer: usize,
    rejected_self: usize,
    duplicate_peer_suppressed: usize,
}

impl BootstrapOutcome {
    fn total_rejected(&self) -> usize {
        self.rejected_invalid
            .saturating_add(self.rejected_missing_peer)
            .saturating_add(self.rejected_self)
            .saturating_add(self.duplicate_peer_suppressed)
    }
}

#[derive(Debug, Clone)]
struct BootstrapInputOutcome {
    accepted: Vec<(PeerId, Multiaddr)>,
    rejected_invalid: usize,
    rejected_missing_peer: usize,
    duplicate_peer_suppressed: usize,
}

impl BootstrapInputOutcome {
    fn total_rejected(&self) -> usize {
        self.rejected_invalid
            .saturating_add(self.rejected_missing_peer)
            .saturating_add(self.duplicate_peer_suppressed)
    }
}

#[derive(Debug)]
struct StartNodeHarness {
    local_peer: PeerId,
    peers: Vec<PeerId>,
    peerbook: HashMap<PeerId, HashSet<Multiaddr>>,
    seed_peers: HashSet<PeerId>,
}

impl StartNodeHarness {
    fn new() -> Self {
        let local_peer = fresh_peer_id();
        let peers = (0..128).map(|_| fresh_peer_id()).collect();

        Self {
            local_peer,
            peers,
            peerbook: HashMap::new(),
            seed_peers: HashSet::new(),
        }
    }

    fn peer(&self, slot: u8) -> PeerId {
        let idx = usize::from(slot) % self.peers.len();
        self.peers[idx]
    }

    fn upsert_seed(&mut self, peer: PeerId, addr: Multiaddr) {
        self.peerbook.entry(peer).or_default().insert(addr);
        self.seed_peers.insert(peer);
    }

    fn upsert_plain(&mut self, peer: PeerId, addr: Multiaddr) {
        self.peerbook.entry(peer).or_default().insert(addr);
    }

    fn top_n(&self, n: usize) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peerbook
            .iter()
            .take(n)
            .map(|(pid, set)| (*pid, set.iter().cloned().take(MAX_ADDRS_PER_PEER_MODEL).collect()))
            .collect()
    }

    fn assert_invariants(&self) {
        assert!(!self.peers.is_empty());
        assert!(self.peerbook.len() <= MAX_BOOTSTRAP_LINES_MODEL.saturating_add(MAX_PEERBOOK_PEERS_MODEL));

        for peer in self.peerbook.keys() {
            assert_ne!(*peer, self.local_peer, "self peer must never be stored as a startup seed");
        }

        for peer in &self.seed_peers {
            assert!(self.peerbook.contains_key(peer));
            assert_ne!(*peer, self.local_peer);
        }

        for addrs in self.peerbook.values() {
            for addr in addrs {
                assert!(extract_trailing_peer(addr).is_some());
            }
        }
    }
}

#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take_u8(&mut self) -> u8 {
        if self.pos >= self.data.len() {
            return 0;
        }

        let b = self.data[self.pos];
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }

    fn take_u16(&mut self) -> u16 {
        let mut out = [0u8; 2];
        self.fill(&mut out);
        u16::from_le_bytes(out)
    }

    fn take_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill(&mut out);
        u32::from_le_bytes(out)
    }

    fn take_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill(&mut out);
        u64::from_le_bytes(out)
    }

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }

        usize::try_from(self.take_u64()).unwrap_or(0) % max
    }

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let bytes = self.take_vec(max_len);
        bytes
            .into_iter()
            .map(|b| {
                let c = b % 96 + 32;
                char::from(c)
            })
            .collect()
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }
}

fn fresh_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn is_ascii_hex_byte(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_hex_text(s: &str) -> bool {
    s.as_bytes().iter().copied().all(is_ascii_hex_byte)
}

fn valid_founder_key_model(s: &str) -> bool {
    s.len() == FOUNDER_KEY_HEX_LEN && is_hex_text(s)
}

fn canon_wallet_model(s: &str) -> Option<String> {
    let trimmed = s.trim();

    if trimmed.len() != REMZAR_WALLET_LEN {
        return None;
    }

    let mut chars = trimmed.chars();
    let prefix = chars.next()?;
    if prefix != 'r' && prefix != 'R' {
        return None;
    }

    let rest = chars.as_str();
    if rest.len() != REMZAR_WALLET_HEX_LEN || !is_hex_text(rest) {
        return None;
    }

    Some(format!("r{}", rest.to_ascii_lowercase()))
}

fn parse_yes_no_model(s: &str) -> Option<YesNo> {
    match s.trim().to_ascii_lowercase().as_str() {
        "yes" => Some(YesNo::Yes),
        "no" => Some(YesNo::No),
        _ => None,
    }
}

fn read_line_capped_model(line: &str, cap: usize) -> Result<&str, &'static str> {
    if line.len() > cap {
        Err("input too long")
    } else {
        Ok(line)
    }
}

fn genesis_metadata_allowed_model(is_file: bool, len: u64) -> bool {
    is_file && len > 0 && len <= MAX_GENESIS_JSON_BYTES_MODEL
}

fn p2p_start_guard_returns_early_model(p2p_running: bool) -> bool {
    // Real start_node returns Ok immediately when the node is already running.
    p2p_running
}

fn founder_start_gate_model(prompt: &str, founder_key_contents: Option<&str>) -> FounderStartGate {
    match prompt.trim().to_ascii_lowercase().as_str() {
        "no" => FounderStartGate::Continue {
            is_founder: false,
            founder_authenticated: false,
        },
        "yes" => match founder_key_contents {
            Some(key) if valid_founder_key_model(key.trim()) => FounderStartGate::Continue {
                is_founder: true,
                founder_authenticated: true,
            },
            _ => FounderStartGate::ReturnToMenu,
        },
        _ => FounderStartGate::ReturnToMenu,
    }
}

fn genesis_start_decision_model(
    needs_genesis: bool,
    is_founder: bool,
    founder_authenticated: bool,
    genesis_file_exists: bool,
) -> GenesisStartDecision {
    if !needs_genesis {
        return GenesisStartDecision::ResumeExistingChain;
    }

    if is_founder && founder_authenticated {
        if genesis_file_exists {
            GenesisStartDecision::FounderInitializesGenesis
        } else {
            GenesisStartDecision::FounderMissingGenesisFile
        }
    } else {
        GenesisStartDecision::NonFounderSyncOnly
    }
}

fn cold_reboot_allowed_model(
    chain_already_exists: bool,
    is_founder: bool,
    founder_authenticated: bool,
    bootstrap_count: usize,
    any_bootstrap_online: bool,
) -> bool {
    if chain_already_exists && !is_founder && !founder_authenticated {
        return bootstrap_count > 0 && any_bootstrap_online;
    }

    true
}

fn wallet_binding_decision_model(
    local_wallet: &str,
    is_founder: bool,
    founder_authenticated: bool,
    existing_binding: Option<&str>,
) -> BindingDecision {
    if local_wallet.trim().is_empty() {
        return BindingDecision::Observer;
    }

    if is_founder && founder_authenticated {
        return BindingDecision::FounderBypass;
    }

    let Some(wallet_canon) = canon_wallet_model(local_wallet) else {
        return BindingDecision::RejectInvalidWallet;
    };

    match existing_binding {
        None => BindingDecision::WriteNewBinding,
        Some(existing) => {
            let Some(existing_canon) = canon_wallet_model(existing) else {
                return BindingDecision::RejectInvalidExistingBinding;
            };

            if existing_canon == wallet_canon {
                BindingDecision::AcceptExistingBinding
            } else {
                BindingDecision::RejectMismatch
            }
        }
    }
}

fn wallet_proof_decision_model(
    wallet_addr: &str,
    wallet_file_exists: bool,
    wallet_read_ok: bool,
    decrypt_ok: bool,
    secret_len_ok: bool,
    pubkey_matches_wallet: bool,
) -> WalletProofDecision {
    if wallet_addr.trim().is_empty() {
        return WalletProofDecision::ObserverMode;
    }

    if canon_wallet_model(wallet_addr).is_none() {
        return WalletProofDecision::RejectInvalidWallet;
    }

    if !wallet_file_exists {
        return WalletProofDecision::RejectWalletFileMissing;
    }

    if !wallet_read_ok {
        return WalletProofDecision::RejectWalletReadFailed;
    }

    if !decrypt_ok {
        return WalletProofDecision::RejectDecryptFailed;
    }

    if !secret_len_ok {
        return WalletProofDecision::RejectSecretLengthMismatch;
    }

    if !pubkey_matches_wallet {
        return WalletProofDecision::RejectPubkeyMismatch;
    }

    WalletProofDecision::AcceptedAndCached
}

fn mining_intent_decision_model(
    chain_already_exists: bool,
    is_founder: bool,
    founder_authenticated: bool,
    non_founder_bootstrap_verified_online: bool,
    identity_registered: bool,
    founder_bc_start_yes: bool,
    local_wallet: &str,
) -> MiningIntentDecision {
    let non_founder_existing_chain_without_verified_bootnode = chain_already_exists
        && !is_founder
        && !founder_authenticated
        && !non_founder_bootstrap_verified_online;

    if non_founder_existing_chain_without_verified_bootnode {
        return MiningIntentDecision::BlockedNonFounderColdReboot;
    }

    if is_founder {
        if identity_registered && founder_bc_start_yes && !local_wallet.trim().is_empty() {
            MiningIntentDecision::FounderMining
        } else {
            MiningIntentDecision::FounderObserver
        }
    } else if identity_registered && !local_wallet.trim().is_empty() {
        MiningIntentDecision::NonFounderMining
    } else {
        MiningIntentDecision::NonFounderObserver
    }
}

fn build_listen_addr_model(ip: &str, port: &str) -> String {
    let ip = if ip.trim().is_empty() { "0.0.0.0" } else { ip.trim() };
    let port = if port.trim().is_empty() { "36213" } else { port.trim() };

    format!("/ip4/{ip}/tcp/{port}")
}

fn listen_addr_parses_model(ip: &str, port: &str) -> bool {
    build_listen_addr_model(ip, port).parse::<Multiaddr>().is_ok()
}

fn extract_trailing_peer(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(Protocol::P2p(pid)) => Some(pid),
        _ => None,
    }
}

fn process_operator_bootstrap_input_model(lines: &[String]) -> BootstrapInputOutcome {
    let mut seen_peer_ids = HashSet::<PeerId>::new();
    let mut out = BootstrapInputOutcome {
        accepted: Vec::new(),
        rejected_invalid: 0,
        rejected_missing_peer: 0,
        duplicate_peer_suppressed: 0,
    };

    for s in lines.iter().take(MAX_BOOTSTRAP_LINES_MODEL) {
        match s.parse::<Multiaddr>() {
            Ok(addr) => {
                let Some(pid) = extract_trailing_peer(&addr) else {
                    out.rejected_missing_peer = out.rejected_missing_peer.saturating_add(1);
                    continue;
                };

                if !seen_peer_ids.insert(pid) {
                    out.duplicate_peer_suppressed = out.duplicate_peer_suppressed.saturating_add(1);
                    continue;
                }

                out.accepted.push((pid, addr));
            }
            Err(_) => {
                out.rejected_invalid = out.rejected_invalid.saturating_add(1);
            }
        }
    }

    out
}

fn validate_bootstrap_addr_model(
    s: &str,
    local_peer: PeerId,
) -> Result<(PeerId, Multiaddr), BootstrapReject> {
    let addr = s.parse::<Multiaddr>().map_err(|_| BootstrapReject::InvalidMultiaddr)?;
    let pid = extract_trailing_peer(&addr).ok_or(BootstrapReject::MissingPeerId)?;

    if pid == local_peer {
        return Err(BootstrapReject::SelfPeer);
    }

    Ok((pid, addr))
}

fn process_bootstrap_lines_model(
    lines: &[String],
    harness: &mut StartNodeHarness,
) -> BootstrapOutcome {
    let mut seen_peer_ids = HashSet::<PeerId>::new();

    let mut out = BootstrapOutcome {
        accepted: Vec::new(),
        rejected_invalid: 0,
        rejected_missing_peer: 0,
        rejected_self: 0,
        duplicate_peer_suppressed: 0,
    };

    for s in lines.iter().take(MAX_BOOTSTRAP_LINES_MODEL) {
        match validate_bootstrap_addr_model(s, harness.local_peer) {
            Ok((pid, addr)) => {
                if !seen_peer_ids.insert(pid) {
                    out.duplicate_peer_suppressed = out.duplicate_peer_suppressed.saturating_add(1);
                    continue;
                }

                harness.upsert_seed(pid, addr.clone());
                out.accepted.push((pid, addr));
            }
            Err(BootstrapReject::InvalidMultiaddr) => {
                out.rejected_invalid = out.rejected_invalid.saturating_add(1);
            }
            Err(BootstrapReject::MissingPeerId) => {
                out.rejected_missing_peer = out.rejected_missing_peer.saturating_add(1);
            }
            Err(BootstrapReject::SelfPeer) => {
                out.rejected_self = out.rejected_self.saturating_add(1);
            }
        }
    }

    out
}

fn build_startup_dial_candidates_model(
    explicit_bootstraps: &[Multiaddr],
    harness: &StartNodeHarness,
) -> Vec<Multiaddr> {
    let mut all_addrs = Vec::<Multiaddr>::new();
    let mut seen_addr_strings = HashSet::<String>::new();

    for addr in explicit_bootstraps {
        let key = addr.to_string();
        if seen_addr_strings.insert(key) {
            all_addrs.push(addr.clone());
        }
    }

    for (_pid, addrs) in harness.top_n(MAX_PEERBOOK_PEERS_MODEL) {
        for addr in addrs {
            let key = addr.to_string();
            if seen_addr_strings.insert(key) {
                all_addrs.push(addr);
            }
        }
    }

    let mut seen_peer_ids = HashSet::<PeerId>::new();
    all_addrs.retain(|addr| {
        let Some(pid) = extract_trailing_peer(addr) else {
            return false;
        };

        if pid == harness.local_peer {
            return false;
        }

        seen_peer_ids.insert(pid)
    });

    if all_addrs.len() > MAX_STARTUP_DIALS_MODEL {
        all_addrs.truncate(MAX_STARTUP_DIALS_MODEL);
    }

    all_addrs
}

fn startup_dial_summary_model(dial_results: &[bool]) -> (usize, usize, usize, bool) {
    let attempts = dial_results.len();
    let accepted = dial_results.iter().filter(|ok| **ok).count();
    let failed = attempts.saturating_sub(accepted);

    let startup_may_continue = true;

    (attempts, accepted, failed, startup_may_continue)
}

fn tcp_endpoint_present_model(addr: &Multiaddr) -> bool {
    let mut has_ip = false;
    let mut has_tcp = false;

    for p in addr.iter() {
        match p {
            Protocol::Ip4(_) | Protocol::Ip6(_) => has_ip = true,
            Protocol::Tcp(_) => has_tcp = true,
            _ => {}
        }
    }

    has_ip && has_tcp
}

fn make_addr_with_shape(cursor: &mut Cursor<'_>, peer: PeerId, local_peer: PeerId) -> String {
    match cursor.take_u8() % 8 {
        0 => format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{}",
            cursor.take_u16().max(1),
            peer
        ),
        1 => format!(
            "/ip6/::1/tcp/{}/p2p/{}",
            cursor.take_u16().max(1),
            peer
        ),
        2 => format!("/dnsaddr/example.com/p2p/{peer}"),
        3 => format!("/ip4/127.0.0.1/tcp/{}", cursor.take_u16().max(1)),
        4 => format!(
            "/ip4/127.0.0.1/tcp/{}/p2p/{}",
            cursor.take_u16().max(1),
            local_peer
        ),
        5 => cursor.take_ascii_string(96),
        6 => format!("/memory/{}/p2p/{peer}", cursor.take_u64()),
        _ => String::new(),
    }
}

fn fuzz_already_running_guard(cursor: &mut Cursor<'_>) {
    let p2p_running = cursor.take_bool();
    let returns_early = p2p_start_guard_returns_early_model(p2p_running);
    assert_eq!(returns_early, p2p_running);
}

fn fuzz_founder_start_gate(cursor: &mut Cursor<'_>) {
    let prompt = match cursor.take_u8() % 6 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "YES".to_string(),
        3 => "NO".to_string(),
        4 => "maybe".to_string(),
        _ => cursor.take_ascii_string(MAX_INPUT_BYTES_MODEL.saturating_add(32)),
    };

    let key_case = cursor.take_u8() % 5;
    let founder_key = match key_case {
        0 => None,
        1 => Some("a".repeat(FOUNDER_KEY_HEX_LEN)),
        2 => Some("g".repeat(FOUNDER_KEY_HEX_LEN)),
        3 => Some("a".repeat(FOUNDER_KEY_HEX_LEN.saturating_sub(1))),
        _ => Some(cursor.take_ascii_string(160)),
    };

    let decision = founder_start_gate_model(&prompt, founder_key.as_deref());

    match prompt.trim().to_ascii_lowercase().as_str() {
        "no" => assert_eq!(
            decision,
            FounderStartGate::Continue {
                is_founder: false,
                founder_authenticated: false,
            }
        ),
        "yes" => {
            let key_valid = founder_key
                .as_deref()
                .is_some_and(|k| valid_founder_key_model(k.trim()));
            if key_valid {
                assert_eq!(
                    decision,
                    FounderStartGate::Continue {
                        is_founder: true,
                        founder_authenticated: true,
                    }
                );
            } else {
                assert_eq!(decision, FounderStartGate::ReturnToMenu);
            }
        }
        _ => assert_eq!(decision, FounderStartGate::ReturnToMenu),
    }
}

fn fuzz_founder_key(cursor: &mut Cursor<'_>) {
    let mut s = cursor.take_ascii_string(160);

    if cursor.take_bool() {
        s = "a".repeat(FOUNDER_KEY_HEX_LEN);
    }

    let valid = valid_founder_key_model(&s);
    assert_eq!(valid, s.len() == FOUNDER_KEY_HEX_LEN && is_hex_text(&s));

    if valid {
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

fn fuzz_yes_no(cursor: &mut Cursor<'_>) {
    let s = match cursor.take_u8() % 6 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "YES".to_string(),
        3 => "No".to_string(),
        4 => cursor.take_ascii_string(MAX_INPUT_BYTES_MODEL.saturating_add(32)),
        _ => String::new(),
    };

    let capped = read_line_capped_model(&s, MAX_INPUT_BYTES_MODEL);
    if s.len() > MAX_INPUT_BYTES_MODEL {
        assert!(capped.is_err());
        return;
    }

    assert!(capped.is_ok());

    let parsed = parse_yes_no_model(&s);
    match s.trim().to_ascii_lowercase().as_str() {
        "yes" => assert_eq!(parsed, Some(YesNo::Yes)),
        "no" => assert_eq!(parsed, Some(YesNo::No)),
        _ => assert_eq!(parsed, None),
    }
}

fn fuzz_genesis_metadata(cursor: &mut Cursor<'_>) {
    let is_file = cursor.take_bool();
    let len = match cursor.take_u8() % 5 {
        0 => 0,
        1 => 1,
        2 => MAX_GENESIS_JSON_BYTES_MODEL,
        3 => MAX_GENESIS_JSON_BYTES_MODEL.saturating_add(1),
        _ => cursor.take_u64(),
    };

    let allowed = genesis_metadata_allowed_model(is_file, len);
    assert_eq!(allowed, is_file && len > 0 && len <= MAX_GENESIS_JSON_BYTES_MODEL);
}

fn fuzz_genesis_start_decision(cursor: &mut Cursor<'_>) {
    let needs_genesis = cursor.take_bool();
    let is_founder = cursor.take_bool();
    let founder_authenticated = cursor.take_bool();
    let genesis_file_exists = cursor.take_bool();

    let decision = genesis_start_decision_model(
        needs_genesis,
        is_founder,
        founder_authenticated,
        genesis_file_exists,
    );

    match decision {
        GenesisStartDecision::ResumeExistingChain => assert!(!needs_genesis),
        GenesisStartDecision::FounderInitializesGenesis => {
            assert!(needs_genesis && is_founder && founder_authenticated && genesis_file_exists);
        }
        GenesisStartDecision::FounderMissingGenesisFile => {
            assert!(needs_genesis && is_founder && founder_authenticated && !genesis_file_exists);
        }
        GenesisStartDecision::NonFounderSyncOnly => {
            assert!(needs_genesis && !(is_founder && founder_authenticated));
        }
    }
}

fn fuzz_wallet_canonicalize(cursor: &mut Cursor<'_>) {
    let s = match cursor.take_u8() % 6 {
        0 => format!("r{}", "0".repeat(REMZAR_WALLET_HEX_LEN)),
        1 => format!("R{}", "A".repeat(REMZAR_WALLET_HEX_LEN)),
        2 => format!("r{}", "g".repeat(REMZAR_WALLET_HEX_LEN)),
        3 => format!("p{}", "0".repeat(REMZAR_WALLET_HEX_LEN)),
        4 => format!("r{}", cursor.take_ascii_string(REMZAR_WALLET_HEX_LEN)),
        _ => cursor.take_ascii_string(180),
    };

    let canon = canon_wallet_model(&s);

    if let Some(c) = canon {
        assert_eq!(c.len(), REMZAR_WALLET_LEN);
        assert!(c.starts_with('r'));
        assert!(c[1..].chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(c, c.to_ascii_lowercase());
    } else {
        let trimmed = s.trim();
        let structurally_valid = trimmed.len() == REMZAR_WALLET_LEN
            && (trimmed.starts_with('r') || trimmed.starts_with('R'))
            && is_hex_text(&trimmed[1..]);
        assert!(!structurally_valid);
    }
}

fn fuzz_wallet_binding(cursor: &mut Cursor<'_>) {
    let is_founder = cursor.take_bool();
    let founder_authenticated = cursor.take_bool();

    let wallet = match cursor.take_u8() % 5 {
        0 => String::new(),
        1 => format!("r{}", "1".repeat(REMZAR_WALLET_HEX_LEN)),
        2 => format!("R{}", "A".repeat(REMZAR_WALLET_HEX_LEN)),
        3 => format!("p{}", "1".repeat(REMZAR_WALLET_HEX_LEN)),
        _ => cursor.take_ascii_string(180),
    };

    let existing_binding = match cursor.take_u8() % 5 {
        0 => None,
        1 => Some(format!("r{}", "1".repeat(REMZAR_WALLET_HEX_LEN))),
        2 => Some(format!("r{}", "2".repeat(REMZAR_WALLET_HEX_LEN))),
        3 => Some(format!("R{}", "A".repeat(REMZAR_WALLET_HEX_LEN))),
        _ => Some(cursor.take_ascii_string(180)),
    };

    let decision =
        wallet_binding_decision_model(&wallet, is_founder, founder_authenticated, existing_binding.as_deref());

    match decision {
        BindingDecision::Observer => assert!(wallet.trim().is_empty()),
        BindingDecision::FounderBypass => {
            assert!(!wallet.trim().is_empty());
            assert!(is_founder && founder_authenticated);
        }
        BindingDecision::WriteNewBinding => {
            assert!(existing_binding.is_none());
            assert!(canon_wallet_model(&wallet).is_some());
            assert!(!(is_founder && founder_authenticated));
        }
        BindingDecision::AcceptExistingBinding => {
            let wallet_canon = canon_wallet_model(&wallet).unwrap();
            let existing_canon = canon_wallet_model(existing_binding.as_deref().unwrap()).unwrap();
            assert_eq!(wallet_canon, existing_canon);
        }
        BindingDecision::RejectInvalidWallet => {
            assert!(!wallet.trim().is_empty());
            assert!(canon_wallet_model(&wallet).is_none());
            assert!(!(is_founder && founder_authenticated));
        }
        BindingDecision::RejectInvalidExistingBinding => {
            assert!(canon_wallet_model(&wallet).is_some());
            assert!(canon_wallet_model(existing_binding.as_deref().unwrap()).is_none());
        }
        BindingDecision::RejectMismatch => {
            let wallet_canon = canon_wallet_model(&wallet).unwrap();
            let existing_canon = canon_wallet_model(existing_binding.as_deref().unwrap()).unwrap();
            assert_ne!(wallet_canon, existing_canon);
        }
    }
}

fn fuzz_wallet_proof(cursor: &mut Cursor<'_>) {
    let wallet = match cursor.take_u8() % 6 {
        0 => String::new(),
        1 => format!("r{}", "1".repeat(REMZAR_WALLET_HEX_LEN)),
        2 => format!("R{}", "A".repeat(REMZAR_WALLET_HEX_LEN)),
        3 => format!("p{}", "1".repeat(REMZAR_WALLET_HEX_LEN)),
        4 => format!("r{}g", "1".repeat(REMZAR_WALLET_HEX_LEN.saturating_sub(1))),
        _ => cursor.take_ascii_string(180),
    };

    let wallet_file_exists = cursor.take_bool();
    let wallet_read_ok = cursor.take_bool();
    let decrypt_ok = cursor.take_bool();
    let secret_len_ok = cursor.take_bool();
    let pubkey_matches_wallet = cursor.take_bool();

    let decision = wallet_proof_decision_model(
        &wallet,
        wallet_file_exists,
        wallet_read_ok,
        decrypt_ok,
        secret_len_ok,
        pubkey_matches_wallet,
    );

    match decision {
        WalletProofDecision::ObserverMode => assert!(wallet.trim().is_empty()),
        WalletProofDecision::AcceptedAndCached => {
            assert!(canon_wallet_model(&wallet).is_some());
            assert!(wallet_file_exists && wallet_read_ok && decrypt_ok && secret_len_ok && pubkey_matches_wallet);
        }
        WalletProofDecision::RejectInvalidWallet => assert!(canon_wallet_model(&wallet).is_none()),
        WalletProofDecision::RejectWalletFileMissing => {
            assert!(canon_wallet_model(&wallet).is_some());
            assert!(!wallet_file_exists);
        }
        WalletProofDecision::RejectWalletReadFailed => assert!(wallet_file_exists && !wallet_read_ok),
        WalletProofDecision::RejectDecryptFailed => assert!(wallet_file_exists && wallet_read_ok && !decrypt_ok),
        WalletProofDecision::RejectSecretLengthMismatch => {
            assert!(wallet_file_exists && wallet_read_ok && decrypt_ok && !secret_len_ok);
        }
        WalletProofDecision::RejectPubkeyMismatch => {
            assert!(wallet_file_exists && wallet_read_ok && decrypt_ok && secret_len_ok && !pubkey_matches_wallet);
        }
    }
}

fn fuzz_listen_address(cursor: &mut Cursor<'_>) {
    let ip = match cursor.take_u8() % 5 {
        0 => String::new(),
        1 => "0.0.0.0".to_string(),
        2 => "127.0.0.1".to_string(),
        3 => "999.999.999.999".to_string(),
        _ => cursor.take_ascii_string(32),
    };

    let port = match cursor.take_u8() % 5 {
        0 => String::new(),
        1 => "36213".to_string(),
        2 => cursor.take_u16().to_string(),
        3 => "notaport".to_string(),
        _ => cursor.take_ascii_string(12),
    };

    let addr = build_listen_addr_model(&ip, &port);
    assert!(addr.starts_with("/ip4/"));
    assert_eq!(listen_addr_parses_model(&ip, &port), addr.parse::<Multiaddr>().is_ok());
}

fn fuzz_bootstrap_input_collection(cursor: &mut Cursor<'_>, harness: &StartNodeHarness) {
    let count = cursor.take_usize_mod(MAX_BOOTSTRAP_LINES_MODEL.saturating_add(1));
    let mut lines = Vec::with_capacity(count);

    for _ in 0..count {
        let peer = harness.peer(cursor.take_u8());
        lines.push(make_addr_with_shape(cursor, peer, harness.local_peer));
    }

    let outcome = process_operator_bootstrap_input_model(&lines);

    assert!(outcome.accepted.len() <= lines.len().min(MAX_BOOTSTRAP_LINES_MODEL));
    assert!(outcome.total_rejected() <= lines.len().min(MAX_BOOTSTRAP_LINES_MODEL));
    assert!(outcome.accepted.len().saturating_add(outcome.total_rejected()) <= lines.len());

    let mut seen = HashSet::new();
    for (pid, addr) in outcome.accepted {
        assert!(seen.insert(pid), "operator bootstrap input must dedupe by PeerId");
        assert_eq!(extract_trailing_peer(&addr), Some(pid));
    }
}

fn fuzz_bootstrap_line(cursor: &mut Cursor<'_>, harness: &mut StartNodeHarness) {
    let peer = harness.peer(cursor.take_u8());
    let s = make_addr_with_shape(cursor, peer, harness.local_peer);

    let result = validate_bootstrap_addr_model(&s, harness.local_peer);

    match result {
        Ok((pid, addr)) => {
            assert_ne!(pid, harness.local_peer);
            assert_eq!(extract_trailing_peer(&addr), Some(pid));
            harness.upsert_seed(pid, addr);
        }
        Err(BootstrapReject::InvalidMultiaddr) => {
            assert!(s.parse::<Multiaddr>().is_err());
        }
        Err(BootstrapReject::MissingPeerId) => {
            let parsed = s.parse::<Multiaddr>();
            assert!(parsed.is_ok());
            assert!(extract_trailing_peer(&parsed.unwrap()).is_none());
        }
        Err(BootstrapReject::SelfPeer) => {
            let parsed = s.parse::<Multiaddr>().unwrap();
            assert_eq!(extract_trailing_peer(&parsed), Some(harness.local_peer));
        }
    }
}

fn fuzz_bootstrap_batch(cursor: &mut Cursor<'_>, harness: &mut StartNodeHarness) {
    let count = cursor.take_usize_mod(MAX_BOOTSTRAP_LINES_MODEL.saturating_add(1));
    let mut lines = Vec::with_capacity(count);

    for _ in 0..count {
        let peer = harness.peer(cursor.take_u8());
        lines.push(make_addr_with_shape(cursor, peer, harness.local_peer));
    }

    let outcome = process_bootstrap_lines_model(&lines, harness);

    assert!(outcome.accepted.len() <= lines.len().min(MAX_BOOTSTRAP_LINES_MODEL));
    assert!(outcome.total_rejected() <= lines.len().min(MAX_BOOTSTRAP_LINES_MODEL));
    assert!(outcome.accepted.len().saturating_add(outcome.total_rejected()) <= lines.len());

    let mut peers = HashSet::new();
    for (pid, addr) in &outcome.accepted {
        assert!(peers.insert(*pid), "accepted bootstrap peers must be deduped by PeerId");
        assert_eq!(extract_trailing_peer(addr), Some(*pid));
        assert_ne!(*pid, harness.local_peer);
        assert!(harness.seed_peers.contains(pid));
    }
}

fn fuzz_peerbook_expansion(cursor: &mut Cursor<'_>, harness: &mut StartNodeHarness) {
    let extra = cursor.take_usize_mod(MAX_PEERBOOK_PEERS_MODEL.saturating_add(1));

    for _ in 0..extra {
        let peer = harness.peer(cursor.take_u8());
        let s = make_addr_with_shape(cursor, peer, harness.local_peer);
        if let Ok((pid, addr)) = validate_bootstrap_addr_model(&s, harness.local_peer) {
            harness.upsert_plain(pid, addr);
        }
    }

    let explicit_count = cursor.take_usize_mod(16);
    let mut explicit = Vec::new();

    for _ in 0..explicit_count {
        let peer = harness.peer(cursor.take_u8());
        let s = make_addr_with_shape(cursor, peer, harness.local_peer);
        if let Ok((_pid, addr)) = validate_bootstrap_addr_model(&s, harness.local_peer) {
            explicit.push(addr);
        }
    }

    let candidates = build_startup_dial_candidates_model(&explicit, harness);

    assert!(candidates.len() <= MAX_STARTUP_DIALS_MODEL);

    let mut seen_peers = HashSet::new();
    for addr in candidates {
        let pid = extract_trailing_peer(&addr).expect("final dial candidates must end with /p2p");
        assert_ne!(pid, harness.local_peer);
        assert!(seen_peers.insert(pid), "final dial candidates must be deduped by PeerId");
    }
}

fn fuzz_cold_reboot(cursor: &mut Cursor<'_>) {
    let chain_already_exists = cursor.take_bool();
    let is_founder = cursor.take_bool();
    let founder_authenticated = cursor.take_bool();
    let bootstrap_count = cursor.take_usize_mod(MAX_BOOTSTRAP_LINES_MODEL.saturating_add(1));
    let any_online = cursor.take_bool();

    let allowed = cold_reboot_allowed_model(
        chain_already_exists,
        is_founder,
        founder_authenticated,
        bootstrap_count,
        any_online,
    );

    if chain_already_exists && !is_founder && !founder_authenticated {
        assert_eq!(allowed, bootstrap_count > 0 && any_online);
    } else {
        assert!(allowed);
    }
}

fn fuzz_mining_intent(cursor: &mut Cursor<'_>) {
    let chain_already_exists = cursor.take_bool();
    let is_founder = cursor.take_bool();
    let founder_authenticated = cursor.take_bool();
    let bootnode_online = cursor.take_bool();
    let identity_registered = cursor.take_bool();
    let founder_bc_start_yes = cursor.take_bool();
    let local_wallet = match cursor.take_u8() % 4 {
        0 => String::new(),
        1 => format!("r{}", "1".repeat(REMZAR_WALLET_HEX_LEN)),
        2 => format!("R{}", "A".repeat(REMZAR_WALLET_HEX_LEN)),
        _ => cursor.take_ascii_string(180),
    };

    let decision = mining_intent_decision_model(
        chain_already_exists,
        is_founder,
        founder_authenticated,
        bootnode_online,
        identity_registered,
        founder_bc_start_yes,
        &local_wallet,
    );

    match decision {
        MiningIntentDecision::BlockedNonFounderColdReboot => {
            assert!(chain_already_exists && !is_founder && !founder_authenticated && !bootnode_online);
        }
        MiningIntentDecision::FounderMining => {
            assert!(is_founder && identity_registered && founder_bc_start_yes && !local_wallet.trim().is_empty());
        }
        MiningIntentDecision::FounderObserver => assert!(is_founder),
        MiningIntentDecision::NonFounderMining => {
            assert!(!is_founder && identity_registered && !local_wallet.trim().is_empty());
        }
        MiningIntentDecision::NonFounderObserver => assert!(!is_founder),
    }
}

fn fuzz_dial_summary(cursor: &mut Cursor<'_>) {
    let count = cursor.take_usize_mod(MAX_STARTUP_DIALS_MODEL.saturating_add(1));
    let mut results = Vec::with_capacity(count);

    for _ in 0..count {
        results.push(cursor.take_bool());
    }

    let (attempts, accepted, failed, may_continue) = startup_dial_summary_model(&results);

    assert_eq!(attempts, results.len());
    assert_eq!(accepted, results.iter().filter(|ok| **ok).count());
    assert_eq!(failed, attempts.saturating_sub(accepted));
    assert!(may_continue, "startup must not abort only because all startup dials failed");
}

fn fuzz_tcp_endpoint(cursor: &mut Cursor<'_>, harness: &StartNodeHarness) {
    let peer = harness.peer(cursor.take_u8());
    let s = make_addr_with_shape(cursor, peer, harness.local_peer);

    if let Ok(addr) = s.parse::<Multiaddr>() {
        let endpoint_present = tcp_endpoint_present_model(&addr);

        let mut has_ip = false;
        let mut has_tcp = false;
        for p in addr.iter() {
            match p {
                Protocol::Ip4(_) | Protocol::Ip6(_) => has_ip = true,
                Protocol::Tcp(_) => has_tcp = true,
                _ => {}
            }
        }

        assert_eq!(endpoint_present, has_ip && has_tcp);
    }
}

fn fuzz_wire_roundtrip(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_vec(MAX_WIRE_BYTES);

    let result = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireStartScenario>(&raw);
    });
    assert!(result.is_ok());

    let scenario = WireStartScenario {
        op: match cursor.take_u8() % 19 {
            0 => StartupOp::AlreadyRunningGuard,
            1 => StartupOp::FounderStartGate,
            2 => StartupOp::FounderKeyCheck,
            3 => StartupOp::YesNoPrompt,
            4 => StartupOp::GenesisMetadata,
            5 => StartupOp::GenesisStartDecision,
            6 => StartupOp::WalletCanonicalize,
            7 => StartupOp::WalletBinding,
            8 => StartupOp::WalletProof,
            9 => StartupOp::ListenAddress,
            10 => StartupOp::BootstrapInputCollection,
            11 => StartupOp::BootstrapLine,
            12 => StartupOp::BootstrapBatch,
            13 => StartupOp::PeerbookExpansion,
            14 => StartupOp::ColdReboot,
            15 => StartupOp::MiningIntent,
            16 => StartupOp::DialSummary,
            17 => StartupOp::TcpEndpoint,
            _ => StartupOp::WireRoundtrip,
        },
        is_founder: cursor.take_bool(),
        founder_authenticated: cursor.take_bool(),
        chain_already_exists: cursor.take_bool(),
        force: cursor.take_bool(),
        bootstrap_count: cursor.take_u16(),
        online_count: cursor.take_u16(),
        accepted_dials: cursor.take_u16(),
        failed_dials: cursor.take_u16(),
        p2p_running: cursor.take_bool(),
        needs_genesis: cursor.take_bool(),
        genesis_exists: cursor.take_bool(),
        identity_registered: cursor.take_bool(),
        founder_bc_start_yes: cursor.take_bool(),
        input: cursor.take_vec(256),
    };

    let encoded = to_allocvec(&scenario).expect("wire start scenario must encode");
    let decoded: WireStartScenario =
        from_bytes(&encoded).expect("freshly encoded wire start scenario must decode");

    assert_eq!(decoded, scenario);
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let mut harness = StartNodeHarness::new();

    let op_count = cursor
        .take_usize_mod(MAX_MODEL_OPS)
        .min(data.len().saturating_add(1))
        .max(1);

    for _ in 0..op_count {
        match cursor.take_u8() % 19 {
            0 => fuzz_already_running_guard(&mut cursor),
            1 => fuzz_founder_start_gate(&mut cursor),
            2 => fuzz_founder_key(&mut cursor),
            3 => fuzz_yes_no(&mut cursor),
            4 => fuzz_genesis_metadata(&mut cursor),
            5 => fuzz_genesis_start_decision(&mut cursor),
            6 => fuzz_wallet_canonicalize(&mut cursor),
            7 => fuzz_wallet_binding(&mut cursor),
            8 => fuzz_wallet_proof(&mut cursor),
            9 => fuzz_listen_address(&mut cursor),
            10 => fuzz_bootstrap_input_collection(&mut cursor, &harness),
            11 => fuzz_bootstrap_line(&mut cursor, &mut harness),
            12 => fuzz_bootstrap_batch(&mut cursor, &mut harness),
            13 => fuzz_peerbook_expansion(&mut cursor, &mut harness),
            14 => fuzz_cold_reboot(&mut cursor),
            15 => fuzz_mining_intent(&mut cursor),
            16 => fuzz_dial_summary(&mut cursor),
            17 => fuzz_tcp_endpoint(&mut cursor, &harness),
            _ => fuzz_wire_roundtrip(&mut cursor),
        }

        harness.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    harness.assert_invariants();
});
