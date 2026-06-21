// fuzz/fuzz_targets/fuzz_p2p_006_sync_runtime.rs

#![no_main]

use clap::Parser;
use libfuzzer_sys::fuzz_target;
use libp2p::{identity, multiaddr::Protocol, Multiaddr, PeerId};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/* ─────────────────────────────────────────────────────────────
Mirrors p2p_006_sync_runtime.rs defensive caps
───────────────────────────────────────────────────────────── */

const MAX_MULTIADDR_BYTES: usize = 256;
const MAX_CLI_BOOTSTRAPS: usize = 256;
const MAX_STARTUP_DIALS: usize = 256;
const MAX_KAD_SEEDS: usize = 2048;

const MAX_MODEL_OPS: usize = 512;
const MAX_MODEL_ADDRS: usize = 128;
const MAX_MODEL_PEERS: usize = 64;
const MAX_MODEL_STRING_BYTES: usize = 512;

// Valid Remzar wallet shape used only for Clap parsing.
const TEST_WALLET_ADDRESS: &str = "r00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
struct NodeOptsModel {
    #[clap(long, default_value = "identity.key")]
    identity_file: String,

    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/36213")]
    listen: String,

    #[clap(long)]
    bootstrap: Vec<String>,

    #[clap(long, default_value = "info")]
    log: String,

    #[clap(long, default_value = "data")]
    data_dir: String,

    #[clap(long)]
    wallet_address: String,

    #[clap(long, alias = "is-founder")]
    founder: bool,
}

/* ─────────────────────────────────────────────────────────────
Pure helper models
───────────────────────────────────────────────────────────── */

#[inline(always)]
fn env_true_value(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("y")
                || v.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

#[inline(always)]
fn multiaddr_within_bounds(a: &Multiaddr) -> bool {
    a.to_vec().len() <= MAX_MULTIADDR_BYTES
}

#[inline(always)]
fn filter_multiaddrs_within_bounds(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs.into_iter().filter(multiaddr_within_bounds).collect()
}

fn parse_cli_bootstraps_model(raw: &[String]) -> Vec<Multiaddr> {
    raw.iter()
        .take(MAX_CLI_BOOTSTRAPS)
        .filter_map(|s| match s.parse::<Multiaddr>() {
            Ok(addr) if multiaddr_within_bounds(&addr) => Some(addr),
            _ => None,
        })
        .collect()
}

fn cli_seed_pairs_model(addrs: &[Multiaddr]) -> Vec<(PeerId, Multiaddr)> {
    addrs
        .iter()
        .filter_map(|addr| {
            let comps: Vec<_> = addr.iter().collect();
            match comps.last().cloned() {
                Some(Protocol::P2p(pid)) => Some((pid, addr.clone())),
                _ => None,
            }
        })
        .collect()
}

fn strip_trailing_p2p(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut comps: Vec<_> = addr.iter().collect();
    match comps.last().cloned() {
        Some(Protocol::P2p(pid)) => {
            comps.pop();
            let base_addr: Multiaddr = comps.into_iter().collect();
            Some((pid, base_addr))
        }
        _ => None,
    }
}

fn cli_kad_seeds_model(addrs: &[Multiaddr]) -> Vec<(PeerId, Multiaddr)> {
    let mut out = Vec::new();

    for addr in addrs {
        if out.len() >= MAX_KAD_SEEDS {
            break;
        }

        if let Some((pid, base_addr)) = strip_trailing_p2p(addr) {
            if multiaddr_within_bounds(&base_addr) {
                out.push((pid, base_addr));
            }
        }
    }

    out
}

fn peerbook_top_model(
    peerbook_like: Vec<(PeerId, Vec<Multiaddr>)>,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    peerbook_like
        .into_iter()
        .map(|(pid, addrs)| (pid, filter_multiaddrs_within_bounds(addrs)))
        .collect()
}

fn startup_dials_model(
    cli_bootstrap_addrs: &[Multiaddr],
    peerbook_top: &[(PeerId, Vec<Multiaddr>)],
) -> Vec<Multiaddr> {
    let mut all_addrs = Vec::new();
    let mut seen_addr_strings = HashSet::<String>::new();

    for addr in cli_bootstrap_addrs {
        let key = addr.to_string();
        if seen_addr_strings.insert(key) {
            all_addrs.push(addr.clone());
        }
    }

    for (_pid, addrs) in peerbook_top {
        for addr in addrs {
            let key = addr.to_string();
            if seen_addr_strings.insert(key) {
                all_addrs.push(addr.clone());
            }
        }
    }

    if all_addrs.len() > MAX_STARTUP_DIALS {
        all_addrs.truncate(MAX_STARTUP_DIALS);
    }

    all_addrs
}

/* ─────────────────────────────────────────────────────────────
Fuzz harness data
───────────────────────────────────────────────────────────── */

#[derive(Debug)]
struct RuntimeHarness {
    peers: Vec<PeerId>,
}

impl RuntimeHarness {
    fn new() -> Self {
        Self {
            peers: (0..MAX_MODEL_PEERS)
                .map(|_| PeerId::from(identity::Keypair::generate_ed25519().public()))
                .collect(),
        }
    }

    fn peer(&self, slot: u8) -> PeerId {
        self.peers[usize::from(slot) % self.peers.len()]
    }

    fn assert_invariants(&self) {
        assert!(MAX_MULTIADDR_BYTES >= 64);
        assert!(MAX_MULTIADDR_BYTES <= 1024);

        assert!(MAX_CLI_BOOTSTRAPS > 0);
        assert!(MAX_STARTUP_DIALS > 0);
        assert!(MAX_KAD_SEEDS >= MAX_STARTUP_DIALS);

        assert_eq!(self.peers.len(), MAX_MODEL_PEERS);
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

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut out = String::with_capacity(len);

        for _ in 0..len {
            let b = self.take_u8();
            let ch = match b % 96 {
                n @ 0..=94 => char::from(32u8.saturating_add(n)),
                _ => '\n',
            };
            out.push(ch);
        }

        out
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }
}

fn make_multiaddr(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) -> Multiaddr {
    let component_count = cursor.take_usize_mod(24);
    let mut addr = Multiaddr::empty();

    for _ in 0..component_count {
        match cursor.take_u8() % 8 {
            0 => {
                let octets = [
                    cursor.take_u8(),
                    cursor.take_u8(),
                    cursor.take_u8(),
                    cursor.take_u8(),
                ];
                addr.push(Protocol::Ip4(Ipv4Addr::from(octets)));
            }
            1 => {
                let mut octets = [0u8; 16];
                cursor.fill(&mut octets);
                addr.push(Protocol::Ip6(Ipv6Addr::from(octets)));
            }
            2 => {
                addr.push(Protocol::Tcp(cursor.take_u16()));
            }
            3 => {
                addr.push(Protocol::Udp(cursor.take_u16()));
            }
            4 => {
                addr.push(Protocol::Memory(cursor.take_u64()));
            }
            5 => {
                let peer = harness.peer(cursor.take_u8());
                addr.push(Protocol::P2p(peer));
            }
            6 => {
                // Force a common valid transport shape.
                addr.push(Protocol::Ip4(Ipv4Addr::LOCALHOST));
                addr.push(Protocol::Tcp(cursor.take_u16()));
            }
            _ => {
                // Intentionally no-op to create empty/sparse multiaddrs.
            }
        }
    }

    if cursor.take_bool() {
        let peer = harness.peer(cursor.take_u8());
        addr.push(Protocol::P2p(peer));
    }

    addr
}

fn make_bootstrap_strings(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) -> Vec<String> {
    let count = cursor.take_usize_mod(MAX_MODEL_ADDRS);
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        if cursor.take_bool() {
            out.push(make_multiaddr(cursor, harness).to_string());
        } else {
            out.push(cursor.take_ascii_string(MAX_MODEL_STRING_BYTES));
        }
    }

    out
}

fn make_peerbook_like(
    cursor: &mut Cursor<'_>,
    harness: &RuntimeHarness,
) -> Vec<(PeerId, Vec<Multiaddr>)> {
    let peer_count = cursor.take_usize_mod(MAX_MODEL_PEERS);
    let mut out = Vec::with_capacity(peer_count);

    for _ in 0..peer_count {
        let peer = harness.peer(cursor.take_u8());
        let addr_count = cursor.take_usize_mod(16);
        let mut addrs = Vec::with_capacity(addr_count);

        for _ in 0..addr_count {
            addrs.push(make_multiaddr(cursor, harness));
        }

        out.push((peer, addrs));
    }

    out
}

/* ─────────────────────────────────────────────────────────────
Fuzz checks
───────────────────────────────────────────────────────────── */

fn fuzz_env_truthiness(cursor: &mut Cursor<'_>) {
    let value = match cursor.take_u8() % 12 {
        0 => None,
        1 => Some("1".to_string()),
        2 => Some("true".to_string()),
        3 => Some("TRUE".to_string()),
        4 => Some("yes".to_string()),
        5 => Some("Y".to_string()),
        6 => Some("on".to_string()),
        7 => Some("0".to_string()),
        8 => Some("false".to_string()),
        9 => Some("off".to_string()),
        10 => Some("  yes  ".to_string()),
        _ => Some(cursor.take_ascii_string(64)),
    };

    let got = env_true_value(value.as_deref());

    let expected = match value.as_deref().map(str::trim) {
        Some(v) => {
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("y")
                || v.eq_ignore_ascii_case("on")
        }
        None => false,
    };

    assert_eq!(got, expected);
}

fn fuzz_multiaddr_bounds(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) {
    let count = cursor.take_usize_mod(MAX_MODEL_ADDRS);
    let mut addrs = Vec::with_capacity(count);

    for _ in 0..count {
        addrs.push(make_multiaddr(cursor, harness));
    }

    let filtered = filter_multiaddrs_within_bounds(addrs.clone());

    assert!(filtered
        .iter()
        .all(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES));

    let expected: Vec<_> = addrs
        .into_iter()
        .filter(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES)
        .collect();

    assert_eq!(filtered, expected);
}

fn fuzz_cli_bootstraps(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) {
    let raw = make_bootstrap_strings(cursor, harness);
    let parsed = parse_cli_bootstraps_model(&raw);

    assert!(parsed.len() <= raw.len().min(MAX_CLI_BOOTSTRAPS));
    assert!(parsed
        .iter()
        .all(|addr| addr.to_vec().len() <= MAX_MULTIADDR_BYTES));

    let expected: Vec<_> = raw
        .iter()
        .take(MAX_CLI_BOOTSTRAPS)
        .filter_map(|s| match s.parse::<Multiaddr>() {
            Ok(addr) if multiaddr_within_bounds(&addr) => Some(addr),
            _ => None,
        })
        .collect();

    assert_eq!(parsed, expected);

    let seed_pairs = cli_seed_pairs_model(&parsed);
    assert!(seed_pairs.len() <= parsed.len());

    for (peer, addr) in &seed_pairs {
        let comps: Vec<_> = addr.iter().collect();
        assert_eq!(comps.last().cloned(), Some(Protocol::P2p(*peer)));
    }

    let kad_seeds = cli_kad_seeds_model(&parsed);
    assert!(kad_seeds.len() <= parsed.len().min(MAX_KAD_SEEDS));

    for (_peer, base_addr) in &kad_seeds {
        assert!(multiaddr_within_bounds(base_addr));
        assert!(base_addr.to_vec().len() <= MAX_MULTIADDR_BYTES);
    }
}

fn fuzz_startup_dials(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) {
    let raw = make_bootstrap_strings(cursor, harness);
    let cli_bootstrap_addrs = parse_cli_bootstraps_model(&raw);

    let peerbook_raw = make_peerbook_like(cursor, harness);
    let peerbook_top = peerbook_top_model(peerbook_raw);

    let all_addrs = startup_dials_model(&cli_bootstrap_addrs, &peerbook_top);

    assert!(all_addrs.len() <= MAX_STARTUP_DIALS);

    let mut seen = HashSet::<String>::new();
    for addr in &all_addrs {
        assert!(seen.insert(addr.to_string()));
    }

    // Startup dials must preserve CLI-first priority.
    let mut expected_prefix = Vec::new();
    let mut expected_seen = HashSet::<String>::new();

    for addr in &cli_bootstrap_addrs {
        let key = addr.to_string();
        if expected_seen.insert(key) {
            expected_prefix.push(addr.clone());
            if expected_prefix.len() >= MAX_STARTUP_DIALS {
                break;
            }
        }
    }

    assert!(all_addrs.starts_with(&expected_prefix));
}

fn fuzz_nodeopts_parse(cursor: &mut Cursor<'_>, harness: &RuntimeHarness) {
    let include_wallet = cursor.take_bool();

    let mut args = vec!["remzar".to_string()];

    if include_wallet {
        args.push("--wallet-address".to_string());
        args.push(TEST_WALLET_ADDRESS.to_string());
    }

    let founder_flag = cursor.take_u8() % 3;
    if founder_flag == 1 {
        args.push("--founder".to_string());
    } else if founder_flag == 2 {
        args.push("--is-founder".to_string());
    }

    if cursor.take_bool() {
        args.push("--identity-file".to_string());
        args.push(cursor.take_ascii_string(64));
    }

    if cursor.take_bool() {
        args.push("--listen".to_string());
        args.push(make_multiaddr(cursor, harness).to_string());
    }

    if cursor.take_bool() {
        args.push("--log".to_string());
        args.push(cursor.take_ascii_string(32));
    }

    if cursor.take_bool() {
        args.push("--data-dir".to_string());
        args.push(cursor.take_ascii_string(64));
    }

    let bootstrap_count = cursor.take_usize_mod(16);
    for _ in 0..bootstrap_count {
        args.push("--bootstrap".to_string());
        if cursor.take_bool() {
            args.push(make_multiaddr(cursor, harness).to_string());
        } else {
            args.push(cursor.take_ascii_string(64));
        }
    }

    let parsed = NodeOptsModel::try_parse_from(args.clone());

    if !include_wallet {
        assert!(parsed.is_err(), "NodeOpts must require --wallet-address");
        return;
    }

    let Ok(opts) = parsed else {
        return;
    };

    assert_eq!(opts.wallet_address, TEST_WALLET_ADDRESS);
    assert_eq!(opts.founder, founder_flag == 1 || founder_flag == 2);

    let expected_bootstrap_count = args.iter().filter(|arg| arg.as_str() == "--bootstrap").count();
    assert_eq!(opts.bootstrap.len(), expected_bootstrap_count);
}

fn regression_nodeopts_requires_wallet_and_accepts_founder_alias() {
    let missing_wallet = NodeOptsModel::try_parse_from(["remzar", "--founder"]);
    assert!(missing_wallet.is_err());

    let founder = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--founder",
    ])
    .expect("--founder should parse with wallet");

    let alias = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--is-founder",
    ])
    .expect("--is-founder should parse with wallet");

    assert!(founder.founder);
    assert!(alias.founder);
}

fn regression_nodeopts_rejects_flag_like_option_values_without_panic() {
    let flag_like_log_value = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--log",
        "--help",
    ]);
    assert!(flag_like_log_value.is_err());

    let missing_identity_value = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--identity-file",
        "--founder",
    ]);
    assert!(missing_identity_value.is_err());

    let missing_bootstrap_value = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--bootstrap",
        "--is-founder",
    ]);
    assert!(missing_bootstrap_value.is_err());
}

fn regression_bootstrap_full_p2p_addr_roundtrips() {
    let peer = PeerId::from(identity::Keypair::generate_ed25519().public());
    let addr = format!("/ip4/127.0.0.1/tcp/36213/p2p/{peer}");

    let opts = NodeOptsModel::try_parse_from([
        "remzar",
        "--wallet-address",
        TEST_WALLET_ADDRESS,
        "--bootstrap",
        addr.as_str(),
    ])
    .expect("full /p2p bootstrap should parse");

    assert_eq!(opts.bootstrap, vec![addr.clone()]);

    let parsed = parse_cli_bootstraps_model(&opts.bootstrap);
    assert_eq!(parsed.len(), 1);

    let seed_pairs = cli_seed_pairs_model(&parsed);
    assert_eq!(seed_pairs.len(), 1);
    assert_eq!(seed_pairs[0].0, peer);

    let kad_seeds = cli_kad_seeds_model(&parsed);
    assert_eq!(kad_seeds.len(), 1);
    assert_eq!(kad_seeds[0].0, peer);
    assert_eq!(kad_seeds[0].1.to_string(), "/ip4/127.0.0.1/tcp/36213");
}

fn regression_startup_dials_are_deduped_and_capped() {
    let peer = PeerId::from(identity::Keypair::generate_ed25519().public());
    let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/36213/p2p/{peer}")
        .parse()
        .expect("static multiaddr should parse");

    let cli = vec![addr.clone(); MAX_STARTUP_DIALS + 32];
    let peerbook = vec![(peer, vec![addr.clone(); 32])];

    let dials = startup_dials_model(&cli, &peerbook);

    assert_eq!(dials.len(), 1);
    assert_eq!(dials[0], addr);
}

fuzz_target!(|data: &[u8]| {
    regression_nodeopts_requires_wallet_and_accepts_founder_alias();
    regression_nodeopts_rejects_flag_like_option_values_without_panic();
    regression_bootstrap_full_p2p_addr_roundtrips();
    regression_startup_dials_are_deduped_and_capped();

    let mut cursor = Cursor::new(data);
    let harness = RuntimeHarness::new();

    harness.assert_invariants();

    let op_count = cursor
        .take_usize_mod(MAX_MODEL_OPS)
        .min(data.len().saturating_add(1));

    for _ in 0..op_count {
        match cursor.take_u8() % 5 {
            0 => fuzz_env_truthiness(&mut cursor),
            1 => fuzz_multiaddr_bounds(&mut cursor, &harness),
            2 => fuzz_cli_bootstraps(&mut cursor, &harness),
            3 => fuzz_startup_dials(&mut cursor, &harness),
            _ => fuzz_nodeopts_parse(&mut cursor, &harness),
        }

        harness.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    harness.assert_invariants();
});
