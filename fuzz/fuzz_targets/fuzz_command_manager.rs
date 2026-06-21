// fuzz/fuzz_targets/fuzz_command_manager.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_OPS: usize = 256;
const MAX_WALLETS: usize = 64;
const MAX_IDENTITIES: usize = 64;
const MAX_QUEUE_CAP: usize = 32;
const MAX_LOG_MESSAGE_BYTES: usize = 2_048;
const MAX_DATA_DIR_BYTES: usize = 256;
const MAX_CHAT_TEXT_BYTES: usize = 8_192;
const JOIN_TIMEOUT_SECS_MODEL: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelErrorKind {
    P2pNotRunning,
    P2pAlreadyRunning,
    CannotSetHandleBeforeStart,
    NetworkNotRunning,
    NetworkFull,
    NetworkClosed,
    ChainMissing,
    DestructiveWhileRunning,
}

type ModelResult<T> = Result<T, ModelErrorKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetState {
    Missing,
    Ready,
    Full,
    Closed,
}

#[derive(Debug, Clone)]
struct NetQueueModel {
    state: NetState,
    queued: usize,
    cap: usize,
}

impl Default for NetQueueModel {
    fn default() -> Self {
        Self {
            state: NetState::Missing,
            queued: 0,
            cap: 1,
        }
    }
}

impl NetQueueModel {
    fn attach(state: NetState, cap: usize, queued_seed: usize) -> Self {
        let cap = cap.clamp(1, MAX_QUEUE_CAP);
        let queued = queued_seed.min(cap);

        Self { state, queued, cap }
    }

    fn try_send(&mut self) -> ModelResult<()> {
        match self.state {
            NetState::Missing => Err(ModelErrorKind::NetworkNotRunning),
            NetState::Closed => Err(ModelErrorKind::NetworkClosed),
            NetState::Full => Err(ModelErrorKind::NetworkFull),
            NetState::Ready => {
                if self.queued >= self.cap {
                    Err(ModelErrorKind::NetworkFull)
                } else {
                    self.queued = self.queued.saturating_add(1);
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RegistrySnapshotModel {
    wallets: BTreeSet<String>,
    identity_map: BTreeMap<String, String>,
    join_heights: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default)]
struct EphemeralRegistryModel {
    wallets: BTreeSet<String>,
    identity_map: BTreeMap<String, String>,
    join_heights: BTreeMap<String, u64>,
    poisoned: bool,
}

impl EphemeralRegistryModel {
    fn sorted_wallets(&self) -> Vec<String> {
        self.wallets.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChatMessageModel {
    from_wallet: String,
    to_wallet: String,
    timestamp_ms: u64,
    plaintext: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChatLogOutcome {
    wrote: bool,
    path: Option<String>,
    message_len: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct CommandManagerModel {
    node_registry: Option<RegistrySnapshotModel>,
    node_ephemeral: Option<EphemeralRegistryModel>,
    p2p_running: bool,
    p2p_handle: bool,
    net_queue: NetQueueModel,
    console_bus_present: bool,
    chain_present: bool,
    identity_path: String,
    local_wallet: String,
    audit_dir: String,
    pdf_dir: String,
    blockchain_db_guard: bool,
    stopped_count: usize,
    sent_commands: usize,
}

impl Default for CommandManagerModel {
    fn default() -> Self {
        Self {
            node_registry: None,
            node_ephemeral: None,
            p2p_running: false,
            p2p_handle: false,
            net_queue: NetQueueModel::default(),
            console_bus_present: true,
            chain_present: false,
            identity_path: "identity.key".to_string(),
            local_wallet: String::new(),
            audit_dir: String::new(),
            pdf_dir: String::new(),
            blockchain_db_guard: false,
            stopped_count: 0,
            sent_commands: 0,
        }
    }
}

impl CommandManagerModel {
    fn new_no_signals(identity_path: String) -> Self {
        Self {
            identity_path,
            ..Self::default()
        }
    }

    fn new_with_audit(audit_dir: String, pdf_dir: String, identity_path: String) -> Self {
        Self {
            audit_dir,
            pdf_dir,
            identity_path,
            ..Self::default()
        }
    }

    fn ensure_node_running(&self) -> ModelResult<()> {
        if self.p2p_running {
            Ok(())
        } else {
            Err(ModelErrorKind::P2pNotRunning)
        }
    }

    fn attach_net_tx(&mut self, state: NetState, cap: usize, queued_seed: usize) {
        self.net_queue = NetQueueModel::attach(state, cap, queued_seed);
    }

    fn send_net_cmd(&mut self) -> ModelResult<()> {
        self.net_queue.try_send().map(|()| {
            self.sent_commands = self.sent_commands.saturating_add(1);
        })
    }

    fn chain_mut(&mut self) -> ModelResult<()> {
        if self.chain_present {
            Ok(())
        } else {
            Err(ModelErrorKind::ChainMissing)
        }
    }

    fn replace_chain(&mut self) -> ModelResult<()> {
        self.ensure_node_running()?;
        self.chain_present = true;
        Ok(())
    }

    fn take_chain(&mut self) -> ModelResult<()> {
        self.ensure_node_running()?;

        if self.chain_present {
            self.chain_present = false;
            Ok(())
        } else {
            Err(ModelErrorKind::P2pNotRunning)
        }
    }

    fn mark_started(&mut self) -> ModelResult<()> {
        if self.p2p_running {
            return Err(ModelErrorKind::P2pAlreadyRunning);
        }

        self.p2p_running = true;
        Ok(())
    }

    fn set_p2p_handle(&mut self) -> ModelResult<()> {
        if !self.p2p_running {
            return Err(ModelErrorKind::CannotSetHandleBeforeStart);
        }

        self.p2p_handle = true;
        Ok(())
    }

    fn stop_node(&mut self) -> ModelResult<()> {
        if !self.p2p_running {
            return Err(ModelErrorKind::P2pNotRunning);
        }

        // Production sends shutdown, waits with timeout, then clears runtime bits.
        let _timeout = JOIN_TIMEOUT_SECS_MODEL;

        self.p2p_handle = false;
        self.p2p_running = false;
        self.net_queue = NetQueueModel::default();
        self.chain_present = false;
        self.blockchain_db_guard = false;
        self.stopped_count = self.stopped_count.saturating_add(1);

        Ok(())
    }

    fn reload_registry_from_db(&mut self) -> ModelResult<()> {
        let mut new_registry = RegistrySnapshotModel::default();

        if let Some(ne) = &self.node_ephemeral {
            if !ne.poisoned {
                for w in ne.sorted_wallets() {
                    new_registry.wallets.insert(w);
                }
                new_registry.identity_map = ne.identity_map.clone();
                new_registry.join_heights = ne.join_heights.clone();
            }
        }

        self.node_registry = Some(new_registry);
        Ok(())
    }

    fn initialize_blockchain_empty(&self) -> ModelResult<()> {
        if self.p2p_running {
            Err(ModelErrorKind::DestructiveWhileRunning)
        } else {
            Ok(())
        }
    }

    fn create_certificates(&self) -> ModelResult<()> {
        self.ensure_node_running()
    }

    fn send_message(&mut self) -> ModelResult<()> {
        self.ensure_node_running()?;
        self.send_net_cmd()
    }

    fn send_files(&mut self) -> ModelResult<()> {
        self.ensure_node_running()?;
        self.send_net_cmd()
    }

    fn play_slot_machine(&mut self) -> ModelResult<()> {
        self.ensure_node_running()?;
        self.send_net_cmd()
    }

    fn save_outgoing_chat_json(
        &self,
        data_dir: &str,
        chat: &ChatMessageModel,
        create_dir_ok: bool,
        open_file_ok: bool,
        write_ok: bool,
    ) -> ChatLogOutcome {
        let mut message = chat
            .plaintext
            .clone()
            .unwrap_or_else(|| "<decode_failed>".to_string());

        if message.len() > MAX_LOG_MESSAGE_BYTES {
            message.truncate(MAX_LOG_MESSAGE_BYTES);
        }

        let path = format!("{}/sender.message/sent_chat.jsonl", data_dir.trim_end_matches('/'));

        if !create_dir_ok || !open_file_ok || !write_ok {
            return ChatLogOutcome {
                wrote: false,
                path: Some(path),
                message_len: message.len(),
            };
        }

        ChatLogOutcome {
            wrote: true,
            path: Some(path),
            message_len: message.len(),
        }
    }

    fn assert_invariants(&self) {
        if !self.p2p_running {
            assert!(!self.p2p_handle);
            assert!(!self.chain_present);
            assert!(!self.blockchain_db_guard);
        }

        assert!(self.console_bus_present);
        assert!(self.net_queue.cap <= MAX_QUEUE_CAP);
        assert!(self.net_queue.queued <= self.net_queue.cap);
        assert!(
            self.sent_commands
                <= self
                    .net_queue
                    .queued
                    .saturating_add(self.stopped_count)
                    .saturating_add(MAX_OPS)
        );

        if let Some(reg) = &self.node_registry {
            assert!(reg.wallets.len() <= MAX_WALLETS);
            assert!(reg.identity_map.len() <= MAX_IDENTITIES);
            assert!(reg.join_heights.len() <= MAX_WALLETS);
        }

        if let Some(eph) = &self.node_ephemeral {
            assert!(eph.wallets.len() <= MAX_WALLETS);
            assert!(eph.identity_map.len() <= MAX_IDENTITIES);
            assert!(eph.join_heights.len() <= MAX_WALLETS);
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

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
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

    fn take_bool(&mut self) -> bool {
        self.take_u8() & 1 == 1
    }

    fn take_usize_mod(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            usize::from(self.take_u16()) % max
        }
    }

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut s = String::with_capacity(len);

        for _ in 0..len {
            let b = self.take_u8();
            let ch = match b % 96 {
                0 => '/',
                1 => '.',
                2 => '_',
                3 => '-',
                4 => ' ',
                n => char::from(32u8.saturating_add(n)),
            };
            s.push(ch);
        }

        s
    }
}

fn net_state_from_byte(b: u8) -> NetState {
    match b % 4 {
        0 => NetState::Missing,
        1 => NetState::Ready,
        2 => NetState::Full,
        _ => NetState::Closed,
    }
}

fn wallet_from_seed(seed: u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(129);
    out.push('r');

    for i in 0..128 {
        let idx = usize::from(seed.wrapping_add(u8::try_from(i).unwrap_or(0)) % 16);
        out.push(char::from(HEX[idx]));
    }

    out
}

fn peer_from_seed(seed: u8) -> String {
    format!("peer-{:02x}", seed)
}

fn ephemeral_from_cursor(cursor: &mut Cursor<'_>) -> EphemeralRegistryModel {
    let mut eph = EphemeralRegistryModel {
        poisoned: cursor.take_bool(),
        ..EphemeralRegistryModel::default()
    };

    let wallet_count = cursor.take_usize_mod(MAX_WALLETS.saturating_add(1));
    for _ in 0..wallet_count {
        let wallet = wallet_from_seed(cursor.take_u8());
        eph.join_heights.insert(wallet.clone(), cursor.take_u64());
        eph.wallets.insert(wallet);
    }

    let identity_count = cursor.take_usize_mod(MAX_IDENTITIES.saturating_add(1));
    let wallets: Vec<String> = eph.wallets.iter().cloned().collect();

    for _ in 0..identity_count {
        if wallets.is_empty() {
            break;
        }

        let peer = peer_from_seed(cursor.take_u8());
        let idx = cursor.take_usize_mod(wallets.len());
        eph.identity_map.insert(peer, wallets[idx].clone());
    }

    eph
}

fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn manager_from_cursor(cursor: &mut Cursor<'_>) -> CommandManagerModel {
    match cursor.take_u8() % 3 {
        0 => CommandManagerModel::default(),
        1 => CommandManagerModel::new_no_signals(non_empty_or(
            cursor.take_ascii_string(MAX_DATA_DIR_BYTES),
            "identity.key",
        )),
        _ => CommandManagerModel::new_with_audit(
            cursor.take_ascii_string(MAX_DATA_DIR_BYTES),
            cursor.take_ascii_string(MAX_DATA_DIR_BYTES),
            non_empty_or(cursor.take_ascii_string(MAX_DATA_DIR_BYTES), "identity.key"),
        ),
    }
}


fn chat_from_cursor(cursor: &mut Cursor<'_>) -> ChatMessageModel {
    let plaintext = if cursor.take_bool() {
        Some(cursor.take_ascii_string(MAX_CHAT_TEXT_BYTES))
    } else {
        None
    };

    ChatMessageModel {
        from_wallet: wallet_from_seed(cursor.take_u8()),
        to_wallet: wallet_from_seed(cursor.take_u8()),
        timestamp_ms: cursor.take_u64(),
        plaintext,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum WireCommand {
    MarkStarted,
    StopNode,
    SendNetCmd,
    AttachNet { state: u8, cap: u8, queued: u8 },
    ReplaceChain,
    TakeChain,
    ReloadRegistry,
    InitializeBlockchainEmpty,
    SaveOutgoingChat { data_dir: String, text: String },
}

fn fuzz_wire_decoding(cursor: &mut Cursor<'_>) {
    let len = cursor.take_usize_mod(1024);
    let mut raw = Vec::with_capacity(len);
    for _ in 0..len {
        raw.push(cursor.take_u8());
    }

    let decoded = std::panic::catch_unwind(|| postcard::from_bytes::<WireCommand>(&raw));
    assert!(decoded.is_ok());

    let expected_state = cursor.take_u8();
    let expected_cap = cursor.take_u8();
    let expected_queued = cursor.take_u8();

    let wire = WireCommand::AttachNet {
        state: expected_state,
        cap: expected_cap,
        queued: expected_queued,
    };

    let encoded = postcard::to_allocvec(&wire).expect("WireCommand should encode");
    let roundtrip: WireCommand =
        postcard::from_bytes(&encoded).expect("freshly encoded WireCommand should decode");

    match roundtrip {
        WireCommand::AttachNet { state, cap, queued } => {
            assert_eq!(state, expected_state);
            assert_eq!(cap, expected_cap);
            assert_eq!(queued, expected_queued);
        }
        _ => panic!("unexpected wire command roundtrip variant"),
    }
}

fn run_fixed_regressions() {
    let mut mgr = CommandManagerModel::default();

    assert_eq!(mgr.send_net_cmd(), Err(ModelErrorKind::NetworkNotRunning));
    assert_eq!(mgr.set_p2p_handle(), Err(ModelErrorKind::CannotSetHandleBeforeStart));
    assert_eq!(mgr.stop_node(), Err(ModelErrorKind::P2pNotRunning));
    assert_eq!(mgr.initialize_blockchain_empty(), Ok(()));

    assert_eq!(mgr.mark_started(), Ok(()));
    assert_eq!(mgr.mark_started(), Err(ModelErrorKind::P2pAlreadyRunning));
    assert_eq!(mgr.set_p2p_handle(), Ok(()));

    mgr.attach_net_tx(NetState::Ready, 1, 0);
    assert_eq!(mgr.send_net_cmd(), Ok(()));
    assert_eq!(mgr.send_net_cmd(), Err(ModelErrorKind::NetworkFull));

    mgr.chain_present = true;
    mgr.blockchain_db_guard = true;

    assert_eq!(
        mgr.initialize_blockchain_empty(),
        Err(ModelErrorKind::DestructiveWhileRunning)
    );

    assert_eq!(mgr.stop_node(), Ok(()));
    assert!(!mgr.p2p_running);
    assert!(!mgr.p2p_handle);
    assert!(!mgr.chain_present);
    assert!(!mgr.blockchain_db_guard);
    assert_eq!(mgr.net_queue.state, NetState::Missing);

    // Public attach_net_tx does not require the node to be running. Holding a
    // sender while stopped is legal; user-facing send paths still call
    // ensure_node_running() before trying to use it.
    let mut mgr = CommandManagerModel::default();
    mgr.attach_net_tx(NetState::Closed, 1, 0);
    assert!(!mgr.p2p_running);
    assert_eq!(mgr.net_queue.state, NetState::Closed);
    assert_eq!(mgr.send_message(), Err(ModelErrorKind::P2pNotRunning));
    mgr.assert_invariants();

    let mut mgr = CommandManagerModel::default();
    let mut eph = EphemeralRegistryModel::default();
    let wallet = wallet_from_seed(7);
    eph.wallets.insert(wallet.clone());
    eph.join_heights.insert(wallet.clone(), 42);
    eph.identity_map.insert("peer".to_string(), wallet.clone());
    mgr.node_ephemeral = Some(eph);
    assert_eq!(mgr.reload_registry_from_db(), Ok(()));
    let reg = mgr.node_registry.expect("registry snapshot should exist");
    assert!(reg.wallets.contains(&wallet));
    assert_eq!(reg.join_heights.get(&wallet), Some(&42));

    let mgr = CommandManagerModel::default();
    let huge = "x".repeat(MAX_LOG_MESSAGE_BYTES.saturating_add(512));
    let chat = ChatMessageModel {
        from_wallet: wallet_from_seed(1),
        to_wallet: wallet_from_seed(2),
        timestamp_ms: 1,
        plaintext: Some(huge),
    };
    let out = mgr.save_outgoing_chat_json("data", &chat, true, true, true);
    assert!(out.wrote);
    assert_eq!(out.message_len, MAX_LOG_MESSAGE_BYTES);
    assert_eq!(
        out.path.as_deref(),
        Some("data/sender.message/sent_chat.jsonl")
    );
}

fn fuzz_lifecycle(cursor: &mut Cursor<'_>) {
    let mut mgr = manager_from_cursor(cursor);
    let ops = cursor.take_usize_mod(MAX_OPS.saturating_add(1));

    for _ in 0..ops {
        match cursor.take_u8() % 18 {
            0 => {
                let _ = mgr.mark_started();
            }
            1 => {
                let _ = mgr.set_p2p_handle();
            }
            2 => {
                let _ = mgr.stop_node();
            }
            3 => {
                let state = net_state_from_byte(cursor.take_u8());
                let cap = cursor.take_usize_mod(MAX_QUEUE_CAP.saturating_add(1)).max(1);
                let queued = cursor.take_usize_mod(MAX_QUEUE_CAP.saturating_add(1));
                mgr.attach_net_tx(state, cap, queued);
            }
            4 => {
                let before = mgr.net_queue.queued;
                let result = mgr.send_net_cmd();

                if result.is_ok() {
                    assert!(mgr.net_queue.queued >= before);
                }
            }
            5 => {
                let _ = mgr.chain_mut();
            }
            6 => {
                let _ = mgr.replace_chain();
            }
            7 => {
                let _ = mgr.take_chain();
            }
            8 => {
                if cursor.take_bool() {
                    mgr.node_ephemeral = Some(ephemeral_from_cursor(cursor));
                } else {
                    mgr.node_ephemeral = None;
                }
            }
            9 => {
                let _ = mgr.reload_registry_from_db();
            }
            10 => {
                let was_running = mgr.p2p_running;
                let result = mgr.initialize_blockchain_empty();

                if was_running {
                    assert_eq!(result, Err(ModelErrorKind::DestructiveWhileRunning));
                } else {
                    assert_eq!(result, Ok(()));
                }
            }
            11 => {
                let result = mgr.create_certificates();
                assert_eq!(result.is_ok(), mgr.p2p_running);
            }
            12 => {
                let result = mgr.send_message();

                if !mgr.p2p_running {
                    assert_eq!(result, Err(ModelErrorKind::P2pNotRunning));
                }
            }
            13 => {
                let result = mgr.send_files();

                if !mgr.p2p_running {
                    assert_eq!(result, Err(ModelErrorKind::P2pNotRunning));
                }
            }
            14 => {
                let result = mgr.play_slot_machine();

                if !mgr.p2p_running {
                    assert_eq!(result, Err(ModelErrorKind::P2pNotRunning));
                }
            }
            15 => {
                mgr.local_wallet = if cursor.take_bool() {
                    wallet_from_seed(cursor.take_u8())
                } else {
                    String::new()
                };
            }
            16 => {
                mgr.blockchain_db_guard = mgr.p2p_running && cursor.take_bool();
            }
            _ => {
                let data_dir = cursor.take_ascii_string(MAX_DATA_DIR_BYTES);
                let chat = chat_from_cursor(cursor);
                let out = mgr.save_outgoing_chat_json(
                    &data_dir,
                    &chat,
                    cursor.take_bool(),
                    cursor.take_bool(),
                    cursor.take_bool(),
                );

                assert!(out.message_len <= MAX_LOG_MESSAGE_BYTES);
                if let Some(path) = out.path {
                    assert!(path.ends_with("sender.message/sent_chat.jsonl"));
                }
            }
        }

        mgr.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    // If a node is still running at the end, model a clean shutdown and verify
    // the same cleanup guarantees production stop_node promises.
    if mgr.p2p_running {
        assert_eq!(mgr.stop_node(), Ok(()));
    }

    mgr.assert_invariants();
}

fuzz_target!(|data: &[u8]| {
    run_fixed_regressions();

    let mut cursor = Cursor::new(data);

    match cursor.take_u8() % 3 {
        0 => fuzz_lifecycle(&mut cursor),
        1 => fuzz_wire_decoding(&mut cursor),
        _ => {
            fuzz_lifecycle(&mut cursor);
            fuzz_wire_decoding(&mut cursor);
        }
    }
});
