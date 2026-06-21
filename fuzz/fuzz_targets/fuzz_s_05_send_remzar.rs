// fuzz/fuzz_targets/fuzz_s_05_send_remzar.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const MAX_YN_INPUT_LEN: usize = 16;
const MAX_MODE_INPUT_LEN: usize = 16;
const MAX_BATCH_INPUT_LEN: usize = 16;
const MAX_BATCH_RECIPIENTS: usize = 10;
const MAX_WALLET_INPUT_LEN: usize = 256;
const MAX_AMOUNT_INPUT_LEN: usize = 256;
const MAX_PRIVATE_RECEIVE_INVOICE_LEN_MODEL: usize = 4096;
const ML_DSA_65_SK_LEN_MODEL: usize = 4032;
const ML_DSA_65_SECRET_HEX_CHARS_MODEL: usize = ML_DSA_65_SK_LEN_MODEL * 2;
const MAX_MODEL_RECIPIENTS: usize = 16;
const MAX_POSTCARD_BYTES: usize = 4096;
const MICRO_UNITS_PER_REMZAR: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelErrorKind {
    InputTooLong,
    InvalidYesNo,
    InvalidWallet,
    InvalidAmount,
    InvalidPrivateReceiveInvoice,
    PassphraseMismatch,
    WalletMissing,
    WalletPayloadInvalidUtf8,
    WalletPayloadHexDecodeFailed,
    WalletPayloadLengthUnsupported,
    WalletAddressMismatch,
    InvalidMode,
    InvalidBatchCount,
    SelfSend,
    DuplicateRecipient,
    InvalidTotalAmount,
    InsufficientBalance,
    Cancelled,
    NetworkNotRunning,
    NetworkFull,
    NetworkClosed,
    SerializationFailed,
}

type ModelResult<T> = Result<T, ModelErrorKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletPayloadKind {
    Missing,
    RawSecretMatchesSender,
    RawSecretWrongSender,
    HexSecretMatchesSender,
    HexSecretWrongSender,
    InvalidUtf8Hex,
    InvalidHex,
    UnsupportedLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetState {
    Missing,
    Ready,
    Full,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendMode {
    PublicSingle,
    PrivateReceiveSingle,
    PublicBatch,
    Exit,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WireTx {
    sender: String,
    recipient: String,
    amount_micro: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WireTxKind {
    tag: u8,
    tx: WireTx,
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

    fn take_vec(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }

    fn take_ascii_string(&mut self, max_len: usize) -> String {
        let len = self.take_usize_mod(max_len.saturating_add(1));
        let mut s = String::with_capacity(len);

        for _ in 0..len {
            let b = self.take_u8();
            let ch = match b % 96 {
                0 => '\n',
                1 => '\r',
                2 => '\t',
                x => char::from(32u8.saturating_add(x)),
            };
            s.push(ch);
        }

        s
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = self.take_u8();
        }
    }
}

fn read_line_capped_model(raw: &str, cap: usize) -> ModelResult<String> {
    if raw.len() > cap {
        return Err(ModelErrorKind::InputTooLong);
    }

    Ok(raw.trim().to_string())
}

fn read_yes_no_model(raw: &str, cap: usize) -> ModelResult<bool> {
    let s = read_line_capped_model(raw, cap)?;

    match s.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" => Ok(true),
        "no" | "n" => Ok(false),
        _ => Err(ModelErrorKind::InvalidYesNo),
    }
}

fn is_hex_ascii(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn canon_wallet_id_checked_model(raw: &str) -> ModelResult<String> {
    let s = raw.trim();
    let bytes = s.as_bytes();

    if bytes.len() != 129 {
        return Err(ModelErrorKind::InvalidWallet);
    }

    if bytes.first().copied() != Some(b'r') && bytes.first().copied() != Some(b'R') {
        return Err(ModelErrorKind::InvalidWallet);
    }

    if !bytes[1..].iter().copied().all(is_hex_ascii) {
        return Err(ModelErrorKind::InvalidWallet);
    }

    Ok(format!("r{}", s[1..].to_ascii_lowercase()))
}

fn wallet_from_seed(seed: u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let ch = char::from(HEX[usize::from(seed % 16)]);
    let mut out = String::with_capacity(129);
    out.push('r');
    for _ in 0..128 {
        out.push(ch);
    }
    out
}

fn maybe_wallet_string(cursor: &mut Cursor<'_>) -> String {
    match cursor.take_u8() % 8 {
        0 => wallet_from_seed(cursor.take_u8()),
        1 => wallet_from_seed(cursor.take_u8()).to_ascii_uppercase(),
        2 => "".to_string(),
        3 => "r".to_string(),
        4 => format!("r{}", "0".repeat(127)),
        5 => format!("p{}", "0".repeat(128)),
        6 => format!("r{}g", "0".repeat(127)),
        _ => cursor.take_ascii_string(MAX_WALLET_INPUT_LEN.saturating_add(8)),
    }
}

fn to_micro_units_str_model(input: &str) -> u64 {
    const MAX_HELPER_INPUT_LEN: usize = 64;

    let s = input.trim();

    if s.is_empty() || s.len() > MAX_HELPER_INPUT_LEN {
        return 0;
    }

    if s.starts_with('-') || s.starts_with('+') {
        return 0;
    }

    if s.as_bytes().iter().any(|b| b.is_ascii_whitespace()) {
        return 0;
    }

    if s.contains('e') || s.contains('E') {
        return 0;
    }

    let (whole_part, frac_part) = match s.split_once('.') {
        Some((w, f)) => {
            if f.contains('.') {
                return 0;
            }
            (w, f)
        }
        None => (s, ""),
    };

    if whole_part.is_empty() && frac_part.is_empty() {
        return 0;
    }

    let whole_str = if whole_part.is_empty() { "0" } else { whole_part };

    if !whole_str.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }

    if !frac_part.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return 0;
    }

    if frac_part.len() > 8 {
        return 0;
    }

    let whole = match whole_str.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let mut frac: u64 = 0;

    for &b in frac_part.as_bytes() {
        let digit = match b.checked_sub(b'0') {
            Some(d) => u64::from(d),
            None => return 0,
        };

        frac = match frac.checked_mul(10).and_then(|v| v.checked_add(digit)) {
            Some(v) => v,
            None => return 0,
        };
    }

    for _ in frac_part.len()..8 {
        frac = match frac.checked_mul(10) {
            Some(v) => v,
            None => return 0,
        };
    }

    let whole_scaled = match whole.checked_mul(MICRO_UNITS_PER_REMZAR) {
        Some(v) => v,
        None => return 0,
    };

    whole_scaled.checked_add(frac).unwrap_or_default()
}

fn read_amount_micro_model(raw: &str) -> ModelResult<u64> {
    let amount_s = read_line_capped_model(raw, MAX_AMOUNT_INPUT_LEN)?;
    let normalized = amount_s.trim().replace(',', ".");
    let amount = to_micro_units_str_model(&normalized);

    if amount == 0 {
        return Err(ModelErrorKind::InvalidAmount);
    }

    Ok(amount)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateReceiveSourceModel {
    Invoice,
    RawOneTimeWallet,
}

fn parse_private_receive_target_model(
    raw: &str,
    sender: &str,
) -> ModelResult<(String, PrivateReceiveSourceModel)> {
    let input = read_line_capped_model(raw, MAX_PRIVATE_RECEIVE_INVOICE_LEN_MODEL)?;
    let trimmed = input.trim();
    const PREFIX: &str = "remzar-private-receive:v1:";

    let (wallet_raw, source) = if let Some(rest) = trimmed.strip_prefix(PREFIX) {
        (rest, PrivateReceiveSourceModel::Invoice)
    } else {
        (trimmed, PrivateReceiveSourceModel::RawOneTimeWallet)
    };

    let one_time_wallet = canon_wallet_id_checked_model(wallet_raw)
        .map_err(|_| ModelErrorKind::InvalidPrivateReceiveInvoice)?;

    if one_time_wallet == sender {
        return Err(ModelErrorKind::SelfSend);
    }

    Ok((one_time_wallet, source))
}

fn maybe_private_receive_target(cursor: &mut Cursor<'_>) -> String {
    match cursor.take_u8() % 7 {
        0 => wallet_from_seed(cursor.take_u8()),
        1 => format!("remzar-private-receive:v1:{}", wallet_from_seed(cursor.take_u8())),
        2 => "remzar-private-receive:v1:".to_string(),
        3 => "remzar-private-receive:v2:not-supported".to_string(),
        4 => format!("remzar-private-receive:v1:p{}", "0".repeat(128)),
        5 => cursor.take_ascii_string(MAX_PRIVATE_RECEIVE_INVOICE_LEN_MODEL.saturating_add(8)),
        _ => maybe_wallet_string(cursor),
    }
}

fn amount_string_from_cursor(cursor: &mut Cursor<'_>) -> String {
    match cursor.take_u8() % 12 {
        0 => "0".to_string(),
        1 => "0.00000001".to_string(),
        2 => "1".to_string(),
        3 => "1.00000000".to_string(),
        4 => "1,5".to_string(),
        5 => "18446744073709551615".to_string(),
        6 => "0.000000001".to_string(),
        7 => "abc".to_string(),
        8 => "-1".to_string(),
        9 => ".5".to_string(),
        10 => "2.".to_string(),
        _ => cursor.take_ascii_string(MAX_AMOUNT_INPUT_LEN.saturating_add(8)),
    }
}

#[derive(Debug)]
struct SendScenario {
    proceed_raw: String,
    sender_raw: String,
    passphrase: String,
    confirm_passphrase: String,
    wallet_payload_kind: WalletPayloadKind,
    mode: SendMode,
    batch_count_raw: String,
    batch_confirm_raw: String,
    recipient_raws: Vec<String>,
    amount_raw: String,
    final_confirm_raw: String,
    cached_balance: u64,
    canonical_balance: u64,
    balance_now: u64,
    net_state: NetState,
    existing_hash_slots: HashSet<usize>,
}

impl SendScenario {
    fn from_cursor(cursor: &mut Cursor<'_>) -> Self {
        let proceed_raw = match cursor.take_u8() % 6 {
            0 => "yes".to_string(),
            1 => "y".to_string(),
            2 => "no".to_string(),
            3 => "n".to_string(),
            4 => "maybe".to_string(),
            _ => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
        };

        let sender_seed = cursor.take_u8();
        let sender_raw = if cursor.take_bool() {
            wallet_from_seed(sender_seed)
        } else {
            maybe_wallet_string(cursor)
        };

        let passphrase = cursor.take_ascii_string(32);
        let confirm_passphrase = if cursor.take_bool() {
            passphrase.clone()
        } else {
            cursor.take_ascii_string(32)
        };

        let wallet_payload_kind = match cursor.take_u8() % 8 {
            0 => WalletPayloadKind::Missing,
            1 => WalletPayloadKind::RawSecretMatchesSender,
            2 => WalletPayloadKind::RawSecretWrongSender,
            3 => WalletPayloadKind::HexSecretMatchesSender,
            4 => WalletPayloadKind::HexSecretWrongSender,
            5 => WalletPayloadKind::InvalidUtf8Hex,
            6 => WalletPayloadKind::InvalidHex,
            _ => WalletPayloadKind::UnsupportedLength,
        };

        let mode = match cursor.take_u8() % 5 {
            0 => SendMode::PublicSingle,
            1 => SendMode::PrivateReceiveSingle,
            2 => SendMode::PublicBatch,
            3 => SendMode::Exit,
            _ => SendMode::Invalid,
        };

        let batch_count_raw = match cursor.take_u8() % 8 {
            0 => "2".to_string(),
            1 => "10".to_string(),
            2 => "1".to_string(),
            3 => "11".to_string(),
            4 => "abc".to_string(),
            5 => "".to_string(),
            6 => cursor.take_ascii_string(MAX_BATCH_INPUT_LEN.saturating_add(8)),
            _ => (cursor.take_usize_mod(20)).to_string(),
        };

        let batch_confirm_raw = if cursor.take_bool() {
            "yes".to_string()
        } else {
            "no".to_string()
        };

        let recipient_count = cursor.take_usize_mod(MAX_MODEL_RECIPIENTS.saturating_add(1));
        let mut recipient_raws = Vec::with_capacity(recipient_count.max(1));

        if cursor.take_bool() {
            // Ensure at least one valid, non-sender recipient path is covered often.
            recipient_raws.push(wallet_from_seed(sender_seed.wrapping_add(1)));
        }

        for _ in 0..recipient_count {
            if matches!(mode, SendMode::PrivateReceiveSingle) {
                recipient_raws.push(maybe_private_receive_target(cursor));
            } else {
                recipient_raws.push(maybe_wallet_string(cursor));
            }
        }

        if recipient_raws.is_empty() {
            recipient_raws.push(wallet_from_seed(sender_seed.wrapping_add(2)));
        }

        if matches!(mode, SendMode::PrivateReceiveSingle) && cursor.take_bool() {
            recipient_raws[0] = format!(
                "remzar-private-receive:v1:{}",
                wallet_from_seed(sender_seed.wrapping_add(3))
            );
        }

        let amount_raw = amount_string_from_cursor(cursor);

        let final_confirm_raw = match cursor.take_u8() % 5 {
            0 => "yes".to_string(),
            1 => "y".to_string(),
            2 => "no".to_string(),
            3 => "n".to_string(),
            _ => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
        };

        let canonical_balance = match cursor.take_u8() % 6 {
            0 => 0,
            1 => 1,
            2 => 100,
            3 => MICRO_UNITS_PER_REMZAR,
            4 => u64::MAX,
            _ => cursor.take_u64(),
        };

        let cached_balance = if cursor.take_bool() {
            canonical_balance
        } else {
            cursor.take_u64()
        };

        let balance_now = if cursor.take_bool() {
            canonical_balance
        } else {
            cursor.take_u64()
        };

        let net_state = match cursor.take_u8() % 4 {
            0 => NetState::Missing,
            1 => NetState::Ready,
            2 => NetState::Full,
            _ => NetState::Closed,
        };

        let mut existing_hash_slots = HashSet::new();
        let slots = cursor.take_usize_mod(MAX_BATCH_RECIPIENTS.saturating_add(1));
        for _ in 0..slots {
            existing_hash_slots.insert(cursor.take_usize_mod(MAX_BATCH_RECIPIENTS));
        }

        Self {
            proceed_raw,
            sender_raw,
            passphrase,
            confirm_passphrase,
            wallet_payload_kind,
            mode,
            batch_count_raw,
            batch_confirm_raw,
            recipient_raws,
            amount_raw,
            final_confirm_raw,
            cached_balance,
            canonical_balance,
            balance_now,
            net_state,
            existing_hash_slots,
        }
    }
}

#[derive(Debug, Default)]
struct SendOutcome {
    returned_to_menu: bool,
    queued: usize,
    broadcasts: usize,
    duplicate_hashes: usize,
    repaired_cache: bool,
    final_balance_checked: bool,
    mempool_writes: usize,
    errors: Vec<ModelErrorKind>,
}

#[derive(Debug)]
struct SendHarness {
    account_cache: HashMap<String, u64>,
    canonical_balances: HashMap<String, u64>,
    mempool_by_hash: HashSet<[u8; 32]>,
    broadcasts: Vec<WireTx>,
}

impl SendHarness {
    fn new() -> Self {
        Self {
            account_cache: HashMap::new(),
            canonical_balances: HashMap::new(),
            mempool_by_hash: HashSet::new(),
            broadcasts: Vec::new(),
        }
    }

    fn send_net_cmd_model(&mut self, state: NetState, tx: WireTx) -> ModelResult<()> {
        match state {
            NetState::Missing => Err(ModelErrorKind::NetworkNotRunning),
            NetState::Ready => {
                self.broadcasts.push(tx);
                Ok(())
            }
            NetState::Full => Err(ModelErrorKind::NetworkFull),
            NetState::Closed => Err(ModelErrorKind::NetworkClosed),
        }
    }

    fn wallet_payload_derived_sender_matches(
        &self,
        payload_kind: WalletPayloadKind,
        sender: &str,
    ) -> ModelResult<bool> {
        match payload_kind {
            WalletPayloadKind::Missing => Err(ModelErrorKind::WalletMissing),
            WalletPayloadKind::RawSecretMatchesSender | WalletPayloadKind::HexSecretMatchesSender => {
                let _expected_len = match payload_kind {
                    WalletPayloadKind::RawSecretMatchesSender => ML_DSA_65_SK_LEN_MODEL,
                    WalletPayloadKind::HexSecretMatchesSender => ML_DSA_65_SECRET_HEX_CHARS_MODEL,
                    _ => unreachable!(),
                };
                Ok(true)
            }
            WalletPayloadKind::RawSecretWrongSender | WalletPayloadKind::HexSecretWrongSender => {
                let derived = wallet_from_seed(250);
                Ok(derived == sender)
            }
            WalletPayloadKind::InvalidUtf8Hex => Err(ModelErrorKind::WalletPayloadInvalidUtf8),
            WalletPayloadKind::InvalidHex => Err(ModelErrorKind::WalletPayloadHexDecodeFailed),
            WalletPayloadKind::UnsupportedLength => {
                Err(ModelErrorKind::WalletPayloadLengthUnsupported)
            }
        }
    }

    fn select_recipients_and_amount(
        &self,
        scenario: &SendScenario,
        sender: &str,
    ) -> ModelResult<(Vec<String>, u64)> {
        match scenario.mode {
            SendMode::PublicSingle => {
                let raw = scenario
                    .recipient_raws
                    .first()
                    .map(String::as_str)
                    .unwrap_or_default();
                let recipient = canon_wallet_id_checked_model(raw)?;

                if recipient == sender {
                    return Err(ModelErrorKind::SelfSend);
                }

                let amount = read_amount_micro_model(&scenario.amount_raw)?;
                Ok((vec![recipient], amount))
            }
            SendMode::PrivateReceiveSingle => {
                let raw = scenario
                    .recipient_raws
                    .first()
                    .map(String::as_str)
                    .unwrap_or_default();
                let (recipient, _source) = parse_private_receive_target_model(raw, sender)?;
                let amount = read_amount_micro_model(&scenario.amount_raw)?;
                Ok((vec![recipient], amount))
            }
            SendMode::PublicBatch => {
                let n_s = read_line_capped_model(&scenario.batch_count_raw, MAX_BATCH_INPUT_LEN)?;
                let n = n_s
                    .parse::<usize>()
                    .map_err(|_| ModelErrorKind::InvalidBatchCount)?;

                if !(2..=MAX_BATCH_RECIPIENTS).contains(&n) {
                    return Err(ModelErrorKind::InvalidBatchCount);
                }

                if !read_yes_no_model(&scenario.batch_confirm_raw, MAX_YN_INPUT_LEN)? {
                    return Err(ModelErrorKind::Cancelled);
                }

                let mut recipients = Vec::with_capacity(n);
                let mut seen = HashSet::<String>::new();

                for i in 0..n {
                    let raw = scenario
                        .recipient_raws
                        .get(i)
                        .map(String::as_str)
                        .unwrap_or_default();
                    let recipient = canon_wallet_id_checked_model(raw)?;

                    if recipient == sender {
                        return Err(ModelErrorKind::SelfSend);
                    }

                    if !seen.insert(recipient.clone()) {
                        return Err(ModelErrorKind::DuplicateRecipient);
                    }

                    recipients.push(recipient);
                }

                let amount = read_amount_micro_model(&scenario.amount_raw)?;
                Ok((recipients, amount))
            }
            SendMode::Exit => Err(ModelErrorKind::Cancelled),
            SendMode::Invalid => Err(ModelErrorKind::InvalidMode),
        }
    }

    fn run_send_model(&mut self, scenario: &SendScenario) -> SendOutcome {
        let mut outcome = SendOutcome::default();

        let proceed = match read_yes_no_model(&scenario.proceed_raw, MAX_YN_INPUT_LEN) {
            Ok(v) => v,
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        };

        if !proceed {
            outcome.returned_to_menu = true;
            return outcome;
        }

        let sender = match read_line_capped_model(&scenario.sender_raw, MAX_WALLET_INPUT_LEN)
            .and_then(|s| canon_wallet_id_checked_model(&s))
        {
            Ok(s) => s,
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        };

        if scenario.passphrase != scenario.confirm_passphrase {
            outcome.errors.push(ModelErrorKind::PassphraseMismatch);
            return outcome;
        }

        match self.wallet_payload_derived_sender_matches(scenario.wallet_payload_kind, &sender) {
            Ok(true) => {}
            Ok(false) => {
                outcome.errors.push(ModelErrorKind::WalletAddressMismatch);
                return outcome;
            }
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        }

        let (recipients, amount_each) = match self.select_recipients_and_amount(scenario, &sender) {
            Ok(v) => v,
            Err(ModelErrorKind::Cancelled) => {
                outcome.returned_to_menu = true;
                return outcome;
            }
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        };

        assert!(!recipients.is_empty());
        assert!(recipients.len() <= MAX_BATCH_RECIPIENTS);
        assert!(amount_each > 0);
        assert!(recipients.iter().all(|r| r != &sender));
        assert_eq!(recipients.iter().collect::<HashSet<_>>().len(), recipients.len());

        let total_amount = amount_each.saturating_mul(recipients.len() as u64);
        if total_amount == 0 {
            outcome.errors.push(ModelErrorKind::InvalidTotalAmount);
            return outcome;
        }

        self.account_cache
            .insert(sender.clone(), scenario.cached_balance);
        self.canonical_balances
            .insert(sender.clone(), scenario.canonical_balance);

        let cached_balance = *self.account_cache.get(&sender).unwrap_or(&0);
        let canonical_balance = *self.canonical_balances.get(&sender).unwrap_or(&0);

        if cached_balance != canonical_balance {
            self.account_cache.insert(sender.clone(), canonical_balance);
            outcome.repaired_cache = true;
        }

        if total_amount > canonical_balance {
            outcome.errors.push(ModelErrorKind::InsufficientBalance);
            return outcome;
        }

        let confirmed = match read_yes_no_model(&scenario.final_confirm_raw, MAX_YN_INPUT_LEN) {
            Ok(v) => v,
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        };

        if !confirmed {
            outcome.returned_to_menu = true;
            return outcome;
        }

        outcome.final_balance_checked = true;
        if total_amount > scenario.balance_now {
            outcome.errors.push(ModelErrorKind::InsufficientBalance);
            return outcome;
        }

        for (i, recipient) in recipients.iter().enumerate() {
            let tx = WireTx {
                sender: sender.clone(),
                recipient: recipient.clone(),
                amount_micro: amount_each,
            };

            let tx_kind = WireTxKind { tag: 1, tx: tx.clone() };
            let tx_bytes = match to_allocvec(&tx_kind) {
                Ok(bytes) => bytes,
                Err(_) => {
                    outcome.errors.push(ModelErrorKind::SerializationFailed);
                    return outcome;
                }
            };

            let hash = blake3::hash(&tx_bytes);
            let hash_bytes = *hash.as_bytes();

            if scenario.existing_hash_slots.contains(&i) || self.mempool_by_hash.contains(&hash_bytes) {
                outcome.duplicate_hashes = outcome.duplicate_hashes.saturating_add(1);
            } else {
                self.mempool_by_hash.insert(hash_bytes);
                outcome.mempool_writes = outcome.mempool_writes.saturating_add(1);
            }

            match self.send_net_cmd_model(scenario.net_state, tx) {
                Ok(()) => {
                    outcome.queued = outcome.queued.saturating_add(1);
                    outcome.broadcasts = outcome.broadcasts.saturating_add(1);
                }
                Err(e) => {
                    outcome.errors.push(e);
                    return outcome;
                }
            }
        }

        outcome
    }

    fn assert_invariants(&self) {
        for wallet in self.account_cache.keys() {
            assert!(canon_wallet_id_checked_model(wallet).is_ok());
        }

        for wallet in self.canonical_balances.keys() {
            assert!(canon_wallet_id_checked_model(wallet).is_ok());
        }

        for tx in &self.broadcasts {
            assert!(canon_wallet_id_checked_model(&tx.sender).is_ok());
            assert!(canon_wallet_id_checked_model(&tx.recipient).is_ok());
            assert_ne!(tx.sender, tx.recipient);
            assert!(tx.amount_micro > 0);
        }
    }
}

fn fuzz_prompt_and_parse_helpers(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_ascii_string(300);
    let cap = cursor.take_usize_mod(260);
    let capped = read_line_capped_model(&raw, cap);

    if raw.len() > cap {
        assert_eq!(capped, Err(ModelErrorKind::InputTooLong));
    } else {
        assert_eq!(capped.as_deref(), Ok(raw.trim()));
    }

    assert_eq!(read_yes_no_model("yes", MAX_YN_INPUT_LEN), Ok(true));
    assert_eq!(read_yes_no_model("y", MAX_YN_INPUT_LEN), Ok(true));
    assert_eq!(read_yes_no_model("no", MAX_YN_INPUT_LEN), Ok(false));
    assert_eq!(read_yes_no_model("n", MAX_YN_INPUT_LEN), Ok(false));
    assert_eq!(read_yes_no_model("maybe", MAX_YN_INPUT_LEN), Err(ModelErrorKind::InvalidYesNo));

    let wallet = wallet_from_seed(cursor.take_u8());
    assert!(canon_wallet_id_checked_model(&wallet).is_ok());
    assert_eq!(canon_wallet_id_checked_model(&wallet.to_ascii_uppercase()).unwrap(), wallet);
    assert!(canon_wallet_id_checked_model("r123").is_err());
    assert!(canon_wallet_id_checked_model(&format!("p{}", "0".repeat(128))).is_err());

    assert_eq!(to_micro_units_str_model("0"), 0);
    assert_eq!(to_micro_units_str_model("0.00000001"), 1);
    assert_eq!(to_micro_units_str_model("1"), MICRO_UNITS_PER_REMZAR);
    assert_eq!(to_micro_units_str_model("1.00000000"), MICRO_UNITS_PER_REMZAR);
    assert_eq!(to_micro_units_str_model("1.5"), 150_000_000);
    assert_eq!(to_micro_units_str_model("0.000000001"), 0);
    assert_eq!(to_micro_units_str_model("1 2"), 0);
    assert_eq!(to_micro_units_str_model("1e2"), 0);
    assert_eq!(read_amount_micro_model("1,5"), Ok(150_000_000));

    let one_time = wallet_from_seed(cursor.take_u8());
    let sender = wallet_from_seed(cursor.take_u8().wrapping_add(1));
    if one_time != sender {
        assert!(parse_private_receive_target_model(&one_time, &sender).is_ok());
        let invoice = format!("remzar-private-receive:v1:{one_time}");
        assert!(parse_private_receive_target_model(&invoice, &sender).is_ok());
    }
    assert!(parse_private_receive_target_model("remzar-private-receive:v1:notwallet", &sender).is_err());
}

fn fuzz_send_scenario(cursor: &mut Cursor<'_>, harness: &mut SendHarness) {
    let scenario = SendScenario::from_cursor(cursor);
    let before_broadcasts = harness.broadcasts.len();
    let outcome = harness.run_send_model(&scenario);

    let processed_for_mempool = outcome
        .mempool_writes
        .saturating_add(outcome.duplicate_hashes);

    assert!(outcome.queued <= MAX_BATCH_RECIPIENTS);
    assert!(outcome.broadcasts <= outcome.queued);
    assert!(processed_for_mempool <= MAX_BATCH_RECIPIENTS);

    assert!(outcome.queued <= processed_for_mempool);

    let has_network_error = outcome.errors.iter().any(|e| {
        matches!(
            e,
            ModelErrorKind::NetworkNotRunning
                | ModelErrorKind::NetworkFull
                | ModelErrorKind::NetworkClosed
        )
    });

    if scenario.net_state != NetState::Ready && processed_for_mempool > outcome.queued {
        assert!(has_network_error);
    }

    if scenario.net_state == NetState::Ready {
        assert_eq!(
            harness.broadcasts.len().saturating_sub(before_broadcasts),
            outcome.broadcasts
        );
    } else {
        assert!(outcome.broadcasts <= before_broadcasts.saturating_add(outcome.queued));
    }

    harness.assert_invariants();
}

fn fuzz_wire_decoding(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_vec(MAX_POSTCARD_BYTES);
    let result = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireTxKind>(&raw);
    });
    assert!(result.is_ok());

    let sender = wallet_from_seed(cursor.take_u8());
    let recipient_seed = cursor.take_u8();
    let mut recipient = wallet_from_seed(recipient_seed);
    if recipient == sender {
        recipient = wallet_from_seed(recipient_seed.wrapping_add(1));
    }

    let wire = WireTxKind {
        tag: cursor.take_u8(),
        tx: WireTx {
            sender,
            recipient,
            amount_micro: cursor.take_u64().max(1),
        },
    };

    let encoded = to_allocvec(&wire).expect("wire tx kind should encode");
    let decoded: WireTxKind = from_bytes(&encoded).expect("freshly encoded wire tx kind should decode");

    assert_eq!(decoded, wire);
}

fn regression_send_model_edges() {
    assert_eq!(read_amount_micro_model("0"), Err(ModelErrorKind::InvalidAmount));
    assert_eq!(read_amount_micro_model("0.00000001"), Ok(1));
    assert_eq!(read_amount_micro_model("1.000000001"), Err(ModelErrorKind::InvalidAmount));

    let sender = wallet_from_seed(1);
    let recipient = wallet_from_seed(2);

    let scenario = SendScenario {
        proceed_raw: "yes".to_string(),
        sender_raw: sender.clone(),
        passphrase: "pw".to_string(),
        confirm_passphrase: "pw".to_string(),
        wallet_payload_kind: WalletPayloadKind::RawSecretMatchesSender,
        mode: SendMode::PublicSingle,
        batch_count_raw: "2".to_string(),
        batch_confirm_raw: "yes".to_string(),
        recipient_raws: vec![recipient],
        amount_raw: "0.00000001".to_string(),
        final_confirm_raw: "yes".to_string(),
        cached_balance: 0,
        canonical_balance: 1,
        balance_now: 1,
        net_state: NetState::Ready,
        existing_hash_slots: HashSet::new(),
    };

    let mut harness = SendHarness::new();
    let outcome = harness.run_send_model(&scenario);
    assert_eq!(outcome.queued, 1);
    assert_eq!(outcome.broadcasts, 1);
    assert_eq!(outcome.mempool_writes, 1);
    assert!(outcome.repaired_cache);
    assert!(outcome.errors.is_empty());
    harness.assert_invariants();

    let private_recipient = wallet_from_seed(3);
    let private_scenario = SendScenario {
        mode: SendMode::PrivateReceiveSingle,
        recipient_raws: vec![format!("remzar-private-receive:v1:{private_recipient}")],
        canonical_balance: 2,
        balance_now: 2,
        ..scenario.clone()
    };
    let mut harness = SendHarness::new();
    let outcome = harness.run_send_model(&private_scenario);
    assert_eq!(outcome.queued, 1);
    assert_eq!(outcome.broadcasts, 1);
    assert!(outcome.errors.is_empty());
    harness.assert_invariants();

    let self_send = SendScenario {
        recipient_raws: vec![sender.clone()],
        ..scenario.clone()
    };
    let mut harness = SendHarness::new();
    let outcome = harness.run_send_model(&self_send);
    assert!(outcome.errors.contains(&ModelErrorKind::SelfSend));

    let no_net = SendScenario {
        net_state: NetState::Missing,
        ..scenario
    };
    let mut harness = SendHarness::new();
    let outcome = harness.run_send_model(&no_net);
    assert!(outcome.errors.contains(&ModelErrorKind::NetworkNotRunning));
}

impl Clone for SendScenario {
    fn clone(&self) -> Self {
        Self {
            proceed_raw: self.proceed_raw.clone(),
            sender_raw: self.sender_raw.clone(),
            passphrase: self.passphrase.clone(),
            confirm_passphrase: self.confirm_passphrase.clone(),
            wallet_payload_kind: self.wallet_payload_kind,
            mode: self.mode,
            batch_count_raw: self.batch_count_raw.clone(),
            batch_confirm_raw: self.batch_confirm_raw.clone(),
            recipient_raws: self.recipient_raws.clone(),
            amount_raw: self.amount_raw.clone(),
            final_confirm_raw: self.final_confirm_raw.clone(),
            cached_balance: self.cached_balance,
            canonical_balance: self.canonical_balance,
            balance_now: self.balance_now,
            net_state: self.net_state,
            existing_hash_slots: self.existing_hash_slots.clone(),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    regression_send_model_edges();

    let mut cursor = Cursor::new(data);
    let mut harness = SendHarness::new();

    let iterations = cursor
        .take_usize_mod(256)
        .min(data.len().saturating_add(1))
        .max(1);

    for _ in 0..iterations {
        match cursor.take_u8() % 3 {
            0 => fuzz_prompt_and_parse_helpers(&mut cursor),
            1 => fuzz_send_scenario(&mut cursor, &mut harness),
            _ => fuzz_wire_decoding(&mut cursor),
        }

        harness.assert_invariants();

        if cursor.remaining() == 0 {
            break;
        }
    }

    harness.assert_invariants();
});
