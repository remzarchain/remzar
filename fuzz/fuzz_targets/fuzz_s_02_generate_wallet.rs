// fuzz/fuzz_targets/fuzz_s_02_generate_wallet.rs

#![no_main]

use libfuzzer_sys::fuzz_target;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_YN_INPUT_LEN: usize = 16;
const MAX_MODE_INPUT_LEN: usize = 16;
const MAX_BATCH_INPUT_LEN: usize = 16;
const MAX_BATCH_WALLETS: usize = 10;
const MIN_BATCH_WALLETS: usize = 2;
const MAX_PASS_PROMPTS: usize = 3;
const MAX_INPUT_BYTES: usize = 4096;
const MAX_WALLET_INPUT_LEN: usize = 256;
const WALLET_LEN: usize = 129;

type ModelResult<T> = Result<T, ModelErrorKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelErrorKind {
    InputTooLong,
    InvalidYesNo,
    InvalidMode,
    InvalidBatchCount,
    InvalidWallet,
    PassphraseReadFailed,
    PassphraseMismatch,
    TooManyPassphraseAttempts,
    DirectoryInitFailed,
    WalletDirCreateFailed,
    WalletFileAlreadyExists,
    WalletTempWriteFailed,
    WalletRenameFailed,
    WalletQrGenerateFailed,
    PrivateReceiveCreateFailed,
    PrivateReceiveIndexFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Single,
    Multiple,
    PrivateReceive,
    WalletQr,
    Exit,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GenerateOutcome {
    generated_wallets: usize,
    qr_generated: bool,
    private_receive_generated: bool,
    cancelled: bool,
    errors: Vec<ModelErrorKind>,
}

#[derive(Debug, Default)]
struct WalletFsModel {
    wallets: HashSet<String>,
    tmp_files: HashSet<String>,
    directory_init_fails: bool,
    wallet_dir_create_fails: bool,
    tmp_write_fails: bool,
    rename_fails: bool,
    private_index_fails: bool,
}

impl WalletFsModel {
    fn new(cursor: &mut Cursor<'_>) -> Self {
        let mut wallets = HashSet::new();

        let existing = cursor.take_usize_mod(8);
        for _ in 0..existing {
            wallets.insert(wallet_from_seed(cursor.take_u8()));
        }

        Self {
            wallets,
            tmp_files: HashSet::new(),
            directory_init_fails: cursor.take_bool(),
            wallet_dir_create_fails: cursor.take_bool(),
            tmp_write_fails: cursor.take_bool(),
            rename_fails: cursor.take_bool(),
            private_index_fails: cursor.take_bool(),
        }
    }

    fn create_wallets_directory(&self) -> ModelResult<()> {
        if self.directory_init_fails {
            return Err(ModelErrorKind::DirectoryInitFailed);
        }

        if self.wallet_dir_create_fails {
            return Err(ModelErrorKind::WalletDirCreateFailed);
        }

        Ok(())
    }

    fn atomic_write_wallet(&mut self, wallet: &str, encrypted_secret: &[u8]) -> ModelResult<()> {
        let wallet = canon_wallet_id_checked_model(wallet)?;

        if self.wallets.contains(&wallet) {
            return Err(ModelErrorKind::WalletFileAlreadyExists);
        }

        let tmp_name = format!("{wallet}.wallet.tmp");

        self.tmp_files.remove(&tmp_name);

        if self.tmp_write_fails || encrypted_secret.is_empty() {
            return Err(ModelErrorKind::WalletTempWriteFailed);
        }

        self.tmp_files.insert(tmp_name.clone());

        if self.rename_fails {
            return Err(ModelErrorKind::WalletRenameFailed);
        }

        self.tmp_files.remove(&tmp_name);
        self.wallets.insert(wallet);

        Ok(())
    }

    fn create_private_receive_wallet(
        &mut self,
        owner_wallet: &str,
        one_time_seed: u8,
        passphrase: &str,
    ) -> ModelResult<String> {
        let owner_wallet = canon_wallet_id_checked_model(owner_wallet)?;

        if !self.wallets.contains(&owner_wallet) || passphrase.is_empty() {
            return Err(ModelErrorKind::PrivateReceiveCreateFailed);
        }

        let one_time_wallet = wallet_from_seed(one_time_seed);
        let encrypted_secret = fake_encrypt_secret(one_time_seed, passphrase);
        self.atomic_write_wallet(&one_time_wallet, &encrypted_secret)
            .map_err(|_| ModelErrorKind::PrivateReceiveCreateFailed)?;

        if self.private_index_fails {
            return Err(ModelErrorKind::PrivateReceiveIndexFailed);
        }

        Ok(one_time_wallet)
    }

    fn has_wallet(&self, wallet: &str) -> bool {
        canon_wallet_id_checked_model(wallet)
            .map(|w| self.wallets.contains(&w))
            .unwrap_or(false)
    }

    fn assert_invariants(&self) {
        for wallet in &self.wallets {
            assert!(canon_wallet_id_checked_model(wallet).is_ok());
        }

        for tmp in &self.tmp_files {
            assert!(tmp.ends_with(".wallet.tmp"));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedWalletModel {
    address: String,
    encrypted_secret: Vec<u8>,
}

impl GeneratedWalletModel {
    fn new(seed: u8, passphrase: &str) -> ModelResult<Self> {
        if passphrase.is_empty() {
            return Err(ModelErrorKind::PassphraseReadFailed);
        }

        let address = wallet_from_seed(seed);
        let encrypted_secret = fake_encrypt_secret(seed, passphrase);

        Ok(Self {
            address,
            encrypted_secret,
        })
    }

    fn validate_self(&self) -> ModelResult<()> {
        canon_wallet_id_checked_model(&self.address)?;
        if self.encrypted_secret.is_empty() {
            return Err(ModelErrorKind::WalletTempWriteFailed);
        }
        Ok(())
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
                v => char::from(32u8.saturating_add(v)),
            };
            s.push(ch);
        }

        s
    }
}

fn is_hex_ascii(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
}

fn canon_wallet_id_checked_model(raw: &str) -> ModelResult<String> {
    let s = raw.trim();
    let bytes = s.as_bytes();

    if bytes.len() != WALLET_LEN {
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

    let mut out = String::with_capacity(WALLET_LEN);
    out.push('r');

    let base = usize::from(seed % 16);
    for i in 0..128usize {
        let idx = (base + i) % HEX.len();
        out.push(char::from(HEX[idx]));
    }

    out
}

fn maybe_wallet_string(cursor: &mut Cursor<'_>) -> String {
    match cursor.take_u8() % 9 {
        0 => wallet_from_seed(cursor.take_u8()),
        1 => wallet_from_seed(cursor.take_u8()).to_ascii_uppercase(),
        2 => String::new(),
        3 => "r".to_string(),
        4 => format!("r{}", "0".repeat(127)),
        5 => format!("p{}", "0".repeat(128)),
        6 => format!("r{}g", "0".repeat(127)),
        7 => format!(" {} ", wallet_from_seed(cursor.take_u8())),
        _ => cursor.take_ascii_string(MAX_WALLET_INPUT_LEN.saturating_add(16)),
    }
}

fn fake_encrypt_secret(seed: u8, passphrase: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"wallet-secret-v1:");
    out.push(seed);
    out.extend_from_slice(passphrase.as_bytes());

    // Do not let arbitrary large fuzz strings create huge model allocations.
    out.truncate(256);
    out
}

fn read_line_capped_model(input: &str, cap: usize) -> ModelResult<String> {
    if input.len() > cap {
        return Err(ModelErrorKind::InputTooLong);
    }

    Ok(input.trim().to_string())
}

fn parse_yes_no_model(input: &str) -> ModelResult<bool> {
    let s = read_line_capped_model(input, MAX_YN_INPUT_LEN)?;

    match s.to_ascii_lowercase().as_str() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(ModelErrorKind::InvalidYesNo),
    }
}

fn parse_mode_model(input: &str) -> ModelResult<Mode> {
    let s = read_line_capped_model(input, MAX_MODE_INPUT_LEN)?;

    match s.as_str() {
        "1" => Ok(Mode::Single),
        "2" => Ok(Mode::Multiple),
        "3" => Ok(Mode::PrivateReceive),
        "4" => Ok(Mode::WalletQr),
        "5" => Ok(Mode::Exit),
        _ => Err(ModelErrorKind::InvalidMode),
    }
}

fn parse_batch_count_model(input: &str) -> ModelResult<usize> {
    let s = read_line_capped_model(input, MAX_BATCH_INPUT_LEN)?;

    match s.parse::<usize>() {
        Ok(n) if (MIN_BATCH_WALLETS..=MAX_BATCH_WALLETS).contains(&n) => Ok(n),
        _ => Err(ModelErrorKind::InvalidBatchCount),
    }
}

fn passphrase_attempts_model(attempts: &[(String, String)]) -> ModelResult<String> {
    let mut used_attempts = 0usize;

    for (pass, confirm) in attempts.iter().take(MAX_PASS_PROMPTS.saturating_add(1)) {
        used_attempts = used_attempts.saturating_add(1);

        if used_attempts > MAX_PASS_PROMPTS {
            return Err(ModelErrorKind::TooManyPassphraseAttempts);
        }

        if pass.is_empty() || confirm.is_empty() {
            return Err(ModelErrorKind::PassphraseReadFailed);
        }

        if pass != confirm {
            continue;
        }

        return Ok(pass.clone());
    }

    Err(ModelErrorKind::PassphraseMismatch)
}

fn passphrase_attempts_from_cursor(cursor: &mut Cursor<'_>) -> Vec<(String, String)> {
    let count = cursor.take_usize_mod(MAX_PASS_PROMPTS.saturating_add(3));
    let mut attempts = Vec::with_capacity(count);

    for _ in 0..count {
        let pass = match cursor.take_u8() % 6 {
            0 => "strong-passphrase!1".to_string(),
            1 => "short".to_string(),
            2 => String::new(),
            3 => cursor.take_ascii_string(32),
            4 => "same".to_string(),
            _ => "different".to_string(),
        };

        let confirm = match cursor.take_u8() % 6 {
            0 => pass.clone(),
            1 => "mismatch".to_string(),
            2 => String::new(),
            3 => cursor.take_ascii_string(32),
            4 => "same".to_string(),
            _ => "different".to_string(),
        };

        attempts.push((pass, confirm));
    }

    attempts
}

fn qr_flow_model(
    cursor: &mut Cursor<'_>,
    fs: &WalletFsModel,
    outcome: &mut GenerateOutcome,
) -> ModelResult<()> {
    let confirm_input = match cursor.take_u8() % 5 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "maybe".to_string(),
        3 => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
        _ => "YES".to_string(),
    };

    let confirmed = parse_yes_no_model(&confirm_input)?;
    if !confirmed {
        outcome.cancelled = true;
        return Ok(());
    }

    let wallet_in = maybe_wallet_string(cursor);
    let wallet = canon_wallet_id_checked_model(&wallet_in)?;

    let attempts = passphrase_attempts_from_cursor(cursor);
    let passphrase = passphrase_attempts_model(&attempts).map_err(|_| ModelErrorKind::WalletQrGenerateFailed)?;

    // Production QR generation verifies ownership via wallet file/passphrase.
    // The model requires the wallet file to exist and the passphrase to be non-empty.
    if !fs.has_wallet(&wallet) || passphrase.is_empty() {
        return Err(ModelErrorKind::WalletQrGenerateFailed);
    }

    outcome.qr_generated = true;
    Ok(())
}

fn private_receive_flow_model(
    cursor: &mut Cursor<'_>,
    fs: &mut WalletFsModel,
    outcome: &mut GenerateOutcome,
) -> ModelResult<()> {
    let confirm_input = match cursor.take_u8() % 5 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "maybe".to_string(),
        3 => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
        _ => "YES".to_string(),
    };

    let confirmed = parse_yes_no_model(&confirm_input)?;
    if !confirmed {
        outcome.cancelled = true;
        return Ok(());
    }

    let owner_wallet_in = maybe_wallet_string(cursor);
    let owner_wallet = canon_wallet_id_checked_model(&owner_wallet_in)?;

    let attempts = passphrase_attempts_from_cursor(cursor);
    let passphrase = passphrase_attempts_model(&attempts)
        .map_err(|_| ModelErrorKind::PrivateReceiveCreateFailed)?;

    let one_time_seed = cursor.take_u8();
    match fs.create_private_receive_wallet(&owner_wallet, one_time_seed, &passphrase) {
        Ok(one_time_wallet) => {
            assert!(canon_wallet_id_checked_model(&one_time_wallet).is_ok());
            outcome.private_receive_generated = true;
            Ok(())
        }
        Err(e @ ModelErrorKind::PrivateReceiveIndexFailed) => {
            // Production can create the one-time wallet and then fail while
            // indexing it. That is an error return with durable partial output.
            outcome.private_receive_generated = true;
            Err(e)
        }
        Err(e) => Err(e),
    }
}

fn generate_wallet_flow_model(cursor: &mut Cursor<'_>, fs: &mut WalletFsModel) -> GenerateOutcome {
    let mut outcome = GenerateOutcome::default();

    let confirm_input = match cursor.take_u8() % 6 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "YES".to_string(),
        3 => "NO".to_string(),
        4 => "maybe".to_string(),
        _ => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
    };

    let proceed = match parse_yes_no_model(&confirm_input) {
        Ok(v) => v,
        Err(e) => {
            outcome.errors.push(e);
            return outcome;
        }
    };

    if !proceed {
        outcome.cancelled = true;
        return outcome;
    }

    let mode_input = match cursor.take_u8() % 8 {
        0 => "1".to_string(),
        1 => "2".to_string(),
        2 => "3".to_string(),
        3 => "4".to_string(),
        4 => "5".to_string(),
        5 => "0".to_string(),
        6 => "99".to_string(),
        _ => cursor.take_ascii_string(MAX_MODE_INPUT_LEN.saturating_add(8)),
    };

    let mode = match parse_mode_model(&mode_input) {
        Ok(v) => v,
        Err(e) => {
            outcome.errors.push(e);
            return outcome;
        }
    };

    let batch_count = match mode {
        Mode::Single => 1usize,
        Mode::Multiple => {
            let count_input = match cursor.take_u8() % 8 {
                0 => "2".to_string(),
                1 => "10".to_string(),
                2 => "1".to_string(),
                3 => "11".to_string(),
                4 => "abc".to_string(),
                5 => cursor.take_ascii_string(MAX_BATCH_INPUT_LEN.saturating_add(8)),
                _ => (cursor.take_usize_mod(16)).to_string(),
            };

            let n = match parse_batch_count_model(&count_input) {
                Ok(v) => v,
                Err(e) => {
                    outcome.errors.push(e);
                    return outcome;
                }
            };

            let confirm_batch_input = match cursor.take_u8() % 5 {
                0 => "yes".to_string(),
                1 => "no".to_string(),
                2 => "YES".to_string(),
                3 => "maybe".to_string(),
                _ => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
            };

            match parse_yes_no_model(&confirm_batch_input) {
                Ok(true) => n,
                Ok(false) => {
                    outcome.cancelled = true;
                    return outcome;
                }
                Err(e) => {
                    outcome.errors.push(e);
                    return outcome;
                }
            }
        }
        Mode::PrivateReceive => {
            if let Err(e) = private_receive_flow_model(cursor, fs, &mut outcome) {
                outcome.errors.push(e);
            }
            return outcome;
        }
        Mode::WalletQr => {
            if let Err(e) = qr_flow_model(cursor, fs, &mut outcome) {
                outcome.errors.push(e);
            }
            return outcome;
        }
        Mode::Exit => {
            outcome.cancelled = true;
            return outcome;
        }
    };

    let security_input = match cursor.take_u8() % 5 {
        0 => "yes".to_string(),
        1 => "no".to_string(),
        2 => "YES".to_string(),
        3 => "maybe".to_string(),
        _ => cursor.take_ascii_string(MAX_YN_INPUT_LEN.saturating_add(8)),
    };

    match parse_yes_no_model(&security_input) {
        Ok(true) => {}
        Ok(false) => {
            outcome.cancelled = true;
            return outcome;
        }
        Err(e) => {
            outcome.errors.push(e);
            return outcome;
        }
    }

    let attempts = passphrase_attempts_from_cursor(cursor);
    let passphrase = match passphrase_attempts_model(&attempts) {
        Ok(p) => p,
        Err(e) => {
            outcome.errors.push(e);
            return outcome;
        }
    };

    if let Err(e) = fs.create_wallets_directory() {
        outcome.errors.push(e);
        return outcome;
    }

    for _ in 0..batch_count {
        let seed = cursor.take_u8();
        let wallet = match GeneratedWalletModel::new(seed, &passphrase) {
            Ok(w) => w,
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        };

        if let Err(e) = wallet.validate_self() {
            outcome.errors.push(e);
            return outcome;
        }

        match fs.atomic_write_wallet(&wallet.address, &wallet.encrypted_secret) {
            Ok(()) => {
                outcome.generated_wallets = outcome.generated_wallets.saturating_add(1);
            }
            Err(e) => {
                outcome.errors.push(e);
                return outcome;
            }
        }
    }

    outcome
}

fn fuzz_parse_helpers(cursor: &mut Cursor<'_>) {
    let s = cursor.take_ascii_string(MAX_INPUT_BYTES.saturating_add(32));
    let cap = cursor.take_usize_mod(MAX_INPUT_BYTES.saturating_add(1));
    let parsed = read_line_capped_model(&s, cap);

    if s.len() > cap {
        assert_eq!(parsed, Err(ModelErrorKind::InputTooLong));
    } else {
        assert_eq!(parsed.as_deref(), Ok(s.trim()));
    }

    assert_eq!(parse_yes_no_model("yes"), Ok(true));
    assert_eq!(parse_yes_no_model("no"), Ok(false));
    assert_eq!(parse_yes_no_model("YES"), Ok(true));
    assert_eq!(parse_yes_no_model("NO"), Ok(false));
    assert_eq!(parse_yes_no_model("y"), Err(ModelErrorKind::InvalidYesNo));
    assert_eq!(parse_yes_no_model("n"), Err(ModelErrorKind::InvalidYesNo));

    assert_eq!(parse_mode_model("1"), Ok(Mode::Single));
    assert_eq!(parse_mode_model("2"), Ok(Mode::Multiple));
    assert_eq!(parse_mode_model("3"), Ok(Mode::PrivateReceive));
    assert_eq!(parse_mode_model("4"), Ok(Mode::WalletQr));
    assert_eq!(parse_mode_model("5"), Ok(Mode::Exit));
    assert_eq!(parse_mode_model("6"), Err(ModelErrorKind::InvalidMode));

    assert_eq!(parse_batch_count_model("2"), Ok(2));
    assert_eq!(parse_batch_count_model("10"), Ok(10));
    assert_eq!(parse_batch_count_model("1"), Err(ModelErrorKind::InvalidBatchCount));
    assert_eq!(parse_batch_count_model("11"), Err(ModelErrorKind::InvalidBatchCount));

    let wallet = wallet_from_seed(cursor.take_u8());
    assert!(canon_wallet_id_checked_model(&wallet).is_ok());
    assert!(canon_wallet_id_checked_model(&wallet.to_ascii_uppercase()).is_ok());
    assert_eq!(canon_wallet_id_checked_model(""), Err(ModelErrorKind::InvalidWallet));
    assert_eq!(
        canon_wallet_id_checked_model(&format!("p{}", "0".repeat(128))),
        Err(ModelErrorKind::InvalidWallet)
    );
    assert_eq!(
        canon_wallet_id_checked_model(&format!("r{}g", "0".repeat(127))),
        Err(ModelErrorKind::InvalidWallet)
    );
}

fn fuzz_generate_wallet_scenario(cursor: &mut Cursor<'_>) {
    let mut fs = WalletFsModel::new(cursor);
    let before_wallet_count = fs.wallets.len();

    let outcome = generate_wallet_flow_model(cursor, &mut fs);
    let added_wallets = fs.wallets.len().saturating_sub(before_wallet_count);

    assert!(outcome.generated_wallets <= MAX_BATCH_WALLETS);
    assert!(fs.wallets.len() >= before_wallet_count);
    assert!(added_wallets <= MAX_BATCH_WALLETS);

    let expected_added = outcome
        .generated_wallets
        .saturating_add(usize::from(outcome.private_receive_generated));
    assert_eq!(added_wallets, expected_added);

    if outcome.generated_wallets > 0 {
        assert!(!outcome.cancelled);
        assert!(!outcome.qr_generated);
        assert!(!outcome.private_receive_generated);
    }

    if outcome.qr_generated {
        assert_eq!(outcome.generated_wallets, 0);
        assert!(!outcome.private_receive_generated);
        assert!(outcome.errors.is_empty());
    }

    if outcome.private_receive_generated {
        assert_eq!(outcome.generated_wallets, 0);
        assert!(!outcome.qr_generated);
    }

    if outcome.cancelled {
        assert_eq!(outcome.generated_wallets, 0);
        assert!(!outcome.qr_generated);
        assert!(!outcome.private_receive_generated);
    }

    if outcome.errors.contains(&ModelErrorKind::WalletFileAlreadyExists) {
        assert_eq!(added_wallets, expected_added);
    }

    fs.assert_invariants();
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum WireWalletMode {
    GenerateSingle,
    GenerateMultiple,
    GeneratePrivateReceive,
    GenerateQr,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireWalletCommand {
    mode: WireWalletMode,
    count: u8,
    wallet_address: String,
    passphrase_len: u16,
}

fn fuzz_wire_decoding(cursor: &mut Cursor<'_>) {
    let raw = cursor.take_vec(1024);

    let decoded = std::panic::catch_unwind(|| {
        let _ = from_bytes::<WireWalletCommand>(&raw);
    });

    assert!(decoded.is_ok());

    let wallet = wallet_from_seed(cursor.take_u8());
    let wire = WireWalletCommand {
        mode: match cursor.take_u8() % 5 {
            0 => WireWalletMode::GenerateSingle,
            1 => WireWalletMode::GenerateMultiple,
            2 => WireWalletMode::GeneratePrivateReceive,
            3 => WireWalletMode::GenerateQr,
            _ => WireWalletMode::Exit,
        },
        count: cursor.take_u8(),
        wallet_address: wallet,
        passphrase_len: u16::from(cursor.take_u8()),
    };

    let encoded = to_allocvec(&wire).expect("wire wallet command should encode");
    let roundtrip: WireWalletCommand =
        from_bytes(&encoded).expect("freshly encoded wire wallet command should decode");

    assert_eq!(roundtrip, wire);
}

fn run_fixed_regressions() {
    assert_eq!(parse_yes_no_model("yes"), Ok(true));
    assert_eq!(parse_yes_no_model("no"), Ok(false));
    assert_eq!(parse_yes_no_model("YES"), Ok(true));
    assert_eq!(parse_yes_no_model("NO"), Ok(false));
    assert_eq!(parse_yes_no_model("y"), Err(ModelErrorKind::InvalidYesNo));
    assert_eq!(parse_yes_no_model("n"), Err(ModelErrorKind::InvalidYesNo));

    assert_eq!(parse_mode_model("1"), Ok(Mode::Single));
    assert_eq!(parse_mode_model("2"), Ok(Mode::Multiple));
    assert_eq!(parse_mode_model("3"), Ok(Mode::PrivateReceive));
    assert_eq!(parse_mode_model("4"), Ok(Mode::WalletQr));
    assert_eq!(parse_mode_model("5"), Ok(Mode::Exit));
    assert_eq!(parse_mode_model("6"), Err(ModelErrorKind::InvalidMode));

    assert_eq!(parse_batch_count_model("2"), Ok(2));
    assert_eq!(parse_batch_count_model("10"), Ok(10));
    assert_eq!(parse_batch_count_model("0"), Err(ModelErrorKind::InvalidBatchCount));
    assert_eq!(parse_batch_count_model("11"), Err(ModelErrorKind::InvalidBatchCount));

    let wallet = wallet_from_seed(0);
    assert_eq!(wallet.len(), WALLET_LEN);
    assert!(canon_wallet_id_checked_model(&wallet).is_ok());

    let attempts = vec![
        ("one".to_string(), "two".to_string()),
        ("three".to_string(), "three".to_string()),
    ];
    assert_eq!(passphrase_attempts_model(&attempts), Ok("three".to_string()));

    let attempts = vec![
        ("one".to_string(), "two".to_string()),
        ("three".to_string(), "four".to_string()),
        ("five".to_string(), "six".to_string()),
        ("seven".to_string(), "seven".to_string()),
    ];
    assert_eq!(
        passphrase_attempts_model(&attempts),
        Err(ModelErrorKind::TooManyPassphraseAttempts)
    );

    let mut fs = WalletFsModel::default();
    let w = GeneratedWalletModel::new(1, "passphrase").expect("valid model wallet");
    assert!(w.validate_self().is_ok());
    assert!(fs.atomic_write_wallet(&w.address, &w.encrypted_secret).is_ok());
    assert_eq!(
        fs.atomic_write_wallet(&w.address, &w.encrypted_secret),
        Err(ModelErrorKind::WalletFileAlreadyExists)
    );

    // Partial batch success is valid: one wallet may be finalized, then a later
    // wallet can hit a duplicate filename and stop the flow.
    let mut fs = WalletFsModel::default();
    let first = GeneratedWalletModel::new(2, "passphrase").expect("valid model wallet");
    let duplicate = first.clone();
    assert!(fs.atomic_write_wallet(&first.address, &first.encrypted_secret).is_ok());
    assert_eq!(
        fs.atomic_write_wallet(&duplicate.address, &duplicate.encrypted_secret),
        Err(ModelErrorKind::WalletFileAlreadyExists)
    );
    assert_eq!(fs.wallets.len(), 1);

    // Private receive requires an existing owner wallet and may create a
    // separate one-time wallet.
    let mut fs = WalletFsModel::default();
    let owner = wallet_from_seed(9);
    fs.wallets.insert(owner.clone());
    let one_time = fs
        .create_private_receive_wallet(&owner, 10, "private-passphrase")
        .expect("private receive should create one-time wallet when owner exists");
    assert!(canon_wallet_id_checked_model(&one_time).is_ok());
    assert!(fs.has_wallet(&one_time));
}

fuzz_target!(|data: &[u8]| {
    run_fixed_regressions();

    let mut cursor = Cursor::new(data);

    let iterations = cursor.take_usize_mod(128).max(1);

    for _ in 0..iterations {
        match cursor.take_u8() % 3 {
            0 => fuzz_parse_helpers(&mut cursor),
            1 => fuzz_generate_wallet_scenario(&mut cursor),
            _ => fuzz_wire_decoding(&mut cursor),
        }

        if cursor.remaining() == 0 {
            break;
        }
    }
});
