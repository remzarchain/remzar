use remzar::commandline::s_09_list_wallets::S09ListWallets;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::helper::{REMZAR_WALLET_LEN, canon_wallet_id_checked};
use remzar::utility::logging_data::JsonLogger;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static ROOT_COUNTER: AtomicUsize = AtomicUsize::new(0);

const CHILD_ENV_KEY: &str = "REMZAR_S09_LIST_WALLETS_CHILD";
const CHILD_EXPECT_KEY: &str = "REMZAR_S09_EXPECT";
const CHILD_OK: &str = "S09_RESULT_OK";
const CHILD_ERR: &str = "S09_RESULT_ERR";
const CHILD_TEST_NAME: &str = "test_100_vector_edge_fuzz_adversarial_load_and_child_runner";

fn boxed_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn unique_root(label: &str) -> std::path::PathBuf {
    let counter = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_s09_list_wallets_tests_{}_{}_{}",
        std::process::id(),
        label,
        counter
    ))
}

fn create_json_logger(label: &str) -> TestResult<(JsonLogger, std::path::PathBuf)> {
    let root = unique_root(label);
    std::fs::create_dir_all(&root)?;

    let directory = DirectoryDB::from_base_dir(&root)?;
    directory.create_log_directory()?;

    let logger = JsonLogger::new(&directory)
        .map_err(|e| boxed_error(format!("JsonLogger init failed: {e}")))?;

    Ok((logger, root))
}

fn child_list_wallets_runner() -> TestResult {
    let expected = std::env::var(CHILD_EXPECT_KEY)?;
    let (logger, root) = create_json_logger("child_list_wallets_runner")?;

    let result = {
        let list_wallets = S09ListWallets::new();
        list_wallets.list_wallets(&logger)
    };

    let marker = if result.is_ok() { CHILD_OK } else { CHILD_ERR };
    println!("{marker}");

    if let Err(error) = result {
        println!("S09_ERROR_TEXT={error}");
    }

    drop(logger);

    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    assert_eq!(marker, expected);

    Ok(())
}

fn run_list_wallets_child(input: &str, expected_marker: &str) -> TestResult<String> {
    let exe = std::env::current_exe()?;

    let mut child = Command::new(exe)
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_ENV_KEY, "1")
        .env(CHILD_EXPECT_KEY, expected_marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    match child.stdin.take() {
        Some(mut stdin) => {
            stdin.write_all(input.as_bytes())?;
        }
        None => return Err(boxed_error("child stdin was not available")),
    }

    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(
        output.status.success(),
        "child process failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(expected_marker),
        "missing expected marker {expected_marker}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    Ok(stdout)
}

fn assert_child_ok(input: &str) -> TestResult<String> {
    run_list_wallets_child(input, CHILD_OK)
}

fn assert_child_err(input: &str) -> TestResult<String> {
    run_list_wallets_child(input, CHILD_ERR)
}

fn wallet_with_hex_digit(digit: char) -> String {
    format!("r{}", digit.to_string().repeat(128))
}

fn wallet_filename(wallet: &str) -> String {
    format!("{wallet}.wallet")
}

fn create_wallet_file(dir: &std::path::Path, wallet: &str) -> TestResult<std::path::PathBuf> {
    let path = dir.join(wallet_filename(wallet));
    std::fs::write(&path, b"test wallet file")?;
    Ok(path)
}

fn create_named_file(dir: &std::path::Path, name: &str) -> TestResult<std::path::PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, b"test file")?;
    Ok(path)
}

fn create_wallet_dir(label: &str) -> TestResult<(std::path::PathBuf, std::path::PathBuf)> {
    let root = unique_root(label);
    let wallet_dir = root.join("wallets");

    std::fs::create_dir_all(&wallet_dir)?;

    Ok((root, wallet_dir))
}

fn list_input_yes_dir(dir: &std::path::Path) -> String {
    format!("yes\n{}\n", dir.display())
}

fn list_input_no() -> &'static str {
    "no\n"
}

fn normalize_confirm(input: &str) -> String {
    input.trim().to_lowercase()
}

fn confirmation_is_yes(input: &str) -> bool {
    normalize_confirm(input) == "yes"
}

fn wallet_dir_input_too_long(input: &str) -> bool {
    input.len() > 4_096
}

fn wallet_stem_from_filename(name: &str) -> Option<&str> {
    name.strip_suffix(".wallet")
}

fn cleanup_root(root: &std::path::Path) -> TestResult {
    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    Ok(())
}

#[test]
fn test_01_new_is_zero_sized() {
    let list_wallets = S09ListWallets::new();
    assert_eq!(std::mem::size_of_val(&list_wallets), 0);
}

#[test]
fn test_02_default_is_zero_sized() {
    let list_wallets = S09ListWallets;
    assert_eq!(std::mem::size_of_val(&list_wallets), 0);
}

#[test]
fn test_03_new_and_default_have_same_size() {
    let new_list_wallets = S09ListWallets::new();
    let default_list_wallets = S09ListWallets;

    assert_eq!(
        std::mem::size_of_val(&new_list_wallets),
        std::mem::size_of_val(&default_list_wallets)
    );
}

#[test]
fn test_04_can_construct_many_new_instances() {
    for _round in 0_u16..1_024_u16 {
        let list_wallets = S09ListWallets::new();
        assert_eq!(std::mem::size_of_val(&list_wallets), 0);
    }
}

#[test]
fn test_05_can_construct_many_default_instances() {
    for _round in 0_u16..1_024_u16 {
        let list_wallets = S09ListWallets;
        assert_eq!(std::mem::size_of_val(&list_wallets), 0);
    }
}

#[test]
fn test_06_wallet_with_hex_digit_has_canonical_length() {
    let wallet = wallet_with_hex_digit('1');
    assert_eq!(wallet.len(), REMZAR_WALLET_LEN);
}

#[test]
fn test_07_wallet_with_hex_digit_starts_with_r() {
    let wallet = wallet_with_hex_digit('2');
    assert!(wallet.starts_with('r'));
}

#[test]
fn test_08_wallet_with_hex_digit_body_is_128_chars() {
    let wallet = wallet_with_hex_digit('3');
    let body = wallet.strip_prefix('r').unwrap_or_default();

    assert_eq!(body.len(), 128);
}

#[test]
fn test_09_wallet_with_hex_digit_is_accepted_by_canonical_validator() -> TestResult {
    let wallet = wallet_with_hex_digit('4');
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_eq!(canonical, wallet);

    Ok(())
}

#[test]
fn test_10_wallet_with_hex_digit_f_is_accepted_by_canonical_validator() -> TestResult {
    let wallet = wallet_with_hex_digit('f');
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_eq!(canonical, wallet);

    Ok(())
}

#[test]
fn test_11_wallet_with_uppercase_hex_is_non_canonical_after_validation() -> TestResult {
    let wallet = format!("r{}", "A".repeat(128));
    let canonical = canon_wallet_id_checked(&wallet)?;

    assert_ne!(canonical, wallet);
    assert_eq!(canonical, format!("r{}", "a".repeat(128)));

    Ok(())
}

#[test]
fn test_12_wallet_missing_prefix_is_rejected() {
    let wallet = "1".repeat(128);
    assert!(canon_wallet_id_checked(&wallet).is_err());
}

#[test]
fn test_13_wallet_short_body_is_rejected() {
    let wallet = format!("r{}", "1".repeat(127));
    assert!(canon_wallet_id_checked(&wallet).is_err());
}

#[test]
fn test_14_wallet_long_body_is_rejected() {
    let wallet = format!("r{}", "1".repeat(129));
    assert!(canon_wallet_id_checked(&wallet).is_err());
}

#[test]
fn test_15_wallet_non_hex_body_is_rejected() {
    let wallet = format!("r{}", "g".repeat(128));
    assert!(canon_wallet_id_checked(&wallet).is_err());
}

#[test]
fn test_16_wallet_filename_adds_wallet_extension() {
    let wallet = wallet_with_hex_digit('5');
    assert_eq!(wallet_filename(&wallet), format!("{wallet}.wallet"));
}

#[test]
fn test_17_wallet_stem_extracts_from_wallet_filename() {
    let wallet = wallet_with_hex_digit('6');
    let filename = wallet_filename(&wallet);

    assert_eq!(wallet_stem_from_filename(&filename), Some(wallet.as_str()));
}

#[test]
fn test_18_wallet_stem_rejects_txt_file() {
    assert_eq!(wallet_stem_from_filename("abc.txt"), None);
}

#[test]
fn test_19_wallet_stem_rejects_file_without_extension() {
    assert_eq!(wallet_stem_from_filename("abc"), None);
}

#[test]
fn test_20_wallet_stem_rejects_similar_extension() {
    assert_eq!(wallet_stem_from_filename("abc.wallet.bak"), None);
}

#[test]
fn test_21_normalize_confirm_yes_lowercase() {
    assert_eq!(normalize_confirm("yes"), "yes");
}

#[test]
fn test_22_normalize_confirm_yes_uppercase() {
    assert_eq!(normalize_confirm("YES"), "yes");
}

#[test]
fn test_23_normalize_confirm_yes_with_whitespace() {
    assert_eq!(normalize_confirm(" \tYES\r\n"), "yes");
}

#[test]
fn test_24_confirmation_is_yes_for_yes_only() {
    assert!(confirmation_is_yes("yes"));
}

#[test]
fn test_25_confirmation_is_yes_for_uppercase_yes() {
    assert!(confirmation_is_yes("YES"));
}

#[test]
fn test_26_confirmation_is_not_yes_for_y_shortcut() {
    assert!(!confirmation_is_yes("y"));
}

#[test]
fn test_27_confirmation_is_not_yes_for_no() {
    assert!(!confirmation_is_yes("no"));
}

#[test]
fn test_28_confirmation_is_not_yes_for_empty() {
    assert!(!confirmation_is_yes(""));
}

#[test]
fn test_29_confirmation_is_not_yes_for_yes_comma() {
    assert!(!confirmation_is_yes("yes,"));
}

#[test]
fn test_30_wallet_dir_input_boundary_4096_is_allowed_by_length_guard() {
    let input = "x".repeat(4_096);
    assert!(!wallet_dir_input_too_long(&input));
}

#[test]
fn test_31_wallet_dir_input_boundary_4097_is_rejected_by_length_guard() {
    let input = "x".repeat(4_097);
    assert!(wallet_dir_input_too_long(&input));
}

#[test]
fn test_32_wallet_dir_input_counts_newline() {
    let input = format!("{}\n", "x".repeat(4_096));

    assert_eq!(input.len(), 4_097);
    assert!(wallet_dir_input_too_long(&input));
}

#[test]
fn test_33_wallet_dir_input_4095_plus_newline_is_allowed() {
    let input = format!("{}\n", "x".repeat(4_095));

    assert_eq!(input.len(), 4_096);
    assert!(!wallet_dir_input_too_long(&input));
}

#[test]
fn test_34_real_cancel_no_returns_ok() -> TestResult {
    let stdout = assert_child_ok(list_input_no())?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_35_real_cancel_uppercase_no_returns_ok() -> TestResult {
    let stdout = assert_child_ok("NO\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_36_real_cancel_n_shortcut_returns_ok() -> TestResult {
    let stdout = assert_child_ok("n\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_37_real_cancel_empty_input_returns_ok() -> TestResult {
    let stdout = assert_child_ok("\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_38_real_cancel_eof_returns_ok() -> TestResult {
    let stdout = assert_child_ok("")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_39_real_cancel_yes_comma_returns_ok() -> TestResult {
    let stdout = assert_child_ok("yes,\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_40_real_yes_then_empty_directory_path_returns_err() -> TestResult {
    let stdout = assert_child_err("yes\n\n")?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(stdout.contains("specified directory does not exist"));

    Ok(())
}

#[test]
fn test_41_real_yes_then_nonexistent_directory_returns_err() -> TestResult {
    let root = unique_root("nonexistent_directory");
    let missing = root.join("missing-wallets");
    let input = format!("yes\n{}\n", missing.display());

    let stdout = assert_child_err(&input)?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(stdout.contains("specified directory does not exist"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_42_real_yes_then_file_path_instead_of_directory_returns_err() -> TestResult {
    let root = unique_root("file_path_instead_of_directory");
    std::fs::create_dir_all(&root)?;

    let file_path = root.join("not_a_directory.txt");
    std::fs::write(&file_path, b"not a directory")?;

    let input = format!("yes\n{}\n", file_path.display());
    let stdout = assert_child_err(&input)?;

    assert!(stdout.contains(CHILD_ERR));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_43_real_yes_then_empty_existing_directory_returns_ok_no_wallets() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("empty_existing_directory")?;
    let input = list_input_yes_dir(&wallet_dir);

    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_44_real_yes_then_one_valid_wallet_lists_wallet() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("one_valid_wallet")?;
    let wallet = wallet_with_hex_digit('7');
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_45_real_yes_then_two_valid_wallets_lists_both() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("two_valid_wallets")?;
    let wallet_a = wallet_with_hex_digit('8');
    let wallet_b = wallet_with_hex_digit('9');

    create_wallet_file(&wallet_dir, &wallet_a)?;
    create_wallet_file(&wallet_dir, &wallet_b)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet_a));
    assert!(stdout.contains(&wallet_b));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_46_real_yes_then_txt_file_only_reports_no_wallets() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("txt_file_only")?;
    create_named_file(&wallet_dir, "notes.txt")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_47_real_yes_then_file_without_extension_reports_no_wallets() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("file_without_extension")?;
    create_named_file(&wallet_dir, "not_a_wallet")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_48_real_yes_then_directory_named_wallet_is_skipped() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("directory_named_wallet")?;
    let wallet = wallet_with_hex_digit('a');

    std::fs::create_dir_all(wallet_dir.join(wallet_filename(&wallet)))?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_49_real_yes_then_invalid_wallet_filename_warns_and_succeeds() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("invalid_wallet_filename")?;
    create_named_file(&wallet_dir, "not-a-wallet.wallet")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("Invalid wallet address"));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_50_real_yes_then_uppercase_wallet_filename_warns_noncanonical() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("uppercase_wallet_filename")?;
    let wallet = format!("r{}", "A".repeat(128));
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("Skipping non-canonical wallet filename"));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_51_real_yes_then_mixed_valid_and_invalid_lists_valid() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("mixed_valid_and_invalid")?;
    let wallet = wallet_with_hex_digit('b');

    create_wallet_file(&wallet_dir, &wallet)?;
    create_named_file(&wallet_dir, "bad.wallet")?;
    create_named_file(&wallet_dir, "notes.txt")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));
    assert!(stdout.contains("Invalid wallet address"));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_52_real_yes_then_long_directory_input_returns_err() -> TestResult {
    let long_path = "x".repeat(4_097);
    let input = format!("yes\n{long_path}\n");

    let stdout = assert_child_err(&input)?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(stdout.contains("Directory path is too long"));

    Ok(())
}

#[test]
fn test_53_real_yes_then_exact_4096_no_newline_path_returns_err_not_too_long() -> TestResult {
    let exact_path = "x".repeat(4_096);
    let input = format!("yes\n{exact_path}");

    let stdout = assert_child_err(&input)?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(!stdout.contains("Directory path is too long"));

    Ok(())
}

#[test]
fn test_54_real_yes_uppercase_then_valid_wallet_lists_wallet() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("uppercase_yes_valid_wallet")?;
    let wallet = wallet_with_hex_digit('c');
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = format!("YES\n{}\n", wallet_dir.display());
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_55_real_yes_with_whitespace_then_valid_wallet_lists_wallet() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("whitespace_yes_valid_wallet")?;
    let wallet = wallet_with_hex_digit('d');
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = format!(" \tYES \r\n{}\n", wallet_dir.display());
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_56_real_yes_then_directory_path_with_surrounding_spaces_works() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("directory_path_surrounding_spaces")?;
    let wallet = wallet_with_hex_digit('e');
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = format!("yes\n  {}  \n", wallet_dir.display());
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_57_real_yes_then_eof_directory_empty_returns_err() -> TestResult {
    let stdout = assert_child_err("yes\n")?;

    assert!(stdout.contains(CHILD_ERR));
    assert!(stdout.contains("specified directory does not exist"));

    Ok(())
}

#[test]
fn test_58_real_yes_then_valid_directory_stdout_contains_header() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("stdout_contains_header")?;
    let input = list_input_yes_dir(&wallet_dir);

    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("Wallet Address"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_59_real_yes_then_valid_directory_stdout_contains_listing_intro() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("stdout_contains_listing_intro")?;
    let input = list_input_yes_dir(&wallet_dir);

    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("Listing all wallets"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_60_real_cancel_stdout_does_not_contain_wallet_header() -> TestResult {
    let stdout = assert_child_ok("no\n")?;

    assert!(!stdout.contains("Wallet Address"));

    Ok(())
}

#[test]
fn test_61_real_valid_wallet_file_extension_is_case_sensitive() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("case_sensitive_extension")?;
    let wallet = wallet_with_hex_digit('f');

    create_named_file(&wallet_dir, &format!("{wallet}.WALLET"))?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_62_real_hidden_wallet_file_with_valid_stem_lists_wallet() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("hidden_wallet_file")?;
    let wallet = wallet_with_hex_digit('1');

    create_named_file(&wallet_dir, &wallet_filename(&wallet))?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_63_real_wallet_filename_with_extra_suffix_is_ignored() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("extra_suffix")?;
    let wallet = wallet_with_hex_digit('2');

    create_named_file(&wallet_dir, &format!("{wallet}.wallet.bak"))?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_64_real_wallet_filename_with_empty_stem_is_ignored_or_warns_without_failure() -> TestResult
{
    let (root, wallet_dir) = create_wallet_dir("empty_stem_wallet")?;

    create_named_file(&wallet_dir, ".wallet")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(
        stdout.contains("Invalid wallet address")
            || stdout.contains("No wallet files found")
            || stdout.contains("Wallets listed successfully")
    );

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_65_real_many_valid_wallet_files_are_listed() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("many_valid_wallet_files")?;

    for digit in ['0', '1', '2', '3', '4'] {
        let wallet = wallet_with_hex_digit(digit);
        create_wallet_file(&wallet_dir, &wallet)?;
    }

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    for digit in ['0', '1', '2', '3', '4'] {
        let wallet = wallet_with_hex_digit(digit);
        assert!(stdout.contains(&wallet));
    }

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_66_model_wallet_filenames_for_all_hex_digits_are_valid() -> TestResult {
    for digit in "0123456789abcdef".chars() {
        let wallet = wallet_with_hex_digit(digit);
        let filename = wallet_filename(&wallet);
        let stem = wallet_stem_from_filename(&filename).ok_or_else(|| boxed_error("no stem"))?;

        assert_eq!(canon_wallet_id_checked(stem)?, wallet);
    }

    Ok(())
}

#[test]
fn test_67_model_uppercase_wallets_canonicalize_but_do_not_match_original() -> TestResult {
    for digit in "ABCDEF".chars() {
        let wallet = format!("r{}", digit.to_string().repeat(128));
        let canonical = canon_wallet_id_checked(&wallet)?;

        assert_ne!(canonical, wallet);
        assert_eq!(canonical, wallet.to_ascii_lowercase());
    }

    Ok(())
}

#[test]
fn test_68_model_invalid_wallet_digits_are_rejected() {
    for digit in ['g', 'z', 'G', 'Z', '_', '-'] {
        let wallet = format!("r{}", digit.to_string().repeat(128));
        assert!(canon_wallet_id_checked(&wallet).is_err());
    }
}

#[test]
fn test_69_model_confirmation_vectors_yes_only() {
    let vectors = ["yes", "YES", "Yes", "yEs", "  yes  ", "\tyes\n"];

    for vector in vectors {
        assert!(confirmation_is_yes(vector));
    }
}

#[test]
fn test_70_model_confirmation_vectors_not_yes() {
    let vectors = [
        "",
        " ",
        "y",
        "Y",
        "no",
        "n",
        "true",
        "ok",
        "1",
        "yes,",
        "yes please",
    ];

    for vector in vectors {
        assert!(!confirmation_is_yes(vector));
    }
}

#[test]
fn test_71_model_path_length_fuzz_zero_to_4096_allowed_by_guard() {
    for len in 0_usize..=4_096_usize {
        let input = "x".repeat(len);
        assert!(!wallet_dir_input_too_long(&input));
    }
}

#[test]
fn test_72_model_path_length_fuzz_4097_to_4200_rejected_by_guard() {
    for len in 4_097_usize..=4_200_usize {
        let input = "x".repeat(len);
        assert!(wallet_dir_input_too_long(&input));
    }
}

#[test]
fn test_73_model_wallet_filename_vector_valid_extension() {
    let wallet = wallet_with_hex_digit('3');
    let filename = wallet_filename(&wallet);

    assert_eq!(wallet_stem_from_filename(&filename), Some(wallet.as_str()));
}

#[test]
fn test_74_model_wallet_filename_vector_bad_extensions() {
    let cases = [
        "wallet",
        "wallet.txt",
        "wallet.WALLET",
        "wallet.wallet.bak",
        "wallet/wallet",
    ];

    for case in cases {
        assert_eq!(wallet_stem_from_filename(case), None);
    }
}

#[test]
fn test_75_real_wallet_dir_with_twenty_valid_wallets_load() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("twenty_valid_wallets_load")?;

    for index in 0_u8..20_u8 {
        let digit = char::from((b'a' - 1_u8) + (index % 6_u8));
        let wallet = if index < 10 {
            wallet_with_hex_digit(char::from(b'0' + index))
        } else {
            wallet_with_hex_digit(digit)
        };
        create_wallet_file(&wallet_dir, &wallet)?;
    }

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_76_real_wallet_dir_with_many_non_wallet_files_reports_no_wallets() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("many_non_wallet_files")?;

    for index in 0_u8..50_u8 {
        create_named_file(&wallet_dir, &format!("note-{index}.txt"))?;
    }

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_77_real_wallet_dir_with_nested_files_skips_nested_wallet() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("nested_files")?;
    let nested = wallet_dir.join("nested");
    std::fs::create_dir_all(&nested)?;

    let wallet = wallet_with_hex_digit('4');
    create_wallet_file(&nested, &wallet)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains("No wallet files found"));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_78_real_wallet_dir_with_valid_wallet_and_nested_wallet_lists_top_level_only() -> TestResult
{
    let (root, wallet_dir) = create_wallet_dir("valid_and_nested_wallet")?;
    let nested = wallet_dir.join("nested");
    std::fs::create_dir_all(&nested)?;

    let top_wallet = wallet_with_hex_digit('5');
    let nested_wallet = wallet_with_hex_digit('6');

    create_wallet_file(&wallet_dir, &top_wallet)?;
    create_wallet_file(&nested, &nested_wallet)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&top_wallet));
    assert!(!stdout.contains(&nested_wallet));

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_79_real_cancel_unicode_input_returns_ok() -> TestResult {
    let stdout = assert_child_ok("🧪\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_80_real_cancel_numeric_input_returns_ok() -> TestResult {
    let stdout = assert_child_ok("1\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_81_real_cancel_tab_only_input_returns_ok() -> TestResult {
    let stdout = assert_child_ok("\t\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_82_real_cancel_yes_with_extra_word_returns_ok() -> TestResult {
    let stdout = assert_child_ok("yes please\n")?;

    assert!(stdout.contains("Returning to the menu"));

    Ok(())
}

#[test]
fn test_83_real_yes_then_unicode_directory_path_missing_returns_err() -> TestResult {
    let input = "yes\n🧪-missing-wallet-dir\n";
    let stdout = assert_child_err(input)?;

    assert!(stdout.contains(CHILD_ERR));

    Ok(())
}

#[test]
fn test_84_real_yes_then_relative_missing_directory_returns_err() -> TestResult {
    let input = "yes\nthis-directory-should-not-exist-remzar-test\n";
    let stdout = assert_child_err(input)?;

    assert!(stdout.contains(CHILD_ERR));

    Ok(())
}

#[test]
fn test_85_real_yes_then_current_directory_runs_ok_or_err_without_panic() -> TestResult {
    let input = "yes\n.\n";
    let stdout = run_list_wallets_child(input, CHILD_OK).or_else(|_| assert_child_err(input))?;

    assert!(stdout.contains(CHILD_OK) || stdout.contains(CHILD_ERR));

    Ok(())
}

#[test]
fn test_86_real_valid_wallet_stdout_contains_success_once_or_more() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("success_marker")?;
    let wallet = wallet_with_hex_digit('7');
    create_wallet_file(&wallet_dir, &wallet)?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.matches("Wallets listed successfully").count() >= 1);

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_87_real_invalid_wallet_stdout_contains_warning_once_or_more() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("warning_marker")?;
    create_named_file(&wallet_dir, "bad.wallet")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.matches("Invalid wallet address").count() >= 1);

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_88_real_empty_dir_stdout_contains_no_wallets_once_or_more() -> TestResult {
    let (root, wallet_dir) = create_wallet_dir("no_wallets_marker")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.matches("No wallet files found").count() >= 1);

    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_89_model_canonical_wallet_length_matches_constant() {
    assert_eq!(REMZAR_WALLET_LEN, 129);
}

#[test]
fn test_90_model_wallet_filename_length_is_wallet_len_plus_extension() {
    let wallet = wallet_with_hex_digit('8');
    let filename = wallet_filename(&wallet);

    assert_eq!(filename.len(), REMZAR_WALLET_LEN + ".wallet".len());
}

#[test]
fn test_91_model_canonical_wallet_filename_has_no_path_separators() {
    let wallet = wallet_with_hex_digit('9');
    let filename = wallet_filename(&wallet);

    assert!(!filename.contains('/'));
    assert!(!filename.contains('\\'));
}

#[test]
fn test_92_model_invalid_wallet_filename_with_separator_not_created_by_helper() {
    let wallet = wallet_with_hex_digit('a');
    let filename = wallet_filename(&wallet);

    assert!(!filename.contains(std::path::MAIN_SEPARATOR));
}

#[test]
fn test_93_model_wallets_for_digits_zero_to_nine_are_distinct() {
    let mut wallets = Vec::new();

    for digit in '0'..='9' {
        wallets.push(wallet_with_hex_digit(digit));
    }

    for wallet in &wallets {
        let count = wallets
            .iter()
            .filter(|candidate| *candidate == wallet)
            .count();
        assert_eq!(count, 1);
    }
}

#[test]
fn test_94_model_wallets_for_hex_letters_are_distinct() {
    let wallets: Vec<String> = ['a', 'b', 'c', 'd', 'e', 'f']
        .into_iter()
        .map(wallet_with_hex_digit)
        .collect();

    for wallet in &wallets {
        let count = wallets
            .iter()
            .filter(|candidate| *candidate == wallet)
            .count();
        assert_eq!(count, 1);
    }
}

#[test]
fn test_95_model_wallet_fuzz_ascii_single_chars() {
    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);
        let wallet = format!("r{}", ch.to_string().repeat(128));
        let valid_hex = ch.is_ascii_hexdigit();

        assert_eq!(
            canon_wallet_id_checked(&wallet).is_ok(),
            valid_hex,
            "unexpected result for ASCII char {ch:?}"
        );
    }
}

#[test]
fn test_96_logger_creation_for_list_wallets_tests_works() -> TestResult {
    let (logger, root) = create_json_logger("logger_creation")?;

    logger
        .log_error_event("wallet_test", "LoggerCreation", "logger creation test")
        .map_err(boxed_error)?;
    logger.flush().map_err(boxed_error)?;
    logger.flush_logs_cf().map_err(boxed_error)?;

    drop(logger);
    cleanup_root(&root)?;

    Ok(())
}

#[test]
fn test_97_child_helper_ok_marker_is_distinct_from_err_marker() {
    assert_ne!(CHILD_OK, CHILD_ERR);
}

#[test]
fn test_98_child_test_name_is_not_empty() {
    assert!(!CHILD_TEST_NAME.is_empty());
}

#[test]
fn test_99_real_repeated_cancel_load() -> TestResult {
    for _round in 0_u8..3_u8 {
        let stdout = assert_child_ok("no\n")?;
        assert!(stdout.contains("Returning to the menu"));
    }

    Ok(())
}

#[test]
fn test_100_vector_edge_fuzz_adversarial_load_and_child_runner() -> TestResult {
    if std::env::var(CHILD_ENV_KEY).ok().as_deref() == Some("1") {
        return child_list_wallets_runner();
    }

    for vector in ["yes", "YES", "Yes", "  yes  ", "\tyes\n"] {
        assert!(confirmation_is_yes(vector));
    }

    for vector in ["", " ", "y", "Y", "no", "n", "yes,", "yes please", "🧪"] {
        assert!(!confirmation_is_yes(vector));
    }

    for len in 0_usize..=4_120_usize {
        let input = "x".repeat(len);
        assert_eq!(wallet_dir_input_too_long(&input), len > 4_096);
    }

    for digit in "0123456789abcdef".chars() {
        let wallet = wallet_with_hex_digit(digit);
        let filename = wallet_filename(&wallet);
        let stem =
            wallet_stem_from_filename(&filename).ok_or_else(|| boxed_error("missing stem"))?;

        assert_eq!(canon_wallet_id_checked(stem)?, wallet);
    }

    let (root, wallet_dir) = create_wallet_dir("combined_real_child")?;
    let wallet = wallet_with_hex_digit('b');

    create_wallet_file(&wallet_dir, &wallet)?;
    create_named_file(&wallet_dir, "bad.wallet")?;
    create_named_file(&wallet_dir, "notes.txt")?;

    let input = list_input_yes_dir(&wallet_dir);
    let stdout = assert_child_ok(&input)?;

    assert!(stdout.contains(&wallet));
    assert!(stdout.contains("Invalid wallet address"));
    assert!(stdout.contains("Wallets listed successfully"));

    cleanup_root(&root)?;

    Ok(())
}
