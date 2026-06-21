use remzar::commandline::s_20_exit::S20Exit;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::logging_data::JsonLogger;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static ROOT_COUNTER: AtomicUsize = AtomicUsize::new(0);

const CHILD_ENV_KEY: &str = "REMZAR_S20_EXIT_CHILD";
const CHILD_EXPECT_KEY: &str = "REMZAR_S20_EXPECT";
const CHILD_TRUE: &str = "S20_RESULT_TRUE";
const CHILD_FALSE: &str = "S20_RESULT_FALSE";
const CHILD_TEST_NAME: &str = "test_100_vector_edge_fuzz_adversarial_load_and_child_runner";

fn boxed_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn unique_root(label: &str) -> std::path::PathBuf {
    let counter = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_s20_exit_tests_{}_{}_{}",
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

fn call_real_exit_once(label: &str) -> TestResult<bool> {
    let (logger, root) = create_json_logger(label)?;

    let result = {
        let mut exit_flow = S20Exit::new();
        exit_flow.exit(&logger)?
    };

    drop(logger);

    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    Ok(result)
}

fn child_exit_runner() -> TestResult {
    let expected = std::env::var(CHILD_EXPECT_KEY)?;
    let actual = call_real_exit_once("child_exit_runner")?;
    let marker = if actual { CHILD_TRUE } else { CHILD_FALSE };

    println!("{marker}");
    assert_eq!(marker, expected);

    Ok(())
}

fn run_exit_child(input: &str, expected_marker: &str) -> TestResult<String> {
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

fn assert_child_true(input: &str) -> TestResult {
    let stdout = run_exit_child(input, CHILD_TRUE)?;
    assert!(stdout.contains(CHILD_TRUE));
    Ok(())
}

fn assert_child_false(input: &str) -> TestResult {
    let stdout = run_exit_child(input, CHILD_FALSE)?;
    assert!(stdout.contains(CHILD_FALSE));
    Ok(())
}

fn normalized_exit_word(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn modeled_yes_no(input: &str) -> Option<bool> {
    match normalized_exit_word(input).as_str() {
        "yes" | "y" => Some(true),
        "no" | "n" => Some(false),
        _ => None,
    }
}

fn is_input_within_exit_cap(input: &str) -> bool {
    input.len() <= 64
}

fn long_line(byte_count_before_newline: usize) -> String {
    format!("{}\n", "x".repeat(byte_count_before_newline))
}

#[test]
fn test_01_new_is_zero_sized() {
    let exit_flow = S20Exit::new();
    assert_eq!(std::mem::size_of_val(&exit_flow), 0);
}

#[test]
fn test_02_default_is_zero_sized() {
    let exit_flow = S20Exit;
    assert_eq!(std::mem::size_of_val(&exit_flow), 0);
}

#[test]
fn test_03_new_and_default_have_same_size() {
    let new_flow = S20Exit::new();
    let default_flow = S20Exit;

    assert_eq!(
        std::mem::size_of_val(&new_flow),
        std::mem::size_of_val(&default_flow)
    );
}

#[test]
fn test_04_can_construct_many_new_instances() {
    for _round in 0_u16..1_024_u16 {
        let exit_flow = S20Exit::new();
        assert_eq!(std::mem::size_of_val(&exit_flow), 0);
    }
}

#[test]
fn test_05_can_construct_many_default_instances() {
    for _round in 0_u16..1_024_u16 {
        let exit_flow = S20Exit;
        assert_eq!(std::mem::size_of_val(&exit_flow), 0);
    }
}

#[test]
fn test_06_normalize_yes_lowercase() {
    assert_eq!(normalized_exit_word("yes"), "yes");
}

#[test]
fn test_07_normalize_yes_uppercase() {
    assert_eq!(normalized_exit_word("YES"), "yes");
}

#[test]
fn test_08_normalize_yes_mixed_case() {
    assert_eq!(normalized_exit_word("YeS"), "yes");
}

#[test]
fn test_09_normalize_yes_with_whitespace() {
    assert_eq!(normalized_exit_word(" \tYES\r\n"), "yes");
}

#[test]
fn test_10_normalize_y_uppercase() {
    assert_eq!(normalized_exit_word("Y"), "y");
}

#[test]
fn test_11_normalize_no_lowercase() {
    assert_eq!(normalized_exit_word("no"), "no");
}

#[test]
fn test_12_normalize_no_uppercase() {
    assert_eq!(normalized_exit_word("NO"), "no");
}

#[test]
fn test_13_normalize_no_mixed_case() {
    assert_eq!(normalized_exit_word("No"), "no");
}

#[test]
fn test_14_normalize_no_with_whitespace() {
    assert_eq!(normalized_exit_word(" \tNO\r\n"), "no");
}

#[test]
fn test_15_normalize_n_uppercase() {
    assert_eq!(normalized_exit_word("N"), "n");
}

#[test]
fn test_16_modeled_yes_is_true() {
    assert_eq!(modeled_yes_no("yes"), Some(true));
}

#[test]
fn test_17_modeled_y_is_true() {
    assert_eq!(modeled_yes_no("y"), Some(true));
}

#[test]
fn test_18_modeled_no_is_false() {
    assert_eq!(modeled_yes_no("no"), Some(false));
}

#[test]
fn test_19_modeled_n_is_false() {
    assert_eq!(modeled_yes_no("n"), Some(false));
}

#[test]
fn test_20_modeled_invalid_is_none() {
    assert_eq!(modeled_yes_no("maybe"), None);
}

#[test]
fn test_21_modeled_empty_is_none() {
    assert_eq!(modeled_yes_no(""), None);
}

#[test]
fn test_22_modeled_whitespace_is_none() {
    assert_eq!(modeled_yes_no(" \t\r\n"), None);
}

#[test]
fn test_23_modeled_yes_with_spaces_is_true() {
    assert_eq!(modeled_yes_no("  yes  \n"), Some(true));
}

#[test]
fn test_24_modeled_no_with_spaces_is_false() {
    assert_eq!(modeled_yes_no("  no  \n"), Some(false));
}

#[test]
fn test_25_modeled_yes_comma_is_invalid() {
    assert_eq!(modeled_yes_no("yes,"), None);
}

#[test]
fn test_26_modeled_no_period_is_invalid() {
    assert_eq!(modeled_yes_no("no."), None);
}

#[test]
fn test_27_modeled_numeric_one_is_invalid() {
    assert_eq!(modeled_yes_no("1"), None);
}

#[test]
fn test_28_modeled_numeric_zero_is_invalid() {
    assert_eq!(modeled_yes_no("0"), None);
}

#[test]
fn test_29_input_cap_accepts_empty() {
    assert!(is_input_within_exit_cap(""));
}

#[test]
fn test_30_input_cap_accepts_one_byte() {
    assert!(is_input_within_exit_cap("y"));
}

#[test]
fn test_31_input_cap_accepts_exactly_sixty_four_bytes() {
    let input = "x".repeat(64);
    assert!(is_input_within_exit_cap(&input));
}

#[test]
fn test_32_input_cap_rejects_sixty_five_bytes() {
    let input = "x".repeat(65);
    assert!(!is_input_within_exit_cap(&input));
}

#[test]
fn test_33_input_cap_counts_newline() {
    let input = long_line(64);
    assert_eq!(input.len(), 65);
    assert!(!is_input_within_exit_cap(&input));
}

#[test]
fn test_34_input_cap_accepts_sixty_three_plus_newline() {
    let input = long_line(63);
    assert_eq!(input.len(), 64);
    assert!(is_input_within_exit_cap(&input));
}

#[test]
fn test_35_real_exit_yes_yes_returns_true() -> TestResult {
    assert_child_true("yes\nyes\n")
}

#[test]
fn test_36_real_exit_y_yes_returns_true() -> TestResult {
    assert_child_true("y\nyes\n")
}

#[test]
fn test_37_real_exit_yes_y_returns_true() -> TestResult {
    assert_child_true("yes\ny\n")
}

#[test]
fn test_38_real_exit_y_y_returns_true() -> TestResult {
    assert_child_true("y\ny\n")
}

#[test]
fn test_39_real_exit_uppercase_yes_yes_returns_true() -> TestResult {
    assert_child_true("YES\nYES\n")
}

#[test]
fn test_40_real_exit_mixed_case_yes_y_returns_true() -> TestResult {
    assert_child_true("YeS\nY\n")
}

#[test]
fn test_41_real_exit_whitespace_yes_yes_returns_true() -> TestResult {
    assert_child_true(" \tyes \r\n \tyes \r\n")
}

#[test]
fn test_42_real_exit_first_no_returns_false() -> TestResult {
    assert_child_false("no\n")
}

#[test]
fn test_43_real_exit_first_n_returns_false() -> TestResult {
    assert_child_false("n\n")
}

#[test]
fn test_44_real_exit_first_uppercase_no_returns_false() -> TestResult {
    assert_child_false("NO\n")
}

#[test]
fn test_45_real_exit_first_mixed_case_n_returns_false() -> TestResult {
    assert_child_false("N\n")
}

#[test]
fn test_46_real_exit_first_whitespace_no_returns_false() -> TestResult {
    assert_child_false(" \tno \r\n")
}

#[test]
fn test_47_real_exit_second_no_returns_false() -> TestResult {
    assert_child_false("yes\nno\n")
}

#[test]
fn test_48_real_exit_second_n_returns_false() -> TestResult {
    assert_child_false("yes\nn\n")
}

#[test]
fn test_49_real_exit_second_uppercase_no_returns_false() -> TestResult {
    assert_child_false("yes\nNO\n")
}

#[test]
fn test_50_real_exit_second_whitespace_no_returns_false() -> TestResult {
    assert_child_false("yes\n \tno \r\n")
}

#[test]
fn test_51_real_exit_invalid_first_then_no_returns_false() -> TestResult {
    assert_child_false("maybe\nno\n")
}

#[test]
fn test_52_real_exit_invalid_first_then_yes_yes_returns_true() -> TestResult {
    assert_child_true("maybe\nyes\nyes\n")
}

#[test]
fn test_53_real_exit_two_invalid_first_then_yes_yes_returns_true() -> TestResult {
    assert_child_true("maybe\nlater\nyes\nyes\n")
}

#[test]
fn test_54_real_exit_invalid_second_then_yes_returns_true() -> TestResult {
    assert_child_true("yes\nmaybe\nyes\n")
}

#[test]
fn test_55_real_exit_invalid_second_then_no_returns_false() -> TestResult {
    assert_child_false("yes\nmaybe\nno\n")
}

#[test]
fn test_56_real_exit_empty_line_first_then_no_returns_false() -> TestResult {
    assert_child_false("\nno\n")
}

#[test]
fn test_57_real_exit_empty_line_second_then_yes_returns_true() -> TestResult {
    assert_child_true("yes\n\nyes\n")
}

#[test]
fn test_58_real_exit_numeric_first_then_no_returns_false() -> TestResult {
    assert_child_false("1\nno\n")
}

#[test]
fn test_59_real_exit_numeric_second_then_yes_returns_true() -> TestResult {
    assert_child_true("yes\n1\nyes\n")
}

#[test]
fn test_60_real_exit_yes_comma_first_then_no_returns_false() -> TestResult {
    assert_child_false("yes,\nno\n")
}

#[test]
fn test_61_real_exit_no_period_first_then_no_returns_false() -> TestResult {
    assert_child_false("no.\nno\n")
}

#[test]
fn test_62_real_exit_long_first_input_then_no_returns_false() -> TestResult {
    let input = format!("{}no\n", long_line(64));
    assert_child_false(&input)
}

#[test]
fn test_63_real_exit_long_first_input_then_yes_yes_returns_true() -> TestResult {
    let input = format!("{}yes\nyes\n", long_line(64));
    assert_child_true(&input)
}

#[test]
fn test_64_real_exit_long_second_input_then_yes_returns_true() -> TestResult {
    let input = format!("yes\n{}yes\n", long_line(64));
    assert_child_true(&input)
}

#[test]
fn test_65_real_exit_long_second_input_then_no_returns_false() -> TestResult {
    let input = format!("yes\n{}no\n", long_line(64));
    assert_child_false(&input)
}

#[test]
fn test_66_real_exit_exact_cap_invalid_first_then_no_returns_false() -> TestResult {
    let input = format!("{}no\n", long_line(63));
    assert_child_false(&input)
}

#[test]
fn test_67_real_exit_exact_cap_invalid_second_then_yes_returns_true() -> TestResult {
    let input = format!("yes\n{}yes\n", long_line(63));
    assert_child_true(&input)
}

#[test]
fn test_68_real_exit_eof_without_input_cancels_false() -> TestResult {
    assert_child_false("")
}

#[test]
fn test_69_real_exit_eof_after_first_yes_cancels_false() -> TestResult {
    assert_child_false("yes\n")
}

#[test]
fn test_70_real_exit_eof_after_invalid_then_yes_cancels_false() -> TestResult {
    assert_child_false("maybe\nyes\n")
}

#[test]
fn test_71_real_exit_ten_invalid_first_attempts_cancel_false() -> TestResult {
    let mut input = String::new();
    for _round in 0_u8..10_u8 {
        input.push_str("invalid\n");
    }

    assert_child_false(&input)
}

#[test]
fn test_72_real_exit_ten_invalid_second_attempts_cancel_false() -> TestResult {
    let mut input = String::from("yes\n");
    for _round in 0_u8..10_u8 {
        input.push_str("invalid\n");
    }

    assert_child_false(&input)
}

#[test]
fn test_73_real_exit_nine_invalid_first_then_yes_yes_returns_true() -> TestResult {
    let mut input = String::new();
    for _round in 0_u8..9_u8 {
        input.push_str("invalid\n");
    }
    input.push_str("yes\nyes\n");

    assert_child_true(&input)
}

#[test]
fn test_74_real_exit_nine_invalid_second_then_yes_returns_true() -> TestResult {
    let mut input = String::from("yes\n");
    for _round in 0_u8..9_u8 {
        input.push_str("invalid\n");
    }
    input.push_str("yes\n");

    assert_child_true(&input)
}

#[test]
fn test_75_real_exit_nine_invalid_second_then_no_returns_false() -> TestResult {
    let mut input = String::from("yes\n");
    for _round in 0_u8..9_u8 {
        input.push_str("invalid\n");
    }
    input.push_str("no\n");

    assert_child_false(&input)
}

#[test]
fn test_76_real_exit_unicode_invalid_first_then_no_returns_false() -> TestResult {
    assert_child_false("🧪\nno\n")
}

#[test]
fn test_77_real_exit_unicode_invalid_second_then_yes_returns_true() -> TestResult {
    assert_child_true("yes\n🧪\nyes\n")
}

#[test]
fn test_78_real_exit_tab_only_first_then_no_returns_false() -> TestResult {
    assert_child_false("\t\nno\n")
}

#[test]
fn test_79_real_exit_spaces_only_second_then_no_returns_false() -> TestResult {
    assert_child_false("yes\n    \nno\n")
}

#[test]
fn test_80_real_exit_yes_yes_stdout_contains_shutdown_marker() -> TestResult {
    let stdout = run_exit_child("yes\nyes\n", CHILD_TRUE)?;
    assert!(stdout.contains("Shutting Down"));
    assert!(stdout.contains("Thank you for using REMZAR"));
    Ok(())
}

#[test]
fn test_81_real_exit_no_stdout_contains_canceled_marker() -> TestResult {
    let stdout = run_exit_child("no\n", CHILD_FALSE)?;
    assert!(stdout.contains("Operation Canceled"));
    assert!(stdout.contains("Returning to the main menu"));
    Ok(())
}

#[test]
fn test_82_real_exit_second_no_stdout_contains_canceled_marker() -> TestResult {
    let stdout = run_exit_child("yes\nno\n", CHILD_FALSE)?;
    assert!(stdout.contains("Operation Canceled"));
    assert!(stdout.contains("Returning to the main menu"));
    Ok(())
}

#[test]
fn test_83_real_exit_invalid_first_stdout_contains_invalid_message() -> TestResult {
    let stdout = run_exit_child("maybe\nno\n", CHILD_FALSE)?;
    assert!(stdout.contains("Invalid input"));
    Ok(())
}

#[test]
fn test_84_real_exit_long_first_stdout_contains_too_long_message() -> TestResult {
    let input = format!("{}no\n", long_line(64));
    let stdout = run_exit_child(&input, CHILD_FALSE)?;
    assert!(stdout.contains("Input too long"));
    Ok(())
}

#[test]
fn test_85_real_exit_too_many_invalid_stdout_contains_canceling_message() -> TestResult {
    let mut input = String::new();
    for _round in 0_u8..10_u8 {
        input.push_str("invalid\n");
    }

    let stdout = run_exit_child(&input, CHILD_FALSE)?;
    assert!(stdout.contains("Too many invalid attempts"));
    Ok(())
}

#[test]
fn test_86_modeled_valid_yes_vectors_are_true() {
    let vectors = ["yes", "YES", "Yes", "y", "Y", "  yes  ", "\ty\n"];

    for vector in vectors {
        assert_eq!(modeled_yes_no(vector), Some(true));
    }
}

#[test]
fn test_87_modeled_valid_no_vectors_are_false() {
    let vectors = ["no", "NO", "No", "n", "N", "  no  ", "\tn\n"];

    for vector in vectors {
        assert_eq!(modeled_yes_no(vector), Some(false));
    }
}

#[test]
fn test_88_modeled_invalid_word_vectors_are_none() {
    let vectors = [
        "",
        " ",
        "maybe",
        "true",
        "false",
        "ok",
        "cancel",
        "exit",
        "quit",
        "yes please",
        "no thanks",
    ];

    for vector in vectors {
        assert_eq!(modeled_yes_no(vector), None);
    }
}

#[test]
fn test_89_modeled_invalid_symbol_vectors_are_none() {
    let vectors = ["!", "?", ".", ",", "-", "_", "/", "\\", "🧪"];

    for vector in vectors {
        assert_eq!(modeled_yes_no(vector), None);
    }
}

#[test]
fn test_90_modeled_ascii_single_byte_fuzz() {
    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);
        let candidate = ch.to_string();
        let modeled = modeled_yes_no(&candidate);

        match candidate.as_str() {
            "y" | "Y" => assert_eq!(modeled, Some(true)),
            "n" | "N" => assert_eq!(modeled, Some(false)),
            _ => assert_eq!(modeled, None),
        }
    }
}

#[test]
fn test_91_modeled_load_many_invalid_strings() {
    for index in 0_u16..2_000_u16 {
        let candidate = format!("invalid-{index}");
        assert_eq!(modeled_yes_no(&candidate), None);
    }
}

#[test]
fn test_92_modeled_load_many_whitespace_wrapped_yes_values() {
    for spaces in 0_usize..32_usize {
        let candidate = format!("{}yes{}", " ".repeat(spaces), " ".repeat(spaces));
        assert_eq!(modeled_yes_no(&candidate), Some(true));
    }
}

#[test]
fn test_93_modeled_load_many_whitespace_wrapped_no_values() {
    for spaces in 0_usize..32_usize {
        let candidate = format!("{}no{}", " ".repeat(spaces), " ".repeat(spaces));
        assert_eq!(modeled_yes_no(&candidate), Some(false));
    }
}

#[test]
fn test_94_cap_boundary_zero_to_sixty_four_valid_lengths() {
    for len in 0_usize..=64_usize {
        let input = "x".repeat(len);
        assert!(is_input_within_exit_cap(&input));
    }
}

#[test]
fn test_95_cap_boundary_sixty_five_to_one_twenty_rejected_lengths() {
    for len in 65_usize..=120_usize {
        let input = "x".repeat(len);
        assert!(!is_input_within_exit_cap(&input));
    }
}

#[test]
fn test_96_child_helper_true_marker_is_distinct_from_false_marker() {
    assert_ne!(CHILD_TRUE, CHILD_FALSE);
}

#[test]
fn test_97_child_test_name_is_not_empty() {
    assert!(!CHILD_TEST_NAME.is_empty());
}

#[test]
fn test_98_logger_creation_for_exit_tests_works() -> TestResult {
    let (logger, root) = create_json_logger("logger_creation")?;

    logger
        .log_error_event("exit_test", "LoggerCreation", "logger creation test")
        .map_err(boxed_error)?;
    logger.flush().map_err(boxed_error)?;
    logger.flush_logs_cf().map_err(boxed_error)?;

    drop(logger);

    if root.exists() {
        std::fs::remove_dir_all(root)?;
    }

    Ok(())
}

#[test]
fn test_99_real_exit_repeated_short_true_flow_load() -> TestResult {
    for _round in 0_u8..3_u8 {
        assert_child_true("yes\nyes\n")?;
    }

    Ok(())
}

#[test]
fn test_100_vector_edge_fuzz_adversarial_load_and_child_runner() -> TestResult {
    if std::env::var(CHILD_ENV_KEY).ok().as_deref() == Some("1") {
        return child_exit_runner();
    }

    let confirmation_vectors = [
        ("yes", Some(true)),
        ("y", Some(true)),
        ("YES", Some(true)),
        ("Y", Some(true)),
        ("no", Some(false)),
        ("n", Some(false)),
        ("NO", Some(false)),
        ("N", Some(false)),
        ("maybe", None),
        ("", None),
        ("yes,", None),
        ("no.", None),
    ];

    for (input, expected) in confirmation_vectors {
        assert_eq!(modeled_yes_no(input), expected);
    }

    for len in 0_usize..=128_usize {
        let input = "x".repeat(len);
        assert_eq!(is_input_within_exit_cap(&input), len <= 64);
    }

    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);
        let input = ch.to_string();
        let modeled = modeled_yes_no(&input);

        if input == "y" || input == "Y" {
            assert_eq!(modeled, Some(true));
        } else if input == "n" || input == "N" {
            assert_eq!(modeled, Some(false));
        } else {
            assert_eq!(modeled, None);
        }
    }

    Ok(())
}
