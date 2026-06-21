use clap::Parser;
use remzar::commandline::command_line_001_interface::{
    BlockchainCommands, BlockchainSubcommand, Commands,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn wallet_with_hex_digit(digit: char) -> String {
    let body: String = std::iter::repeat_n(digit, 128).collect();
    format!("r{body}")
}

fn parse_chain_from_strs(args: &[&str]) -> Result<Option<BlockchainSubcommand>, clap::Error> {
    let parsed = BlockchainCommands::try_parse_from(args)?;
    Ok(match parsed.command {
        Some(Commands::Chain(command)) => Some(command),
        Some(Commands::Node(_)) | None => None,
    })
}

fn parse_chain_from_strings(
    args: Vec<String>,
) -> Result<Option<BlockchainSubcommand>, clap::Error> {
    let parsed = BlockchainCommands::try_parse_from(args)?;
    Ok(match parsed.command {
        Some(Commands::Chain(command)) => Some(command),
        Some(Commands::Node(_)) | None => None,
    })
}

fn parse_node_from_strings(
    args: Vec<String>,
) -> Result<remzar::runtime::p2p_006_sync_runtime::NodeOpts, Box<dyn std::error::Error>> {
    let parsed = BlockchainCommands::try_parse_from(args)?;
    match parsed.command {
        Some(Commands::Node(opts)) => Ok(opts),
        Some(Commands::Chain(_)) | None => Err("expected node command".into()),
    }
}

fn assert_chain_parse(args: &[&str], expected: BlockchainSubcommand) -> TestResult {
    let parsed = parse_chain_from_strs(args)?;
    assert_eq!(parsed, Some(expected));
    Ok(())
}

fn chain_command_cases() -> [(&'static str, BlockchainSubcommand); 20] {
    [
        ("setup-database", BlockchainSubcommand::SetupDatabase),
        ("generate-wallet", BlockchainSubcommand::GenerateWallet),
        ("start-node", BlockchainSubcommand::StartNode),
        ("view-console", BlockchainSubcommand::ViewConsole),
        ("send-remzar", BlockchainSubcommand::SendRemzar),
        ("receive-remzar", BlockchainSubcommand::ReceiveRemzar),
        ("view-status", BlockchainSubcommand::ViewStatus),
        ("check-balance", BlockchainSubcommand::CheckBalance),
        ("list-wallets", BlockchainSubcommand::ListWallets),
        ("create-nft", BlockchainSubcommand::CreateNft),
        ("send-chat", BlockchainSubcommand::SendChat),
        ("send-file", BlockchainSubcommand::SendFile),
        ("open-encrypted-key", BlockchainSubcommand::OpenEncryptedKey),
        ("backup-wallet", BlockchainSubcommand::BackupWallet),
        ("debug-keys", BlockchainSubcommand::DebugKeys),
        ("debug-log-info", BlockchainSubcommand::DebugLogInfo),
        ("audit-report", BlockchainSubcommand::AuditReport),
        ("play-slots", BlockchainSubcommand::PlaySlots),
        ("faq", BlockchainSubcommand::Faq),
        ("exit", BlockchainSubcommand::Exit),
    ]
}

#[test]
fn test_01_from_choice_maps_all_valid_menu_numbers() {
    let expected = [
        (1_u32, BlockchainSubcommand::SetupDatabase),
        (2, BlockchainSubcommand::GenerateWallet),
        (3, BlockchainSubcommand::StartNode),
        (4, BlockchainSubcommand::ViewConsole),
        (5, BlockchainSubcommand::SendRemzar),
        (6, BlockchainSubcommand::ReceiveRemzar),
        (7, BlockchainSubcommand::ViewStatus),
        (8, BlockchainSubcommand::CheckBalance),
        (9, BlockchainSubcommand::ListWallets),
        (10, BlockchainSubcommand::CreateNft),
        (11, BlockchainSubcommand::SendChat),
        (12, BlockchainSubcommand::SendFile),
        (13, BlockchainSubcommand::OpenEncryptedKey),
        (14, BlockchainSubcommand::BackupWallet),
        (15, BlockchainSubcommand::DebugKeys),
        (16, BlockchainSubcommand::DebugLogInfo),
        (17, BlockchainSubcommand::AuditReport),
        (18, BlockchainSubcommand::PlaySlots),
        (19, BlockchainSubcommand::Faq),
        (20, BlockchainSubcommand::Exit),
    ];

    for (choice, command) in expected {
        assert_eq!(BlockchainSubcommand::from_choice(choice), Some(command));
    }
}

#[test]
fn test_02_from_choice_rejects_zero() {
    assert_eq!(BlockchainSubcommand::from_choice(0), None);
}

#[test]
fn test_03_from_choice_rejects_twenty_one() {
    assert_eq!(BlockchainSubcommand::from_choice(21), None);
}

#[test]
fn test_04_from_choice_rejects_u32_max() {
    assert_eq!(BlockchainSubcommand::from_choice(u32::MAX), None);
}

#[test]
fn test_05_all_returns_exactly_twenty_commands() {
    assert_eq!(BlockchainSubcommand::all().len(), 20);
}

#[test]
fn test_06_all_round_trips_against_from_choice_order() -> TestResult {
    let all = BlockchainSubcommand::all();

    for (position, (_label, command)) in all.iter().enumerate() {
        let one_based = position.checked_add(1).ok_or("menu position overflow")?;
        let choice = u32::try_from(one_based)?;
        assert_eq!(BlockchainSubcommand::from_choice(choice), Some(*command));
    }

    Ok(())
}

#[test]
fn test_07_all_labels_are_not_empty() {
    for (label, _command) in BlockchainSubcommand::all() {
        assert!(!label.trim().is_empty());
    }
}

#[test]
fn test_08_all_labels_are_unique() {
    let all = BlockchainSubcommand::all();

    for (index, (label, _command)) in all.iter().enumerate() {
        let duplicate_count = all
            .iter()
            .enumerate()
            .filter(|(other_index, (other_label, _other_command))| {
                *other_index != index && *other_label == *label
            })
            .count();

        assert_eq!(duplicate_count, 0);
    }
}

#[test]
fn test_09_all_variants_are_unique() {
    let all = BlockchainSubcommand::all();

    for (index, (_label, command)) in all.iter().enumerate() {
        let duplicate_count = all
            .iter()
            .enumerate()
            .filter(|(other_index, (_other_label, other_command))| {
                *other_index != index && *other_command == *command
            })
            .count();

        assert_eq!(duplicate_count, 0);
    }
}

#[test]
fn test_10_all_labels_match_expected_menu_text() {
    let actual: Vec<&'static str> = BlockchainSubcommand::all()
        .into_iter()
        .map(|(label, _command)| label)
        .collect();

    let expected = vec![
        "Setup Database",
        "Generate Wallet",
        "Start Node",
        "View Blockchain Console",
        "Send REMZAR",
        "Receive REMZAR",
        "View Participant Status",
        "Balance of Wallet",
        "List Wallets",
        "Create Certificates (mint)",
        "Send Chat (p2p message)",
        "Send File (p2p file sharing)",
        "Debug: Open Encrypted Private Key",
        "Debug: Backup Wallet",
        "Debug: List Raw Database Keys",
        "Debug: Log Information",
        "Debug: Audit Report",
        "Slot Machine Game",
        "FAQ (MUST READ)",
        "Exit",
    ];

    assert_eq!(actual, expected);
}

#[test]
fn test_11_all_variants_match_expected_menu_order() {
    let actual: Vec<BlockchainSubcommand> = BlockchainSubcommand::all()
        .into_iter()
        .map(|(_label, command)| command)
        .collect();

    let expected = vec![
        BlockchainSubcommand::SetupDatabase,
        BlockchainSubcommand::GenerateWallet,
        BlockchainSubcommand::StartNode,
        BlockchainSubcommand::ViewConsole,
        BlockchainSubcommand::SendRemzar,
        BlockchainSubcommand::ReceiveRemzar,
        BlockchainSubcommand::ViewStatus,
        BlockchainSubcommand::CheckBalance,
        BlockchainSubcommand::ListWallets,
        BlockchainSubcommand::CreateNft,
        BlockchainSubcommand::SendChat,
        BlockchainSubcommand::SendFile,
        BlockchainSubcommand::OpenEncryptedKey,
        BlockchainSubcommand::BackupWallet,
        BlockchainSubcommand::DebugKeys,
        BlockchainSubcommand::DebugLogInfo,
        BlockchainSubcommand::AuditReport,
        BlockchainSubcommand::PlaySlots,
        BlockchainSubcommand::Faq,
        BlockchainSubcommand::Exit,
    ];

    assert_eq!(actual, expected);
}

#[test]
fn test_12_parse_setup_database_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "setup-database"],
        BlockchainSubcommand::SetupDatabase,
    )
}

#[test]
fn test_13_parse_generate_wallet_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "generate-wallet"],
        BlockchainSubcommand::GenerateWallet,
    )
}

#[test]
fn test_14_parse_start_node_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "start-node"], BlockchainSubcommand::StartNode)
}

#[test]
fn test_15_parse_view_console_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "view-console"],
        BlockchainSubcommand::ViewConsole,
    )
}

#[test]
fn test_16_parse_send_remzar_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "send-remzar"], BlockchainSubcommand::SendRemzar)
}

#[test]
fn test_17_parse_receive_remzar_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "receive-remzar"],
        BlockchainSubcommand::ReceiveRemzar,
    )
}

#[test]
fn test_18_parse_view_status_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "view-status"], BlockchainSubcommand::ViewStatus)
}

#[test]
fn test_19_parse_check_balance_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "check-balance"],
        BlockchainSubcommand::CheckBalance,
    )
}

#[test]
fn test_20_parse_list_wallets_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "list-wallets"],
        BlockchainSubcommand::ListWallets,
    )
}

#[test]
fn test_21_parse_create_nft_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "create-nft"], BlockchainSubcommand::CreateNft)
}

#[test]
fn test_22_parse_send_chat_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "send-chat"], BlockchainSubcommand::SendChat)
}

#[test]
fn test_23_parse_send_file_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "send-file"], BlockchainSubcommand::SendFile)
}

#[test]
fn test_24_parse_open_encrypted_key_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "open-encrypted-key"],
        BlockchainSubcommand::OpenEncryptedKey,
    )
}

#[test]
fn test_25_parse_backup_wallet_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "backup-wallet"],
        BlockchainSubcommand::BackupWallet,
    )
}

#[test]
fn test_26_parse_debug_keys_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "debug-keys"], BlockchainSubcommand::DebugKeys)
}

#[test]
fn test_27_parse_debug_log_info_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "debug-log-info"],
        BlockchainSubcommand::DebugLogInfo,
    )
}

#[test]
fn test_28_parse_audit_report_subcommand() -> TestResult {
    assert_chain_parse(
        &["remzar", "audit-report"],
        BlockchainSubcommand::AuditReport,
    )
}

#[test]
fn test_29_parse_play_slots_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "play-slots"], BlockchainSubcommand::PlaySlots)
}

#[test]
fn test_30_parse_faq_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "faq"], BlockchainSubcommand::Faq)
}

#[test]
fn test_31_parse_exit_subcommand() -> TestResult {
    assert_chain_parse(&["remzar", "exit"], BlockchainSubcommand::Exit)
}

#[test]
fn test_32_parse_node_minimal_uses_node_defaults() -> TestResult {
    let wallet = wallet_with_hex_digit('1');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet.clone(),
    ])?;

    assert_eq!(opts.identity_file, "identity.key");
    assert_eq!(opts.listen, "/ip4/0.0.0.0/tcp/36213");
    assert_eq!(opts.bootstrap, Vec::<String>::new());
    assert_eq!(opts.log, "info");
    assert_eq!(opts.data_dir, "data");
    assert_eq!(opts.wallet_address, wallet);
    assert!(!opts.founder);

    Ok(())
}

#[test]
fn test_33_parse_node_with_all_explicit_options() -> TestResult {
    let wallet = wallet_with_hex_digit('2');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--identity-file".to_string(),
        "keys/local.identity".to_string(),
        "--listen".to_string(),
        "/ip4/127.0.0.1/tcp/36213".to_string(),
        "--bootstrap".to_string(),
        "/ip4/127.0.0.1/tcp/36214".to_string(),
        "--bootstrap".to_string(),
        "/dns4/bootstrap.remzar.test/tcp/36213".to_string(),
        "--log".to_string(),
        "debug".to_string(),
        "--data-dir".to_string(),
        "tmp/remzar-node-a".to_string(),
        "--wallet-address".to_string(),
        wallet.clone(),
        "--founder".to_string(),
    ])?;

    assert_eq!(opts.identity_file, "keys/local.identity");
    assert_eq!(opts.listen, "/ip4/127.0.0.1/tcp/36213");
    assert_eq!(
        opts.bootstrap,
        vec![
            "/ip4/127.0.0.1/tcp/36214".to_string(),
            "/dns4/bootstrap.remzar.test/tcp/36213".to_string(),
        ]
    );
    assert_eq!(opts.log, "debug");
    assert_eq!(opts.data_dir, "tmp/remzar-node-a");
    assert_eq!(opts.wallet_address, wallet);
    assert!(opts.founder);

    Ok(())
}

#[test]
fn test_34_parse_node_accepts_is_founder_alias() -> TestResult {
    let wallet = wallet_with_hex_digit('3');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--is-founder".to_string(),
    ])?;

    assert!(opts.founder);

    Ok(())
}

#[test]
fn test_35_parse_short_genesis_flag_without_command() -> TestResult {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "-g", "genesis.local.json"])?;

    assert_eq!(
        parsed.genesis,
        Some(std::path::PathBuf::from("genesis.local.json"))
    );
    assert!(parsed.command.is_none());

    Ok(())
}

#[test]
fn test_36_parse_long_genesis_flag_with_chain_command() -> TestResult {
    let parsed =
        BlockchainCommands::try_parse_from(["remzar", "--genesis", "custom-genesis.json", "faq"])?;

    assert_eq!(
        parsed.genesis,
        Some(std::path::PathBuf::from("custom-genesis.json"))
    );

    match parsed.command {
        Some(Commands::Chain(command)) => assert_eq!(command, BlockchainSubcommand::Faq),
        Some(Commands::Node(_)) | None => return Err("expected faq chain command".into()),
    }

    Ok(())
}

#[test]
fn test_37_rejects_unknown_root_command() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "not-a-real-command"]);
    assert!(parsed.is_err());
}

#[test]
fn test_38_rejects_misspelled_chain_command() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "send-remzarr"]);
    assert!(parsed.is_err());
}

#[test]
fn test_39_rejects_node_without_required_wallet_address() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "node"]);
    assert!(parsed.is_err());
}

#[test]
fn test_40_vectors_property_fuzz_adversarial_and_load_cli_surface() -> TestResult {
    for (name, expected) in chain_command_cases() {
        let parsed = parse_chain_from_strings(vec!["remzar".to_string(), name.to_string()])?;
        assert_eq!(parsed, Some(expected));
    }

    for choice in 0_u32..=500_u32 {
        let mapped = BlockchainSubcommand::from_choice(choice);
        if (1..=20).contains(&choice) {
            assert!(mapped.is_some());
        } else {
            assert!(mapped.is_none());
        }
    }

    let wallet = wallet_with_hex_digit('4');
    let mut adversarial_args = vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet.clone(),
    ];

    let oversized_bootstrap = "x".repeat(512);
    let adversarial_bootstraps = vec![
        String::new(),
        "not-a-multiaddr".to_string(),
        "/ip4/127.0.0.1/tcp/36213".to_string(),
        "/ip4/127.0.0.1/tcp/36213".to_string(),
        "/dns4/example.invalid/tcp/36213/p2p/not-a-real-peer-id".to_string(),
        oversized_bootstrap,
    ];

    for bootstrap in adversarial_bootstraps {
        adversarial_args.push("--bootstrap".to_string());
        adversarial_args.push(bootstrap);
    }

    let adversarial_opts = parse_node_from_strings(adversarial_args)?;
    assert_eq!(adversarial_opts.wallet_address, wallet);
    assert_eq!(adversarial_opts.bootstrap.len(), 6);

    let mut load_args = vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet_with_hex_digit('5'),
    ];

    for index in 0_usize..256_usize {
        let port = 36_213_usize
            .checked_add(index)
            .ok_or("port calculation overflow")?;

        load_args.push("--bootstrap".to_string());
        load_args.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let load_opts = parse_node_from_strings(load_args)?;
    assert_eq!(load_opts.bootstrap.len(), 256);

    for _round in 0_u8..25_u8 {
        for (name, expected) in chain_command_cases() {
            let parsed = parse_chain_from_strings(vec!["remzar".to_string(), name.to_string()])?;
            assert_eq!(parsed, Some(expected));
        }
    }

    Ok(())
}

#[test]
fn test_41_parse_no_args_has_no_genesis_and_no_command() -> TestResult {
    let parsed = BlockchainCommands::try_parse_from(["remzar"])?;

    assert!(parsed.genesis.is_none());
    assert!(parsed.command.is_none());

    Ok(())
}

#[test]
fn test_42_parse_long_genesis_without_command() -> TestResult {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "--genesis", "genesis.json"])?;

    assert_eq!(
        parsed.genesis,
        Some(std::path::PathBuf::from("genesis.json"))
    );
    assert!(parsed.command.is_none());

    Ok(())
}

#[test]
fn test_43_rejects_genesis_flag_without_value() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "--genesis"]);
    assert!(parsed.is_err());
}

#[test]
fn test_44_rejects_short_genesis_flag_without_value() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "-g"]);
    assert!(parsed.is_err());
}

#[test]
fn test_45_rejects_duplicate_genesis_flags() {
    let parsed = BlockchainCommands::try_parse_from([
        "remzar",
        "--genesis",
        "one.json",
        "--genesis",
        "two.json",
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_46_rejects_genesis_after_chain_subcommand() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "faq", "--genesis", "late.json"]);
    assert!(parsed.is_err());
}

#[test]
fn test_47_rejects_two_chain_subcommands_in_one_invocation() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "faq", "exit"]);
    assert!(parsed.is_err());
}

#[test]
fn test_48_rejects_numeric_menu_choice_as_cli_command() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "1"]);
    assert!(parsed.is_err());
}

#[test]
fn test_49_rejects_uppercase_chain_command() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "FAQ"]);
    assert!(parsed.is_err());
}

#[test]
fn test_50_rejects_underscore_chain_command_spelling() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "setup_database"]);
    assert!(parsed.is_err());
}

#[test]
fn test_51_rejects_camel_case_chain_command_spelling() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "setupDatabase"]);
    assert!(parsed.is_err());
}

#[test]
fn test_52_rejects_chain_command_with_unknown_flag() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "faq", "--unknown"]);
    assert!(parsed.is_err());
}

#[test]
fn test_53_rejects_chain_command_with_extra_positional_argument() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "exit", "now"]);
    assert!(parsed.is_err());
}

#[test]
fn test_54_help_flag_returns_display_help_error_kind() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "--help"]);

    match parsed {
        Ok(_) => panic!("expected --help to return a display-help error"),
        Err(error) => assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp),
    }
}

#[test]
fn test_55_node_help_flag_returns_display_help_error_kind() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "node", "--help"]);

    match parsed {
        Ok(_) => panic!("expected node --help to return a display-help error"),
        Err(error) => assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp),
    }
}

#[test]
fn test_56_chain_subcommand_help_returns_display_help_error_kind() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "start-node", "--help"]);

    match parsed {
        Ok(_) => panic!("expected start-node --help to return a display-help error"),
        Err(error) => assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp),
    }
}

#[test]
fn test_57_all_commands_parse_from_generated_vector_table() -> TestResult {
    for (cli_name, expected) in chain_command_cases() {
        let args = vec!["remzar".to_string(), cli_name.to_string()];
        let parsed = parse_chain_from_strings(args)?;
        assert_eq!(parsed, Some(expected));
    }

    Ok(())
}

#[test]
fn test_58_all_commands_reject_uppercase_generated_names() {
    for (cli_name, _expected) in chain_command_cases() {
        let upper = cli_name.to_ascii_uppercase();
        let parsed = BlockchainCommands::try_parse_from(vec!["remzar".to_string(), upper]);
        assert!(parsed.is_err());
    }
}

#[test]
fn test_59_all_commands_reject_underscore_generated_names() {
    for (cli_name, _expected) in chain_command_cases() {
        if !cli_name.contains('-') {
            continue;
        }

        let underscored = cli_name.replace('-', "_");
        let parsed = BlockchainCommands::try_parse_from(vec!["remzar".to_string(), underscored]);
        assert!(parsed.is_err());
    }
}

#[test]
fn test_60_all_commands_reject_trailing_extra_argument() {
    for (cli_name, _expected) in chain_command_cases() {
        let parsed = BlockchainCommands::try_parse_from(vec![
            "remzar".to_string(),
            cli_name.to_string(),
            "extra".to_string(),
        ]);
        assert!(parsed.is_err());
    }
}

#[test]
fn test_61_from_choice_rejects_large_invalid_range() {
    for choice in 21_u32..=1_000_u32 {
        assert_eq!(BlockchainSubcommand::from_choice(choice), None);
    }
}

#[test]
fn test_62_from_choice_accepts_exact_valid_range_only() {
    for choice in 1_u32..=20_u32 {
        assert!(BlockchainSubcommand::from_choice(choice).is_some());
    }
}

#[test]
fn test_63_all_commands_have_menu_numbers_that_resolve_back() -> TestResult {
    for (index, (_label, command)) in BlockchainSubcommand::all().iter().enumerate() {
        let menu_number = u32::try_from(index.checked_add(1).ok_or("menu index overflow")?)?;
        assert_eq!(
            BlockchainSubcommand::from_choice(menu_number),
            Some(*command)
        );
    }

    Ok(())
}

#[test]
fn test_64_all_commands_clone_and_copy_without_changing_value() {
    for (_label, command) in BlockchainSubcommand::all() {
        let copied = command;
        let cloned = command;

        assert_eq!(command, copied);
        assert_eq!(command, cloned);
    }
}

#[test]
fn test_65_all_command_debug_names_are_non_empty() {
    for (_label, command) in BlockchainSubcommand::all() {
        let debug_name = format!("{command:?}");
        assert!(!debug_name.trim().is_empty());
    }
}

#[test]
fn test_66_specific_debug_names_match_variants() {
    let cases = [
        (BlockchainSubcommand::SetupDatabase, "SetupDatabase"),
        (BlockchainSubcommand::GenerateWallet, "GenerateWallet"),
        (BlockchainSubcommand::StartNode, "StartNode"),
        (BlockchainSubcommand::ViewConsole, "ViewConsole"),
        (BlockchainSubcommand::SendRemzar, "SendRemzar"),
        (BlockchainSubcommand::ReceiveRemzar, "ReceiveRemzar"),
        (BlockchainSubcommand::ViewStatus, "ViewStatus"),
        (BlockchainSubcommand::CheckBalance, "CheckBalance"),
        (BlockchainSubcommand::ListWallets, "ListWallets"),
        (BlockchainSubcommand::CreateNft, "CreateNft"),
        (BlockchainSubcommand::SendChat, "SendChat"),
        (BlockchainSubcommand::SendFile, "SendFile"),
        (BlockchainSubcommand::OpenEncryptedKey, "OpenEncryptedKey"),
        (BlockchainSubcommand::BackupWallet, "BackupWallet"),
        (BlockchainSubcommand::DebugKeys, "DebugKeys"),
        (BlockchainSubcommand::DebugLogInfo, "DebugLogInfo"),
        (BlockchainSubcommand::AuditReport, "AuditReport"),
        (BlockchainSubcommand::PlaySlots, "PlaySlots"),
        (BlockchainSubcommand::Faq, "Faq"),
        (BlockchainSubcommand::Exit, "Exit"),
    ];

    for (command, expected_debug) in cases {
        assert_eq!(format!("{command:?}"), expected_debug);
    }
}

#[test]
fn test_67_node_rejects_unknown_flag() {
    let wallet = wallet_with_hex_digit('6');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--not-real".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_68_node_rejects_identity_file_without_value() {
    let wallet = wallet_with_hex_digit('7');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--identity-file".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_69_node_rejects_listen_without_value() {
    let wallet = wallet_with_hex_digit('8');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--listen".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_70_node_rejects_bootstrap_without_value() {
    let wallet = wallet_with_hex_digit('9');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--bootstrap".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_71_node_rejects_log_without_value() {
    let wallet = wallet_with_hex_digit('a');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--log".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_72_node_rejects_data_dir_without_value() {
    let wallet = wallet_with_hex_digit('b');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--data-dir".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_73_node_rejects_wallet_address_without_value() {
    let parsed = BlockchainCommands::try_parse_from(["remzar", "node", "--wallet-address"]);
    assert!(parsed.is_err());
}

#[test]
fn test_74_node_accepts_empty_wallet_value_when_argument_is_present() -> TestResult {
    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        String::new(),
    ])?;

    assert_eq!(opts.wallet_address, "");

    Ok(())
}

#[test]
fn test_75_node_accepts_empty_identity_file_value() -> TestResult {
    let wallet = wallet_with_hex_digit('c');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--identity-file".to_string(),
        String::new(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.identity_file, "");

    Ok(())
}

#[test]
fn test_76_node_accepts_empty_data_dir_value() -> TestResult {
    let wallet = wallet_with_hex_digit('d');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--data-dir".to_string(),
        String::new(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.data_dir, "");

    Ok(())
}

#[test]
fn test_77_node_accepts_empty_bootstrap_value_as_raw_cli_string() -> TestResult {
    let wallet = wallet_with_hex_digit('e');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--bootstrap".to_string(),
        String::new(),
    ])?;

    assert_eq!(opts.bootstrap, vec![String::new()]);

    Ok(())
}

#[test]
fn test_78_node_preserves_bootstrap_order_and_duplicates() -> TestResult {
    let wallet = wallet_with_hex_digit('f');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--bootstrap".to_string(),
        "/ip4/127.0.0.1/tcp/36213".to_string(),
        "--bootstrap".to_string(),
        "/ip4/127.0.0.1/tcp/36213".to_string(),
        "--bootstrap".to_string(),
        "/ip4/127.0.0.1/tcp/36214".to_string(),
    ])?;

    assert_eq!(
        opts.bootstrap,
        vec![
            "/ip4/127.0.0.1/tcp/36213".to_string(),
            "/ip4/127.0.0.1/tcp/36213".to_string(),
            "/ip4/127.0.0.1/tcp/36214".to_string(),
        ]
    );

    Ok(())
}

#[test]
fn test_79_node_accepts_bootstrap_value_that_starts_with_dash_when_assigned() -> TestResult {
    let wallet = wallet_with_hex_digit('1');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--bootstrap=-not-a-flag".to_string(),
    ])?;

    assert_eq!(opts.bootstrap, vec!["-not-a-flag".to_string()]);

    Ok(())
}

#[test]
fn test_80_node_rejects_bootstrap_value_that_starts_with_dash_unescaped() {
    let wallet = wallet_with_hex_digit('2');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--bootstrap".to_string(),
        "-not-a-flag".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_81_node_accepts_identity_file_with_spaces_as_single_argument() -> TestResult {
    let wallet = wallet_with_hex_digit('3');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--identity-file".to_string(),
        "folder name/local identity.key".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.identity_file, "folder name/local identity.key");

    Ok(())
}

#[test]
fn test_82_node_accepts_data_dir_with_spaces_as_single_argument() -> TestResult {
    let wallet = wallet_with_hex_digit('4');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--data-dir".to_string(),
        "data folder/node one".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.data_dir, "data folder/node one");

    Ok(())
}

#[test]
fn test_83_node_accepts_arbitrary_listen_string_without_runtime_validation() -> TestResult {
    let wallet = wallet_with_hex_digit('5');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--listen".to_string(),
        "not-a-real-multiaddr".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.listen, "not-a-real-multiaddr");

    Ok(())
}

#[test]
fn test_84_node_accepts_arbitrary_wallet_string_without_cli_validation() -> TestResult {
    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        "not-a-wallet".to_string(),
    ])?;

    assert_eq!(opts.wallet_address, "not-a-wallet");

    Ok(())
}

#[test]
fn test_85_node_accepts_arbitrary_log_filter_string() -> TestResult {
    let wallet = wallet_with_hex_digit('6');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--log".to_string(),
        "remzar=trace,libp2p=warn".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert_eq!(opts.log, "remzar=trace,libp2p=warn");

    Ok(())
}

#[test]
fn test_86_node_founder_defaults_false_without_flag() -> TestResult {
    let wallet = wallet_with_hex_digit('7');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ])?;

    assert!(!opts.founder);

    Ok(())
}

#[test]
fn test_87_node_founder_long_flag_sets_true() -> TestResult {
    let wallet = wallet_with_hex_digit('8');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--founder".to_string(),
    ])?;

    assert!(opts.founder);

    Ok(())
}

#[test]
fn test_88_node_is_founder_alias_sets_true() -> TestResult {
    let wallet = wallet_with_hex_digit('9');

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--is-founder".to_string(),
    ])?;

    assert!(opts.founder);

    Ok(())
}

#[test]
fn test_89_node_rejects_founder_flag_with_value() {
    let wallet = wallet_with_hex_digit('a');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--founder=true".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_90_node_rejects_is_founder_alias_with_value() {
    let wallet = wallet_with_hex_digit('b');

    let parsed = BlockchainCommands::try_parse_from(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
        "--is-founder=true".to_string(),
    ]);

    assert!(parsed.is_err());
}

#[test]
fn test_91_node_load_accepts_two_hundred_fifty_six_bootstraps() -> TestResult {
    let mut args = vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet_with_hex_digit('c'),
    ];

    for index in 0_usize..256_usize {
        args.push("--bootstrap".to_string());
        args.push(format!("/ip4/10.0.0.1/tcp/{index}"));
    }

    let opts = parse_node_from_strings(args)?;

    assert_eq!(opts.bootstrap.len(), 256);
    assert_eq!(
        opts.bootstrap.first(),
        Some(&"/ip4/10.0.0.1/tcp/0".to_string())
    );
    assert_eq!(
        opts.bootstrap.last(),
        Some(&"/ip4/10.0.0.1/tcp/255".to_string())
    );

    Ok(())
}

#[test]
fn test_92_chain_parser_property_every_valid_command_is_some() -> TestResult {
    for (cli_name, _expected) in chain_command_cases() {
        let parsed = parse_chain_from_strings(vec!["remzar".to_string(), cli_name.to_string()])?;
        assert!(parsed.is_some());
    }

    Ok(())
}

#[test]
fn test_93_chain_parser_property_invalid_single_byte_names_rejected() {
    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);
        let candidate = ch.to_string();

        if candidate.chars().all(|c| c.is_ascii_alphanumeric()) {
            let parsed = BlockchainCommands::try_parse_from(vec!["remzar".to_string(), candidate]);
            assert!(parsed.is_err());
        }
    }
}

#[test]
fn test_94_chain_parser_adversarial_long_unknown_name_rejected() {
    let long_name = "x".repeat(8_192);
    let parsed = BlockchainCommands::try_parse_from(vec!["remzar".to_string(), long_name]);

    assert!(parsed.is_err());
}

#[test]
fn test_95_node_parser_adversarial_long_wallet_is_preserved_by_cli_layer() -> TestResult {
    let long_wallet = "r".repeat(8_192);

    let opts = parse_node_from_strings(vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        long_wallet.clone(),
    ])?;

    assert_eq!(opts.wallet_address, long_wallet);

    Ok(())
}

#[test]
fn test_96_node_parser_adversarial_many_unknown_flags_rejected() {
    let wallet = wallet_with_hex_digit('d');
    let mut args = vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet,
    ];

    for index in 0_usize..64_usize {
        args.push(format!("--unknown-flag-{index}"));
    }

    let parsed = BlockchainCommands::try_parse_from(args);
    assert!(parsed.is_err());
}

#[test]
fn test_97_root_parser_rejects_random_adversarial_tokens() {
    let cases = [
        "",
        "-",
        "---",
        "--node",
        "node-start",
        "startnode",
        "wallet-generate",
        "debug-log",
        "audit",
        "slots",
    ];

    for case in cases {
        let parsed = BlockchainCommands::try_parse_from(["remzar", case]);
        assert!(parsed.is_err(), "case should be rejected: {case:?}");
    }
}

#[test]
fn test_98_menu_labels_contain_expected_security_and_network_words() {
    let labels: Vec<&'static str> = BlockchainSubcommand::all()
        .into_iter()
        .map(|(label, _command)| label)
        .collect();

    assert!(labels.iter().any(|label| label.contains("Database")));
    assert!(labels.iter().any(|label| label.contains("Wallet")));
    assert!(labels.iter().any(|label| label.contains("Blockchain")));
    assert!(labels.iter().any(|label| label.contains("REMZAR")));
    assert!(labels.iter().any(|label| label.contains("p2p")));
    assert!(labels.iter().any(|label| label.contains("Debug")));
    assert!(labels.iter().any(|label| label.contains("Audit")));
}

#[test]
fn test_99_property_choice_mapping_matches_all_vector_length() -> TestResult {
    let all = BlockchainSubcommand::all();
    let all_len_u32 = u32::try_from(all.len())?;

    assert_eq!(all_len_u32, 20);

    for choice in 1_u32..=all_len_u32 {
        let zero_based = usize::try_from(choice.checked_sub(1).ok_or("choice underflow")?)?;
        let expected = all
            .get(zero_based)
            .map(|(_label, command)| *command)
            .ok_or("missing command for menu choice")?;

        assert_eq!(BlockchainSubcommand::from_choice(choice), Some(expected));
    }

    Ok(())
}

#[test]
fn test_100_combined_vector_edge_fuzz_adversarial_and_load_suite() -> TestResult {
    for (cli_name, expected) in chain_command_cases() {
        let parsed = parse_chain_from_strings(vec!["remzar".to_string(), cli_name.to_string()])?;
        assert_eq!(parsed, Some(expected));
    }

    for choice in 0_u32..=2_000_u32 {
        let mapped = BlockchainSubcommand::from_choice(choice);
        assert_eq!(mapped.is_some(), (1..=20).contains(&choice));
    }

    let adversarial_names = [
        "nodee",
        "setup--database",
        "setup database",
        " setup-database",
        "setup-database ",
        "../setup-database",
        "🧪",
        "\t",
        "\n",
    ];

    for name in adversarial_names {
        let parsed = BlockchainCommands::try_parse_from(["remzar", name]);
        assert!(parsed.is_err());
    }

    let wallet = wallet_with_hex_digit('e');
    let mut node_args = vec![
        "remzar".to_string(),
        "node".to_string(),
        "--wallet-address".to_string(),
        wallet.clone(),
        "--log".to_string(),
        "trace".to_string(),
        "--data-dir".to_string(),
        "load-test-data".to_string(),
    ];

    for index in 0_usize..512_usize {
        node_args.push("--bootstrap".to_string());
        node_args.push(format!("/ip4/127.0.0.1/tcp/{index}"));
    }

    let opts = parse_node_from_strings(node_args)?;

    assert_eq!(opts.wallet_address, wallet);
    assert_eq!(opts.log, "trace");
    assert_eq!(opts.data_dir, "load-test-data");
    assert_eq!(opts.bootstrap.len(), 512);

    Ok(())
}
