use remzar::commandline::command_line_001_interface::BlockchainSubcommand;
use remzar::commandline::command_line_002_menu::Menu;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REAL_MENU_SOURCE: &str = include_str!("../src/commandline/command_line_002_menu.rs");

#[derive(Clone, Copy)]
struct MenuRow {
    choice: u32,
    fragment: &'static str,
    command: BlockchainSubcommand,
    all_label: &'static str,
    debug_name: &'static str,
}

fn menu_rows() -> [MenuRow; 20] {
    [
        MenuRow {
            choice: 1,
            fragment: "│ [1]   🛢️   Setup Database                                  │",
            command: BlockchainSubcommand::SetupDatabase,
            all_label: "Setup Database",
            debug_name: "SetupDatabase",
        },
        MenuRow {
            choice: 2,
            fragment: "│ [2]   💳   Generate New Wallet                             │",
            command: BlockchainSubcommand::GenerateWallet,
            all_label: "Generate Wallet",
            debug_name: "GenerateWallet",
        },
        MenuRow {
            choice: 3,
            fragment: "│ [3]   🌐   START ⇒  REMZAR BLOCKCHAIN NODE                 │",
            command: BlockchainSubcommand::StartNode,
            all_label: "Start Node",
            debug_name: "StartNode",
        },
        MenuRow {
            choice: 4,
            fragment: "│ [4]   🖥️   View Blockchain Console                         │",
            command: BlockchainSubcommand::ViewConsole,
            all_label: "View Blockchain Console",
            debug_name: "ViewConsole",
        },
        MenuRow {
            choice: 5,
            fragment: "│ [5]   📤   Send       ⇒    Remzar COIN                     │",
            command: BlockchainSubcommand::SendRemzar,
            all_label: "Send REMZAR",
            debug_name: "SendRemzar",
        },
        MenuRow {
            choice: 6,
            fragment: "│ [6]   📥   Receive    ⇐    Remzar COIN                     │",
            command: BlockchainSubcommand::ReceiveRemzar,
            all_label: "Receive REMZAR",
            debug_name: "ReceiveRemzar",
        },
        MenuRow {
            choice: 7,
            fragment: "│ [7]   ✅   View Participant Status                         │",
            command: BlockchainSubcommand::ViewStatus,
            all_label: "View Participant Status",
            debug_name: "ViewStatus",
        },
        MenuRow {
            choice: 8,
            fragment: "│ [8]   💰   Balance of Wallet                               │",
            command: BlockchainSubcommand::CheckBalance,
            all_label: "Balance of Wallet",
            debug_name: "CheckBalance",
        },
        MenuRow {
            choice: 9,
            fragment: "│ [9]   💼   List Wallets                                    │",
            command: BlockchainSubcommand::ListWallets,
            all_label: "List Wallets",
            debug_name: "ListWallets",
        },
        MenuRow {
            choice: 10,
            fragment: "│ [10]  🖼️   Create Certificates (mint)                      │",
            command: BlockchainSubcommand::CreateNft,
            all_label: "Create Certificates (mint)",
            debug_name: "CreateNft",
        },
        MenuRow {
            choice: 11,
            fragment: "│ [11]  💬   Send Chat (p2p message)                         │",
            command: BlockchainSubcommand::SendChat,
            all_label: "Send Chat (p2p message)",
            debug_name: "SendChat",
        },
        MenuRow {
            choice: 12,
            fragment: "│ [12]  📂   Send File (p2p file sharing)                    │",
            command: BlockchainSubcommand::SendFile,
            all_label: "Send File (p2p file sharing)",
            debug_name: "SendFile",
        },
        MenuRow {
            choice: 13,
            fragment: "│ [13]  🔓   Debug: Open Encrypted Private Key               │",
            command: BlockchainSubcommand::OpenEncryptedKey,
            all_label: "Debug: Open Encrypted Private Key",
            debug_name: "OpenEncryptedKey",
        },
        MenuRow {
            choice: 14,
            fragment: "│ [14]  💾   Debug: Backup Wallet                            │",
            command: BlockchainSubcommand::BackupWallet,
            all_label: "Debug: Backup Wallet",
            debug_name: "BackupWallet",
        },
        MenuRow {
            choice: 15,
            fragment: "│ [15]  🛠️   Debug: List Raw Database Keys                   │",
            command: BlockchainSubcommand::DebugKeys,
            all_label: "Debug: List Raw Database Keys",
            debug_name: "DebugKeys",
        },
        MenuRow {
            choice: 16,
            fragment: "│ [16]  📜   Debug: Log Information                          │",
            command: BlockchainSubcommand::DebugLogInfo,
            all_label: "Debug: Log Information",
            debug_name: "DebugLogInfo",
        },
        MenuRow {
            choice: 17,
            fragment: "│ [17]  📑   Debug: Audit Report                             │",
            command: BlockchainSubcommand::AuditReport,
            all_label: "Debug: Audit Report",
            debug_name: "AuditReport",
        },
        MenuRow {
            choice: 18,
            fragment: "│ [18]  🎰   Slot Machine Game                               │",
            command: BlockchainSubcommand::PlaySlots,
            all_label: "Slot Machine Game",
            debug_name: "PlaySlots",
        },
        MenuRow {
            choice: 19,
            fragment: "│ [19]  ❓   FAQ (MUST READ)                                 │",
            command: BlockchainSubcommand::Faq,
            all_label: "FAQ (MUST READ)",
            debug_name: "Faq",
        },
        MenuRow {
            choice: 20,
            fragment: "│ [20]  🚪   Exit                                            │",
            command: BlockchainSubcommand::Exit,
            all_label: "Exit",
            debug_name: "Exit",
        },
    ]
}

fn menu_row_by_choice(choice: u32) -> Option<MenuRow> {
    menu_rows().into_iter().find(|row| row.choice == choice)
}

fn assert_real_menu_contains(fragment: &str) {
    assert!(
        REAL_MENU_SOURCE.contains(fragment),
        "real command_line_002_menu.rs is missing expected menu fragment: {fragment}"
    );
}

fn simulated_command_from_open_input(input: &str) -> Option<BlockchainSubcommand> {
    const MAX_INPUT_BYTES: usize = 64;

    if input.len() > MAX_INPUT_BYTES {
        return None;
    }

    let trimmed = input.trim();
    let Ok(choice) = trimmed.parse::<u32>() else {
        return None;
    };

    if !(1..=20).contains(&choice) {
        return None;
    }

    BlockchainSubcommand::from_choice(choice)
}

#[test]
fn test_01_menu_new_is_zero_sized() {
    let menu = Menu::new();
    assert_eq!(std::mem::size_of_val(&menu), 0);
}

#[test]
fn test_02_menu_default_is_zero_sized() {
    let menu = Menu;
    assert_eq!(std::mem::size_of_val(&menu), 0);
}

#[test]
fn test_03_menu_new_and_default_have_same_size() {
    let new_menu = Menu::new();
    let default_menu = Menu;

    assert_eq!(
        std::mem::size_of_val(&new_menu),
        std::mem::size_of_val(&default_menu)
    );
}

#[test]
fn test_04_menu_new_display_does_not_panic() {
    let result = std::panic::catch_unwind(|| {
        let menu = Menu::new();
        menu.display();
    });

    assert!(result.is_ok());
}

#[test]
fn test_05_menu_default_display_does_not_panic() {
    let result = std::panic::catch_unwind(|| {
        let menu = Menu;
        menu.display();
    });

    assert!(result.is_ok());
}

#[test]
fn test_06_menu_display_load_three_render_calls_do_not_panic() {
    let result = std::panic::catch_unwind(|| {
        let menu = Menu::new();
        for _round in 0_u8..3_u8 {
            menu.display();
        }
    });

    assert!(result.is_ok());
}

#[test]
fn test_07_menu_row_vector_has_twenty_entries() {
    assert_eq!(menu_rows().len(), 20);
}

#[test]
fn test_08_menu_row_choices_are_contiguous_one_to_twenty() -> TestResult {
    for expected_choice in 1_u32..=20_u32 {
        let row = menu_row_by_choice(expected_choice).ok_or("missing menu row")?;
        assert_eq!(row.choice, expected_choice);
    }

    Ok(())
}

#[test]
fn test_09_menu_row_choices_are_unique() {
    let rows = menu_rows();

    for row in rows {
        let count = menu_rows()
            .into_iter()
            .filter(|candidate| candidate.choice == row.choice)
            .count();

        assert_eq!(count, 1);
    }
}

#[test]
fn test_10_menu_row_commands_are_unique() {
    let rows = menu_rows();

    for row in rows {
        let count = menu_rows()
            .into_iter()
            .filter(|candidate| candidate.command == row.command)
            .count();

        assert_eq!(count, 1);
    }
}

#[test]
fn test_11_menu_row_fragments_are_unique() {
    let rows = menu_rows();

    for row in rows {
        let count = menu_rows()
            .into_iter()
            .filter(|candidate| candidate.fragment == row.fragment)
            .count();

        assert_eq!(count, 1);
    }
}

#[test]
fn test_12_menu_row_fragments_are_box_lines() {
    for row in menu_rows() {
        assert!(row.fragment.starts_with('│'));
        assert!(row.fragment.ends_with('│'));
    }
}

#[test]
fn test_13_menu_row_fragments_contain_choice_brackets() {
    for row in menu_rows() {
        let marker = format!("[{}]", row.choice);
        assert!(row.fragment.contains(&marker));
    }
}

#[test]
fn test_14_menu_row_fragments_are_not_empty() {
    for row in menu_rows() {
        assert!(!row.fragment.trim().is_empty());
    }
}

#[test]
fn test_15_every_menu_row_maps_through_from_choice() {
    for row in menu_rows() {
        assert_eq!(
            BlockchainSubcommand::from_choice(row.choice),
            Some(row.command)
        );
    }
}

#[test]
fn test_16_from_choice_zero_is_none() {
    assert_eq!(BlockchainSubcommand::from_choice(0), None);
}

#[test]
fn test_17_from_choice_twenty_one_is_none() {
    assert_eq!(BlockchainSubcommand::from_choice(21), None);
}

#[test]
fn test_18_from_choice_u32_max_is_none() {
    assert_eq!(BlockchainSubcommand::from_choice(u32::MAX), None);
}

#[test]
fn test_19_from_choice_one_thousand_is_none() {
    assert_eq!(BlockchainSubcommand::from_choice(1_000), None);
}

#[test]
fn test_20_from_choice_all_valid_choices_are_some() {
    for choice in 1_u32..=20_u32 {
        assert!(BlockchainSubcommand::from_choice(choice).is_some());
    }
}

#[test]
fn test_21_from_choice_invalid_range_is_none() {
    for choice in 21_u32..=100_u32 {
        assert_eq!(BlockchainSubcommand::from_choice(choice), None);
    }
}

#[test]
fn test_22_interface_all_has_twenty_entries() {
    assert_eq!(BlockchainSubcommand::all().len(), 20);
}

#[test]
fn test_23_interface_all_order_matches_menu_rows() -> TestResult {
    let all = BlockchainSubcommand::all();

    for row in menu_rows() {
        let index = usize::try_from(row.choice.checked_sub(1).ok_or("choice underflow")?)?;
        let found = all
            .get(index)
            .map(|(_label, command)| *command)
            .ok_or("missing command")?;

        assert_eq!(found, row.command);
    }

    Ok(())
}

#[test]
fn test_24_interface_all_labels_match_menu_rows() -> TestResult {
    let all = BlockchainSubcommand::all();

    for row in menu_rows() {
        let found = all
            .iter()
            .find(|(_label, command)| *command == row.command)
            .ok_or("missing command label")?;

        let (label, _command) = *found;
        assert_eq!(label, row.all_label);
    }

    Ok(())
}

#[test]
fn test_25_interface_all_commands_are_unique() {
    let all = BlockchainSubcommand::all();

    for (_label, command) in &all {
        let count = all
            .iter()
            .filter(|(_candidate_label, candidate_command)| candidate_command == command)
            .count();

        assert_eq!(count, 1);
    }
}

#[test]
fn test_26_debug_names_match_menu_rows() {
    for row in menu_rows() {
        assert_eq!(format!("{:?}", row.command), row.debug_name);
    }
}

#[test]
fn test_27_command_copy_trait_round_trip() {
    fn copy_value<T: Copy>(value: T) -> T {
        value
    }

    for row in menu_rows() {
        let copied = copy_value(row.command);
        assert_eq!(copied, row.command);
    }
}

#[test]
fn test_28_command_clone_trait_round_trip() {
    fn clone_value<T: Clone>(value: &T) -> T {
        value.clone()
    }

    for row in menu_rows() {
        let cloned = clone_value(&row.command);
        assert_eq!(cloned, row.command);
    }
}

#[test]
fn test_29_menu_new_can_be_constructed_many_times() {
    for _round in 0_u16..1_024_u16 {
        let menu = Menu::new();
        assert_eq!(std::mem::size_of_val(&menu), 0);
    }
}

#[test]
fn test_30_from_choice_01_setup_database() {
    assert_eq!(
        BlockchainSubcommand::from_choice(1),
        Some(BlockchainSubcommand::SetupDatabase)
    );
}

#[test]
fn test_31_from_choice_02_generate_wallet() {
    assert_eq!(
        BlockchainSubcommand::from_choice(2),
        Some(BlockchainSubcommand::GenerateWallet)
    );
}

#[test]
fn test_32_from_choice_03_start_node() {
    assert_eq!(
        BlockchainSubcommand::from_choice(3),
        Some(BlockchainSubcommand::StartNode)
    );
}

#[test]
fn test_33_from_choice_04_view_console() {
    assert_eq!(
        BlockchainSubcommand::from_choice(4),
        Some(BlockchainSubcommand::ViewConsole)
    );
}

#[test]
fn test_34_from_choice_05_send_remzar() {
    assert_eq!(
        BlockchainSubcommand::from_choice(5),
        Some(BlockchainSubcommand::SendRemzar)
    );
}

#[test]
fn test_35_from_choice_06_receive_remzar() {
    assert_eq!(
        BlockchainSubcommand::from_choice(6),
        Some(BlockchainSubcommand::ReceiveRemzar)
    );
}

#[test]
fn test_36_from_choice_07_view_status() {
    assert_eq!(
        BlockchainSubcommand::from_choice(7),
        Some(BlockchainSubcommand::ViewStatus)
    );
}

#[test]
fn test_37_from_choice_08_check_balance() {
    assert_eq!(
        BlockchainSubcommand::from_choice(8),
        Some(BlockchainSubcommand::CheckBalance)
    );
}

#[test]
fn test_38_from_choice_09_list_wallets() {
    assert_eq!(
        BlockchainSubcommand::from_choice(9),
        Some(BlockchainSubcommand::ListWallets)
    );
}

#[test]
fn test_39_from_choice_10_create_nft() {
    assert_eq!(
        BlockchainSubcommand::from_choice(10),
        Some(BlockchainSubcommand::CreateNft)
    );
}

#[test]
fn test_40_from_choice_11_send_chat() {
    assert_eq!(
        BlockchainSubcommand::from_choice(11),
        Some(BlockchainSubcommand::SendChat)
    );
}

#[test]
fn test_41_from_choice_12_send_file() {
    assert_eq!(
        BlockchainSubcommand::from_choice(12),
        Some(BlockchainSubcommand::SendFile)
    );
}

#[test]
fn test_42_from_choice_13_open_encrypted_key() {
    assert_eq!(
        BlockchainSubcommand::from_choice(13),
        Some(BlockchainSubcommand::OpenEncryptedKey)
    );
}

#[test]
fn test_43_from_choice_14_backup_wallet() {
    assert_eq!(
        BlockchainSubcommand::from_choice(14),
        Some(BlockchainSubcommand::BackupWallet)
    );
}

#[test]
fn test_44_from_choice_15_debug_keys() {
    assert_eq!(
        BlockchainSubcommand::from_choice(15),
        Some(BlockchainSubcommand::DebugKeys)
    );
}

#[test]
fn test_45_from_choice_16_debug_log_info() {
    assert_eq!(
        BlockchainSubcommand::from_choice(16),
        Some(BlockchainSubcommand::DebugLogInfo)
    );
}

#[test]
fn test_46_from_choice_17_audit_report() {
    assert_eq!(
        BlockchainSubcommand::from_choice(17),
        Some(BlockchainSubcommand::AuditReport)
    );
}

#[test]
fn test_47_from_choice_18_play_slots() {
    assert_eq!(
        BlockchainSubcommand::from_choice(18),
        Some(BlockchainSubcommand::PlaySlots)
    );
}

#[test]
fn test_48_from_choice_19_faq() {
    assert_eq!(
        BlockchainSubcommand::from_choice(19),
        Some(BlockchainSubcommand::Faq)
    );
}

#[test]
fn test_49_from_choice_20_exit() {
    assert_eq!(
        BlockchainSubcommand::from_choice(20),
        Some(BlockchainSubcommand::Exit)
    );
}

#[test]
fn test_50_real_menu_fragment_01_setup_database() {
    let expected = "│ [1]   🛢️   Setup Database                                  │";
    assert_eq!(
        menu_row_by_choice(1).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_51_real_menu_fragment_02_generate_new_wallet() {
    let expected = "│ [2]   💳   Generate New Wallet                             │";
    assert_eq!(
        menu_row_by_choice(2).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_52_real_menu_fragment_03_start_node() {
    let expected = "│ [3]   🌐   START ⇒  REMZAR BLOCKCHAIN NODE                 │";
    assert_eq!(
        menu_row_by_choice(3).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_53_real_menu_fragment_04_view_blockchain_console() {
    let expected = "│ [4]   🖥️   View Blockchain Console                         │";
    assert_eq!(
        menu_row_by_choice(4).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_54_real_menu_fragment_05_send_remzar_coin() {
    let expected = "│ [5]   📤   Send       ⇒    Remzar COIN                     │";
    assert_eq!(
        menu_row_by_choice(5).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_55_real_menu_fragment_06_receive_remzar_coin() {
    let expected = "│ [6]   📥   Receive    ⇐    Remzar COIN                     │";
    assert_eq!(
        menu_row_by_choice(6).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_56_real_menu_fragment_07_view_participant_status() {
    let expected = "│ [7]   ✅   View Participant Status                         │";
    assert_eq!(
        menu_row_by_choice(7).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_57_real_menu_fragment_08_balance_of_wallet() {
    let expected = "│ [8]   💰   Balance of Wallet                               │";
    assert_eq!(
        menu_row_by_choice(8).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_58_real_menu_fragment_09_list_wallets() {
    let expected = "│ [9]   💼   List Wallets                                    │";
    assert_eq!(
        menu_row_by_choice(9).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_59_real_menu_fragment_10_create_certificates() {
    let expected = "│ [10]  🖼️   Create Certificates (mint)                      │";
    assert_eq!(
        menu_row_by_choice(10).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_60_real_menu_fragment_11_send_chat() {
    let expected = "│ [11]  💬   Send Chat (p2p message)                         │";
    assert_eq!(
        menu_row_by_choice(11).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_61_real_menu_fragment_12_send_file() {
    let expected = "│ [12]  📂   Send File (p2p file sharing)                    │";
    assert_eq!(
        menu_row_by_choice(12).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_62_real_menu_fragment_13_open_encrypted_key() {
    let expected = "│ [13]  🔓   Debug: Open Encrypted Private Key               │";
    assert_eq!(
        menu_row_by_choice(13).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_63_real_menu_fragment_14_backup_wallet() {
    let expected = "│ [14]  💾   Debug: Backup Wallet                            │";
    assert_eq!(
        menu_row_by_choice(14).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_64_real_menu_fragment_15_debug_keys() {
    let expected = "│ [15]  🛠️   Debug: List Raw Database Keys                   │";
    assert_eq!(
        menu_row_by_choice(15).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_65_real_menu_fragment_16_log_information() {
    let expected = "│ [16]  📜   Debug: Log Information                          │";
    assert_eq!(
        menu_row_by_choice(16).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_66_real_menu_fragment_17_audit_report() {
    let expected = "│ [17]  📑   Debug: Audit Report                             │";
    assert_eq!(
        menu_row_by_choice(17).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_67_real_menu_fragment_18_slot_machine_game() {
    let expected = "│ [18]  🎰   Slot Machine Game                               │";
    assert_eq!(
        menu_row_by_choice(18).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_68_real_menu_fragment_19_faq() {
    let expected = "│ [19]  ❓   FAQ (MUST READ)                                 │";
    assert_eq!(
        menu_row_by_choice(19).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_69_real_menu_fragment_20_exit() {
    let expected = "│ [20]  🚪   Exit                                            │";
    assert_eq!(
        menu_row_by_choice(20).map(|row| row.fragment),
        Some(expected)
    );
    assert_real_menu_contains(expected);
}

#[test]
fn test_70_interface_label_01_setup_database() {
    assert_eq!(
        menu_row_by_choice(1).map(|row| row.all_label),
        Some("Setup Database")
    );
}

#[test]
fn test_71_interface_label_02_generate_wallet() {
    assert_eq!(
        menu_row_by_choice(2).map(|row| row.all_label),
        Some("Generate Wallet")
    );
}

#[test]
fn test_72_interface_label_03_start_node() {
    assert_eq!(
        menu_row_by_choice(3).map(|row| row.all_label),
        Some("Start Node")
    );
}

#[test]
fn test_73_interface_label_04_view_console() {
    assert_eq!(
        menu_row_by_choice(4).map(|row| row.all_label),
        Some("View Blockchain Console")
    );
}

#[test]
fn test_74_interface_label_05_send_remzar() {
    assert_eq!(
        menu_row_by_choice(5).map(|row| row.all_label),
        Some("Send REMZAR")
    );
}

#[test]
fn test_75_interface_label_06_receive_remzar() {
    assert_eq!(
        menu_row_by_choice(6).map(|row| row.all_label),
        Some("Receive REMZAR")
    );
}

#[test]
fn test_76_interface_label_07_view_status() {
    assert_eq!(
        menu_row_by_choice(7).map(|row| row.all_label),
        Some("View Participant Status")
    );
}

#[test]
fn test_77_interface_label_08_check_balance() {
    assert_eq!(
        menu_row_by_choice(8).map(|row| row.all_label),
        Some("Balance of Wallet")
    );
}

#[test]
fn test_78_interface_label_09_list_wallets() {
    assert_eq!(
        menu_row_by_choice(9).map(|row| row.all_label),
        Some("List Wallets")
    );
}

#[test]
fn test_79_interface_label_10_create_certificates() {
    assert_eq!(
        menu_row_by_choice(10).map(|row| row.all_label),
        Some("Create Certificates (mint)")
    );
}

#[test]
fn test_80_interface_label_11_send_chat() {
    assert_eq!(
        menu_row_by_choice(11).map(|row| row.all_label),
        Some("Send Chat (p2p message)")
    );
}

#[test]
fn test_81_interface_label_12_send_file() {
    assert_eq!(
        menu_row_by_choice(12).map(|row| row.all_label),
        Some("Send File (p2p file sharing)")
    );
}

#[test]
fn test_82_interface_label_13_open_encrypted_key() {
    assert_eq!(
        menu_row_by_choice(13).map(|row| row.all_label),
        Some("Debug: Open Encrypted Private Key")
    );
}

#[test]
fn test_83_interface_label_14_backup_wallet() {
    assert_eq!(
        menu_row_by_choice(14).map(|row| row.all_label),
        Some("Debug: Backup Wallet")
    );
}

#[test]
fn test_84_interface_label_15_debug_keys() {
    assert_eq!(
        menu_row_by_choice(15).map(|row| row.all_label),
        Some("Debug: List Raw Database Keys")
    );
}

#[test]
fn test_85_interface_label_16_debug_log_info() {
    assert_eq!(
        menu_row_by_choice(16).map(|row| row.all_label),
        Some("Debug: Log Information")
    );
}

#[test]
fn test_86_interface_label_17_audit_report() {
    assert_eq!(
        menu_row_by_choice(17).map(|row| row.all_label),
        Some("Debug: Audit Report")
    );
}

#[test]
fn test_87_interface_label_18_play_slots() {
    assert_eq!(
        menu_row_by_choice(18).map(|row| row.all_label),
        Some("Slot Machine Game")
    );
}

#[test]
fn test_88_interface_label_19_faq() {
    assert_eq!(
        menu_row_by_choice(19).map(|row| row.all_label),
        Some("FAQ (MUST READ)")
    );
}

#[test]
fn test_89_interface_label_20_exit() {
    assert_eq!(
        menu_row_by_choice(20).map(|row| row.all_label),
        Some("Exit")
    );
}

#[test]
fn test_90_simulated_open_input_choice_one_maps_to_setup_database() {
    assert_eq!(
        simulated_command_from_open_input("1"),
        Some(BlockchainSubcommand::SetupDatabase)
    );
}

#[test]
fn test_91_simulated_open_input_whitespace_twenty_maps_to_exit() {
    assert_eq!(
        simulated_command_from_open_input(" \t20\r\n"),
        Some(BlockchainSubcommand::Exit)
    );
}

#[test]
fn test_92_simulated_open_input_zero_is_not_a_command() {
    assert_eq!(simulated_command_from_open_input("0"), None);
}

#[test]
fn test_93_simulated_open_input_twenty_one_is_ignored() {
    assert_eq!(simulated_command_from_open_input("21"), None);
}

#[test]
fn test_94_simulated_open_input_alpha_is_ignored() {
    assert_eq!(simulated_command_from_open_input("not-a-number"), None);
}

#[test]
fn test_95_simulated_open_input_negative_number_is_ignored() {
    assert_eq!(simulated_command_from_open_input("-1"), None);
}

#[test]
fn test_96_simulated_open_input_decimal_number_is_ignored() {
    assert_eq!(simulated_command_from_open_input("1.0"), None);
}

#[test]
fn test_97_simulated_open_input_over_max_bytes_is_ignored() {
    let input = "1".repeat(65);
    assert_eq!(input.len(), 65);
    assert_eq!(simulated_command_from_open_input(&input), None);
}

#[test]
fn test_98_simulated_open_input_exact_max_bytes_still_parses() {
    let input = format!("{}3", " ".repeat(63));

    assert_eq!(input.len(), 64);
    assert_eq!(
        simulated_command_from_open_input(&input),
        Some(BlockchainSubcommand::StartNode)
    );
}

#[test]
fn test_99_simulated_open_input_ascii_fuzz_non_digits_are_ignored() {
    for byte in 1_u8..=127_u8 {
        let ch = char::from(byte);

        if ch.is_ascii_digit() {
            continue;
        }

        let candidate = ch.to_string();
        assert_eq!(simulated_command_from_open_input(&candidate), None);
    }
}

#[test]
fn test_100_vector_edge_fuzz_and_load_menu_choice_suite() {
    for row in menu_rows() {
        assert_eq!(
            simulated_command_from_open_input(&row.choice.to_string()),
            Some(row.command)
        );

        assert_real_menu_contains(row.fragment);
    }

    for choice in 0_u32..=500_u32 {
        let parsed = simulated_command_from_open_input(&choice.to_string());
        let expected = if (1..=20).contains(&choice) {
            BlockchainSubcommand::from_choice(choice)
        } else {
            None
        };

        assert_eq!(parsed, expected);
    }

    let adversarial_inputs = [
        "",
        " ",
        "\t",
        "\n",
        "00",
        "000",
        "twenty",
        "1 2",
        "1\n2",
        "99999999999999999999999999999999999999999999999999999999999999999",
        "🧪",
    ];

    for input in adversarial_inputs {
        assert_eq!(simulated_command_from_open_input(input), None);
    }
}
