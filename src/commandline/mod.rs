//! Command-Line Interface (CLI) Module
//!
//! This module implements all command-line interfaces and related utilities for the Remzar project.
//! It handles user interaction, menu systems, and command management for both interactive and
//! scripted use cases.
//!
//! Included submodules:
//! - CLI interface and argument parsing
//! - Interactive menu system
//! - Command dispatch and execution manager

pub mod command_line_001_interface;
pub mod command_line_002_menu;
pub mod command_line_003_manager;
pub mod s_01_setup_database;
pub mod s_02_generate_wallet;
pub mod s_03_startnode;
pub mod s_04_view_blockchain_console;
pub mod s_05_send_remzar;
pub mod s_06_receive_remzar;
pub mod s_07_view_status;
pub mod s_08_check_balance;
pub mod s_09_list_wallets;
pub mod s_10_create_certificates;
pub mod s_11_send_chat;
pub mod s_12_send_file;
pub mod s_13_wallet_utilities;
pub mod s_14_backup_wallet;
pub mod s_15_debug_wallet_storage_keys;
pub mod s_16_debug_logs;
pub mod s_17_debug_audit_report;
pub mod s_18_games;
pub mod s_19_frequently_asked_questions;
pub mod s_20_exit;
