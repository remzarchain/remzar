//! command_line_002_menu.rs
//! Interactive coloured TUI for REMZAR.

use crate::commandline::command_line_001_interface::{BlockchainSubcommand, CommandHandler};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;
use colored::Colorize;
use std::io::{self, Write};

/// Interactive menu.
pub struct Menu;

impl Menu {
    pub fn new() -> Self {
        Self
    }

    /// Render the full menu.
    pub fn display(&self) {
        println!(
            "\n{}",
            "╭──────────────────────────────────────────────────╮"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "│                 Remzar Management                │".cyan()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤"
                .cyan()
                .bold()
        );

        // Database Setup
        println!(
            "{}",
            "│ [1]   🛢️    Setup Database                       │".bright_green()
        );

        // Wallet Mgmt
        println!(
            "{}",
            "│ [2]   💳    Generate New Wallet                  │".bright_green()
        );

        // Added separator between [2] and [3]
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤".magenta()
        );

        // Blockchain init (START NODE block on its own)
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤".magenta()
        );
        println!(
            "{}",
            "│ [3]   🌐    'START' REMZAR BLOCKCHAIN NODE       │"
                .magenta()
                .bold()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤".magenta()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤".magenta()
        );
        println!(
            "{}",
            "│ [4]   🖥️    View Blockchain Console              │"
                .bright_cyan()
                .bold()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤"
                .white()
                .bold()
        );
        println!(
            "{}",
            "│ [5]   📤    Send       ⇒    Remzar COIN          │".white()
        );
        println!(
            "{}",
            "│ [6]   📥    Receive    ⇐    Remzar COIN          │".white()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤"
                .white()
                .bold()
        );

        // Status
        println!(
            "{}",
            "│ [7]   ✅    View Participant Status              │".cyan()
        );

        // Balance
        println!(
            "{}",
            "│ [8]   💰    Balance of Wallet                    │".cyan()
        );

        // Wallet Utilities
        println!(
            "{}",
            "│ [9]   💼    List Wallets                         │".cyan()
        );

        // Export / Off-chain (moved up above debug)
        println!(
            "{}",
            "│ [10]  🖼️    Create Certificates (mint)           │".blue()
        );
        println!(
            "{}",
            "│ [11]  💬    Send Chat (p2p message)              │".blue()
        );
        println!(
            "{}",
            "│ [12]  📂    Send File (p2p file sharing)         │".blue()
        );

        // Debug
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤"
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "│ [13]  🔓    Debug: Open Encrypted Private Key    │".yellow()
        );
        println!(
            "{}",
            "│ [14]  💾    Debug: Backup Wallet                 │".yellow()
        );
        println!(
            "{}",
            "│ [15]  🛠️    Debug: List Raw Database Keys        │".yellow()
        );
        println!(
            "{}",
            "│ [16]  📜    Debug: Log Information               │".yellow()
        );
        println!(
            "{}",
            "│ [17]  📑    Debug: Audit Report                  │".yellow()
        );
        println!(
            "{}",
            "├──────────────────────────────────────────────────┤"
                .yellow()
                .bold()
        );

        // Game
        println!(
            "{}",
            "│ [18]  🎰    Slot Machine Game                    │".green()
        );

        // FAQ (moved up)
        println!(
            "{}",
            "│ [19]  ❓    FAQ (MUST READ)                      │".bright_white()
        );

        // Exit (moved up)
        println!(
            "{}",
            "│ [20]  🚪    Exit                                 │"
                .red()
                .bold()
        );

        println!(
            "{}",
            "╰──────────────────────────────────────────────────╯"
                .cyan()
                .bold()
        );
    }

    pub async fn process_input(
        handler: &mut CommandHandler,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let menu = Menu::new();

        const MAX_INPUT_BYTES: usize = 64;
        const MAX_READ_ERRORS: usize = 3;
        let mut read_errors = 0usize;

        // Menu is "closed" by default.
        // While closed: ONLY "0" will open the menu; all other inputs are ignored silently.
        let mut menu_open = false;
        let mut render_menu_next = false;

        // When the menu is closed, print the "Press 0..." prompt ONCE,
        // then block for input. If the user types junk, ignore it and block again
        // WITHOUT re-printing the prompt (no spam during mining output).
        let mut closed_prompt_printed = false;

        // When the menu is open, print the "Enter your command..." prompt ONCE,
        // then block for input. If the user types junk, ignore it and block again
        // WITHOUT re-printing the prompt (prevents spam while mining logs stream).
        let mut open_prompt_printed = false;

        loop {
            // Only render the menu when explicitly requested via "0".
            if render_menu_next {
                println!();
                menu.display();
                render_menu_next = false;

                // After rendering the menu, we want the command prompt to appear once.
                open_prompt_printed = false;
            }

            /* Prompt */
            if menu_open {
                // When open, show the command prompt ONCE, then stay quiet unless state changes.
                if !open_prompt_printed {
                    print!("{}", "Enter your command choice (0=menu, 1-20): ".cyan());
                    io::stdout().flush().map_err(|e| {
                        let msg = format!("Failed to flush stdout: {}", e);
                        json_logger
                            .log_error_event("menu", "FlushStdout", &msg)
                            .ok();
                        ErrorDetection::ExecutionError { details: msg }
                    })?;
                    open_prompt_printed = true;
                }
            } else if !closed_prompt_printed {
                // When closed, show a single prompt then stay quiet until "0" is entered.
                print!("{}", "Press 0 to open the menu: ".cyan());
                io::stdout().flush().map_err(|e| {
                    let msg = format!("Failed to flush stdout: {}", e);
                    json_logger
                        .log_error_event("menu", "FlushStdout", &msg)
                        .ok();
                    ErrorDetection::ExecutionError { details: msg }
                })?;
                closed_prompt_printed = true;
            }

            /* Read line */
            let mut input = String::new();
            match io::stdin().read_line(&mut input) {
                Ok(0) => {
                    // EOF (stdin closed). Defensive: exit menu gracefully (avoid infinite loop stall).
                    json_logger
                        .log_error_event(
                            "menu",
                            "StdinEOF",
                            "stdin returned EOF; exiting menu loop",
                        )
                        .ok();
                    break;
                }
                Ok(_) => {
                    read_errors = 0; // reset after successful read
                }
                Err(e) => {
                    read_errors = read_errors.saturating_add(1);
                    let msg = format!("Error reading input: {}", e);
                    json_logger.log_error_event("menu", "ReadInput", &msg).ok();

                    // Defensive: don't spin forever on a broken stdin.
                    if read_errors >= MAX_READ_ERRORS {
                        return Err(ErrorDetection::ExecutionError {
                            details: "Repeated stdin read failures; aborting menu loop".to_string(),
                        });
                    }
                    continue;
                }
            }

            // Defensive: reject absurdly large inputs (CLI DoS / accidental paste).
            // Per request: do not print errors; just ignore the input and continue.
            if input.len() > MAX_INPUT_BYTES {
                continue;
            }

            let trimmed = input.trim();

            // Universal gate: "0" shows the menu (even if already open).
            if trimmed == "0" {
                menu_open = true;
                render_menu_next = true;

                // Once the user explicitly requests the menu, we reset both prompt guards.
                closed_prompt_printed = false;
                open_prompt_printed = false;
                continue;
            }

            // If the menu is closed, ignore everything except "0" silently.
            if !menu_open {
                continue;
            }

            // Menu is open:
            // - "1..=20" executes a command (then menu auto-closes)
            // - anything else is ignored silently (no error output, no redraw, no prompt spam)
            let Ok(choice) = trimmed.parse::<u32>() else {
                continue;
            };

            if !(1..=20).contains(&choice) {
                continue;
            }

            let Some(cmd) = BlockchainSubcommand::from_choice(choice) else {
                continue;
            };

            if let Err(e) = Box::pin(handler.handle_command(cmd, json_logger)).await {
                json_logger
                    .log_error_event("menu", "CommandExecutionError", &e.to_string())
                    .ok();
            }

            // After any command (including StartNode), auto-close the menu so mining can "flow".
            // User must press "0" again to re-open the menu.
            menu_open = false;
            render_menu_next = false;

            // Reset prompt guards so the correct single-line prompt prints next time.
            closed_prompt_printed = false;
            open_prompt_printed = false;

            if handler.exit_requested() {
                break;
            }
        }

        Ok(())
    }
}

impl Default for Menu {
    fn default() -> Self {
        Self::new()
    }
}
