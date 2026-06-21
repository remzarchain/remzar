//! src/commandline/s_20_exit.rs

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;

/* ───────────────  S20Exit  ─────────────── */

pub struct S20Exit;

impl S20Exit {
    pub fn new() -> Self {
        Self
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 20.  Exit
    // ─────────────────────────────────────────────────────────────────────────────
    /// Handles exiting the application with warnings and confirmation.
    /// Returns Ok(true)  if the user confirmed “yes” (so caller can exit),
    ///         Ok(false) if the user chose “no”  (so caller can continue),
    ///         Err(_)   on any detection error.
    pub fn exit(&mut self, json_logger: &JsonLogger) -> Result<bool, ErrorDetection> {
        use colored::Colorize;
        use std::io::{self, Write};

        // Defensive caps: prevents infinite stalls + prevents pathological input sizes.
        const MAX_ATTEMPTS: usize = 10;
        const MAX_INPUT_BYTES: usize = 64;

        // Small helper: normalize input without allocating a new String via to_lowercase().
        // Keeps behavior equivalent for ASCII "yes/no/y/n".
        let normalize = |s: &str| s.trim().to_ascii_lowercase();

        // ── Confirmation banner ───────────────────────────────────────
        println!(
            "\n{}",
            "╭───────────────────────────────────────────────────╮"
                .red()
                .bold()
        );
        println!(
            "{}",
            "│            === Exit Confirmation ===              │"
                .red()
                .bold()
        );
        println!(
            "{}",
            "├───────────────────────────────────────────────────┤"
                .red()
                .bold()
        );
        println!(
            "{}",
            "╰───────────────────────────────────────────────────╯"
                .red()
                .bold()
        );
        println!(
            "{}",
            "│ Shutting down the node and the reward system.     │".yellow()
        );
        println!(
            "{}",
            "│ You will lose incoming rewards, if applied.       │".yellow()
        );
        println!(
            "{}",
            "│ If exit, rewards will be halted.                  │".yellow()
        );
        println!(
            "{}",
            "│ If re-start, redo all operations for consistency. │".yellow()
        );
        println!(
            "{}",
            "│ ‘Yes,’ you must re-start P2P and blockchain.      │".yellow()
        );
        println!(
            "{}",
            "│ Overall, it is safe to shut down.                 │".yellow()
        );
        println!(
            "{}",
            "╰───────────────────────────────────────────────────╯"
                .red()
                .bold()
        );
        println!(
            "{}",
            "Exits the Remzar Management System, turning off the node and reward system."
                .white()
                .bold()
        );

        // ── First confirmation loop ────────────────────────────────────
        let mut attempts_1 = 0usize;
        loop {
            attempts_1 = attempts_1.saturating_add(1);
            if attempts_1 > MAX_ATTEMPTS {
                // Defensive: do not stall forever on invalid input.
                // Choose "continue running" on excessive invalid input rather than erroring-out.
                // Caller can log this as a warning if desired.
                println!(
                    "{}",
                    "Too many invalid attempts. Canceling exit.".red().bold()
                );
                return Ok(false);
            }

            print!(
                "{}",
                "Are you sure you want to exit? (yes/no): ".yellow().bold()
            );
            io::stdout().flush().map_err(|e| {
                let msg = format!("Failed to flush stdout: {}", e);
                json_logger
                    .log_error_event("exit", "FlushStdout1", &msg)
                    .ok();
                ErrorDetection::ExecutionError { details: msg }
            })?;

            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(|e| {
                let msg = format!("Failed to read confirmation: {}", e);
                json_logger.log_error_event("exit", "ReadInput1", &msg).ok();
                ErrorDetection::ExecutionError { details: msg }
            })?;

            // Defensive: cap input length (untrusted / pasted / piped).
            if input.len() > MAX_INPUT_BYTES {
                println!(
                    "{}",
                    format!(
                        "Input too long (max {} bytes). Please type 'yes' or 'no'.",
                        MAX_INPUT_BYTES
                    )
                    .red()
                );
                continue;
            }

            match normalize(&input).as_str() {
                "yes" | "y" => {
                    // ── Second, deeper confirmation ───────────────────
                    println!(
                        "\n{}",
                        "⚠️  Remzar Blockchain is about to EXIT ⚠️".red().bold()
                    );

                    let mut attempts_2 = 0usize;
                    loop {
                        attempts_2 = attempts_2.saturating_add(1);
                        if attempts_2 > MAX_ATTEMPTS {
                            // Defensive: do not stall forever on invalid input.
                            println!(
                                "{}",
                                "Too many invalid attempts. Canceling exit.".red().bold()
                            );
                            return Ok(false);
                        }

                        print!(
                            "{}",
                            "This action will END OPERATION – proceed? (yes/no): "
                                .red()
                                .bold()
                        );
                        io::stdout().flush().map_err(|e| {
                            let msg = format!("Failed to flush stdout: {}", e);
                            json_logger
                                .log_error_event("exit", "FlushStdout2", &msg)
                                .ok();
                            ErrorDetection::ExecutionError { details: msg }
                        })?;

                        let mut second = String::new();
                        io::stdin().read_line(&mut second).map_err(|e| {
                            let msg = format!("Failed to read confirmation: {}", e);
                            json_logger.log_error_event("exit", "ReadInput2", &msg).ok();
                            ErrorDetection::ExecutionError { details: msg }
                        })?;

                        // Defensive: cap input length.
                        if second.len() > MAX_INPUT_BYTES {
                            println!(
                                "{}",
                                format!(
                                    "Input too long (max {} bytes). Please type 'yes' or 'no'.",
                                    MAX_INPUT_BYTES
                                )
                                .red()
                            );
                            continue;
                        }

                        match normalize(&second).as_str() {
                            "yes" | "y" => {
                                println!(
                                    "\n{}",
                                    "╭──────────────────────────────────────────────────╮"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "{}",
                                    "│           === Shutting Down ===                  │"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "{}",
                                    "├──────────────────────────────────────────────────┤"
                                        .red()
                                        .bold()
                                );
                                println!(
                                    "{}",
                                    "╰──────────────────────────────────────────────────╯"
                                        .red()
                                        .bold()
                                );
                                println!("{}", "Thank you for using REMZAR.".green().bold());
                                return Ok(true);
                            }
                            "no" | "n" => {
                                println!(
                                    "\n{}",
                                    "╭──────────────────────────────────────────────────╮"
                                        .green()
                                        .bold()
                                );
                                println!(
                                    "{}",
                                    "│          === Operation Canceled ===              │"
                                        .white()
                                        .bold()
                                );
                                println!(
                                    "{}",
                                    "╰──────────────────────────────────────────────────╯"
                                        .green()
                                        .bold()
                                );
                                println!("{}", "Returning to the main menu.".green().bold());
                                return Ok(false);
                            }
                            _ => {
                                println!("{}", "Invalid input. Please type 'yes' or 'no'.".red());
                            }
                        }
                    }
                }
                "no" | "n" => {
                    println!(
                        "\n{}",
                        "╭──────────────────────────────────────────────────╮"
                            .green()
                            .bold()
                    );
                    println!(
                        "{}",
                        "│          === Operation Canceled ===              │"
                            .white()
                            .bold()
                    );
                    println!(
                        "{}",
                        "╰──────────────────────────────────────────────────╯"
                            .green()
                            .bold()
                    );
                    println!("{}", "Returning to the main menu.".green().bold());
                    return Ok(false);
                }
                _ => {
                    println!("{}", "Invalid input. Please type 'yes' or 'no'.".red());
                }
            }
        }
    }
}

impl Default for S20Exit {
    fn default() -> Self {
        Self::new()
    }
}
