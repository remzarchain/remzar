//! src/commandline/s_11_send_chat.rs

use crate::network::p2p_014_chat::ChatMessage;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{canon_wallet_id_checked, wallet_id_matches_pubkey_bytes_checked};
use colored::Colorize;

/// Section 11: Send Chat (message to message via p2p).
pub struct S11SendChat;

impl S11SendChat {
    pub fn new() -> Self {
        Self
    }

    // ───────────────────────────────────────────────────────────────────────────────
    // 11) Send Chat (message to message via p2p)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn send_message(&mut self, opts: &NodeOpts) -> Result<Option<ChatMessage>, ErrorDetection> {
        use std::fs;
        use std::io::{self, Write};

        use fips204::ml_dsa_65;

        println!();
        println!("{}", "💬 Off-chain Chat (p2p)".cyan());

        const MAX_ATTEMPTS: usize = 10;
        const MAX_INPUT_BYTES: usize = 256;
        const MAX_MESSAGE_CHARS: usize = 500;
        const MAX_MESSAGE_BYTES: usize = 8 * 1024; // 8 KiB
        const MAX_WALLET_FILE_BYTES: u64 = 512 * 1024;
        const MAX_PASSPHRASE_BYTES: usize = 256;

        let flush_stdout = |stage: &'static str| -> Result<(), ErrorDetection> {
            io::stdout().flush().map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to flush stdout ({stage}): {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })
        };

        let read_line_capped = |stage: &'static str| -> Result<String, ErrorDetection> {
            let mut s = String::new();
            io::stdin()
                .read_line(&mut s)
                .map_err(|e| ErrorDetection::IoError {
                    message: format!("Failed to read input ({stage}): {e}"),
                    code: e.raw_os_error(),
                    source: Some(Box::new(e)),
                })?;
            if s.len() > MAX_INPUT_BYTES {
                return Err(ErrorDetection::ValidationError {
                    message: format!("Input too long ({stage}): max {} bytes", MAX_INPUT_BYTES),
                    tx_id: None,
                });
            }
            Ok(s)
        };

        {
            let mut attempts = 0usize;
            loop {
                attempts = attempts.saturating_add(1);
                if attempts > MAX_ATTEMPTS {
                    println!(
                        "{}",
                        "❌ Too many invalid attempts. Returning to menu.".red()
                    );
                    return Ok(None);
                }

                print!("{}", "Do you want to send a message? (yes/no): ".yellow());
                flush_stdout("send_message.confirm.flush")?;

                let line = read_line_capped("send_message.confirm.read")?;
                match line.trim().to_ascii_lowercase().as_str() {
                    "yes" => break,
                    "no" => {
                        println!("{}", "↩️  Cancelled. Returning to menu.".yellow());
                        return Ok(None);
                    }
                    _ => println!("{}", "❌ Please type 'yes' or 'no'.".red()),
                }
            }
        }

        fn canonicalize_wallet(addr: &str) -> Result<String, ErrorDetection> {
            canon_wallet_id_checked(addr)
        }

        fn load_signing_key_from_wallet(
            wallet_file: &std::path::Path,
            passphrase: &str,
        ) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
            use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
            use fips204::traits::SerDes;
            use zeroize::{Zeroize, Zeroizing};

            let encrypted = fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read wallet file: {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

            let plaintext: Zeroizing<Vec<u8>> =
                Zeroizing::new(Cryption::decrypt_private_key_bytes(&encrypted, passphrase)?);

            if plaintext.len() == ml_dsa_65::SK_LEN {
                let sk_arr: [u8; ml_dsa_65::SK_LEN] =
                    plaintext.as_slice().try_into().map_err(|_| {
                        ErrorDetection::ValidationError {
                            message: format!(
                                "Failed to convert decrypted secret to [u8; {}]",
                                ml_dsa_65::SK_LEN
                            ),
                            tx_id: None,
                        }
                    })?;

                return ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                    ErrorDetection::CryptographicError {
                        message: format!("Invalid ML-DSA-65 secret key bytes: {e}"),
                    }
                });
            }

            let maybe_utf8 = std::str::from_utf8(plaintext.as_slice()).map_err(|_| {
                ErrorDetection::ValidationError {
                    message: format!(
                        "Decrypted secret is not {} raw bytes and is not valid UTF-8; wallet format unknown/corrupt",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                }
            })?;

            let secret_hex = maybe_utf8.trim();

            if secret_hex.len() != ml_dsa_65::SK_LEN * 2
                || !secret_hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Decrypted secret has unexpected length/format: got {} bytes (raw) / {} chars (utf8)",
                        plaintext.len(),
                        secret_hex.len()
                    ),
                    tx_id: None,
                });
            }

            let mut secret_bytes =
                hex::decode(secret_hex).map_err(|e| ErrorDetection::ValidationError {
                    message: format!("Cannot decode decrypted secret hex: {e:?}"),
                    tx_id: None,
                })?;

            if secret_bytes.len() != ml_dsa_65::SK_LEN {
                secret_bytes.zeroize();
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Decoded secret must be {} bytes, got {}",
                        ml_dsa_65::SK_LEN,
                        secret_bytes.len()
                    ),
                    tx_id: None,
                });
            }

            let sk_arr: [u8; ml_dsa_65::SK_LEN] =
                secret_bytes.as_slice().try_into().map_err(|_| {
                    secret_bytes.zeroize();
                    ErrorDetection::ValidationError {
                        message: format!(
                            "Failed to convert decoded secret to [u8; {}]",
                            ml_dsa_65::SK_LEN
                        ),
                        tx_id: None,
                    }
                })?;

            secret_bytes.zeroize();

            ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                ErrorDetection::CryptographicError {
                    message: format!("Invalid ML-DSA-65 secret key bytes: {e}"),
                }
            })
        }

        fn verify_sender_wallet_matches_signing_key(
            sender_wallet: &str,
            signing_key: &ml_dsa_65::PrivateKey,
        ) -> Result<(), ErrorDetection> {
            use fips204::traits::{SerDes, Signer};

            let public_key = signing_key.get_public_key();
            let public_key_bytes = public_key.into_bytes();

            wallet_id_matches_pubkey_bytes_checked(sender_wallet, &public_key_bytes)?;
            Ok(())
        }

        println!();
        print!("{}", "Enter your SENDER wallet address: ".yellow());
        flush_stdout("send_message.from_wallet.flush")?;

        let from_wallet_raw = read_line_capped("send_message.from_wallet.read")?;

        if from_wallet_raw.trim().is_empty() {
            println!(
                "{}",
                "❌ Sender wallet cannot be empty. Returning to menu.".red()
            );
            return Ok(None);
        }

        let from_wallet = match canonicalize_wallet(&from_wallet_raw) {
            Ok(w) => w,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Invalid sender wallet format. Returning to menu.".red()
                );
                println!("   Details: {:?}", e);
                return Ok(None);
            }
        };

        let directory = DirectoryDB::from_node_opts(opts).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to init directories: {e}"),
            code: None,
            source: None,
        })?;

        let wallet_file = directory
            .wallets_path
            .join(format!("{}.wallet", from_wallet));

        if !wallet_file.exists() {
            println!(
                "{}",
                format!(
                    "❌ Wallet file not found for {} at {}. Returning to menu.",
                    from_wallet,
                    wallet_file.display()
                )
                .red()
            );
            return Ok(None);
        }

        let wallet_meta = fs::metadata(&wallet_file).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat wallet file {}: {e}", wallet_file.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !wallet_meta.is_file() {
            println!(
                "{}",
                "❌ Wallet path is not a regular file. Returning to menu.".red()
            );
            return Ok(None);
        }
        if wallet_meta.len() == 0 {
            println!(
                "{}",
                "❌ Wallet file is empty/corrupt. Returning to menu.".red()
            );
            return Ok(None);
        }
        if wallet_meta.len() > MAX_WALLET_FILE_BYTES {
            println!(
                "{}",
                format!(
                    "❌ Wallet file too large ({} bytes). Safety max is {} bytes. Returning to menu.",
                    wallet_meta.len(),
                    MAX_WALLET_FILE_BYTES
                )
                .red()
            );
            return Ok(None);
        }

        let passphrase = dialoguer::Password::new()
            .with_prompt("🔒 Enter passphrase to unlock this wallet")
            .allow_empty_password(false)
            .interact()
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read passphrase: {e}"),
                code: None,
                source: Some(Box::new(e)),
            })?;

        if passphrase.len() > MAX_PASSPHRASE_BYTES {
            println!(
                "{}",
                format!(
                    "❌ Passphrase too long (max {} bytes). Returning to menu.",
                    MAX_PASSPHRASE_BYTES
                )
                .red()
            );
            return Ok(None);
        }

        let signing_key: ml_dsa_65::PrivateKey =
            match load_signing_key_from_wallet(&wallet_file, &passphrase) {
                Ok(sk) => sk,
                Err(e) => {
                    println!(
                        "{}",
                        "❌ Failed to unlock wallet (bad passphrase or corrupt file).".red()
                    );
                    println!("   Details: {:?}", e);
                    return Ok(None);
                }
            };

        if let Err(e) = verify_sender_wallet_matches_signing_key(&from_wallet, &signing_key) {
            println!(
                "{}",
                "❌ Sender wallet does not match the unlocked signing key. Returning to menu."
                    .red()
            );
            println!("   Details: {:?}", e);
            return Ok(None);
        }

        println!();
        print!("{}", "Enter the RECEIVER wallet address: ".yellow());
        flush_stdout("send_message.to_wallet.flush")?;

        let to_wallet_raw = read_line_capped("send_message.to_wallet.read")?;

        if to_wallet_raw.trim().is_empty() {
            println!(
                "{}",
                "❌ Receiver wallet cannot be empty. Returning to menu.".red()
            );
            return Ok(None);
        }

        let to_wallet = match canonicalize_wallet(&to_wallet_raw) {
            Ok(w) => w,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Invalid receiver wallet format. Returning to menu.".red()
                );
                println!("   Details: {:?}", e);
                return Ok(None);
            }
        };

        if from_wallet == to_wallet {
            println!(
                "{}",
                "❌ Sender and receiver wallet cannot be the same for chat routing. Returning to menu."
                    .red()
            );
            return Ok(None);
        }

        println!();
        println!(
            "{}",
            "📝 Please write a 500 character message or less, then press Enter:".cyan()
        );
        print!("> ");
        flush_stdout("send_message.msg.flush")?;

        let mut msg_raw = String::new();
        io::stdin()
            .read_line(&mut msg_raw)
            .map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read message: {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

        if msg_raw.len() > MAX_MESSAGE_BYTES {
            println!(
                "{}",
                format!(
                    "❌ Message too large (max {} bytes). Returning to menu.",
                    MAX_MESSAGE_BYTES
                )
                .red()
            );
            return Ok(None);
        }

        let msg = msg_raw.trim().to_string();

        if msg.is_empty() {
            println!("{}", "❌ Message cannot be empty. Returning to menu.".red());
            return Ok(None);
        }

        if msg.chars().count() > MAX_MESSAGE_CHARS {
            println!(
                "{}",
                "❌ Message is longer than 500 characters. Returning to menu.".red()
            );
            return Ok(None);
        }

        let chat_msg = match ChatMessage::new_signed(from_wallet, to_wallet, &msg, &signing_key) {
            Ok(cm) => cm,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Failed to build chat message. Returning to menu.".red()
                );
                println!("   Details: {:?}", e);
                return Ok(None);
            }
        };

        Ok(Some(chat_msg))
    }
}

impl Default for S11SendChat {
    fn default() -> Self {
        Self::new()
    }
}
