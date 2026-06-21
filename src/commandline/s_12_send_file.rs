//! src/commandline/s_12_send_file.rs

use crate::cryptography::ml_dsa_65_005_encryption::Cryption;
use crate::network::p2p_010_netcmd::NetCmd;
use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::{canon_wallet_id_checked, wallet_id_matches_pubkey_bytes_checked};
use colored::Colorize;

/// Section 12: Send File (file sharing via p2p).
pub struct S12SendFile;

impl S12SendFile {
    pub fn new() -> Self {
        Self
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // 12) Send File (file sharing via p2p)
    // ──────────────────────────────────────────────────────────────────────────────
    pub fn send_files(
        &mut self,
        opts: &NodeOpts,
        send_net_cmd: &mut dyn FnMut(NetCmd) -> Result<(), ErrorDetection>,
    ) -> Result<(), ErrorDetection> {
        use std::fs;
        use std::io::{self, Write};
        use std::path::{Component, Path};

        // Use utility module for file sending
        use crate::utility::send_file::{FILE_CHUNK_SIZE, MAX_P2P_FILE_BYTES, SendFile};

        println!();
        println!("{}", "📁 Off-chain File Send (p2p)".cyan());

        // ─────────────────────────────────────────────────────────────
        // Safety / paranoia caps (wiring only; no crypto changes)
        // ─────────────────────────────────────────────────────────────
        const MAX_ATTEMPTS: usize = 10;
        const MAX_INPUT_BYTES: usize = 256;
        const MAX_PATH_BYTES: usize = 1024;
        const MAX_FILENAME_BYTES: usize = 256;
        const MAX_WALLET_FILE_BYTES: u64 = 512 * 1024;
        const MAX_DIR_ENTRIES: usize = 50_000;
        const MAX_CHUNKS_PER_FILE: u32 = 2_000_000;
        const MAX_PASSPHRASE_BYTES: usize = 256;

        // Small helper: prompt+flush with graceful error.
        let flush_stdout = |stage: &'static str| -> Result<(), ErrorDetection> {
            io::stdout().flush().map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to flush stdout ({stage}): {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })
        };

        // Small helper: read_line with a length cap + graceful error.
        let read_line_capped =
            |stage: &'static str, cap: usize| -> Result<String, ErrorDetection> {
                let mut s = String::new();
                io::stdin()
                    .read_line(&mut s)
                    .map_err(|e| ErrorDetection::IoError {
                        message: format!("Failed to read input ({stage}): {e}"),
                        code: e.raw_os_error(),
                        source: Some(Box::new(e)),
                    })?;
                if s.len() > cap {
                    return Err(ErrorDetection::ValidationError {
                        message: format!("Input too long ({stage}): max {} bytes", cap),
                        tx_id: None,
                    });
                }
                Ok(s)
            };

        // Helper: ensure a user-provided filename is a safe single path component.
        fn validate_safe_leaf_filename(name: &str) -> Result<(), ErrorDetection> {
            use std::path::Path;

            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(ErrorDetection::ValidationError {
                    message: "Filename cannot be empty".into(),
                    tx_id: None,
                });
            }

            let p = Path::new(trimmed);

            if p.is_absolute() {
                return Err(ErrorDetection::ValidationError {
                    message: "Filename must not be an absolute path".into(),
                    tx_id: None,
                });
            }

            let mut comps = p.components();
            let first = comps.next();
            let second = comps.next();

            match (first, second) {
                (Some(Component::Normal(_)), None) => {}
                _ => {
                    return Err(ErrorDetection::ValidationError {
                        message: "Filename must be a single file name, not a path".into(),
                        tx_id: None,
                    });
                }
            }

            if trimmed == "." || trimmed == ".." {
                return Err(ErrorDetection::ValidationError {
                    message: "Filename is invalid".into(),
                    tx_id: None,
                });
            }

            Ok(())
        }

        // ─────────────────────────────────────────────────────────────
        // top-level choice for this menu entry
        //  [1] Send a file
        //  [2] Auto-merge received chunks into full files
        //  [3] Cancel / back to main menu
        // ─────────────────────────────────────────────────────────────
        {
            let mut attempts = 0usize;
            loop {
                attempts = attempts.saturating_add(1);
                if attempts > MAX_ATTEMPTS {
                    println!(
                        "{}",
                        "❌ Too many invalid attempts. Returning to menu.".red()
                    );
                    return Ok(());
                }

                println!();
                println!("{}", "What would you like to do?".cyan());
                println!("  [1] 📤 Send a file to another wallet");
                println!("  [2] 🧩 Auto-merge received file chunks into full files");
                println!("  [3] ↩️  Cancel and return to main menu");
                print!("Enter choice (1-3): ");
                flush_stdout("send_files.menu.flush")?;

                let choice = read_line_capped("send_files.menu.read", MAX_INPUT_BYTES)?;
                match choice.trim() {
                    "1" => {
                        // Proceed into the existing "send file" flow below.
                        break;
                    }
                    "2" => {
                        // ─────────────────────────────────────────────────────
                        // Option 2: Auto-merge received file chunks
                        //
                        // Supports TWO layouts:
                        //
                        //   A) multi-file root:
                        //      <recv_root>/
                        //          <file_id_hex>/
                        //              meta.json
                        //              chunk_000000.bin
                        //              ...
                        //
                        //   B) single-file folder:
                        //      <recv_root>/
                        //          meta.json (optional)
                        //          chunk_000000.bin
                        //          chunk_000001.bin
                        //          ...
                        //
                        // In layout B, <recv_root> is exactly the directory
                        // holding the chunk_*.bin files.
                        // ─────────────────────────────────────────────────────

                        println!();
                        println!(
                            "{}",
                            "🧩 Auto-merge received file chunks into full files".cyan()
                        );

                        // Confirm intent (bounded attempts)
                        {
                            let mut tries = 0usize;
                            loop {
                                tries = tries.saturating_add(1);
                                if tries > MAX_ATTEMPTS {
                                    println!(
                                        "{}",
                                        "❌ Too many invalid attempts. Returning to menu.".red()
                                    );
                                    return Ok(());
                                }

                                print!(
                                    "{}",
                                    "Do you want to auto-merge all completed received files now? (yes/no): "
                                        .yellow()
                                );
                                flush_stdout("send_files.merge.confirm.flush")?;

                                let line = read_line_capped(
                                    "send_files.merge.confirm.read",
                                    MAX_INPUT_BYTES,
                                )?;
                                match line.trim().to_ascii_lowercase().as_str() {
                                    "yes" => break,
                                    "no" => {
                                        println!(
                                            "{}",
                                            "↩️  Cancelled auto-merge. Returning to main menu."
                                                .yellow()
                                        );
                                        return Ok(());
                                    }
                                    _ => {
                                        println!("{}", "❌ Please type 'yes' or 'no'.".red());
                                    }
                                }
                            }
                        }

                        // Local helper: meta.json layout for received files (multi-file mode).
                        #[derive(serde::Deserialize)]
                        struct ReceivedFileMeta {
                            content_hash_hex: String,
                            file_id_hex: String,
                            file_size_bytes: u64,
                            filename: String,
                            from_wallet: String,
                            to_wallet: String,
                            total_chunks: u32,
                        }

                        // ─────────────────────────────────────────────────────
                        // Let the user choose where the chunks live.
                        // Default: <opts.data_dir>/receiver.files
                        // ─────────────────────────────────────────────────────
                        let data_dir_path = Path::new(&opts.data_dir);
                        let default_recv_root = data_dir_path.join("receiver.files");

                        println!();
                        println!("{}", "📂 Configure received-chunks location:".cyan());
                        println!(
                            "   Default directory for this node: {}",
                            default_recv_root.display()
                        );
                        println!(
                            "   This folder can be either:\n   - a ROOT with one subfolder per file_id, OR\n   - EXACTLY the folder that contains chunk_*.bin."
                        );
                        println!();
                        println!("Press Enter to use the default, or type a custom path.");
                        print!("Received-file root path: ");
                        flush_stdout("send_files.merge.root.flush")?;

                        let root_input =
                            read_line_capped("send_files.merge.root.read", MAX_PATH_BYTES)?;
                        let root_input = root_input.trim();

                        let recv_root = if root_input.is_empty() {
                            default_recv_root
                        } else {
                            Path::new(root_input).to_path_buf()
                        };

                        let display_root = match recv_root.canonicalize() {
                            Ok(p) => p,
                            Err(_) => recv_root.clone(),
                        };

                        if !recv_root.exists() {
                            println!(
                                "{}",
                                format!(
                                    "⚠️  No received-chunks directory found.\n   Checked path: {}",
                                    display_root.display()
                                )
                                .yellow()
                            );
                            println!(
                                "{}",
                                "ℹ️  Tip: run auto-merge on the RECEIVER node and point this to the folder that stores chunk_*.bin."
                                    .yellow()
                            );

                            println!();
                            print!("Press Enter to return to the main menu...");
                            flush_stdout("send_files.merge.missing.pause.flush")?;
                            let _ = read_line_capped(
                                "send_files.merge.missing.pause.read",
                                MAX_INPUT_BYTES,
                            )?;
                            return Ok(());
                        }

                        // ─────────────────────────────────────────────────────
                        // FIRST: detect if recv_root itself looks like a
                        // "single-file folder" full of chunk_*.bin.
                        // ─────────────────────────────────────────────────────
                        let mut chunk_files: Vec<(u32, std::path::PathBuf)> = Vec::new();
                        let mut has_subdirs = false;

                        let dir_iter = match fs::read_dir(&recv_root) {
                            Ok(it) => it,
                            Err(e) => {
                                println!(
                                    "{}",
                                    format!(
                                        "❌ Failed to read directory {}: {}",
                                        recv_root.display(),
                                        e
                                    )
                                    .red()
                                );
                                return Ok(());
                            }
                        };

                        let mut dir_entries_seen = 0usize;
                        for entry in dir_iter {
                            dir_entries_seen = dir_entries_seen.saturating_add(1);
                            if dir_entries_seen > MAX_DIR_ENTRIES {
                                println!(
                                    "{}",
                                    format!(
                                        "❌ Too many entries in {} (>{}). Refusing to scan further.",
                                        recv_root.display(),
                                        MAX_DIR_ENTRIES
                                    )
                                    .red()
                                );
                                return Ok(());
                            }

                            let entry = match entry {
                                Ok(e) => e,
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Skipping unreadable directory entry in {}: {}",
                                            recv_root.display(),
                                            e
                                        )
                                        .yellow()
                                    );
                                    continue;
                                }
                            };

                            let p = entry.path();
                            if p.is_dir() {
                                has_subdirs = true;
                                continue;
                            }

                            if p.is_file()
                                && let Some(name) = p.file_name().and_then(|s| s.to_str())
                            {
                                // Expect pattern chunk_000000.bin
                                if name.starts_with("chunk_") && name.ends_with(".bin") {
                                    // Extract the 6-digit index between "chunk_" and ".bin"
                                    let idx_str = name
                                        .strip_prefix("chunk_")
                                        .and_then(|s| s.strip_suffix(".bin"));
                                    if let Some(idx_str) = idx_str
                                        && let Ok(idx) = idx_str.parse::<u32>()
                                    {
                                        chunk_files.push((idx, p.clone()));
                                    }
                                }
                            }
                        }

                        // If found chunk files and no subdirs, treat recv_root
                        // as a SINGLE-FILE FOLDER and merge directly here.
                        if !chunk_files.is_empty() && !has_subdirs {
                            println!();
                            println!(
                                "{}",
                                format!(
                                    "🔎 Detected {} chunk file(s) directly under {}.",
                                    chunk_files.len(),
                                    recv_root.display()
                                )
                                .cyan()
                            );

                            // Sort by chunk index
                            chunk_files.sort_by_key(|(idx, _)| *idx);

                            // Defensive: if chunks imply an absurd size, stop early.
                            if (chunk_files.len() as u64).saturating_mul(FILE_CHUNK_SIZE as u64)
                                > (MAX_P2P_FILE_BYTES as u64).saturating_add(FILE_CHUNK_SIZE as u64)
                            {
                                println!(
                                    "{}",
                                    "❌ Too many chunks for a single-file merge (safety ceiling)."
                                        .red()
                                );
                                return Ok(());
                            }

                            let mut all_bytes: Vec<u8> = Vec::new();
                            let mut total_read: u64 = 0;

                            for (idx, path) in &chunk_files {
                                match fs::read(path) {
                                    Ok(b) => {
                                        total_read = total_read.saturating_add(b.len() as u64);

                                        // Defensive: cap merged total size
                                        if total_read > (MAX_P2P_FILE_BYTES as u64) {
                                            println!(
                                                "{}",
                                                format!(
                                                    "❌ Merged data exceeds MAX_P2P_FILE_BYTES ({}). Aborting merge.",
                                                    MAX_P2P_FILE_BYTES
                                                )
                                                .red()
                                            );
                                            return Ok(());
                                        }

                                        println!(
                                            "  ✅ Reading chunk {} from {} ({} bytes)",
                                            idx,
                                            path.display(),
                                            b.len()
                                        );
                                        all_bytes.extend_from_slice(&b);
                                    }
                                    Err(e) => {
                                        println!(
                                            "{}",
                                            format!(
                                                "❌ Failed to read chunk {} at {}: {}",
                                                idx,
                                                path.display(),
                                                e
                                            )
                                            .red()
                                        );
                                        return Ok(());
                                    }
                                }
                            }

                            println!();
                            println!("{}", "✅ All chunks read successfully.".green());
                            println!(
                                "   Total size after merge: {} bytes (from {} chunk file[s])",
                                all_bytes.len(),
                                chunk_files.len()
                            );

                            // Compute hash for info
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(&all_bytes);
                            let digest = hasher.finalize();
                            let hash_hex = hex::encode(digest.as_bytes());
                            println!(
                                "{}",
                                format!("   BLAKE3 hash of merged file: {}", hash_hex).cyan()
                            );

                            // Ask for output filename
                            println!();
                            println!(
                                "{}",
                                "Enter a name for the merged file (e.g. menu.png). Press Enter to use 'merged.bin':"
                                    .cyan()
                            );
                            print!("Output filename: ");
                            flush_stdout("send_files.merge.outname.flush")?;

                            let out_name = read_line_capped(
                                "send_files.merge.outname.read",
                                MAX_FILENAME_BYTES,
                            )?;
                            let out_name = out_name.trim();
                            let out_name = if out_name.is_empty() {
                                "merged.bin"
                            } else {
                                out_name
                            };

                            if let Err(e) = validate_safe_leaf_filename(out_name) {
                                println!(
                                    "{}",
                                    "❌ Invalid output filename. Returning to menu.".red()
                                );
                                println!("   Details: {:?}", e);
                                return Ok(());
                            }

                            let out_path = recv_root.join(out_name);

                            if out_path.exists() {
                                // Confirm overwrite (bounded attempts)
                                let mut tries = 0usize;
                                loop {
                                    tries = tries.saturating_add(1);
                                    if tries > MAX_ATTEMPTS {
                                        println!(
                                            "{}",
                                            "❌ Too many invalid attempts. Returning to menu."
                                                .red()
                                        );
                                        return Ok(());
                                    }

                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Output file already exists at {}. Overwrite? (yes/no):",
                                            out_path.display()
                                        )
                                        .yellow()
                                    );
                                    let ans = read_line_capped(
                                        "send_files.merge.overwrite.read",
                                        MAX_INPUT_BYTES,
                                    )?;
                                    match ans.trim().to_ascii_lowercase().as_str() {
                                        "yes" => break,
                                        "no" => {
                                            println!(
                                                "{}",
                                                "↩️  Not overwriting. Auto-merge finished with no file written."
                                                    .yellow()
                                            );
                                            return Ok(());
                                        }
                                        _ => {
                                            println!("{}", "❌ Please type 'yes' or 'no'.".red());
                                        }
                                    }
                                }
                            }

                            match fs::write(&out_path, &all_bytes) {
                                Ok(_) => {
                                    println!();
                                    println!(
                                        "{}",
                                        format!("✅ Merged file written to {}", out_path.display())
                                            .green()
                                    );
                                }
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "❌ Failed to write merged file {}: {}",
                                            out_path.display(),
                                            e
                                        )
                                        .red()
                                    );
                                }
                            }

                            return Ok(());
                        }

                        // ─────────────────────────────────────────────────────
                        // Multi-file root logic (folder per file_id_hex)
                        // ─────────────────────────────────────────────────────
                        println!();
                        println!(
                            "{}",
                            format!("🔎 Scanning for received files in {}…", recv_root.display())
                                .cyan()
                        );

                        let entries = match fs::read_dir(&recv_root) {
                            Ok(e) => e,
                            Err(e) => {
                                println!(
                                    "{}",
                                    format!(
                                        "❌ Failed to read received-chunks directory {}: {}",
                                        recv_root.display(),
                                        e
                                    )
                                    .red()
                                );
                                return Ok(());
                            }
                        };

                        let mut merged_count = 0usize;
                        let mut skipped_count = 0usize;
                        let mut seen_entries = 0usize;

                        for entry in entries {
                            seen_entries = seen_entries.saturating_add(1);
                            if seen_entries > MAX_DIR_ENTRIES {
                                println!(
                                    "{}",
                                    format!(
                                        "❌ Too many entries in {} (>{}). Refusing to scan further.",
                                        recv_root.display(),
                                        MAX_DIR_ENTRIES
                                    )
                                    .red()
                                );
                                return Ok(());
                            }

                            let entry = match entry {
                                Ok(e) => e,
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Skipping unreadable directory entry in {}: {}",
                                            recv_root.display(),
                                            e
                                        )
                                        .yellow()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                    continue;
                                }
                            };

                            let dir_path = entry.path();
                            if !dir_path.is_dir() {
                                continue;
                            }

                            let meta_path = dir_path.join("meta.json");
                            if !meta_path.exists() {
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            let meta_bytes = match fs::read(&meta_path) {
                                Ok(b) => b,
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Failed to read meta.json at {}: {}",
                                            meta_path.display(),
                                            e
                                        )
                                        .yellow()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                    continue;
                                }
                            };

                            let meta: ReceivedFileMeta = match serde_json::from_slice(&meta_bytes) {
                                Ok(m) => m,
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Failed to parse meta.json at {}: {:?}",
                                            meta_path.display(),
                                            e
                                        )
                                        .yellow()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                    continue;
                                }
                            };

                            // Defensive: basic sanity bounds
                            if meta.file_size_bytes == 0 {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  meta.json says file_size_bytes=0 for file_id {}. Skipping.",
                                        meta.file_id_hex
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            let file_size_usize = match usize::try_from(meta.file_size_bytes) {
                                Ok(v) => v,
                                Err(_) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  meta.json file_size_bytes={} exceeds MAX_P2P_FILE_BYTES={} for file_id {}. Skipping.",
                                            meta.file_size_bytes, MAX_P2P_FILE_BYTES, meta.file_id_hex
                                        )
                                        .yellow()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                    continue;
                                }
                            };

                            if file_size_usize > MAX_P2P_FILE_BYTES {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  meta.json file_size_bytes={} exceeds MAX_P2P_FILE_BYTES={} for file_id {}. Skipping.",
                                        meta.file_size_bytes, MAX_P2P_FILE_BYTES, meta.file_id_hex
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            if meta.total_chunks == 0 || meta.total_chunks > MAX_CHUNKS_PER_FILE {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  meta.json total_chunks={} is invalid for file_id {}. Skipping.",
                                        meta.total_chunks, meta.file_id_hex
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            if let Err(e) = validate_safe_leaf_filename(&meta.filename) {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  meta.json filename is unsafe for file_id {}. Skipping.",
                                        meta.file_id_hex
                                    )
                                    .yellow()
                                );
                                println!("   Details: {:?}", e);
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            // Defensive: total_chunks must be consistent with file_size_bytes + FILE_CHUNK_SIZE.
                            let expected_max_chunks_u64 =
                                meta.file_size_bytes.div_ceil(FILE_CHUNK_SIZE as u64);
                            let expected_max_chunks =
                                u32::try_from(expected_max_chunks_u64).unwrap_or(u32::MAX);

                            if meta.total_chunks != expected_max_chunks {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  meta.json total_chunks={} does not match expected={} for file_id {}. Skipping.",
                                        meta.total_chunks, expected_max_chunks, meta.file_id_hex
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            // Checked conversion for Vec capacity (avoid usize overflow)
                            let cap_usize = match usize::try_from(meta.file_size_bytes) {
                                Ok(v) => v,
                                Err(_) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  file_size_bytes={} cannot fit usize on this platform. Skipping file_id {}.",
                                            meta.file_size_bytes, meta.file_id_hex
                                        )
                                        .yellow()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                    continue;
                                }
                            };

                            // Rebuild file from chunk_000000.bin .. chunk_{total_chunks-1}.bin
                            let mut all_bytes = Vec::with_capacity(cap_usize);
                            let mut ok_file = true;

                            for idx in 0..meta.total_chunks {
                                let chunk_name = format!("chunk_{:06}.bin", idx);
                                let chunk_path = dir_path.join(&chunk_name);

                                let chunk_bytes = match fs::read(&chunk_path) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        println!(
                                            "{}",
                                            format!(
                                                "⚠️  Missing or unreadable chunk {} for file_id={} ({})",
                                                chunk_name, meta.file_id_hex, e
                                            )
                                            .yellow()
                                        );
                                        ok_file = false;
                                        break;
                                    }
                                };

                                // Defensive: keep merge bounded to MAX_P2P_FILE_BYTES
                                if all_bytes.len().saturating_add(chunk_bytes.len())
                                    > MAX_P2P_FILE_BYTES
                                {
                                    println!(
                                        "{}",
                                        format!(
                                            "⚠️  Merge would exceed MAX_P2P_FILE_BYTES for file_id {}. Skipping.",
                                            meta.file_id_hex
                                        )
                                        .yellow()
                                    );
                                    ok_file = false;
                                    break;
                                }

                                all_bytes.extend_from_slice(&chunk_bytes);
                            }

                            if !ok_file {
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            if all_bytes.len() as u64 != meta.file_size_bytes {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  Size mismatch for file_id {}: reconstructed={} expected={}",
                                        meta.file_id_hex,
                                        all_bytes.len(),
                                        meta.file_size_bytes
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            // Verify BLAKE3 hash against content_hash_hex
                            let mut hasher = blake3::Hasher::new();
                            hasher.update(&all_bytes);
                            let digest = hasher.finalize();
                            let hash_hex = hex::encode(digest.as_bytes());

                            if hash_hex != meta.content_hash_hex {
                                println!(
                                    "{}",
                                    format!(
                                        "⚠️  Hash mismatch for file_id {}: got {} expected {}",
                                        meta.file_id_hex, hash_hex, meta.content_hash_hex
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            // Where to write the merged file
                            let merged_root = recv_root.join("merged");
                            if let Err(e) = fs::create_dir_all(&merged_root) {
                                println!(
                                    "{}",
                                    format!(
                                        "❌ Failed to create merged output directory {}: {}",
                                        merged_root.display(),
                                        e
                                    )
                                    .red()
                                );
                                return Ok(());
                            }

                            let prefix_len = std::cmp::min(16, meta.file_id_hex.len());
                            let prefix = meta
                                .file_id_hex
                                .get(..prefix_len)
                                .unwrap_or(meta.file_id_hex.as_str());
                            let out_name = format!("{}_{}", prefix, meta.filename);
                            let out_path = merged_root.join(out_name);

                            if out_path.exists() {
                                println!(
                                    "{}",
                                    format!(
                                        "ℹ️  Merged file already exists, skipping: {}",
                                        out_path.display()
                                    )
                                    .yellow()
                                );
                                skipped_count = skipped_count.saturating_add(1);
                                continue;
                            }

                            match fs::write(&out_path, &all_bytes) {
                                Ok(_) => {
                                    // Use from_wallet/to_wallet so they are not dead fields
                                    println!(
                                        "  ✅ Merged {} (from {} → {}) → {}",
                                        meta.filename,
                                        meta.from_wallet,
                                        meta.to_wallet,
                                        out_path.display()
                                    );
                                    merged_count = merged_count.saturating_add(1);
                                }
                                Err(e) => {
                                    println!(
                                        "{}",
                                        format!(
                                            "❌ Failed to write merged file {}: {}",
                                            out_path.display(),
                                            e
                                        )
                                        .red()
                                    );
                                    skipped_count = skipped_count.saturating_add(1);
                                }
                            }
                        }

                        println!();
                        println!(
                            "{}",
                            format!(
                                "✅ Auto-merge complete. Merged {} file(s), skipped {} folder(s).",
                                merged_count, skipped_count
                            )
                            .green()
                        );

                        return Ok(());
                    }
                    "3" => {
                        println!("{}", "↩️  Cancelled. Returning to menu.".yellow());
                        return Ok(());
                    }
                    _ => {
                        println!("{}", "❌ Please type 1, 2, or 3.".red());
                    }
                }
            }
        }

        // ─────────────────────────────────────────────────────────────
        // FROM HERE DOWN: existing "send file" flow
        // ─────────────────────────────────────────────────────────────

        // PQ Migration: ML-DSA-65 key types + traits for (de)serialization + pubkey derivation
        use fips204::ml_dsa_65;

        // Small helper: canonicalize and validate Remzar wallet address.
        fn canonicalize_wallet(addr: &str) -> Result<String, ErrorDetection> {
            canon_wallet_id_checked(addr)
        }

        // Helper: load ML-DSA-65 PrivateKey from .wallet file using Cryption
        fn load_signing_key_from_wallet(
            wallet_file: &std::path::Path,
            passphrase: &str,
        ) -> Result<ml_dsa_65::PrivateKey, ErrorDetection> {
            use fips204::traits::SerDes;
            use zeroize::{Zeroize, Zeroizing};

            // Read encrypted secret bytes from file
            let encrypted = std::fs::read(wallet_file).map_err(|e| ErrorDetection::IoError {
                message: format!("Failed to read wallet file: {e}"),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            })?;

            // Preferred (new PQ wallets): decrypt → raw secret bytes (4032 bytes)
            let plaintext: Zeroizing<Vec<u8>> =
                Zeroizing::new(Cryption::decrypt_private_key_bytes(&encrypted, passphrase)?);

            // Path A: plaintext is exactly the ML-DSA-65 secret key bytes
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

            // Path B (legacy compatibility): decrypted plaintext is a UTF-8 hex string
            let maybe_utf8 =
                std::str::from_utf8(plaintext.as_slice()).map_err(|_| ErrorDetection::ValidationError {
                    message: format!(
                        "Decrypted secret is not {} raw bytes and is not valid UTF-8; wallet format unknown/corrupt",
                        ml_dsa_65::SK_LEN
                    ),
                    tx_id: None,
                })?;

            let secret_hex = maybe_utf8.trim();

            // 4032 bytes -> 8064 hex chars
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

            let pk = signing_key.get_public_key();
            let pub_bytes: [u8; ml_dsa_65::PK_LEN] = pk.into_bytes();

            wallet_id_matches_pubkey_bytes_checked(sender_wallet, &pub_bytes)?;
            Ok(())
        }

        // 1) Confirm intent (bounded attempts)
        {
            let mut attempts = 0usize;
            loop {
                attempts = attempts.saturating_add(1);
                if attempts > MAX_ATTEMPTS {
                    println!(
                        "{}",
                        "❌ Too many invalid attempts. Returning to menu.".red()
                    );
                    return Ok(());
                }

                print!("{}", "Do you want to send a file? (yes/no): ".yellow());
                flush_stdout("send_files.send.confirm.flush")?;

                let line = read_line_capped("send_files.send.confirm.read", MAX_INPUT_BYTES)?;
                match line.trim().to_ascii_lowercase().as_str() {
                    "yes" => break,
                    "no" => {
                        println!("{}", "↩️  Cancelled. Returning to menu.".yellow());
                        return Ok(());
                    }
                    _ => {
                        println!("{}", "❌ Please type 'yes' or 'no'.".red());
                    }
                }
            }
        }

        // 2) Sender wallet (from_wallet)
        println!();
        print!("{}", "Enter your SENDER wallet address: ".yellow());
        flush_stdout("send_files.from_wallet.flush")?;

        let from_wallet_raw = read_line_capped("send_files.from_wallet.read", MAX_INPUT_BYTES)?;

        if from_wallet_raw.trim().is_empty() {
            println!(
                "{}",
                "❌ Sender wallet cannot be empty. Returning to menu.".red()
            );
            return Ok(());
        }

        let from_wallet = match canonicalize_wallet(&from_wallet_raw) {
            Ok(w) => w,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Invalid sender wallet format. Returning to menu.".red()
                );
                println!("   Details: {:?}", e);
                return Ok(());
            }
        };

        // 3) Unlock signing key from wallet file (wallet + passphrase)
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
            return Ok(());
        }

        // Defensive: size check before reading wallet file into memory
        let wallet_meta = fs::metadata(&wallet_file).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat wallet file {}: {e}", wallet_file.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;
        if !wallet_meta.is_file()
            || wallet_meta.len() == 0
            || wallet_meta.len() > MAX_WALLET_FILE_BYTES
        {
            println!(
                "{}",
                format!(
                    "❌ Wallet file invalid size/type at {} (len={}). Returning to menu.",
                    wallet_file.display(),
                    wallet_meta.len()
                )
                .red()
            );
            return Ok(());
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
            return Ok(());
        }

        // ML-DSA-65 signing key
        let signing_key: ml_dsa_65::PrivateKey =
            match load_signing_key_from_wallet(&wallet_file, &passphrase) {
                Ok(sk) => sk,
                Err(e) => {
                    println!(
                        "{}",
                        "❌ Failed to unlock wallet (bad passphrase or corrupt file).".red()
                    );
                    println!("   Details: {:?}", e);
                    return Ok(());
                }
            };

        // Verify key ↔ address using helper.rs single source of truth
        if let Err(e) = verify_sender_wallet_matches_signing_key(&from_wallet, &signing_key) {
            println!(
                "{}",
                "❌ Unlocked key does *not* correspond to the given SENDER wallet. Returning to menu."
                    .red()
            );
            println!("   Details: {:?}", e);
            return Ok(());
        }

        // 4) Receiver wallet (to_wallet)
        println!();
        print!("{}", "Enter the RECEIVER wallet address: ".yellow());
        flush_stdout("send_files.to_wallet.flush")?;

        let to_wallet_raw = read_line_capped("send_files.to_wallet.read", MAX_INPUT_BYTES)?;

        if to_wallet_raw.trim().is_empty() {
            println!(
                "{}",
                "❌ Receiver wallet cannot be empty. Returning to menu.".red()
            );
            return Ok(());
        }

        let to_wallet = match canonicalize_wallet(&to_wallet_raw) {
            Ok(w) => w,
            Err(e) => {
                println!(
                    "{}",
                    "❌ Invalid receiver wallet format. Returning to menu.".red()
                );
                println!("   Details: {:?}", e);
                return Ok(());
            }
        };

        if from_wallet == to_wallet {
            println!(
                "{}",
                "❌ Sender and receiver wallet cannot be the same. Returning to menu.".red()
            );
            return Ok(());
        }

        // 5) File path
        println!();
        println!(
            "{}",
            "📄 Enter the path to the FILE you want to send (e.g. ./certs/certificate_abc.pdf):"
                .cyan()
        );
        print!("File path: ");
        flush_stdout("send_files.filepath.flush")?;

        let file_path_raw = read_line_capped("send_files.filepath.read", MAX_PATH_BYTES)?;
        let file_path_raw = file_path_raw.trim().to_string();

        if file_path_raw.is_empty() {
            println!(
                "{}",
                "❌ File path cannot be empty. Returning to menu.".red()
            );
            return Ok(());
        }

        let path = Path::new(&file_path_raw);

        let meta = fs::metadata(path).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to stat file {file_path_raw}: {e}"),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !meta.is_file() {
            println!(
                "{}",
                "❌ Path is not a regular file. Returning to menu.".red()
            );
            return Ok(());
        }

        // Checked conversion: u64 -> usize
        let file_size_u64 = meta.len();
        let file_size = match usize::try_from(file_size_u64) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    "❌ File size too large for this platform. Returning to menu.".red()
                );
                return Ok(());
            }
        };

        if file_size == 0 {
            println!("{}", "❌ File is empty. Returning to menu.".red());
            return Ok(());
        }
        if file_size > MAX_P2P_FILE_BYTES {
            println!(
                "{}",
                format!(
                    "❌ File is too large ({} bytes). Max allowed is {} bytes.",
                    file_size, MAX_P2P_FILE_BYTES
                )
                .red()
            );
            return Ok(());
        }

        // 6) Use SendFile helper
        let send_file = match SendFile::from_path(from_wallet, to_wallet, &file_path_raw) {
            Ok(sf) => sf,
            Err(e) => {
                println!(
                    "{}",
                    format!("❌ Failed to prepare file for sending: {:?}", e).red()
                );
                return Ok(());
            }
        };

        let file_name = send_file.filename.clone();
        let file_size_bytes = send_file.file_size_bytes;
        let total_chunks = send_file.total_chunks;
        let file_id_hex = hex::encode(send_file.file_id);

        // Defensive: sanity-check total_chunks
        if total_chunks == 0 || total_chunks > MAX_CHUNKS_PER_FILE {
            println!(
                "{}",
                format!(
                    "❌ Refusing to send: invalid total_chunks={} (safety ceiling).",
                    total_chunks
                )
                .red()
            );
            return Ok(());
        }

        // Log outgoing file
        crate::network::p2p_016_file_store::save_outgoing_file(
            opts,
            crate::network::p2p_016_file_store::SaveOutgoingFileArgs {
                file_id: send_file.file_id,
                from_wallet: send_file.from_wallet.as_str(),
                to_wallet: send_file.to_wallet.as_str(),
                filename: send_file.filename.as_str(),
                file_size_bytes: send_file.file_size_bytes,
                content_hash_hex: send_file.content_hash_hex.as_str(),
                original_path: file_path_raw.as_str(),
            },
        );

        println!();
        println!("{}", "Summary:".cyan());
        println!("  From wallet:  {}", send_file.from_wallet);
        println!("  To wallet:    {}", send_file.to_wallet);
        println!("  File:         {} ({} bytes)", file_name, file_size_bytes);
        println!("  File ID:      {}", file_id_hex);
        println!(
            "  Chunks:       {} ({} bytes each, last may be smaller)",
            total_chunks, FILE_CHUNK_SIZE
        );

        // Final confirmation (bounded attempts)
        {
            let mut attempts = 0usize;
            loop {
                attempts = attempts.saturating_add(1);
                if attempts > MAX_ATTEMPTS {
                    println!(
                        "{}",
                        "❌ Too many invalid attempts. Returning to menu.".red()
                    );
                    return Ok(());
                }

                println!();
                print!(
                    "{}",
                    "Proceed to queue this file for delivery? (yes/no): ".yellow()
                );
                flush_stdout("send_files.final_confirm.flush")?;

                let answer = read_line_capped("send_files.final_confirm.read", MAX_INPUT_BYTES)?;
                match answer.trim().to_ascii_lowercase().as_str() {
                    "yes" => break,
                    "no" => {
                        println!("{}", "↩️  Cancelled. Returning to menu.".yellow());
                        return Ok(());
                    }
                    _ => {
                        println!("{}", "❌ Please type 'yes' or 'no'.".red());
                    }
                }
            }
        }

        // 7) Chunk + queue via NetCmd::SendFileChunk
        println!();
        println!(
            "{}",
            "📡 Queuing file chunks to background P2P task…".cyan()
        );

        for (idx, chunk) in send_file.iter_chunks().enumerate() {
            let chunk_no = idx.saturating_add(1);

            if let Err(e) = send_net_cmd(NetCmd::SendFileChunk(chunk)) {
                println!(
                    "{}",
                    format!(
                        "❌ Failed to queue file chunk {}/{} for sending: {:?}",
                        chunk_no, total_chunks, e
                    )
                    .red()
                );
                return Err(e);
            }

            println!("  ✅ Queued chunk {}/{}", chunk_no, total_chunks);
        }

        println!();
        println!(
            "{}",
            format!(
                "✅ File queued for delivery: {} ({} bytes in {} chunks)",
                file_name, file_size_bytes, total_chunks
            )
            .green()
        );

        Ok(())
    }
}

impl Default for S12SendFile {
    fn default() -> Self {
        Self::new()
    }
}
