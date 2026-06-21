//! s_19_frequently_asked_questions.rs

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use colored::Colorize;

pub struct S19FrequentlyAskedQuestions;

impl S19FrequentlyAskedQuestions {
    pub fn faq() -> Result<(), ErrorDetection> {
        println!(
            "\n{}",
            "╭───────────────────────────────────────────────────────────────╮"
                .blue()
                .bold()
        );
        println!(
            "{}",
            "│           === Remzar SYSTEM FAQ & USER MANUAL ===             │"
                .white()
                .bold()
        );
        println!(
            "{}",
            "╰───────────────────────────────────────────────────────────────╯"
                .blue()
                .bold()
        );
        println!();

        println!(
            "{}",
            "A PQ L1 blockchain ledger built as a sovereign base layer for verified data."
                .magenta()
        );
        println!();

        // ─────────────────────────────────────────────────────────────────────
        // [1] Setup Database
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [1] Setup Database".green().bold());
        println!("   Select [1], type yes, then press Enter.");
        println!("   Creates CLI Database (DB) folders and status metadata.");
        println!("   Safe to rerun; skips if already initialized.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [2] Generate a New Wallet
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [2] Generate a New Wallet".green().bold());
        println!("   Select [2], type yes; choose single, batch 2–10, QR, or exit.");
        println!("   Creates encrypted ML-DSA65 wallet files in the wallets directory.");
        println!(
            "   Passphrase is hidden; saves atomically, private send is 'basic real cover' and QR stores address only.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [3] Start Node (P2P + Blockchain)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [3] Start Node (P2P + Blockchain)".green().bold());
        println!("   Select [3]; choose node role, listen IP/port, bootstrap peers, and wallet.");
        println!(
            "   Starts/resumes chain DB, P2P networking, peer discovery, sync, and mining/observer mode."
        );
        println!("   Guards against mismatchs.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [4] View Blockchain Console (Real-Time Viewing)
        // ─────────────────────────────────────────────────────────────────────
        println!(
            "{}",
            "│ [4] View Blockchain Console (Real-Time Viewing)"
                .green()
                .bold()
        );
        println!("   Select [4], then choose live view, latest, last 50, genesis, or range.");
        println!("   Live view streams minted/accepted blocks in real time without opening DB.");
        println!("   DB lookup options [2–5] read safely through a DB secondary reader.");
        println!(
            "   Options [2–5] will create/use: 003.blockchain_db_console_secondary_<process_id>."
        );
        println!(
            "   Secondary console folder is temporary/read-only and can be safely deleted, if needed"
        );
        println!("   after the node/console is fully stopped. Do not delete 002.blockchain_db.");
        println!("   Input is capped and range searches are limited.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [5] Send Coins
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [5] Send Coins".green().bold());
        println!(
            "   Select [5]; confirm, enter sender wallet, passphrase, recipients, and amount."
        );
        println!(
            "   Verifies wallet ownership, balance, unique recipients, then queues signed transfers."
        );
        println!(
            "   Rechecks balance before broadcast; rejects bad addresses, self-send, and duplicates.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [6] Receive Coins
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [6] Receive Coins".green().bold());
        println!("   Select [6], confirm, then enter your wallet address or type exit.");
        println!("   Scans pending mempool transfers sent to your wallet.");
        println!(
            "   Read-only check; deduplicates transactions and validates canonical addresses.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [7] View Participant Status
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [7] View Participant Status".green().bold());
        println!("   Select [7] to view current validators, leaders, wallets, and PeerId.");
        println!("   Reads the ephemeral registry and chain tip to calculate leader order.");
        println!("   Read-only status check; registry is memory-only and resets on restart.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [8] Check Balance
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [8] Check Balance".green().bold());
        println!("   Select [8], confirm, enter wallet address, then authenticate passphrase.");
        println!("   Verifies the local wallet file belongs to that address.");
        println!("   Reads balance from account state, with state-tree fallback if needed.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [9] List Wallets
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [9] List Wallets".green().bold());
        println!("   Select [9], confirm, then enter the wallet directory path.");
        println!("   Lists valid canonical .wallet filenames as wallet addresses.");
        println!("   Read-only scan; skips invalid files and caps large directory output.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [10] Create Certificate / NFT
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [10] Create Certificate / NFT".green().bold());
        println!(
            "   Select [10], confirm, then choose NFT, badge, legal doc, I.D., RWA, certificate, or release."
        );
        println!(
            "   Mint mode hashes a file, creates NftMintTx, submits it, then writes JSON/PDF receipts."
        );
        println!(
            "   Verify mode checks certificate or Digital I.D. JSON against on-chain NFT records."
        );
        println!("   Transfer mode submits NftTransferTx and writes a new owner certificate.");
        println!("   Export mode rebuilds JSON/PDF proof from an existing on-chain NFT ID.");
        println!("   Digital I.D. creates a signed identity NFT with JSON, PDF, and QR receipt.");
        println!(
            "   Safety: validates wallets, file size, hashes, NFT IDs, JSON limits, and content proofs.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [11] Send Chat (Off-chain Message)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [11] Send Chat (Off-chain Message)".green().bold());
        println!(
            "   Select [11], confirm, enter sender wallet, passphrase, receiver, and message."
        );
        println!("   Builds a signed off-chain P2P chat message between wallets.");
        println!(
            "   Validates wallet ownership, receiver address, size limits, and blocks self-chat.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [12] Send File (Off-chain File Transfer)
        // ─────────────────────────────────────────────────────────────────────
        println!(
            "{}",
            "│ [12] Send File (Off-chain File Transfer)".green().bold()
        );
        println!("   Select [12], then choose send file, auto-merge chunks, or cancel.");
        println!(
            "   Send mode unlocks sender wallet, verifies ownership, receiver, and file path."
        );
        println!("   Files are split into signed P2P chunks and queued for delivery.");
        println!("   Merge mode rebuilds received chunk files into complete local files.");
        println!(
            "   Safety: validates wallets, file size, chunk counts, hashes, paths, and filenames.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [13] Wallet Utilities (Advanced)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [13] Wallet Utilities (Advanced)".green().bold());
        println!("   Select [13], then choose view private key, recover address, or return.");
        println!("   Private-key mode decrypts a wallet file and verifies it matches the address.");
        println!(
            "   Recovery mode derives the public wallet address from a raw ML-DSA-65 private key."
        );
        println!(
            "   High-risk tool; inputs are capped, secrets zeroized, and temp key files auto-delete.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [14] Backup Wallet (Copy Encrypted Wallet File)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [14] Backup Wallet (Encrypted)".green().bold());
        println!(
            "   Select [14], confirm, enter wallet address, passphrase, and backup directory."
        );
        println!("   Verifies the encrypted wallet decrypts and matches the address.");
        println!(
            "   Copies the .wallet file safely; refuses overwrite and live-wallet backup paths.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [15] Debug Wallet Storage Keys (Validate Wallet + Show Metadata)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [15] Debug Wallet Storage Keys".green().bold());
        println!(
            "   Select [15], confirm, enter wallet address, passphrase, and wallet directory."
        );
        println!("   Validates address format, decrypts wallet, and checks ML-DSA-65 key size.");
        println!(
            "   Debug-only tool; zeroizes secrets and prints wallet metadata/key specifications.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [16] Debug Log Information (Export Latest Logs)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [16] Debug Log Information".green().bold());
        println!("   Select [16] and confirm to export recent error logs.");
        println!("   Reads latest bounded DB log entries and writes remzar_error_log.json.");
        println!("   Debug-only export; caps size, skips huge entries, and writes atomically.\n");

        // ─────────────────────────────────────────────────────────────────────
        // [17] Audit Report (Export JSON/PDF)
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [17] Audit Report (Export JSON/PDF)".green().bold());
        println!(
            "   Select [17], confirm, then enter output folder, blockchain DB path, and block range."
        );
        println!("   Loads selected blocks and exports an audit report as JSON or PDF.");
        println!(
            "   Debug/export tool; requires existing paths and limits ranges to 250 blocks.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [18] Games — Slot Machine
        // ─────────────────────────────────────────────────────────────────────
        println!("{}", "│ [18] Games — Slot Machine".green().bold());
        println!("   Select [18], then follow the slot machine prompts.");
        println!("   Uses wallet balance checks and queues game actions through the P2P network.");
        println!(
            "   Game aborts safely if balance lookup, broadcast queue, or network state fails.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [19] Frequently Asked Questions (FAQ+)
        // ─────────────────────────────────────────────────────────────────────
        println!(
            "{}",
            "│ [19] Frequently Asked Questions (FAQ)".green().bold()
        );
        println!("   Select [19] to open the built-in operator manual.");
        println!("   Explains each menu option, usage steps, and technical purpose.");
        println!("   Read-only help screen; no blockchain, wallet, or network changes are made.\n");

        println!(
            "       Only use burn addresses if you explicitly intend to destroy the coins, and always triple-check the address."
        );
        println!("     • **Known burn addresses**:");
        println!(
            "        1) r0bbea8ab481babcd6bbf18f9e042225ce5a301d018af36cbe2fa268e072b42d4bbb6d5a27bfebef4f33c0f9c2fdaef300cace7e6da258d52f1da24119fb1bc01"
        );
        println!(
            "        2) r0c67ffbeee58d0fdd331d1adf9730bde9e2499ff1b833077ac9419b1a80a9df7c889a5818bfd48e7be4f6f471fdebee9ee378981b31c7e5efe2f20f67e76d6f7"
        );
        println!(
            "        3) r023de0ef87458573f9cd4031e3ae45e9fa5123e2b7365fb71c97644f90b2609e1747dd03398f5eb06f4c2086d1907d8c852641d5977370e10abcb9f35c88a248\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [20] Exit — Safe Shutdown + add-ons
        // ─────────────────────────────────────────────────────────────────────
        println!(
            "{}",
            "│ [20] Exit — Safe Shutdown + Double Confirmation"
                .green()
                .bold()
        );
        println!("   Select [20] to safely exit the blockchain node and stop node operations.");
        println!("   Requires two confirmations before ending blockchain and reward operations.");
        println!(
            "   Safe cancel path; input is capped and invalid attempts stop without exiting.\n"
        );

        // ─────────────────────────────────────────────────────────────────────
        // [000] Summary of Remzar
        // ─────────────────────────────────────────────────────────────────────
        println!("│ Summary of Remzar");
        println!();
        println!(
            "   A deterministic L1 post-quantum blockchain built on NIST FIPS 203 and FIPS 204,"
        );
        println!(
            "   designed to replace fragmented interoperability with one unified sovereign data layer."
        );
        println!(
            "   Instead of bridges, the chain becomes its own permanent network architecture:"
        );
        println!(
            "   a raw data ledger that self-executes, preserves truth, and forms an immutable library of inscribed records."
        );
        println!(
            "   It is not a blockchain computer; it is a hard drive for truth — sovereign, permanent, post-quantum secure,"
        );
        println!("   and built to stand as its own source of truth for thousands of years.\n");

        Ok(())
    }
}
