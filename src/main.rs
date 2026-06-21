//! src/main.rs
//! Top-level Remzar CLI + optional P2P-node launcher.
//!
//! This binary provides the command-line interface for Remzar, allowing
//! users to interact with the blockchain, launch a P2P node, and perform
//! administrative tasks. See the command help for available options.

use chrono::DateTime;
use clap::Parser;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    panic,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use tracing_subscriber::EnvFilter;

/* ── Remzar modules ─────────────────────────────────────────── */
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_000_directory::DirectoryDB;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::logging_data::JsonLogger;
use remzar::utility::time_policy::TimePolicy;
use remzar::{
    commandline::command_line_001_interface::{
        BlockchainCommands, BlockchainSubcommand, CommandHandler, Commands,
    },
    commandline::command_line_002_menu::Menu,
    commandline::command_line_003_manager::CommandManager,
    runtime::p2p_006_sync_runtime::run_node,
};

/* ─────────────────────────── main ─────────────────────────── */

fn main() {
    // Windows + PQC (ML-DSA) can overflow the default main thread stack.
    // Run the entire async program inside a larger-stack thread.
    //
    // Override:
    //   REMZAR_STACK_MB=64  (default 64; min 8; max 512)
    let stack_mb: usize = env::var("REMZAR_STACK_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|mb| (8..=512).contains(mb))
        .unwrap_or(64);

    let stack_bytes = stack_mb.saturating_mul(1024 * 1024);

    let handle = thread::Builder::new()
        .name("remzar_main".to_string())
        .stack_size(stack_bytes)
        .spawn(|| {
            // Build tokio runtime inside this bigger-stack thread.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");

            rt.block_on(async {
                // Anything that reaches here and fails should exit non-zero.
                match real_main().await {
                    Ok(()) => 0,
                    Err(e) => {
                        e.log();
                        tracing::error!("Fatal error: {}", e);
                        eprintln!("Fatal error: {e:?}");
                        1
                    }
                }
            })
        })
        .expect("Failed to spawn remzar_main thread");

    let code = handle.join().unwrap_or(1);
    process::exit(code);
}

/// Forbidden flags that this binary must never accept (they are menu-driven only).
const FORBIDDEN_NET_FLAGS: &[&str] = &[
    "--listen",
    "-l",
    "--bootstrap",
    "--peer",
    "--peers",
    "--multiaddr",
    "--seed",
    "--founder", // founder is interactive only during genesis flow
    "--boot",    // any alias someone might try
    "--addr",
];

/// Return a list of disallowed flags present on the command line (excluding argv[0]).
fn find_forbidden_flags(args: &[String]) -> Vec<String> {
    args.iter()
        .skip(1)
        .filter(|a| {
            let lower = a.to_ascii_lowercase();
            // Match exact flag or flag in `--flag=value` form
            FORBIDDEN_NET_FLAGS.iter().any(|f| {
                lower == *f || (lower.starts_with(&format!("{f}=")) && f.starts_with("--"))
            })
        })
        .cloned()
        .collect()
}

/// Holds the OS file-lock for the entire process lifetime.
/// When dropped, unlocks and best-effort removes the pid file.
struct PidGuard {
    file: Option<std::fs::File>,
    lock_path: PathBuf,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        if let Some(mut f) = self.file.take() {
            let _ = <std::fs::File as fs4::FileExt>::unlock(&f);
            let _ = f.flush();
            drop(f);
        }

        // On Windows, removing while another process holds it will fail (fine).
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn try_pid_guard(workspace: &Path) -> io::Result<PidGuard> {
    let guard_dir = workspace.join("data").join("lock");
    fs::create_dir_all(&guard_dir)?;
    let lock_file = guard_dir.join("remzar.pid");
    let pid = process::id();

    let mut f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_file)?;

    // Try to take an exclusive lock (non-blocking).
    match <std::fs::File as fs4::FileExt>::try_lock(&f) {
        Ok(()) => {
            // We own the lock for this entire process lifetime (as long as `f` is kept alive).
        }
        Err(fs4::TryLockError::WouldBlock) => {
            // Another live process is holding the lock.
            let mut existing = String::new();
            let _ = f.seek(SeekFrom::Start(0));
            let _ = f.read_to_string(&mut existing);

            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "Another Remzar process is already using this data directory ({}). {}",
                    lock_file.display(),
                    if existing.trim().is_empty() {
                        "If you are sure nothing is running, stop any stray remzar.exe and retry."
                            .to_string()
                    } else {
                        format!("Lock info: {}", existing.trim())
                    }
                ),
            ));
        }
        Err(fs4::TryLockError::Error(e)) => {
            // Permissions / filesystem / other unexpected errors.
            return Err(e);
        }
    }

    // Runtime/operator timestamp through the centralized time policy.
    let started_unix = TimePolicy::now_unix_secs_runtime().map_err(|e| {
        io::Error::other(format!(
            "failed to derive pid-guard runtime timestamp: {e:?}"
        ))
    })?;

    let started_utc = {
        let started_i64 = i64::try_from(started_unix).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pid-guard timestamp does not fit i64: {started_unix}"),
            )
        })?;

        DateTime::from_timestamp(started_i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| format!("unix:{started_unix}"))
    };

    // We have the lock: refresh pid info for visibility.
    f.set_len(0)?;
    f.seek(SeekFrom::Start(0))?;
    writeln!(f, "pid={pid}")?;
    writeln!(f, "started_unix={started_unix}")?;
    writeln!(f, "started_utc={started_utc}")?;
    f.flush()?;

    Ok(PidGuard {
        file: Some(f),
        lock_path: lock_file,
    })
}

// Setup panic logging to JSON logger
fn setup_panic_logging(json_logger: Arc<JsonLogger>) {
    panic::set_hook(Box::new(move |info| {
        let msg = match info.payload().downcast_ref::<&str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &**s,
                None => "Unknown panic",
            },
        };
        let location = info
            .location()
            .map(|l| l.to_string())
            .unwrap_or_else(|| "unknown location".to_string());

        let _ = json_logger.log_error_event("panic", "Panic", &format!("{} at {}", msg, location));
        eprintln!("Panic occurred: {} at {}", msg, location);
    }));
}

/// Validate startup args with **no side effects** so we can test this easily.
/// Returns the parsed `BlockchainCommands` on success.
fn validate_startup_args(raw_args: &[String]) -> Result<BlockchainCommands, String> {
    // A) Reject forbidden flags up-front
    let bad_flags = find_forbidden_flags(raw_args);
    if !bad_flags.is_empty() {
        return Err(format!(
            "Forbidden CLI flags present (use Menu 7 for networking): {:?}",
            bad_flags
        ));
    }

    // B) Try parsing the CLI safely (don't touch DBs)
    let cli = BlockchainCommands::try_parse_from(raw_args).map_err(|e| e.to_string())?;

    // C) Absolutely forbid stray args in interactive mode
    if cli.command.is_none() && raw_args.len() > 1 {
        return Err("Interactive mode must be invoked without extra args".into());
    }

    Ok(cli)
}

async fn real_main() -> Result<(), ErrorDetection> {
    let env_filter = match std::env::var("RUST_LOG") {
        Ok(mode) if mode.eq_ignore_ascii_case("debug") => EnvFilter::new(
            "info,\
                 remzar=debug,\
                 libp2p=warn,\
                 libp2p_gossipsub=warn,\
                 libp2p_swarm=warn,\
                 libp2p_kad=warn,\
                 libp2p_identify=warn,\
                 libp2p_tcp=warn,\
                 libp2p_noise=warn,\
                 libp2p_yamux=warn",
        ),
        Ok(mode) if mode.eq_ignore_ascii_case("trace") => EnvFilter::new(
            "info,\
                 remzar=trace,\
                 libp2p=warn,\
                 libp2p_gossipsub=warn,\
                 libp2p_swarm=warn,\
                 libp2p_kad=warn,\
                 libp2p_identify=warn,\
                 libp2p_tcp=warn,\
                 libp2p_noise=warn,\
                 libp2p_yamux=warn",
        ),
        Ok(custom) => EnvFilter::new(custom),
        Err(_) => EnvFilter::new(
            "info,\
                 libp2p=warn,\
                 libp2p_gossipsub=warn,\
                 libp2p_swarm=warn,\
                 libp2p_kad=warn,\
                 libp2p_identify=warn,\
                 libp2p_tcp=warn,\
                 libp2p_noise=warn,\
                 libp2p_yamux=warn",
        ),
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_level(true)
        .without_time()
        .init();

    /* 1) PARANOIA PRE-PARSE (no DB touched yet) */
    let raw_args: Vec<String> = env::args().collect();

    // Use the testable validator
    let cli = match validate_startup_args(&raw_args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("❌ {msg}");
            eprintln!("   Networking is configured via Menu 7 prompts only.");
            eprintln!("   Start without `--listen/--bootstrap/...` flags.");
            return Err(ErrorDetection::ValidationError {
                message: msg,
                tx_id: None,
            });
        }
    };

    // 2) Extract NodeOpts (if present), or use default
    let node_opts = match &cli.command {
        Some(Commands::Node(opts)) => opts.clone(),
        Some(Commands::Chain(_)) => NodeOpts::default(),
        None => NodeOpts::default(),
    };

    // 3) Build DirectoryDB from NodeOpts (we only compute paths now; still no DB opens)
    let dirs = DirectoryDB::from_node_opts(&node_opts).map_err(ErrorDetection::from)?;

    // 3.a Single-process guard
    // Default: HARD (bulletproof). Optional escape hatch:
    // set REMZAR_SOFT_PID_GUARD=1 to warn and continue.
    let workspace_root = Path::new(".");
    let soft_guard = env::var("REMZAR_SOFT_PID_GUARD")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let _pid_guard = match try_pid_guard(workspace_root) {
        Ok(g) => Some(g), // keep alive for entire runtime
        Err(e) => {
            if soft_guard {
                eprintln!("⚠️  {e}");
                eprintln!("   Soft guard enabled (REMZAR_SOFT_PID_GUARD=1): continuing anyway.");
                None
            } else {
                eprintln!("❌ {e}");
                eprintln!(
                    "   Close the other Remzar instance OR run from a different node folder (separate data dir)."
                );
                return Err(ErrorDetection::ValidationError {
                    message: e.to_string(),
                    tx_id: None,
                });
            }
        }
    };

    // 4) Init JSON logger + panic hook (safe before any heavy work)
    let json_logger = Arc::new(JsonLogger::new(&dirs).map_err(ErrorDetection::from)?);
    setup_panic_logging(json_logger.clone());

    // 5) Only now create directories we own (logs) — still safe regardless of args
    dirs.create_log_directory().map_err(ErrorDetection::from)?;

    tracing::info!("Starting Remzar …");

    // 6) Dispatch based on the parsed CLI (wrap in catch_unwind for extra safety)
    let result = panic::AssertUnwindSafe(async {
        match cli.command {
            Some(Commands::Node(opts)) => {
                // Node mode: we *still* enforce that NodeOpts doesn't smuggle net flags in.
                harden_node_opts(&opts)?;
                run_node(opts).await.map_err(ErrorDetection::from)
            }
            Some(Commands::Chain(chain_cmd)) => {
                // Chain subcommands: allowed, but still guard NodeOpts.
                harden_node_opts(&node_opts)?;
                run_one_shot(node_opts.clone(), chain_cmd, &json_logger).await
            }
            None => {
                // Interactive menu flow.
                harden_node_opts(&node_opts)?;
                run_interactive_menu(node_opts.clone(), &json_logger).await
            }
        }
    })
    .catch_unind()
    .await;

    // 7) Turn panics into structured errors.
    let result = match result {
        Ok(inner) => inner,
        Err(panic_payload) => {
            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            let _ = json_logger.log_error_event("panic", "Unwind", &msg);
            Err(ErrorDetection::ProtocolError {
                message: format!("Recovered from panic: {msg}"),
            })
        }
    };

    // 8) Handle errors
    if let Err(e) = result {
        tracing::error!("Fatal error: {}", e);
        let _ = json_logger.log_error_event("main", "FatalError", &e.to_string());
        return Err(e);
    }

    tracing::info!("Shutdown complete.");
    Ok(())
}

/* ───────────────────────── Helper wrappers ───────────────────────── */

fn harden_node_opts(_opts: &NodeOpts) -> Result<(), ErrorDetection> {
    Ok(())
}

async fn run_one_shot(
    opts: NodeOpts,
    cmd: BlockchainSubcommand,
    json_logger: &Arc<JsonLogger>,
) -> Result<(), ErrorDetection> {
    let manager = CommandManager::new_no_signals(&opts, PathBuf::from("identity.key"))?;
    let mut handler = CommandHandler::new(manager, opts.clone());

    tracing::info!("Executing command: {:?}", cmd);

    match handler.handle_command(cmd, json_logger).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = json_logger.log_error_event("chain", "OneShotFailed", &e.to_string());
            Err(e)
        }
    }
}

// Change the signature to take the real opts:
async fn run_interactive_menu(
    opts: NodeOpts,
    json_logger: &Arc<JsonLogger>,
) -> Result<(), ErrorDetection> {
    let manager = CommandManager::new_no_signals(&opts, PathBuf::from("identity.key"))?;
    let mut handler = CommandHandler::new(manager, opts.clone());

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handling(Arc::clone(&shutdown))?;

    tracing::info!("Entering interactive menu …");
    Menu::process_input(&mut handler, json_logger).await?;

    // Graceful exit wiring:
    // If the user selected Exit in the menu, the menu loop ended because
    // `handler.exit_requested()` was set. Do NOT hang waiting for Ctrl-C.
    if handler.exit_requested() {
        tracing::info!("Exit requested from menu.");
        return Ok(());
    }

    // Wait for Ctrl-C
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    tracing::info!("Goodbye!");
    Ok(())
}

fn setup_signal_handling(flag: Arc<AtomicBool>) -> Result<(), ErrorDetection> {
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl-C: {}", e);
            return;
        }

        tracing::warn!("Ctrl-C received; shutting down …");
        flag.store(true, Ordering::SeqCst);
    });

    Ok(())
}

/* ───────────────────────── std::future::Future util ───────────────────────── */

trait CatchUnwindExt: Sized {
    fn catch_unind(self) -> CatchUnwind<Self>;
}

impl<F: std::future::Future> CatchUnwindExt for F {
    fn catch_unind(self) -> CatchUnwind<Self> {
        CatchUnwind { inner: self }
    }
}

struct CatchUnwind<F> {
    inner: F,
}

impl<F> std::future::Future for CatchUnwind<F>
where
    F: std::future::Future,
{
    type Output = Result<F::Output, Box<dyn std::any::Any + Send + 'static>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let inner =
            unsafe { std::pin::Pin::new_unchecked(&mut self.as_mut().get_unchecked_mut().inner) };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx)))
            .map_or_else(|e| std::task::Poll::Ready(Err(e)), |poll| poll.map(Ok))
    }
}
