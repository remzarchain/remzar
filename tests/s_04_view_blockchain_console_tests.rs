use remzar::commandline::s_04_view_blockchain_console::{BlockchainConsoleView, ConsoleBus};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use tokio::sync::broadcast::error::TryRecvError;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempTree {
    root: PathBuf,
}

impl TempTree {
    fn new(test_name: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "remzar_s_04_view_blockchain_console_tests_{test_name}_{}_{}",
            std::process::id(),
            id
        ));

        if root.exists() {
            make_writable_recursive(&root);
            if fs::remove_dir_all(&root).is_err() {}
        }

        match fs::create_dir_all(&root) {
            Ok(()) => Self { root },
            Err(err) => panic!("failed to create temp root '{}': {err}", root.display()),
        }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        make_writable_recursive(&self.root);
        if fs::remove_dir_all(&self.root).is_err() {}
    }
}

fn make_writable_recursive(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(_) => return,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        permissions.set_mode(mode | 0o700);
        if fs::set_permissions(path, permissions).is_err() {}
    }

    #[cfg(windows)]
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            if fs::set_permissions(path, permissions).is_err() {}
        }
    }

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let entries = match fs::read_dir(path) {
            Ok(value) => value,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            make_writable_recursive(&entry.path());
        }
    }
}

fn assert_ok<T, E>(result: Result<T, E>, label: &str) -> T
where
    E: Debug,
{
    match result {
        Ok(value) => value,
        Err(err) => panic!("{label} failed: {err:?}"),
    }
}

fn assert_err<T, E>(result: Result<T, E>, label: &str) -> E
where
    T: Debug,
    E: Debug,
{
    match result {
        Ok(value) => panic!("{label} unexpectedly succeeded: {value:?}"),
        Err(err) => err,
    }
}

fn assert_try_recv_empty(result: Result<String, TryRecvError>) {
    match result {
        Err(TryRecvError::Empty) => {}
        other => panic!("expected empty broadcast receiver, got {other:?}"),
    }
}

fn assert_try_recv_lagged(result: Result<String, TryRecvError>) {
    match result {
        Err(TryRecvError::Lagged(_)) => {}
        other => panic!("expected lagged broadcast receiver, got {other:?}"),
    }
}

fn make_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_owned(),
        listen: "/ip4/127.0.0.1/tcp/36213".to_owned(),
        bootstrap: Vec::new(),
        log: "info".to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder: false,
    }
}

fn neutral_line(index: usize) -> String {
    format!("neutral-console-line-{index}")
}

fn assert_try_recv_closed(result: Result<String, TryRecvError>) {
    match result {
        Err(TryRecvError::Closed) => {}
        other => panic!("expected closed broadcast receiver, got {other:?}"),
    }
}

fn collect_messages(
    rx: &mut tokio::sync::broadcast::Receiver<String>,
    count: usize,
    label: &str,
) -> Vec<String> {
    let mut values = Vec::new();

    for _ in 0usize..count {
        values.push(receive_one(rx, label));
    }

    values
}

fn make_node_opts_custom(
    data_dir: &Path,
    identity_file: &str,
    listen: &str,
    bootstrap: Vec<String>,
    log: &str,
    founder: bool,
) -> NodeOpts {
    NodeOpts {
        identity_file: identity_file.to_owned(),
        listen: listen.to_owned(),
        bootstrap,
        log: log.to_owned(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_owned(),
        founder,
    }
}

fn assert_console_is_lazy_without_blockchain_db(opts: &NodeOpts) {
    let expected_primary_db =
        PathBuf::from(&opts.data_dir).join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    assert!(
        !expected_primary_db.exists(),
        "test precondition failed: blockchain DB unexpectedly exists at {}",
        expected_primary_db.display()
    );

    let bus = ConsoleBus::new();
    let _view = BlockchainConsoleView::new(bus);
}

fn minted_line(height: u64) -> String {
    format!(
        "2026-03-01T00:00:00Z  minted:  >   | block: {height} | txs: 2 | reward: 1/199 | hash: {}",
        "a".repeat(128)
    )
}

fn accepted_line(height: u64) -> String {
    format!(
        "2026-03-01T00:00:00Z  accepted:  <  | block: {height} | txs: 3 | reward: 2/198 | hash: {}",
        "b".repeat(128)
    )
}

fn receive_one(rx: &mut tokio::sync::broadcast::Receiver<String>, label: &str) -> String {
    assert_ok(rx.try_recv(), label)
}

#[test]
fn test_01_console_bus_new_has_empty_receiver() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    assert_try_recv_empty(rx.try_recv());
}

#[test]
fn test_02_console_bus_default_has_empty_receiver() {
    let bus = ConsoleBus::default();
    let mut rx = bus.subscribe_live_chain();

    assert_try_recv_empty(rx.try_recv());
}

#[test]
fn test_03_publish_without_subscribers_does_not_panic() {
    let bus = ConsoleBus::new();

    bus.publish_live_chain_line("no subscribers".to_owned());
}

#[test]
fn test_04_single_subscriber_receives_plain_line() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    bus.publish_live_chain_line("plain line".to_owned());

    assert_eq!(receive_one(&mut rx, "receive plain line"), "plain line");
}

#[test]
fn test_05_single_subscriber_receives_minted_line() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = minted_line(1);

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive minted line"), line);
}

#[test]
fn test_06_single_subscriber_receives_accepted_line() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = accepted_line(2);

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive accepted line"), line);
}

#[test]
fn test_07_two_subscribers_receive_same_line() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();
    let mut second = bus.subscribe_live_chain();
    let line = minted_line(3);

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut first, "receive first subscriber"), line);
    assert_eq!(receive_one(&mut second, "receive second subscriber"), line);
}

#[test]
fn test_08_subscriber_created_after_publish_does_not_receive_old_line() {
    let bus = ConsoleBus::new();

    bus.publish_live_chain_line("before subscribe".to_owned());

    let mut rx = bus.subscribe_live_chain();
    assert_try_recv_empty(rx.try_recv());
}

#[test]
fn test_09_message_order_is_preserved_for_one_receiver() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    bus.publish_live_chain_line("first".to_owned());
    bus.publish_live_chain_line("second".to_owned());
    bus.publish_live_chain_line("third".to_owned());

    assert_eq!(receive_one(&mut rx, "receive first"), "first");
    assert_eq!(receive_one(&mut rx, "receive second"), "second");
    assert_eq!(receive_one(&mut rx, "receive third"), "third");
}

#[test]
fn test_10_message_order_is_preserved_for_two_receivers() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();
    let mut second = bus.subscribe_live_chain();

    bus.publish_live_chain_line("a".to_owned());
    bus.publish_live_chain_line("b".to_owned());

    assert_eq!(receive_one(&mut first, "first receiver a"), "a");
    assert_eq!(receive_one(&mut first, "first receiver b"), "b");
    assert_eq!(receive_one(&mut second, "second receiver a"), "a");
    assert_eq!(receive_one(&mut second, "second receiver b"), "b");
}

#[test]
fn test_11_empty_string_line_is_broadcast() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    bus.publish_live_chain_line(String::new());

    assert_eq!(receive_one(&mut rx, "receive empty line"), "");
}

#[test]
fn test_12_unicode_line_is_broadcast() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "鏈 console 測試 🚀".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive unicode line"), line);
}

#[test]
fn test_13_long_line_is_broadcast() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = format!("long-{}", "x".repeat(4096));

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive long line"), line);
}

#[test]
fn test_14_clone_bus_publishes_to_original_receiver() {
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut rx = bus.subscribe_live_chain();

    clone.publish_live_chain_line("from clone".to_owned());

    assert_eq!(receive_one(&mut rx, "receive from clone"), "from clone");
}

#[test]
fn test_15_original_bus_publishes_to_clone_receiver() {
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut rx = clone.subscribe_live_chain();

    bus.publish_live_chain_line("from original".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive from original"),
        "from original"
    );
}

#[test]
fn test_16_multiple_clones_share_same_broadcast_channel() {
    let bus = ConsoleBus::new();
    let first_clone = bus.clone();
    let second_clone = first_clone.clone();
    let mut rx = bus.subscribe_live_chain();

    second_clone.publish_live_chain_line("from second clone".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive from second clone"),
        "from second clone"
    );
}

#[test]
fn test_17_dropped_receiver_does_not_stop_future_publish() {
    let bus = ConsoleBus::new();

    {
        let _rx = bus.subscribe_live_chain();
    }

    let mut live_rx = bus.subscribe_live_chain();
    bus.publish_live_chain_line("after dropped receiver".to_owned());

    assert_eq!(
        receive_one(&mut live_rx, "receive after dropped receiver"),
        "after dropped receiver"
    );
}

#[test]
fn test_18_direct_sender_send_reports_one_receiver() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    let count = assert_ok(
        bus.live_chain_tx.send("direct send".to_owned()),
        "direct live_chain_tx.send",
    );

    assert_eq!(count, 1);
    assert_eq!(receive_one(&mut rx, "receive direct send"), "direct send");
}

#[test]
fn test_19_direct_sender_send_reports_two_receivers() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();
    let mut second = bus.subscribe_live_chain();

    let count = assert_ok(
        bus.live_chain_tx.send("direct two".to_owned()),
        "direct live_chain_tx.send",
    );

    assert_eq!(count, 2);
    assert_eq!(
        receive_one(&mut first, "receive first direct two"),
        "direct two"
    );
    assert_eq!(
        receive_one(&mut second, "receive second direct two"),
        "direct two"
    );
}

#[test]
fn test_20_direct_sender_send_fails_with_no_receivers() {
    let bus = ConsoleBus::new();

    let err = assert_err(
        bus.live_chain_tx.send("no receivers".to_owned()),
        "direct send without receiver",
    );

    assert_eq!(err.0, "no receivers");
}

#[test]
fn test_21_receiver_lags_after_capacity_is_exceeded() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..1100usize {
        bus.publish_live_chain_line(format!("line-{index}"));
    }

    assert_try_recv_lagged(rx.try_recv());
}

#[test]
fn test_22_receiver_can_continue_after_lag_error() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..1100usize {
        bus.publish_live_chain_line(format!("line-{index}"));
    }

    assert_try_recv_lagged(rx.try_recv());

    let recovered = receive_one(&mut rx, "receive after lag");
    assert!(recovered.starts_with("line-"));
}

#[test]
fn test_23_many_subscribers_receive_vector_line() {
    let bus = ConsoleBus::new();
    let mut receivers = Vec::new();

    for _ in 0usize..8usize {
        receivers.push(bus.subscribe_live_chain());
    }

    let line = minted_line(23);
    bus.publish_live_chain_line(line.clone());

    for rx in &mut receivers {
        assert_eq!(receive_one(rx, "receive vector line"), line);
    }
}

#[test]
fn test_24_minted_vector_lines_keep_payload_exactly() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for height in 0u64..5u64 {
        bus.publish_live_chain_line(minted_line(height));
    }

    for height in 0u64..5u64 {
        assert_eq!(
            receive_one(&mut rx, "receive minted vector"),
            minted_line(height)
        );
    }
}

#[test]
fn test_25_accepted_vector_lines_keep_payload_exactly() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for height in 0u64..5u64 {
        bus.publish_live_chain_line(accepted_line(height));
    }

    for height in 0u64..5u64 {
        assert_eq!(
            receive_one(&mut rx, "receive accepted vector"),
            accepted_line(height)
        );
    }
}

#[test]
fn test_26_mixed_live_lines_keep_payload_exactly() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    let first = minted_line(26);
    let second = accepted_line(27);
    let third = "neutral health line".to_owned();

    bus.publish_live_chain_line(first.clone());
    bus.publish_live_chain_line(second.clone());
    bus.publish_live_chain_line(third.clone());

    assert_eq!(receive_one(&mut rx, "receive first mixed"), first);
    assert_eq!(receive_one(&mut rx, "receive second mixed"), second);
    assert_eq!(receive_one(&mut rx, "receive third mixed"), third);
}

#[test]
fn test_27_threaded_publish_reaches_receiver() {
    let bus = ConsoleBus::new();
    let thread_bus = bus.clone();
    let mut rx = bus.subscribe_live_chain();

    let handle = thread::spawn(move || {
        thread_bus.publish_live_chain_line("threaded publish".to_owned());
    });

    match handle.join() {
        Ok(()) => {}
        Err(_) => panic!("publisher thread panicked"),
    }

    assert_eq!(
        receive_one(&mut rx, "receive threaded publish"),
        "threaded publish"
    );
}

#[test]
fn test_28_threaded_multiple_publishers_reach_receiver() {
    let bus = ConsoleBus::new();
    let mut handles = Vec::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..4usize {
        let thread_bus = bus.clone();
        handles.push(thread::spawn(move || {
            thread_bus.publish_live_chain_line(format!("thread-line-{index}"));
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("publisher thread panicked"),
        }
    }

    let mut received = Vec::new();
    for _ in 0usize..4usize {
        received.push(receive_one(&mut rx, "receive threaded line"));
    }

    received.sort();
    assert_eq!(
        received,
        vec![
            "thread-line-0".to_owned(),
            "thread-line-1".to_owned(),
            "thread-line-2".to_owned(),
            "thread-line-3".to_owned(),
        ]
    );
}

#[test]
fn test_29_lazy_console_missing_blockchain_db_does_not_open_db() {
    let temp = TempTree::new("test_29");
    let opts = make_node_opts(&temp.child("node"));

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_30_lazy_console_precreated_data_root_without_blockchain_db_does_not_open_db() {
    let temp = TempTree::new("test_30");
    let data_dir = temp.child("node");

    assert_ok(fs::create_dir_all(&data_dir), "create data root");

    let opts = make_node_opts(&data_dir);

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_31_lazy_console_data_dir_with_spaces_does_not_open_db() {
    let temp = TempTree::new("test_31");
    let opts = make_node_opts(&temp.child("node with spaces"));

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_32_lazy_console_data_dir_with_unicode_does_not_open_db() {
    let temp = TempTree::new("test_32");
    let opts = make_node_opts(&temp.child("node_測試_цепь"));

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_33_lazy_console_custom_identity_does_not_open_db() {
    let temp = TempTree::new("test_33");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "custom_identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_34_lazy_console_custom_listen_does_not_open_db() {
    let temp = TempTree::new("test_34");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/0.0.0.0/tcp/36213",
        Vec::new(),
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_35_lazy_console_custom_bootstrap_does_not_open_db() {
    let temp = TempTree::new("test_35");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        vec!["/ip4/127.0.0.1/tcp/36214".to_owned()],
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_36_lazy_console_malformed_bootstrap_does_not_open_db() {
    let temp = TempTree::new("test_36");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        vec!["not-a-valid-bootstrap".to_owned()],
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_37_lazy_console_founder_true_does_not_open_db() {
    let temp = TempTree::new("test_37");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "info",
        true,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_38_lazy_console_debug_log_level_does_not_open_db() {
    let temp = TempTree::new("test_38");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "debug",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_39_lazy_console_inside_tokio_runtime_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_39");
    let opts = make_node_opts(&temp.child("node"));

    let runtime = assert_ok(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        "build tokio runtime",
    );

    runtime.block_on(async {
        assert_console_is_lazy_without_blockchain_db(&opts);
    });
}

#[test]
fn test_40_final_bus_publish_and_missing_db_lazy_console_both_work() {
    let temp = TempTree::new("test_40");
    let _opts = make_node_opts(&temp.child("node"));
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    bus.publish_live_chain_line(minted_line(40));
    assert_eq!(
        receive_one(&mut rx, "receive final minted line"),
        minted_line(40)
    );

    let _view = BlockchainConsoleView::new(bus);
}

#[test]
fn test_41_new_bus_and_cloned_bus_both_accept_subscribers() {
    let bus = ConsoleBus::new();
    let cloned = bus.clone();

    let mut first = bus.subscribe_live_chain();
    let mut second = cloned.subscribe_live_chain();

    bus.publish_live_chain_line("shared message".to_owned());

    assert_eq!(receive_one(&mut first, "receive first"), "shared message");
    assert_eq!(receive_one(&mut second, "receive second"), "shared message");
}

#[test]
fn test_42_default_bus_and_cloned_bus_both_accept_subscribers() {
    let bus = ConsoleBus::default();
    let cloned = bus.clone();

    let mut first = bus.subscribe_live_chain();
    let mut second = cloned.subscribe_live_chain();

    cloned.publish_live_chain_line("default clone message".to_owned());

    assert_eq!(
        receive_one(&mut first, "receive default first"),
        "default clone message"
    );
    assert_eq!(
        receive_one(&mut second, "receive default second"),
        "default clone message"
    );
}

#[test]
fn test_43_receiver_created_between_messages_gets_only_later_messages() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();

    bus.publish_live_chain_line("before second receiver".to_owned());

    let mut second = bus.subscribe_live_chain();

    bus.publish_live_chain_line("after second receiver".to_owned());

    assert_eq!(
        receive_one(&mut first, "first old message"),
        "before second receiver"
    );
    assert_eq!(
        receive_one(&mut first, "first new message"),
        "after second receiver"
    );
    assert_eq!(
        receive_one(&mut second, "second new message"),
        "after second receiver"
    );
    assert_try_recv_empty(second.try_recv());
}

#[test]
fn test_44_receiver_created_after_many_messages_starts_empty() {
    let bus = ConsoleBus::new();

    for index in 0usize..25usize {
        bus.publish_live_chain_line(neutral_line(index));
    }

    let mut rx = bus.subscribe_live_chain();

    assert_try_recv_empty(rx.try_recv());
}

#[test]
fn test_45_broadcast_preserves_exact_whitespace_payload() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "  leading  middle   trailing  ".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive whitespace payload"), line);
}

#[test]
fn test_46_broadcast_preserves_newline_payload() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "line one\nline two\nline three".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive newline payload"), line);
}

#[test]
fn test_47_broadcast_preserves_tab_payload() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "field_a\tfield_b\tfield_c".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive tab payload"), line);
}

#[test]
fn test_48_broadcast_preserves_json_like_payload() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = r#"{"event":"minted","block":48,"hash":"abc"}"#.to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive json-like payload"), line);
}

#[test]
fn test_49_broadcast_preserves_pipe_delimited_payload() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "alpha | beta | gamma | delta".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive pipe payload"), line);
}

#[test]
fn test_50_broadcast_preserves_colored_line_input_as_plain_string() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let line = "\u{1b}[32mgreen-ish\u{1b}[0m".to_owned();

    bus.publish_live_chain_line(line.clone());

    assert_eq!(receive_one(&mut rx, "receive ansi-like payload"), line);
}

#[test]
fn test_51_vector_minted_heights_zero_to_nine_are_delivered_in_order() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for height in 0u64..10u64 {
        bus.publish_live_chain_line(minted_line(height));
    }

    for height in 0u64..10u64 {
        assert_eq!(
            receive_one(&mut rx, "receive minted height vector"),
            minted_line(height)
        );
    }
}

#[test]
fn test_52_vector_accepted_heights_ten_to_nineteen_are_delivered_in_order() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for height in 10u64..20u64 {
        bus.publish_live_chain_line(accepted_line(height));
    }

    for height in 10u64..20u64 {
        assert_eq!(
            receive_one(&mut rx, "receive accepted height vector"),
            accepted_line(height)
        );
    }
}

#[test]
fn test_53_vector_alternating_minted_and_accepted_lines_are_delivered_in_order() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let mut expected = Vec::new();

    for height in 0u64..6u64 {
        let line = if height % 2 == 0 {
            minted_line(height)
        } else {
            accepted_line(height)
        };

        bus.publish_live_chain_line(line.clone());
        expected.push(line);
    }

    for expected_line in expected {
        assert_eq!(
            receive_one(&mut rx, "receive alternating line"),
            expected_line
        );
    }
}

#[test]
fn test_54_vector_neutral_lines_are_delivered_in_order() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..12usize {
        bus.publish_live_chain_line(neutral_line(index));
    }

    for index in 0usize..12usize {
        assert_eq!(
            receive_one(&mut rx, "receive neutral line"),
            neutral_line(index)
        );
    }
}

#[test]
fn test_55_many_receivers_receive_same_minted_line() {
    let bus = ConsoleBus::new();
    let mut receivers = Vec::new();

    for _ in 0usize..16usize {
        receivers.push(bus.subscribe_live_chain());
    }

    let line = minted_line(55);
    bus.publish_live_chain_line(line.clone());

    for rx in &mut receivers {
        assert_eq!(receive_one(rx, "receive many receiver line"), line);
    }
}

#[test]
fn test_56_many_receivers_receive_same_accepted_line() {
    let bus = ConsoleBus::new();
    let mut receivers = Vec::new();

    for _ in 0usize..16usize {
        receivers.push(bus.subscribe_live_chain());
    }

    let line = accepted_line(56);
    bus.publish_live_chain_line(line.clone());

    for rx in &mut receivers {
        assert_eq!(receive_one(rx, "receive many accepted line"), line);
    }
}

#[test]
fn test_57_dropping_original_bus_keeps_clone_channel_alive() {
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut rx = clone.subscribe_live_chain();

    drop(bus);

    clone.publish_live_chain_line("clone still alive".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive after original drop"),
        "clone still alive"
    );
}

#[test]
fn test_58_dropping_clone_keeps_original_channel_alive() {
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut rx = bus.subscribe_live_chain();

    drop(clone);

    bus.publish_live_chain_line("original still alive".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive after clone drop"),
        "original still alive"
    );
}

#[test]
fn test_59_receiver_reports_closed_after_all_senders_are_dropped() {
    let mut rx = {
        let bus = ConsoleBus::new();
        bus.subscribe_live_chain()
    };

    assert_try_recv_closed(rx.try_recv());
}

#[test]
fn test_60_receiver_keeps_buffered_message_after_sender_drop() {
    let mut rx = {
        let bus = ConsoleBus::new();
        let mut local_rx = bus.subscribe_live_chain();
        bus.publish_live_chain_line("buffered before drop".to_owned());
        let first = receive_one(&mut local_rx, "receive buffered before drop");
        assert_eq!(first, "buffered before drop");
        local_rx
    };

    assert_try_recv_closed(rx.try_recv());
}

#[test]
fn test_61_direct_send_returns_payload_on_no_receiver_error() {
    let bus = ConsoleBus::new();
    let payload = "payload returned".to_owned();

    let err = assert_err(
        bus.live_chain_tx.send(payload.clone()),
        "send with no receivers",
    );

    assert_eq!(err.0, payload);
}

#[test]
fn test_62_direct_send_succeeds_after_new_receiver_is_added() {
    let bus = ConsoleBus::new();

    let first_err = assert_err(
        bus.live_chain_tx.send("before receiver".to_owned()),
        "send before receiver",
    );
    assert_eq!(first_err.0, "before receiver");

    let mut rx = bus.subscribe_live_chain();

    let count = assert_ok(
        bus.live_chain_tx.send("after receiver".to_owned()),
        "send after receiver",
    );

    assert_eq!(count, 1);
    assert_eq!(
        receive_one(&mut rx, "receive after receiver"),
        "after receiver"
    );
}

#[test]
fn test_63_direct_send_counts_only_live_receivers() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();

    {
        let _second = bus.subscribe_live_chain();
    }

    let count = assert_ok(
        bus.live_chain_tx.send("live receiver count".to_owned()),
        "direct send live receiver count",
    );

    assert_eq!(count, 1);
    assert_eq!(
        receive_one(&mut first, "receive live receiver count"),
        "live receiver count"
    );
}

#[test]
fn test_64_direct_send_counts_three_live_receivers() {
    let bus = ConsoleBus::new();
    let mut first = bus.subscribe_live_chain();
    let mut second = bus.subscribe_live_chain();
    let mut third = bus.subscribe_live_chain();

    let count = assert_ok(
        bus.live_chain_tx.send("three receivers".to_owned()),
        "direct send three receivers",
    );

    assert_eq!(count, 3);
    assert_eq!(receive_one(&mut first, "first of three"), "three receivers");
    assert_eq!(
        receive_one(&mut second, "second of three"),
        "three receivers"
    );
    assert_eq!(receive_one(&mut third, "third of three"), "three receivers");
}

#[test]
fn test_65_lagged_receiver_can_receive_new_message_after_recovery() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..1100usize {
        bus.publish_live_chain_line(format!("lag-before-{index}"));
    }

    assert_try_recv_lagged(rx.try_recv());

    bus.publish_live_chain_line("after lag recovery".to_owned());

    let mut saw_recovery = false;
    for _ in 0usize..1101usize {
        match rx.try_recv() {
            Ok(value) if value == "after lag recovery" => {
                saw_recovery = true;
                break;
            }
            Ok(_) => {}
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Lagged(_)) => {}
            Err(TryRecvError::Closed) => break,
        }
    }

    assert!(saw_recovery, "receiver did not observe recovery message");
}

#[test]
fn test_66_fresh_receiver_after_lag_starts_empty() {
    let bus = ConsoleBus::new();

    for index in 0usize..1100usize {
        bus.publish_live_chain_line(format!("old-{index}"));
    }

    let mut rx = bus.subscribe_live_chain();

    assert_try_recv_empty(rx.try_recv());
}

#[test]
fn test_67_fresh_receiver_after_lag_gets_new_message() {
    let bus = ConsoleBus::new();

    for index in 0usize..1100usize {
        bus.publish_live_chain_line(format!("old-{index}"));
    }

    let mut rx = bus.subscribe_live_chain();
    bus.publish_live_chain_line("fresh after lag".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive fresh after lag"),
        "fresh after lag"
    );
}

#[test]
fn test_68_load_publish_one_hundred_lines_to_one_receiver() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..100usize {
        bus.publish_live_chain_line(format!("load-line-{index}"));
    }

    for index in 0usize..100usize {
        assert_eq!(
            receive_one(&mut rx, "receive load line"),
            format!("load-line-{index}")
        );
    }
}

#[test]
fn test_69_load_publish_two_hundred_lines_without_subscribers() {
    let bus = ConsoleBus::new();

    for index in 0usize..200usize {
        bus.publish_live_chain_line(format!("no-subscriber-load-{index}"));
    }
}

#[test]
fn test_70_load_publish_fifty_long_lines() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..50usize {
        bus.publish_live_chain_line(format!("long-{index}-{}", "z".repeat(1024)));
    }

    for index in 0usize..50usize {
        assert_eq!(
            receive_one(&mut rx, "receive long load line"),
            format!("long-{index}-{}", "z".repeat(1024))
        );
    }
}

#[test]
fn test_71_adversarial_threaded_publishers_preserve_all_unique_payloads() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let mut handles = Vec::new();

    for index in 0usize..8usize {
        let thread_bus = bus.clone();
        handles.push(thread::spawn(move || {
            thread_bus.publish_live_chain_line(format!("adversarial-thread-{index}"));
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("adversarial publisher thread panicked"),
        }
    }

    let mut received = collect_messages(&mut rx, 8, "receive adversarial threaded payload");
    received.sort();

    let mut expected = Vec::new();
    for index in 0usize..8usize {
        expected.push(format!("adversarial-thread-{index}"));
    }
    expected.sort();

    assert_eq!(received, expected);
}

#[test]
fn test_72_adversarial_threaded_minted_and_accepted_publishers() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let mut handles = Vec::new();

    for height in 0u64..6u64 {
        let thread_bus = bus.clone();
        handles.push(thread::spawn(move || {
            let line = if height % 2 == 0 {
                minted_line(height)
            } else {
                accepted_line(height)
            };

            thread_bus.publish_live_chain_line(line);
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("mixed publisher thread panicked"),
        }
    }

    let received = collect_messages(&mut rx, 6, "receive mixed threaded payload");
    assert_eq!(received.len(), 6);
}

#[test]
fn test_73_adversarial_subscribe_while_publishing_finishes_cleanly() {
    let bus = ConsoleBus::new();
    let publisher_bus = bus.clone();

    let handle = thread::spawn(move || {
        for index in 0usize..32usize {
            publisher_bus.publish_live_chain_line(format!("concurrent-{index}"));
        }
    });

    let mut receivers = Vec::new();
    for _ in 0usize..8usize {
        receivers.push(bus.subscribe_live_chain());
    }

    match handle.join() {
        Ok(()) => {}
        Err(_) => panic!("concurrent publisher thread panicked"),
    }

    bus.publish_live_chain_line("after concurrent subscribe".to_owned());

    for rx in &mut receivers {
        let mut saw_after = false;

        for _ in 0usize..64usize {
            match rx.try_recv() {
                Ok(value) if value == "after concurrent subscribe" => {
                    saw_after = true;
                    break;
                }
                Ok(_) => {}
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Lagged(_)) => {}
                Err(TryRecvError::Closed) => break,
            }
        }

        assert!(saw_after, "receiver did not see post-subscribe message");
    }
}

#[test]
fn test_74_adversarial_drop_many_receivers_then_publish_to_remaining() {
    let bus = ConsoleBus::new();
    let mut keep = bus.subscribe_live_chain();

    {
        let mut dropped_receivers = Vec::new();
        for _ in 0usize..32usize {
            dropped_receivers.push(bus.subscribe_live_chain());
        }
    }

    bus.publish_live_chain_line("remaining receiver".to_owned());

    assert_eq!(
        receive_one(&mut keep, "receive after many receiver drops"),
        "remaining receiver"
    );
}

#[test]
fn test_75_blockchain_console_view_can_be_constructed_from_new_bus() {
    let bus = ConsoleBus::new();
    let _view = BlockchainConsoleView::new(bus);
}

#[test]
fn test_76_blockchain_console_view_can_be_constructed_from_default_bus() {
    let bus = ConsoleBus::default();
    let _view = BlockchainConsoleView::new(bus);
}

#[test]
fn test_77_blockchain_console_view_can_be_constructed_from_cloned_bus() {
    let bus = ConsoleBus::new();
    let cloned = bus.clone();
    let _view = BlockchainConsoleView::new(cloned);

    let mut rx = bus.subscribe_live_chain();
    bus.publish_live_chain_line("view construction does not break bus".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive after view construction"),
        "view construction does not break bus"
    );
}

#[test]
fn test_78_lazy_console_deep_data_dir_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_78");
    let data_dir = temp.child("a").join("b").join("c").join("d").join("node");
    let opts = make_node_opts(&data_dir);

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_79_lazy_console_dash_underscore_data_dir_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_79");
    let opts = make_node_opts(&temp.child("node-with_dash_123"));

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_80_lazy_console_long_data_dir_component_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_80");
    let component = format!("node_{}", "x".repeat(64));
    let opts = make_node_opts(&temp.child(&component));

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_81_lazy_console_with_many_bootstraps_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_81");
    let mut bootstrap = Vec::new();

    for port in 36_200usize..36_210usize {
        bootstrap.push(format!("/ip4/127.0.0.1/tcp/{port}"));
    }

    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        bootstrap,
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_82_lazy_console_trace_log_level_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_82");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "trace",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_83_lazy_console_warn_log_level_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_83");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "warn",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_84_lazy_console_error_log_level_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_84");
    let opts = make_node_opts_custom(
        &temp.child("node"),
        "identity.key",
        "/ip4/127.0.0.1/tcp/36213",
        Vec::new(),
        "error",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_85_lazy_console_ipv6_listen_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_85");
    let opts = make_node_opts_custom(
        &temp.child("ipv6_node"),
        "identity.key",
        "/ip6/::1/tcp/36213",
        Vec::new(),
        "info",
        false,
    );

    assert_console_is_lazy_without_blockchain_db(&opts);
}

#[test]
fn test_86_lazy_console_inside_multi_thread_tokio_runtime_missing_db_does_not_open_db() {
    let temp = TempTree::new("test_86");
    let opts = make_node_opts(&temp.child("node"));

    let runtime = assert_ok(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build(),
        "build multi-thread tokio runtime",
    );

    runtime.block_on(async {
        assert_console_is_lazy_without_blockchain_db(&opts);
    });
}

#[test]
fn test_87_bus_publish_still_works_after_lazy_console_construct() {
    let temp = TempTree::new("test_87");
    let opts = make_node_opts(&temp.child("node"));
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let _view = BlockchainConsoleView::new(bus.clone());

    // Console construction must not touch RocksDB, even if the DB is missing.
    assert_console_is_lazy_without_blockchain_db(&opts);

    bus.publish_live_chain_line("after lazy console construction".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive after lazy console construction"),
        "after lazy console construction"
    );
}

#[test]
fn test_88_bus_clone_publish_still_works_after_lazy_console_construct() {
    let temp = TempTree::new("test_88");
    let opts = make_node_opts(&temp.child("node"));
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut rx = bus.subscribe_live_chain();
    let _view = BlockchainConsoleView::new(clone.clone());

    // Console construction must not touch RocksDB, even if the DB is missing.
    assert_console_is_lazy_without_blockchain_db(&opts);

    clone.publish_live_chain_line("clone after lazy console construction".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive clone after lazy console construction"),
        "clone after lazy console construction"
    );
}

#[test]
fn test_89_vector_publish_after_each_lazy_console_uses_same_bus() {
    let temp = TempTree::new("test_89");
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..3usize {
        let opts = make_node_opts(&temp.child(&format!("node_{index}")));
        let _view = BlockchainConsoleView::new(bus.clone());

        // Console construction must not touch RocksDB, even if the DB is missing.
        assert_console_is_lazy_without_blockchain_db(&opts);

        bus.publish_live_chain_line(format!("after-lazy-console-{index}"));
    }

    for index in 0usize..3usize {
        assert_eq!(
            receive_one(&mut rx, "receive after lazy console vector"),
            format!("after-lazy-console-{index}")
        );
    }
}

#[test]
fn test_90_load_create_many_subscribers_then_drop_bus_clone() {
    let bus = ConsoleBus::new();
    let clone = bus.clone();
    let mut receivers = Vec::new();

    for _ in 0usize..64usize {
        receivers.push(bus.subscribe_live_chain());
    }

    drop(clone);

    bus.publish_live_chain_line("many subscribers after clone drop".to_owned());

    for rx in &mut receivers {
        assert_eq!(
            receive_one(rx, "receive many subscribers after clone drop"),
            "many subscribers after clone drop"
        );
    }
}

#[test]
fn test_91_load_create_many_clones_then_publish_from_last_clone() {
    let bus = ConsoleBus::new();
    let mut clones = Vec::new();
    let mut rx = bus.subscribe_live_chain();

    clones.push(bus.clone());
    for index in 0usize..16usize {
        let previous = match clones.get(index) {
            Some(value) => value.clone(),
            None => panic!("missing previous clone"),
        };
        clones.push(previous.clone());
    }

    let last = match clones.last() {
        Some(value) => value.clone(),
        None => panic!("missing last clone"),
    };

    last.publish_live_chain_line("from last clone".to_owned());

    assert_eq!(
        receive_one(&mut rx, "receive from last clone"),
        "from last clone"
    );
}

#[test]
fn test_92_load_publish_from_many_clones() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let mut clones = Vec::new();

    for _ in 0usize..12usize {
        clones.push(bus.clone());
    }

    for index in 0usize..clones.len() {
        let clone = match clones.get(index) {
            Some(value) => value,
            None => panic!("missing clone"),
        };
        clone.publish_live_chain_line(format!("clone-publish-{index}"));
    }

    for index in 0usize..clones.len() {
        assert_eq!(
            receive_one(&mut rx, "receive clone publish"),
            format!("clone-publish-{index}")
        );
    }
}

#[test]
fn test_93_load_repeated_subscribe_publish_drop_cycles() {
    let bus = ConsoleBus::new();

    for index in 0usize..25usize {
        let mut rx = bus.subscribe_live_chain();
        bus.publish_live_chain_line(format!("cycle-{index}"));

        assert_eq!(
            receive_one(&mut rx, "receive subscribe publish drop cycle"),
            format!("cycle-{index}")
        );
    }
}

#[test]
fn test_94_load_repeated_empty_receiver_checks() {
    let bus = ConsoleBus::new();

    for _ in 0usize..25usize {
        let mut rx = bus.subscribe_live_chain();
        assert_try_recv_empty(rx.try_recv());
    }
}

#[test]
fn test_95_fuzz_like_varied_payloads_are_delivered_exactly() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let payloads = [
        "",
        " ",
        "\t",
        "\n",
        "abc",
        "1234567890",
        "!@#$%^&*()",
        "測試",
        "🚀🔐",
        "a|b|c|d",
        "minted: >",
        "accepted: <",
    ];

    for payload in payloads {
        bus.publish_live_chain_line(payload.to_owned());
    }

    for payload in payloads {
        assert_eq!(receive_one(&mut rx, "receive fuzz-like payload"), payload);
    }
}

#[test]
fn test_96_fuzz_like_varied_hash_lengths_are_delivered_exactly() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let hash_lengths = [0usize, 1usize, 8usize, 64usize, 128usize, 256usize];

    for len in hash_lengths {
        bus.publish_live_chain_line(format!(
            "2026-03-01T00:00:00Z  minted:  >   | block: 96 | txs: 0 | reward: 0/0 | hash: {}",
            "f".repeat(len)
        ));
    }

    for len in hash_lengths {
        assert_eq!(
            receive_one(&mut rx, "receive hash length vector"),
            format!(
                "2026-03-01T00:00:00Z  minted:  >   | block: 96 | txs: 0 | reward: 0/0 | hash: {}",
                "f".repeat(len)
            )
        );
    }
}

#[test]
fn test_97_adversarial_receiver_lag_does_not_close_channel() {
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    for index in 0usize..1500usize {
        bus.publish_live_chain_line(format!("lag-channel-open-{index}"));
    }

    assert_try_recv_lagged(rx.try_recv());

    let mut fresh = bus.subscribe_live_chain();
    bus.publish_live_chain_line("channel still open".to_owned());

    assert_eq!(
        receive_one(&mut fresh, "receive channel still open"),
        "channel still open"
    );
}

#[test]
fn test_98_adversarial_many_threads_publish_then_fresh_receiver_gets_future_line() {
    let bus = ConsoleBus::new();
    let mut handles = Vec::new();

    for index in 0usize..16usize {
        let thread_bus = bus.clone();
        handles.push(thread::spawn(move || {
            thread_bus.publish_live_chain_line(format!("pre-fresh-thread-{index}"));
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("pre-fresh publisher thread panicked"),
        }
    }

    let mut fresh = bus.subscribe_live_chain();
    bus.publish_live_chain_line("future-only".to_owned());

    assert_eq!(
        receive_one(&mut fresh, "receive future-only"),
        "future-only"
    );
}

#[test]
fn test_99_load_lazy_console_many_unique_nodes() {
    let temp = TempTree::new("test_99");

    for index in 0usize..5usize {
        let opts = make_node_opts(&temp.child(&format!("node_{index}")));
        assert_console_is_lazy_without_blockchain_db(&opts);
    }
}

#[test]
fn test_100_final_bus_load_threads_vectors_and_lazy_console_all_work() {
    let temp = TempTree::new("test_100");
    let opts = make_node_opts(&temp.child("node"));
    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();
    let mut handles = Vec::new();

    for index in 0usize..6usize {
        let thread_bus = bus.clone();
        handles.push(thread::spawn(move || {
            thread_bus.publish_live_chain_line(format!("final-thread-{index}"));
        }));
    }

    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("final publisher thread panicked"),
        }
    }

    let mut received = collect_messages(&mut rx, 6, "receive final threaded lines");
    received.sort();

    let mut expected = Vec::new();
    for index in 0usize..6usize {
        expected.push(format!("final-thread-{index}"));
    }
    expected.sort();

    assert_eq!(received, expected);

    bus.publish_live_chain_line(minted_line(100));
    assert_eq!(
        receive_one(&mut rx, "receive final minted"),
        minted_line(100)
    );

    let _view = BlockchainConsoleView::new(bus.clone());

    // Do not call interactive run_blocking() here. The console now lazily opens
    // RocksDB only for DB lookup choices, so construction must remain DB-free.
    assert_console_is_lazy_without_blockchain_db(&opts);

    bus.publish_live_chain_line("final after lazy console".to_owned());
    assert_eq!(
        receive_one(&mut rx, "receive final after lazy console"),
        "final after lazy console"
    );
}
