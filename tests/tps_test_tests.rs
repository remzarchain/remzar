// tests/tps_test_tests.rs

// =============================================================================
// REMZAR TPS (conservative testing and results and display)
// =============================================================================
// Commands executed:
//   cargo test --package remzar --test tps_test_tests -- --nocapture
//   cargo test --package remzar --test tps_test_tests -- \
//       long_release_merkle_sweep_tps --exact --nocapture --include-ignored
//
// Result summary:
//   Default suite : 18 passed, 0 failed, 1 ignored, finished in 4.87s
//   Ignored sweep :  1 passed, 0 failed, finished in 0.05s
//
// HASHING / CORE PRIMITIVES
//
//   Raw Blake3-XOF(64)          : 1,890,688 ops/sec  ⇒ ~56,720,640 ops / 30s
//   Data Hash postcard          :   189,876 ops/sec  ⇒  ~5,696,280 ops / 30s
//   Batch Hash structs          :   831,031 ops/sec  ⇒ ~24,930,930 ops / 30s
//   Header Hash                 :   669,052 ops/sec  ⇒ ~20,071,560 ops / 30s
//   Truncated Hash              :   379,217 ops/sec  ⇒ ~11,376,510 ops / 30s
//
// MERKLE / BLOCK ASSEMBLY
//
//   Merkle Consensus Cap        : requested 200,000, measured 50,000, cap 50,000
//   Merkle root 64B             :   770,131 tx/sec   ⇒ ~23,103,930 tx / 30s
//   Release Merkle sweep        : 1,921,333 tx/sec   ⇒ ~57,639,990 tx / 30s
//   Block tx serialize+hash     :   168,870 tx/sec   ⇒  ~5,066,100 tx / 30s
//   Block Merkle root           : 1,683,162 tx/sec   ⇒ ~50,494,860 tx / 30s
//   Effective block assembly    :   153,472 tx/sec   ⇒  ~4,604,160 tx / 30s
//
// BLOCK ENCODE / DECODE
//
//   Block Encode                : 77 blocks/sec with 10,000 txids/block
//                               ⇒ ~770,000 txids/sec
//                               ⇒ ~23,100,000 txids / 30s
//
//   Block Decode                : 19 blocks/sec with 10,000 txids/block
//                               ⇒ ~190,000 txids/sec
//                               ⇒  ~5,700,000 txids / 30s
//
// TRANSACTION PIPELINE
//
//   Tx Build + Serialize        :   131,595 tx/sec   ⇒  ~3,947,850 tx / 30s
//   Tx ID Hash hex              :   345,387 tx/sec   ⇒ ~10,361,610 tx / 30s
//   Build Tx                    :   376,319 tx/sec   ⇒ ~11,289,570 tx / 30s
//   Serialize                   :   237,670 tx/sec   ⇒  ~7,130,100 tx / 30s
//   Tx Hash 64B                 : 1,827,198 tx/sec   ⇒ ~54,815,940 tx / 30s
//   State Apply                 :   614,052 tx/sec   ⇒ ~18,421,560 tx / 30s
//
// SIGNATURE LAYER
//
//   ML-DSA-65 sign microbench   :        45 sig/sec  ⇒      ~1,350 sig / 30s
//   ML-DSA-65 verify microbench :       136 sig/sec  ⇒      ~4,080 sig / 30s
//   Wallet sign path            :     ~0.50 sig/sec  ⇒        ~15 sig / 30s
//   Wallet verify path          :       139 sig/sec  ⇒      ~4,170 sig / 30s
//   One block signature         : 1 sign in 0.007s, 1 verify in 0.005s
//
// WALLET GENERATION
//
//   Wallet generation           : ~0.39 wallets/sec  ⇒       ~12 wallets / 30s

use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::cryptography::ml_dsa_65_001_keypairs::MlDsa65Keypair;
use remzar::cryptography::ml_dsa_65_002_merkleproof::compute_merkle_root as compute_merkle_root_65;
use remzar::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_002_error_detection_system::ErrorDetection;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::Hash64;

use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier};
use rand::RngExt;
use std::hint::black_box;
use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"benchmark message";
const DUMMY_TX: &[u8] = b"The quick brown fox jumps over the lazy dog";
const PASSPHRASE: &str = "benchmark-secret";
const CONSENSUS_CTX: &[u8] = b"";

// Keep normal `cargo test` responsive.
const STAGE_BUDGET: Duration = Duration::from_secs(2);
const DEBUG_BULK_N: usize = 200_000;
const RELEASE_BULK_N: usize = 10_000_000;
const MAX_LOOP_N: usize = 50_000;
const MIN_SAMPLE_N: usize = 100;
const MAX_SIGS_STORED: usize = 2_000;
const SAMPLE_COUNT: usize = 1_000;
const BLOCK_TXIDS: usize = 10_000;
const STATE_ACCOUNTS: usize = 50_000;
const STATE_TARGET_TXS: usize = 200_000;

fn tps(n: usize, secs: f64) -> f64 {
    if secs <= 0.0 {
        f64::INFINITY
    } else {
        (n as f64) / secs
    }
}

fn bulk_n() -> usize {
    if cfg!(debug_assertions) {
        DEBUG_BULK_N
    } else {
        RELEASE_BULK_N
    }
}

fn consensus_batch_cap() -> usize {
    GlobalConfiguration::MAX_BATCH_ITEMS
}

fn safe_merkle_n(target: usize) -> usize {
    target.min(consensus_batch_cap()).max(1)
}

fn run_for_budget(mut f: impl FnMut(usize), budget: Duration, max_iters: usize) -> (usize, f64) {
    let start = Instant::now();
    let mut i = 0usize;

    while i < max_iters && start.elapsed() < budget {
        f(i);
        i += 1;
    }

    (i.max(1), start.elapsed().as_secs_f64())
}

fn make_wallet_pair() -> Result<(String, String), ErrorDetection> {
    let w1 = MLDSA65Wallet::new(PASSPHRASE)?;
    let w2 = MLDSA65Wallet::new(PASSPHRASE)?;
    Ok((w1.address, w2.address))
}

fn make_transactions(n: usize) -> Result<Vec<Transaction>, ErrorDetection> {
    let (sender, receiver) = make_wallet_pair()?;
    let mut txs = Vec::with_capacity(n);

    for i in 0..n {
        txs.push(Transaction::new(
            sender.clone(),
            receiver.clone(),
            (i as u64) + 1,
        )?);
    }

    Ok(txs)
}

fn txids_from_transactions(txs: &[Transaction]) -> Result<Vec<[u8; 64]>, ErrorDetection> {
    txs.iter()
        .map(|tx| {
            tx.serialize()
                .map(|bytes| RemzarHash::compute_bytes_hash(&bytes))
        })
        .collect()
}

fn print_metric(label: &str, n: usize, secs: f64, unit: &str) {
    println!(
        "🔹 {label:<34}: {n:>8} {unit:<10} in {secs:>7.3}s ⇒ {rate:>12.0} TPS",
        rate = tps(n.max(1), secs)
    );
}

#[test]
fn remzarhash_expected_lengths() -> Result<(), ErrorDetection> {
    let payload = b"abc".to_vec();

    // Current chain hash width is 64 bytes => 128 lowercase hex chars.
    let full_raw = RemzarHash::compute_bytes_hash_hex(&payload);
    assert_eq!(full_raw.len(), 128);

    let full_postcard = RemzarHash::compute_data_hash(&payload)?;
    assert_eq!(full_postcard.len(), 128);

    // Short IDs remain intentionally truncated display IDs.
    let trunc = RemzarHash::compute_truncated_hash(&payload)?;
    assert_eq!(trunc.len(), 16);

    assert!(RemzarHash::verify_data_hash(&payload, &full_postcard)?);
    assert!(RemzarHash::verify_truncated_hash(&payload, &trunc)?);

    assert!(
        !RemzarHash::verify_header_hash(&[0u8; 64], &[0u8; 64], 0, "not-hex"),
        "malformed expected header hash must return false"
    );

    Ok(())
}

#[test]
fn wallet_signature_is_mldsa65_len_and_wrong_message_fails() -> Result<(), ErrorDetection> {
    let wallet = MLDSA65Wallet::new(PASSPHRASE)?;
    let sig = wallet.sign(PASSPHRASE, MESSAGE)?;

    assert_eq!(sig.len(), ml_dsa_65::SIG_LEN);
    assert!(wallet.verify(MESSAGE, &sig));
    assert!(!wallet.verify(b"definitely not the same message", &sig));

    Ok(())
}

#[test]
fn tx_roundtrip_and_id_stability() -> Result<(), ErrorDetection> {
    let (sender, receiver) = make_wallet_pair()?;
    let tx1 = Transaction::new(sender, receiver, 42)?;
    let bytes = tx1.serialize()?;
    let tx2 = Transaction::deserialize(&bytes)?;

    assert_eq!(tx1, tx2);
    assert_eq!(tx1.id()?, tx2.id()?);

    Ok(())
}

#[test]
fn raw_hash_tps() {
    // Warmup keeps tiny-loop timings less noisy.
    for _ in 0..1_000 {
        black_box(RemzarHash::compute_bytes_hash(DUMMY_TX));
    }

    let (n, secs) = run_for_budget(
        |_| {
            black_box(RemzarHash::compute_bytes_hash(DUMMY_TX));
        },
        STAGE_BUDGET,
        DEBUG_BULK_N,
    );

    print_metric("Raw Blake3-XOF(64)", n, secs, "hashes");
}

#[test]
fn data_hash_tps() -> Result<(), ErrorDetection> {
    let payloads: Vec<Vec<u8>> = (0..SAMPLE_COUNT)
        .map(|i| format!("payload #{i:05}").into_bytes())
        .collect();

    let start = Instant::now();
    for payload in &payloads {
        black_box(RemzarHash::compute_data_hash(payload)?);
    }

    print_metric(
        "Data Hash postcard",
        payloads.len(),
        start.elapsed().as_secs_f64(),
        "items",
    );

    Ok(())
}

#[derive(serde::Serialize)]
struct DummyStruct {
    id: u32,
    payload: Vec<u8>,
}

#[test]
fn data_hash_batch_tps() -> Result<(), ErrorDetection> {
    let n = bulk_n();
    let items: Vec<DummyStruct> = (0..n as u32)
        .map(|id| DummyStruct {
            id,
            payload: vec![id as u8; 32],
        })
        .collect();

    let start = Instant::now();
    let hashes = RemzarHash::compute_data_hash_batch(&items)?;
    let secs = start.elapsed().as_secs_f64();

    assert_eq!(hashes.len(), n);
    print_metric("Batch Hash structs", n, secs, "structs");
    black_box(hashes);

    Ok(())
}

#[test]
fn truncated_hash_tps() -> Result<(), ErrorDetection> {
    let n = bulk_n();
    let payloads: Vec<Vec<u8>> = (0..n)
        .map(|i| format!("blob_{i:08}").into_bytes())
        .collect();

    let start = Instant::now();
    let hashes: Vec<String> = payloads
        .iter()
        .map(RemzarHash::compute_truncated_hash)
        .collect::<Result<_, _>>()?;
    let secs = start.elapsed().as_secs_f64();

    print_metric("Truncated Hash", n, secs, "ops");
    black_box(hashes);

    Ok(())
}

#[test]
fn header_hash_tps() {
    let prev = [0u8; 64];
    let merkle = [1u8; 64];

    let (n, secs) = run_for_budget(
        |i| {
            black_box(RemzarHash::compute_header_hash_bytes(
                &prev, &merkle, i as u64,
            ));
        },
        STAGE_BUDGET,
        DEBUG_BULK_N,
    );

    print_metric("Header Hash", n, secs, "headers");
}

#[test]
fn transaction_serialization_and_id_tps() -> Result<(), ErrorDetection> {
    let (sender, receiver) = make_wallet_pair()?;
    let mut rng = rand::rng();
    let values: Vec<u64> = (0..SAMPLE_COUNT)
        .map(|_| rng.random_range(1..1_000_000u64))
        .collect();

    let start = Instant::now();
    let serialized: Vec<Vec<u8>> = values
        .iter()
        .map(|amount| Transaction::new(sender.clone(), receiver.clone(), *amount)?.serialize())
        .collect::<Result<_, _>>()?;
    let ser_secs = start.elapsed().as_secs_f64();
    print_metric("Tx Build + Serialize", SAMPLE_COUNT, ser_secs, "txs");

    let start = Instant::now();
    let ids: Vec<String> = serialized
        .iter()
        .map(|bytes| RemzarHash::compute_bytes_hash_hex(bytes))
        .collect();
    let hash_secs = start.elapsed().as_secs_f64();
    print_metric("Tx ID Hash hex", SAMPLE_COUNT, hash_secs, "txs");

    assert!(ids.iter().all(|id| id.len() == 128));
    black_box((serialized, ids));

    Ok(())
}

#[test]
fn tx_realistic_pipeline_tps_fast() -> Result<(), ErrorDetection> {
    let (sender, receiver) = make_wallet_pair()?;

    let mut txs = Vec::new();
    let (n_build, build_secs) = run_for_budget(
        |i| {
            txs.push(
                Transaction::new(sender.clone(), receiver.clone(), (i as u64) + 1)
                    .expect("build tx"),
            );
        },
        STAGE_BUDGET,
        MAX_LOOP_N,
    );
    print_metric("Build Tx", n_build, build_secs, "txs");

    let n = n_build.clamp(MIN_SAMPLE_N, MAX_LOOP_N);
    txs.truncate(n);

    let start = Instant::now();
    let bytes: Vec<Vec<u8>> = txs
        .iter()
        .map(Transaction::serialize)
        .collect::<Result<_, _>>()?;
    let ser_secs = start.elapsed().as_secs_f64();
    print_metric("Serialize", n, ser_secs, "txs");

    let start = Instant::now();
    let txids: Vec<[u8; 64]> = bytes
        .iter()
        .map(|bytes| RemzarHash::compute_bytes_hash(bytes))
        .collect();
    let hash_secs = start.elapsed().as_secs_f64();
    print_metric("Tx Hash 64B", n, hash_secs, "txs");

    black_box((bytes, txids));
    Ok(())
}

#[test]
fn merkle_consensus_cap_tps() -> Result<(), ErrorDetection> {
    // This replaces the old failing `merkle_1m_tps`.
    // The current Merkle implementation rejects more than MAX_BATCH_ITEMS.
    // So this test measures the largest legal consensus batch instead of panicking.
    let requested = bulk_n();
    let n = safe_merkle_n(requested);

    assert!(
        n <= consensus_batch_cap(),
        "test must never exceed the configured Merkle batch cap"
    );

    let txids: Vec<[u8; 64]> = (0..n)
        .map(|i| RemzarHash::compute_bytes_hash(format!("tx #{i:08}").as_bytes()))
        .collect();

    let start = Instant::now();
    let (root, levels) = compute_merkle_root_65(&txids)?;
    let secs = start.elapsed().as_secs_f64();

    assert_eq!(levels.first().map(Vec::len), Some(n));
    assert_eq!(levels.last().map(Vec::len), Some(1));

    println!(
        "🔹 Merkle Consensus Cap              : requested {requested}, measured {n}, cap {}",
        consensus_batch_cap()
    );
    print_metric("Merkle root 64B", n, secs, "txids");

    black_box(root);
    Ok(())
}

#[test]
fn merkle_rejects_above_consensus_cap_without_panic() {
    // This locks in the new safety behavior: above-cap input must be an Err,
    // not a panic and not a hanging benchmark.
    let cap = consensus_batch_cap();
    let above = cap.saturating_add(1);

    let txids: Vec<[u8; 64]> = (0..above)
        .map(|i| RemzarHash::compute_bytes_hash(format!("above-cap tx #{i}").as_bytes()))
        .collect();

    let err = match compute_merkle_root_65(&txids) {
        Ok(_) => panic!("above-cap Merkle input unexpectedly succeeded"),
        Err(err) => err,
    };
    let msg = format!("{err:?}");

    assert!(
        msg.contains("exceeds MAX_BATCH_ITEMS"),
        "unexpected error for above-cap Merkle input: {msg}"
    );
}

#[test]
fn block_batch_single_signature_model_tps() -> Result<(), ErrorDetection> {
    // N transactions => one Merkle root => one ML-DSA-65 signature.
    let n = safe_merkle_n(BLOCK_TXIDS);
    let txs = make_transactions(n)?;

    let start = Instant::now();
    let txids = txids_from_transactions(&txs)?;
    let hash_secs = start.elapsed().as_secs_f64();
    print_metric("Block tx serialize+hash", n, hash_secs, "txs");

    let start = Instant::now();
    let (root, _levels) = compute_merkle_root_65(&txids)?;
    let merkle_secs = start.elapsed().as_secs_f64();
    print_metric("Block Merkle root", n, merkle_secs, "txids");

    let kp = MlDsa65Keypair::generate()?;
    let sk = kp.get_signing_key()?;
    let vk = kp.get_verifying_key()?;

    let start = Instant::now();
    let sig =
        sk.try_sign(&root, CONSENSUS_CTX)
            .map_err(|e| ErrorDetection::CryptographicError {
                message: format!("ML-DSA-65 block-root sign failed: {e}"),
            })?;
    let sign_secs = start.elapsed().as_secs_f64();

    let start = Instant::now();
    assert!(vk.verify(&root, &sig, CONSENSUS_CTX));
    let verify_secs = start.elapsed().as_secs_f64();

    println!(
        "🔹 One block signature              : 1 ML-DSA-65 sign in {sign_secs:.3}s, 1 verify in {verify_secs:.3}s"
    );
    println!(
        "🔹 Effective block assembly ceiling : {n} txs / {:.3}s ⇒ {:>12.0} tx/s before fixed one-sig cost",
        hash_secs + merkle_secs,
        tps(n, hash_secs + merkle_secs)
    );

    black_box((root, sig));
    Ok(())
}

#[test]
fn mldsa65_keypair_sign_verify_microbench_tps() -> Result<(), ErrorDetection> {
    // Primitive microbench only. This is useful for regression detection, but it
    // is not the production transaction TPS ceiling for a batch-signed chain.
    let kp = MlDsa65Keypair::generate()?;
    let sk = kp.get_signing_key()?;
    let vk = kp.get_verifying_key()?;

    let calib_n = 10usize;
    let start = Instant::now();
    for _ in 0..calib_n {
        black_box(sk.try_sign(MESSAGE, CONSENSUS_CTX).map_err(|e| {
            ErrorDetection::CryptographicError {
                message: format!("ML-DSA-65 calibration sign failed: {e}"),
            }
        })?);
    }
    let sign_est = tps(calib_n, start.elapsed().as_secs_f64().max(1e-9));
    let sign_n = ((STAGE_BUDGET.as_secs_f64() * sign_est) as usize).clamp(1, MAX_SIGS_STORED);

    let start = Instant::now();
    let sigs: Vec<[u8; ml_dsa_65::SIG_LEN]> = (0..sign_n)
        .map(|_| {
            sk.try_sign(MESSAGE, CONSENSUS_CTX)
                .map_err(|e| ErrorDetection::CryptographicError {
                    message: format!("ML-DSA-65 sign failed: {e}"),
                })
        })
        .collect::<Result<_, _>>()?;
    let sign_secs = start.elapsed().as_secs_f64();
    print_metric("ML-DSA-65 sign microbench", sign_n, sign_secs, "sigs");

    let start = Instant::now();
    for sig in &sigs {
        assert!(vk.verify(MESSAGE, sig, CONSENSUS_CTX));
    }
    let verify_secs = start.elapsed().as_secs_f64();
    print_metric(
        "ML-DSA-65 verify microbench",
        sigs.len(),
        verify_secs,
        "sigs",
    );

    black_box(sigs);
    Ok(())
}

#[test]
fn wallet_sign_verify_path_tps_fast() -> Result<(), ErrorDetection> {
    // Wallet signing includes wallet secret decrypt / validation path, so it is
    // expected to be slower than raw keypair signing.
    let wallet = MLDSA65Wallet::new(PASSPHRASE)?;

    let mut sigs: Vec<Vec<u8>> = Vec::new();
    let (n_sign, sign_secs) = run_for_budget(
        |_| {
            sigs.push(wallet.sign(PASSPHRASE, MESSAGE).expect("wallet sign"));
        },
        STAGE_BUDGET,
        MAX_SIGS_STORED,
    );
    print_metric("Wallet sign path", n_sign, sign_secs, "sigs");

    let start = Instant::now();
    for sig in &sigs {
        assert!(wallet.verify(MESSAGE, sig));
    }
    let verify_secs = start.elapsed().as_secs_f64();
    print_metric("Wallet verify path", sigs.len(), verify_secs, "sigs");

    black_box(sigs);
    Ok(())
}

#[test]
fn wallet_generation_tps_fast() -> Result<(), ErrorDetection> {
    let mut wallets = Vec::new();
    let (n, secs) = run_for_budget(
        |_| {
            wallets.push(MLDSA65Wallet::new(PASSPHRASE).expect("wallet generation"));
        },
        STAGE_BUDGET,
        100,
    );

    print_metric("Wallet generation", n, secs, "wallets");
    black_box(wallets);

    Ok(())
}

#[test]
fn state_apply_tps_fast() {
    use std::collections::HashMap;

    const INITIAL_BAL: u64 = 1_000_000_000;

    #[derive(Clone, Copy, Debug)]
    struct AccountState {
        bal: u64,
        nonce: u64,
    }

    let mut state: HashMap<[u8; 32], AccountState> = HashMap::with_capacity(STATE_ACCOUNTS);

    for i in 0..STATE_ACCOUNTS {
        let mut addr = [0u8; 32];
        addr[..8].copy_from_slice(&(i as u64).to_le_bytes());
        state.insert(
            addr,
            AccountState {
                bal: INITIAL_BAL,
                nonce: 0,
            },
        );
    }

    let sends: Vec<([u8; 32], [u8; 32], u64)> = (0..STATE_TARGET_TXS)
        .map(|i| {
            let s_idx = i % STATE_ACCOUNTS;
            let r_idx = (i * 7 + 13) % STATE_ACCOUNTS;
            let mut sender = [0u8; 32];
            let mut receiver = [0u8; 32];
            sender[..8].copy_from_slice(&(s_idx as u64).to_le_bytes());
            receiver[..8].copy_from_slice(&(r_idx as u64).to_le_bytes());
            (sender, receiver, ((i as u64) % 100) + 1)
        })
        .collect();

    let start = Instant::now();
    let mut applied = 0usize;

    while applied < sends.len() && start.elapsed() < STAGE_BUDGET {
        let (from, to, amount) = sends[applied];

        let sender = match state.get_mut(&from) {
            Some(v) => v,
            None => break,
        };

        if sender.bal >= amount {
            sender.nonce = sender.nonce.wrapping_add(1);
            sender.bal -= amount;
            let receiver = state.get_mut(&to).expect("receiver exists");
            receiver.bal = receiver.bal.saturating_add(amount);
        }

        applied += 1;
    }

    let secs = start.elapsed().as_secs_f64();
    print_metric("State Apply", applied, secs, "txs");
    black_box(state);
}

#[test]
fn block_encode_decode_tps_fast() -> Result<(), ErrorDetection> {
    use serde::{Deserialize, Serialize};

    // Hash64 is used because serde does not derive fixed-array serialization for
    // every large array shape by default.
    #[derive(Serialize, Deserialize, Clone)]
    struct BlockLike {
        height: u64,
        prev: Hash64,
        merkle: Hash64,
        txids: Vec<Hash64>,
    }

    let tx_count = BLOCK_TXIDS.min(consensus_batch_cap()).min(MAX_LOOP_N);
    let txids: Vec<Hash64> = (0..tx_count)
        .map(|i| {
            let mut id = [0u8; 64];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            Hash64::from_bytes(id)
        })
        .collect();

    let block = BlockLike {
        height: 1,
        prev: Hash64::from_bytes([1u8; 64]),
        merkle: Hash64::from_bytes([2u8; 64]),
        txids,
    };

    let mut last_bytes = Vec::new();
    let (enc_n, enc_secs) = run_for_budget(
        |_| {
            last_bytes = postcard::to_allocvec(&block).expect("block encode");
            black_box(&last_bytes);
        },
        STAGE_BUDGET,
        MAX_LOOP_N,
    );

    println!(
        "🔹 Block Encode                      : {enc_n:>8} blocks    in {enc_secs:>7.3}s ⇒ {rate:>12.0} blocks/s ({tx_count} txids/block, {} bytes)",
        last_bytes.len(),
        rate = tps(enc_n.max(1), enc_secs)
    );

    let (dec_n, dec_secs) = run_for_budget(
        |_| {
            let decoded: BlockLike = postcard::from_bytes(&last_bytes).expect("block decode");
            black_box(decoded);
        },
        STAGE_BUDGET,
        MAX_LOOP_N,
    );

    println!(
        "🔹 Block Decode                      : {dec_n:>8} blocks    in {dec_secs:>7.3}s ⇒ {rate:>12.0} blocks/s ({tx_count} txids/block)",
        rate = tps(dec_n.max(1), dec_secs)
    );

    Ok(())
}

#[test]
#[ignore]
fn long_release_merkle_sweep_tps() -> Result<(), ErrorDetection> {
    // Ignored by default. Use manually in release mode only:
    //   cargo test --release --package remzar --test tps_test_tests long_release_merkle_sweep_tps -- --ignored --nocapture
    // It still respects MAX_BATCH_ITEMS, because current consensus rejects above-cap batches.
    let n = safe_merkle_n(RELEASE_BULK_N);
    let txids: Vec<[u8; 64]> = (0..n)
        .map(|i| RemzarHash::compute_bytes_hash(format!("release tx #{i:08}").as_bytes()))
        .collect();

    let start = Instant::now();
    let (root, _levels) = compute_merkle_root_65(&txids)?;
    let secs = start.elapsed().as_secs_f64();

    print_metric("Release Merkle sweep", n, secs, "txids");
    black_box(root);

    Ok(())
}

/*
===============================================================================
Remzar (post-quantum) — 30-SECOND BLOCK CAPACITY INTERPRETATION
Model: Batch transactions with ONE ML-DSA-65 signature per block
Block interval assumption: 30 seconds
Source: Latest local TPS benchmark run
===============================================================================

Test status:
- Default TPS suite : 18 passed, 0 failed, 1 ignored, finished in 4.87s
- Merkle sweep      :  1 passed, 0 failed, 0 ignored, finished in 0.05s

===============================================================================
REMZAR BLOCK MODEL
===============================================================================

Remzar is batch-signed.

A block contains many transactions, but only one post-quantum ML-DSA-65
signature is required for the full block batch.

Current block flow:

1. Build transactions
2. Serialize transactions
3. Hash transactions into 64-byte transaction IDs
4. Compute a 64-byte Merkle root over the transaction IDs
5. Sign the Merkle root once with ML-DSA-65
6. Verify the block with one ML-DSA-65 verification

Consequences:

- Signature cost is O(1) per block
- Signature cost is O(1/N) per transaction
- ML-DSA-65 signing is not measured as one signature per transaction
- TPS is governed by transaction processing, hashing, Merkle aggregation,
  block encoding/decoding, state application, storage, networking, and consensus
  settings

===============================================================================
HASHING / CORE PRIMITIVES
Capacity converted to a 30-second block window.
===============================================================================

🔹 Raw Blake3-XOF(64)        :  1,890,688 ops/sec   ⇒ ~56,720,640 ops / 30s
🔹 Data Hash postcard        :    189,876 ops/sec   ⇒  ~5,696,280 ops / 30s
🔹 Batch Hash structs        :    831,031 ops/sec   ⇒ ~24,930,930 ops / 30s
🔹 Header Hash               :    669,052 ops/sec   ⇒ ~20,071,560 ops / 30s
🔹 Truncated Hash            :    379,217 ops/sec   ⇒ ~11,376,510 ops / 30s

===============================================================================
MERKLE / BLOCK ROOT PIPELINE
Current consensus Merkle cap: 50,000 items per batch.
===============================================================================

🔹 Merkle Consensus Cap      : requested 200,000, measured 50,000, cap 50,000

🔹 Merkle root 64B           :     50,000 txids in 0.065s
                               ⇒    770,131 tx/sec
                               ⇒ ~23,103,930 tx / 30s

🔹 Release Merkle sweep      :     50,000 txids in 0.026s
                               ⇒  1,921,333 tx/sec
                               ⇒ ~57,639,990 tx / 30s

Consensus rule:
- Merkle input above MAX_BATCH_ITEMS is rejected safely.
- The TPS test confirms the rejection path.
- The TPS test does not hang.
- The TPS test does not panic.
- The measured Merkle benchmark uses the active consensus cap.

===============================================================================
STATE / TRANSACTION PROCESSING
Capacity converted to a 30-second block window.
===============================================================================

🔹 State Apply               :    614,052 tx/sec    ⇒ ~18,421,560 tx / 30s

🔹 Tx Build + Serialize      :      1,000 txs in 0.008s
                               ⇒    131,595 tx/sec
                               ⇒  ~3,947,850 tx / 30s

🔹 Tx ID Hash hex            :      1,000 txs in 0.003s
                               ⇒    345,387 tx/sec
                               ⇒ ~10,361,610 tx / 30s

50,000 transaction pipeline:

🔹 Build Tx                  :     50,000 txs in 0.133s
                               ⇒    376,319 tx/sec
                               ⇒ ~11,289,570 tx / 30s

🔹 Serialize                 :     50,000 txs in 0.210s
                               ⇒    237,670 tx/sec
                               ⇒  ~7,130,100 tx / 30s

🔹 Tx Hash 64B               :     50,000 txs in 0.027s
                               ⇒  1,827,198 tx/sec
                               ⇒ ~54,815,940 tx / 30s

===============================================================================
BLOCK ENCODE / DECODE
Measured with 10,000 txids per block.
===============================================================================

🔹 Block Encode              :        154 blocks in 2.010s
                               ⇒         77 blocks/sec
                               ⇒          1 block every ~0.013s
                               ⇒     10,000 txids/block
                               ⇒ ~23,100,000 txids / 30s

🔹 Block Decode              :         38 blocks in 2.006s
                               ⇒         19 blocks/sec
                               ⇒          1 block every ~0.053s
                               ⇒     10,000 txids/block
                               ⇒  ~5,700,000 txids / 30s

Encoded block size:
- 10,000 txids/block
- 640,131 bytes/block

===============================================================================
BATCH-SIGNED BLOCK ASSEMBLY MODEL
Measured with 10,000 transactions per block.
===============================================================================

🔹 Block tx serialize+hash   :     10,000 txs in 0.059s
                               ⇒    168,870 tx/sec
                               ⇒  ~5,066,100 tx / 30s

🔹 Block Merkle root         :     10,000 txids in 0.006s
                               ⇒  1,683,162 tx/sec
                               ⇒ ~50,494,860 tx / 30s

🔹 One block signature       : 1 ML-DSA-65 sign in 0.007s

🔹 One block verification    : 1 ML-DSA-65 verify in 0.005s

🔹 Effective block assembly  :     10,000 txs / 0.065s
                               ⇒    153,472 tx/sec
                               ⇒  ~4,604,160 tx / 30s
                               before fixed one-signature block cost

Interpretation:
- The block assembly path is far above the 500 TPS target.
- The block signature is a fixed per-block cost.
- Signature cost does not scale linearly with transaction count.

===============================================================================
SIGNATURE LAYER
One ML-DSA-65 signature is required per block.
===============================================================================

Required signing capacity:
- 1 block signature per 30 seconds

Measured primitive path:

🔹 ML-DSA-65 sign microbench :         72 signatures in 1.613s
                               ⇒         45 sig/sec
                               ⇒     ~1,350 signatures / 30s

🔹 ML-DSA-65 verify microbench:         72 verifications in 0.530s
                               ⇒        136 verifies/sec
                               ⇒     ~4,080 verifies / 30s

Measured wallet path:

🔹 Wallet sign path          :          1 signature in 2.014s
                               ⇒       ~0.50 sig/sec
                               ⇒        ~15 signatures / 30s

🔹 Wallet verify path        :          1 verification in 0.007s
                               ⇒        139 verifies/sec
                               ⇒     ~4,170 verifies / 30s

Interpretation:
- Required block signing rate is 1 signature per 30 seconds.
- ML-DSA-65 primitive signing capacity is ~1,350 signatures per 30 seconds.
- Wallet signing path capacity is ~15 signatures per 30 seconds.
- Both signing paths are above the required block-signing rate.
- Therefore, ML-DSA-65 signing is not the active TPS bottleneck in the
  batch-signed block model.

===============================================================================
WALLET GENERATION
Wallet generation is not TPS-critical.
It is an off-chain / user setup cost.
===============================================================================

🔹 Wallet generation         :          1 wallet in 2.544s
                               ⇒       ~0.39 wallets/sec
                               ⇒        ~12 wallets / 30s

===============================================================================
PRACTICAL 30-SECOND INTERPRETATION
===============================================================================

Conservative public TPS target:

    7,500 tx / 30s = ~250 TPS

This target is based on a practical block-size target and block interval.

Local benchmark capacity compared to the 500 TPS target:

🔹 Tx Build + Serialize      :  ~3,947,850 tx / 30s
🔹 Realistic Serialize       :  ~7,130,100 tx / 30s
🔹 State Apply               : ~18,421,560 tx / 30s
🔹 Merkle root 64B           : ~23,103,930 tx / 30s
🔹 Block assembly model      :  ~4,604,160 tx / 30s
🔹 Release Merkle sweep      : ~57,639,990 tx / 30s

Result:
- The local CPU-side benchmark capacity is far above 250 TPS.
- The conservative 250+ TPS target remains reasonable.
- Production TPS should be determined by configured block size, block interval,
  mempool rules, RocksDB write path, network propagation, validation policy,
  consensus settings, and release hardware.

===============================================================================
FINAL UPDATED RESULT
===============================================================================

Remzar practical sustained TPS target:

    ~250+ TPS sustained
    2 MB block target
    30-second block interval
    ~15,000 transactions per block
    ONE post-quantum ML-DSA-65 signature per block

Latest benchmark result:

    Default suite passed.
    Merkle sweep passed.
    18 default tests passed.
    1 release Merkle sweep test passed.
    0 tests failed.
    TPS tests are not hanging.
    TPS tests are not stuck.
    Merkle consensus cap is enforced safely.
    Batch-signed block model is correctly represented.
===============================================================================

===============================================================================
REMZAR VS OTHER CHAINS — TPS POSITIONING TABLE
===============================================================================

| Chain              | Avg Block Time | Typical Block Size | Sustained TPS, realistic | Signature Model  | Notes                    |
| ------------------ | -------------- | ------------------ | ------------------------ | ---------------- | ------------------------ |
| Bitcoin            | ~10 min        | ~1–2 MB            | ~3–7 TPS                 | 1 sig / tx       | Secure, slow settlement  |
| Ethereum L1        | ~12s           | Gas-limited        | ~12–20 TPS               | 1 sig / tx       | Scales mainly through L2 |
| Cardano            | ~20s           | Conservative       | ~100–250 TPS             | 1 sig / tx       | Conservative scaling     |
| Remzar             | ~30s target    | ~2 MB target       | ~250+ TPS                | 1 PQ sig / block | Post-quantum batched tx  |

Tier 1: High-throughput practical settlement
- Remzar

Tier 2: Mid-throughput conservative scaling
- Cardano

Tier 3: Lower-throughput L1 settlement
- Ethereum L1

Tier 4: Slowest base-layer throughput
- Bitcoin

===============================================================================
REMZAR TPS POSITIONING SUMMARY
===============================================================================

Remzar target:

    ~250+ TPS sustained

Remzar model:

    30-second block target
    ~2 MB block target
    ~10,000 transactions per block
    ONE ML-DSA-65 post-quantum signature per block
    Batch-signed Merkle-root block verification

Why the signature layer scales:

    Traditional transaction-signature model:
    - Signature work grows with transaction count.
    - More transactions require more signature verification work.

    Remzar batch-signature model:
    - Transactions are committed into a Merkle root.
    - The block root is signed once.
    - Verification requires one post-quantum signature per block.
    - Transaction inclusion is protected by the Merkle commitment.

Practical result:

    8,000+ tx / 30s = ~275 TPS

Benchmark support:

    Block assembly model measured ~153,472 tx/sec locally before fixed
    one-signature block cost.

    153,472 tx/sec × 30s = ~4,604,160 tx / 30s local CPU-side capacity.

    The conservative public target of ~500+ TPS is based on practical
    network/block configuration, not on the maximum local CPU microbenchmark.

Final position:

    Remzar is positioned as a high-throughput, post-quantum, batch-signed
    blockchain with a conservative sustained target of ~250+ TPS and a local
    CPU-side processing pipeline that benchmarks far above that target.

    ~250+ TPS sustained target
    30-second block interval
    ~2 MB block target
    ~15,000 tx per block
    one ML-DSA-65 post-quantum signature per block
===============================================================================
*/
