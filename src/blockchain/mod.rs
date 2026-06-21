//! Blockchain Module
//!
//! This module defines the core blockchain logic and data structures for the Remzar project.
//! It covers everything from block and transaction management to validation, initialization,
//! wallet and node registries, minting, rewards, and mempool management.
//!
//! Included submodules:
//! - Wallet and node registries (REMZAR/ZAR node and wallet modules)
//! - Genesis block creation and pre-minting logic
//! - Block metadata, block validation, and block updates
//! - Blockchain indexing and initialization routines
//! - Transaction types, batching, and reward logic
//! - Mempool management for unconfirmed transactions
//! - Reward management and halving schedule logic

pub mod block_001_metadata;
pub mod block_002_blocks;
pub mod block_003_puzzleproof;
pub mod blockchain_000_consensus;
pub mod blockchain_001_builder;
pub mod blockchain_002_orchestration_display;
pub mod blockchain_003_orchestration_engine;
pub mod blockchain_004_orchestration_run;
pub mod blockchain_005_start;
pub mod genesis_001_block;
pub mod genesis_002_file;
pub mod halving_schedule;
pub mod mempool;
pub mod transaction_001_tx;
pub mod transaction_002_tx_register;
pub mod transaction_003_tx_reward;
pub mod transaction_004_tx_kind;
pub mod transaction_005_tx_account_tree;
pub mod transaction_005_tx_batch;
pub mod transaction_006_tx_account_tree_guards;
pub mod validation;
pub mod validatorstate;
