//! Storage Module
//!
//! This module contains all persistent storage backends and helpers for the Remzar project.
//! It is focused on managing the RocksDB-backed blockchain database and its configurations.
//!
//! Included submodules:
//! - Directory setup and discovery
//! - Column family (CF) descriptors and schema management
//! - Batched writes and transactional helpers
//! - Database configuration and lifecycle management
//! - Storage manager and database handle logic

pub mod rocksdb_000_directory;
pub mod rocksdb_001_cf_descriptors;
pub mod rocksdb_002_schema;
pub mod rocksdb_003_batches;
pub mod rocksdb_004_config;
pub mod rocksdb_005_manager;
pub mod rocksdb_006_manager_ext;
pub mod rocksdb_007_db_guard;
pub mod rocksdb_008_helper;
