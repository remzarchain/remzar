//! storage/rocksdb_001_cf_descriptors.rs

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use rust_rocksdb::UniversalCompactOptions;
use rust_rocksdb::{ColumnFamilyDescriptor, DBCompactionStyle, DBCompressionType, Options};

pub struct CFDescriptors;

impl CFDescriptors {
    // --- Universal compaction options, used for all non-log/fifo CFs ---
    fn universal_opts() -> Options {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        // Primary compression for active/hot data.
        opts.set_compression_type(DBCompressionType::Lz4);

        // Bottommost compression for colder data.
        opts.set_bottommost_compression_type(DBCompressionType::Zstd);

        // Safety / correctness guardrails.
        opts.set_paranoid_checks(true);

        // Memory-bounded tuning.
        opts.set_write_buffer_size(16 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);
        opts.set_min_write_buffer_number_to_merge(1);
        opts.set_target_file_size_base(32 * 1024 * 1024);
        opts.set_max_background_jobs(4);
        opts.set_max_open_files(512);

        // Keep direct I/O enabled.
        opts.set_use_direct_io_for_flush_and_compaction(true);
        opts.set_use_direct_reads(true);

        // Bound parallelism. 16 is too aggressive for normal nodes.
        let parallelism = i32::try_from(num_cpus::get().min(4)).unwrap_or(4);
        opts.increase_parallelism(parallelism);

        // Keep universal compaction ON.
        opts.set_compaction_style(DBCompactionStyle::Universal);

        let mut u = UniversalCompactOptions::default();
        u.set_min_merge_width(2);
        u.set_max_merge_width(8);
        u.set_size_ratio(50);
        opts.set_universal_compaction_options(&u);

        opts.set_disable_auto_compactions(false);

        opts
    }

    // --- Network/registry data: **durable**, use universal compaction ---
    // Holds pubkey:<wallet>, join_height:<wallet>, other persistent metadata.
    fn network_data_opts() -> Options {
        Self::universal_opts()
    }

    // --- Log retention (for LOGS column) ---
    fn logs_data_opts() -> Options {
        let mut opts = Self::universal_opts();
        opts.set_max_log_file_size(20 * 1024 * 1024); // 20 MB
        opts.set_keep_log_file_num(10);
        opts
    }

    // -- All the rest: now all use universal_opts() --
    fn meta_data_opts() -> Options {
        Self::universal_opts()
    }
    fn global_data_opts() -> Options {
        Self::universal_opts()
    }
    fn transaction_data_opts() -> Options {
        Self::universal_opts()
    }
    fn transaction_batch_data_opts() -> Options {
        Self::universal_opts()
    }
    fn blockmint_data_opts() -> Options {
        Self::universal_opts()
    }
    fn reward_data_opts() -> Options {
        Self::universal_opts()
    }
    fn reward_batch_data_opts() -> Options {
        Self::universal_opts()
    }
    fn account_data_opts() -> Options {
        Self::universal_opts()
    }
    fn sidechain_data_opts() -> Options {
        Self::universal_opts()
    }
    fn state_data_opts() -> Options {
        Self::universal_opts()
    }
    fn identity_data_opts() -> Options {
        Self::universal_opts()
    }

    // ---------- HELPERS ----------

    pub fn clone_column_family_descriptor(cfd: &ColumnFamilyDescriptor) -> ColumnFamilyDescriptor {
        let name = cfd.name().to_string();
        let options = match name.as_str() {
            "default" => Self::universal_opts(),
            GlobalConfiguration::META_DATA_COLUMN_NAME => Self::meta_data_opts(),
            GlobalConfiguration::GLOBAL_COLUMN_NAME => Self::global_data_opts(),
            GlobalConfiguration::ACCOUNT_COLUMN_NAME => Self::account_data_opts(),
            GlobalConfiguration::NETWORK_COLUMN_NAME => Self::network_data_opts(),
            GlobalConfiguration::SIDECHAIN_COLUMN_NAME => Self::sidechain_data_opts(),
            GlobalConfiguration::STATE_COLUMN_NAME => Self::state_data_opts(),
            GlobalConfiguration::TRANSACTION_COLUMN_NAME
            | GlobalConfiguration::TX_TO_HASH_COLUMN_NAME => Self::transaction_data_opts(),
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME
            | GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME => {
                Self::transaction_batch_data_opts()
            }
            GlobalConfiguration::REWARD_COLUMN_NAME => Self::reward_data_opts(),
            GlobalConfiguration::REWARD_BATCH_COLUMN_NAME => Self::reward_batch_data_opts(),
            GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME
            | GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME
            | GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME
            | GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
            | GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME => Self::blockmint_data_opts(),
            GlobalConfiguration::LOGS_COLUMN_NAME => Self::logs_data_opts(),
            GlobalConfiguration::IDENTITY_COLUMN_NAME => Self::identity_data_opts(),
            _ => Self::universal_opts(),
        };
        ColumnFamilyDescriptor::new(name, options)
    }

    pub fn get_cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        vec![
            ColumnFamilyDescriptor::new("default", Self::universal_opts()),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::META_DATA_COLUMN_NAME,
                Self::meta_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::GLOBAL_COLUMN_NAME,
                Self::global_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::ACCOUNT_COLUMN_NAME,
                Self::account_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::NETWORK_COLUMN_NAME,
                Self::network_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
                Self::sidechain_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::STATE_COLUMN_NAME,
                Self::state_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::TRANSACTION_COLUMN_NAME,
                Self::transaction_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
                Self::transaction_batch_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::REWARD_COLUMN_NAME,
                Self::reward_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
                Self::reward_batch_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
                Self::blockmint_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::LOGS_COLUMN_NAME,
                Self::logs_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
                Self::blockmint_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
                Self::transaction_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::IDENTITY_COLUMN_NAME,
                Self::identity_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
                Self::blockmint_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
                Self::transaction_batch_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
                Self::blockmint_data_opts(),
            ),
            ColumnFamilyDescriptor::new(
                GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
                Self::blockmint_data_opts(),
            ),
        ]
    }
}
