use remzar::storage::rocksdb_001_cf_descriptors::CFDescriptors;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use rust_rocksdb::{ColumnFamilyDescriptor, Options};
use std::collections::BTreeSet;

type TestResult = Result<(), String>;

fn expected_cf_names() -> [&'static str; 20] {
    [
        "default",
        GlobalConfiguration::META_DATA_COLUMN_NAME,
        GlobalConfiguration::GLOBAL_COLUMN_NAME,
        GlobalConfiguration::ACCOUNT_COLUMN_NAME,
        GlobalConfiguration::NETWORK_COLUMN_NAME,
        GlobalConfiguration::SIDECHAIN_COLUMN_NAME,
        GlobalConfiguration::STATE_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        GlobalConfiguration::REWARD_COLUMN_NAME,
        GlobalConfiguration::REWARD_BATCH_COLUMN_NAME,
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::LOGS_COLUMN_NAME,
        GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::TX_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::IDENTITY_COLUMN_NAME,
        GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME,
        GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME,
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME,
    ]
}

fn descriptor_names(descriptors: &[ColumnFamilyDescriptor]) -> Vec<String> {
    descriptors
        .iter()
        .map(|descriptor| descriptor.name().to_owned())
        .collect()
}

fn descriptor_name_set(descriptors: &[ColumnFamilyDescriptor]) -> BTreeSet<String> {
    descriptor_names(descriptors).into_iter().collect()
}

fn descriptor_with_name(name: &str) -> ColumnFamilyDescriptor {
    ColumnFamilyDescriptor::new(name, Options::default())
}

fn clone_name(name: &str) -> String {
    let original = descriptor_with_name(name);
    let cloned = CFDescriptors::clone_column_family_descriptor(&original);

    cloned.name().to_owned()
}

fn assert_clone_preserves_name(name: &str) -> TestResult {
    let original = descriptor_with_name(name);
    let cloned = CFDescriptors::clone_column_family_descriptor(&original);

    assert_eq!(original.name(), name);
    assert_eq!(cloned.name(), name);

    Ok(())
}

fn deterministic_cf_name(seed: usize) -> String {
    let mut value = seed as u64;
    let mut output = String::from("generated_cf_");

    for _ in 0..16 {
        value = value
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);

        let bucket = ((value >> 32) % 36) as u8;
        let ch = if bucket < 10 {
            char::from(b'0' + bucket)
        } else {
            char::from(b'a' + (bucket - 10))
        };

        output.push(ch);
    }

    output
}

#[test]
fn cf_descriptors_001_returns_default_plus_all_configured_columns() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    assert_eq!(descriptors.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);

    Ok(())
}

#[test]
fn cf_descriptors_002_first_descriptor_is_default() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    assert_eq!(
        descriptors.first().map(ColumnFamilyDescriptor::name),
        Some("default")
    );

    Ok(())
}

#[test]
fn cf_descriptors_003_descriptor_order_matches_configuration() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let actual = descriptor_names(&descriptors);
    let expected = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn cf_descriptors_004_contains_every_expected_descriptor_name() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let actual = descriptor_name_set(&descriptors);

    for expected_name in expected_cf_names() {
        assert!(
            actual.contains(expected_name),
            "missing descriptor name: {expected_name}"
        );
    }

    Ok(())
}

#[test]
fn cf_descriptors_005_has_no_duplicate_names() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let names = descriptor_names(&descriptors);
    let unique_names = descriptor_name_set(&descriptors);

    assert_eq!(names.len(), unique_names.len());

    Ok(())
}

#[test]
fn cf_descriptors_006_expected_name_vector_matches_descriptor_count() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    assert_eq!(descriptors.len(), expected_cf_names().len());

    Ok(())
}

#[test]
fn cf_descriptors_007_all_descriptor_names_are_non_empty() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    for descriptor in descriptors {
        assert!(!descriptor.name().is_empty());
    }

    Ok(())
}

#[test]
fn cf_descriptors_008_all_production_names_use_safe_identifier_characters() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    for descriptor in descriptors {
        let name = descriptor.name();

        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
            "unexpected descriptor name characters: {name}"
        );
    }

    Ok(())
}

#[test]
fn cf_descriptors_009_all_production_names_avoid_path_separators() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    for descriptor in descriptors {
        let name = descriptor.name();

        assert!(!name.contains('/'));
        assert!(!name.contains('\\'));
    }

    Ok(())
}

#[test]
fn cf_descriptors_010_generation_is_deterministic_across_calls() -> TestResult {
    let first = descriptor_names(&CFDescriptors::get_cf_descriptors());
    let second = descriptor_names(&CFDescriptors::get_cf_descriptors());
    let third = descriptor_names(&CFDescriptors::get_cf_descriptors());

    assert_eq!(first, second);
    assert_eq!(second, third);

    Ok(())
}

#[test]
fn cf_descriptors_011_default_descriptor_appears_exactly_once() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let default_count = descriptors
        .iter()
        .filter(|descriptor| descriptor.name() == "default")
        .count();

    assert_eq!(default_count, 1);

    Ok(())
}

#[test]
fn cf_descriptors_012_each_descriptor_appears_at_expected_index() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    for (index, expected_name) in expected_cf_names().into_iter().enumerate() {
        assert_eq!(descriptors[index].name(), expected_name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_013_cloning_all_descriptors_preserves_order() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let original_names = descriptor_names(&descriptors);

    let cloned_names = descriptors
        .iter()
        .map(|descriptor| {
            CFDescriptors::clone_column_family_descriptor(descriptor)
                .name()
                .to_owned()
        })
        .collect::<Vec<_>>();

    assert_eq!(cloned_names, original_names);

    Ok(())
}

#[test]
fn cf_descriptors_014_clone_preserves_default_descriptor_name() -> TestResult {
    assert_clone_preserves_name("default")
}

#[test]
fn cf_descriptors_015_clone_preserves_meta_data_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::META_DATA_COLUMN_NAME)
}

#[test]
fn cf_descriptors_016_clone_preserves_global_data_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::GLOBAL_COLUMN_NAME)
}

#[test]
fn cf_descriptors_017_clone_preserves_account_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::ACCOUNT_COLUMN_NAME)
}

#[test]
fn cf_descriptors_018_clone_preserves_network_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::NETWORK_COLUMN_NAME)
}

#[test]
fn cf_descriptors_019_clone_preserves_sidechain_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::SIDECHAIN_COLUMN_NAME)
}

#[test]
fn cf_descriptors_020_clone_preserves_state_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::STATE_COLUMN_NAME)
}

#[test]
fn cf_descriptors_021_clone_preserves_transaction_descriptor_names() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::TRANSACTION_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)?;

    Ok(())
}

#[test]
fn cf_descriptors_022_clone_preserves_transaction_batch_descriptor_names() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME)?;

    Ok(())
}

#[test]
fn cf_descriptors_023_clone_preserves_reward_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::REWARD_COLUMN_NAME)
}

#[test]
fn cf_descriptors_024_clone_preserves_reward_batch_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::REWARD_BATCH_COLUMN_NAME)
}

#[test]
fn cf_descriptors_025_clone_preserves_blockmint_family_descriptor_names() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME)?;
    assert_clone_preserves_name(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME)?;

    Ok(())
}

#[test]
fn cf_descriptors_026_clone_preserves_logs_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::LOGS_COLUMN_NAME)
}

#[test]
fn cf_descriptors_027_clone_preserves_identity_descriptor_name() -> TestResult {
    assert_clone_preserves_name(GlobalConfiguration::IDENTITY_COLUMN_NAME)
}

#[test]
fn cf_descriptors_028_clone_unknown_descriptor_preserves_unknown_name() -> TestResult {
    let unknown_name = "unknown_future_column_family";

    assert_eq!(clone_name(unknown_name), unknown_name);

    Ok(())
}

#[test]
fn cf_descriptors_029_clone_empty_descriptor_name_preserves_empty_name() -> TestResult {
    assert_eq!(clone_name(""), "");

    Ok(())
}

#[test]
fn cf_descriptors_030_clone_whitespace_descriptor_name_preserves_whitespace_name() -> TestResult {
    let whitespace_name = "   ";

    assert_eq!(clone_name(whitespace_name), whitespace_name);

    Ok(())
}

#[test]
fn cf_descriptors_031_clone_unicode_descriptor_name_preserves_unicode_name() -> TestResult {
    let unicode_name = "validator_δ_测试";

    assert_eq!(clone_name(unicode_name), unicode_name);

    Ok(())
}

#[test]
fn cf_descriptors_032_clone_mixed_case_default_is_not_normalized() -> TestResult {
    let mixed_case = "Default";

    assert_eq!(clone_name(mixed_case), mixed_case);
    assert_ne!(clone_name(mixed_case), "default");

    Ok(())
}

#[test]
fn cf_descriptors_033_clone_descriptor_with_trailing_space_does_not_trim() -> TestResult {
    let name = "default ";

    assert_eq!(clone_name(name), name);
    assert_ne!(clone_name(name), "default");

    Ok(())
}

#[test]
fn cf_descriptors_034_all_configured_names_clone_to_themselves() -> TestResult {
    for name in expected_cf_names() {
        assert_eq!(clone_name(name), name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_035_cloned_configured_descriptors_remain_unique() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    let cloned_names = descriptors
        .iter()
        .map(|descriptor| {
            CFDescriptors::clone_column_family_descriptor(descriptor)
                .name()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(cloned_names.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);

    Ok(())
}

#[test]
fn cf_descriptors_036_descriptor_order_stays_stable_over_many_generations() -> TestResult {
    let baseline = descriptor_names(&CFDescriptors::get_cf_descriptors());

    for _ in 0..100 {
        let current = descriptor_names(&CFDescriptors::get_cf_descriptors());

        assert_eq!(current, baseline);
    }

    Ok(())
}

#[test]
fn cf_descriptors_037_fuzz_generated_unknown_names_clone_without_loss() -> TestResult {
    for seed in 0..128 {
        let generated_name = deterministic_cf_name(seed);
        let cloned_name = clone_name(&generated_name);

        assert_eq!(cloned_name, generated_name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_038_fuzz_generated_unknown_names_do_not_collide_with_production_names()
-> TestResult {
    let production_names = descriptor_name_set(&CFDescriptors::get_cf_descriptors());

    for seed in 0..128 {
        let generated_name = deterministic_cf_name(seed);

        assert!(
            !production_names.contains(&generated_name),
            "generated name collided with production CF: {generated_name}"
        );
    }

    Ok(())
}

#[test]
fn cf_descriptors_039_clone_extremely_long_unknown_name_preserves_name() -> TestResult {
    let long_name = format!("unknown_{}", "x".repeat(16 * 1024));

    assert_eq!(clone_name(&long_name), long_name);

    Ok(())
}

#[test]
fn cf_descriptors_040_load_repeated_generation_and_cloning_keeps_expected_count() -> TestResult {
    let mut generated_descriptor_count = 0_usize;
    let mut cloned_descriptor_count = 0_usize;

    for _ in 0..250 {
        let descriptors = CFDescriptors::get_cf_descriptors();
        let clones = descriptors
            .iter()
            .map(CFDescriptors::clone_column_family_descriptor)
            .collect::<Vec<_>>();

        generated_descriptor_count += descriptors.len();
        cloned_descriptor_count += clones.len();

        assert_eq!(descriptors.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);
        assert_eq!(clones.len(), descriptors.len());
        assert_eq!(descriptor_names(&clones), descriptor_names(&descriptors));
    }

    assert_eq!(
        generated_descriptor_count,
        250 * (GlobalConfiguration::TOTAL_COLUMNS + 1)
    );
    assert_eq!(cloned_descriptor_count, generated_descriptor_count);

    Ok(())
}

#[test]
fn cf_descriptors_041_expected_name_list_matches_total_column_count_plus_default() -> TestResult {
    assert_eq!(
        expected_cf_names().len(),
        GlobalConfiguration::TOTAL_COLUMNS + 1
    );

    Ok(())
}

#[test]
fn cf_descriptors_042_expected_name_list_has_no_duplicates() -> TestResult {
    let names = expected_cf_names();
    let unique = names.into_iter().collect::<BTreeSet<_>>();

    assert_eq!(unique.len(), GlobalConfiguration::TOTAL_COLUMNS + 1);

    Ok(())
}

#[test]
fn cf_descriptors_043_production_descriptor_name_set_matches_expected_name_set() -> TestResult {
    let actual = descriptor_name_set(&CFDescriptors::get_cf_descriptors());
    let expected = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn cf_descriptors_044_no_production_name_has_leading_or_trailing_whitespace() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        let name = descriptor.name();

        assert_eq!(name, name.trim());
    }

    Ok(())
}

#[test]
fn cf_descriptors_045_no_production_name_contains_ascii_whitespace() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        let name = descriptor.name();

        assert!(
            !name.chars().any(char::is_whitespace),
            "descriptor name contains whitespace: {name:?}"
        );
    }

    Ok(())
}

#[test]
fn cf_descriptors_046_all_production_names_are_ascii() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        assert!(descriptor.name().is_ascii());
    }

    Ok(())
}

#[test]
fn cf_descriptors_047_all_production_names_are_lowercase() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        let name = descriptor.name();

        assert_eq!(name, name.to_ascii_lowercase());
    }

    Ok(())
}

#[test]
fn cf_descriptors_048_no_production_name_starts_with_underscore() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        assert!(!descriptor.name().starts_with('_'));
    }

    Ok(())
}

#[test]
fn cf_descriptors_049_no_production_name_ends_with_underscore() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        assert!(!descriptor.name().ends_with('_'));
    }

    Ok(())
}

#[test]
fn cf_descriptors_050_non_default_production_names_contain_underscore() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        let name = descriptor.name();

        if name != "default" {
            assert!(
                name.contains('_'),
                "non-default CF name missing underscore: {name}"
            );
        }
    }

    Ok(())
}

#[test]
fn cf_descriptors_051_production_names_have_reasonable_length_bounds() -> TestResult {
    for descriptor in CFDescriptors::get_cf_descriptors() {
        let len = descriptor.name().len();

        assert!(len >= 5);
        assert!(len <= 64);
    }

    Ok(())
}

#[test]
fn cf_descriptors_052_default_appears_only_at_index_zero() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    assert_eq!(descriptors[0].name(), "default");

    for descriptor in descriptors.iter().skip(1) {
        assert_ne!(descriptor.name(), "default");
    }

    Ok(())
}

#[test]
fn cf_descriptors_053_logs_descriptor_is_at_expected_index() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();

    assert_eq!(
        descriptors[12].name(),
        GlobalConfiguration::LOGS_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn cf_descriptors_054_block_hash_descriptor_is_before_tx_hash_descriptor() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let names = descriptor_names(&descriptors);

    let block_hash_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME)
        .ok_or_else(|| "block hash descriptor missing".to_string())?;

    let tx_hash_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
        .ok_or_else(|| "tx hash descriptor missing".to_string())?;

    assert!(block_hash_index < tx_hash_index);

    Ok(())
}

#[test]
fn cf_descriptors_055_canonical_descriptors_are_last_two_entries() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let names = descriptor_names(&descriptors);

    assert_eq!(
        names[names.len() - 2],
        GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME
    );
    assert_eq!(
        names[names.len() - 1],
        GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME
    );

    Ok(())
}

#[test]
fn cf_descriptors_056_blockmint_related_descriptors_are_present() -> TestResult {
    let names = descriptor_name_set(&CFDescriptors::get_cf_descriptors());

    assert!(names.contains(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::BLOCK_TO_HASH_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::CANONICAL_HEIGHT_TO_HASH_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::CANONICAL_CHAIN_VIEW_COLUMN_NAME));

    Ok(())
}

#[test]
fn cf_descriptors_057_transaction_related_descriptors_are_present() -> TestResult {
    let names = descriptor_name_set(&CFDescriptors::get_cf_descriptors());

    assert!(names.contains(GlobalConfiguration::TRANSACTION_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::TX_TO_HASH_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME));

    Ok(())
}

#[test]
fn cf_descriptors_058_reward_related_descriptors_are_present() -> TestResult {
    let names = descriptor_name_set(&CFDescriptors::get_cf_descriptors());

    assert!(names.contains(GlobalConfiguration::REWARD_COLUMN_NAME));
    assert!(names.contains(GlobalConfiguration::REWARD_BATCH_COLUMN_NAME));

    Ok(())
}

#[test]
fn cf_descriptors_059_clone_preserves_name_byte_length_for_all_configured_names() -> TestResult {
    for name in expected_cf_names() {
        let cloned = clone_name(name);

        assert_eq!(cloned.len(), name.len());
        assert_eq!(cloned.as_bytes(), name.as_bytes());
    }

    Ok(())
}

#[test]
fn cf_descriptors_060_clone_of_clone_preserves_configured_names() -> TestResult {
    for name in expected_cf_names() {
        let first = CFDescriptors::clone_column_family_descriptor(&descriptor_with_name(name));
        let second = CFDescriptors::clone_column_family_descriptor(&first);

        assert_eq!(first.name(), name);
        assert_eq!(second.name(), name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_061_clone_of_clone_preserves_unknown_name() -> TestResult {
    let unknown = "future_cf_not_known_to_current_code";
    let first = CFDescriptors::clone_column_family_descriptor(&descriptor_with_name(unknown));
    let second = CFDescriptors::clone_column_family_descriptor(&first);

    assert_eq!(first.name(), unknown);
    assert_eq!(second.name(), unknown);

    Ok(())
}

#[test]
fn cf_descriptors_062_clone_preserves_hyphenated_unknown_name() -> TestResult {
    let name = "future-column-family-name";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_063_clone_preserves_name_with_forward_slash() -> TestResult {
    let name = "future/path/cf";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_064_clone_preserves_name_with_backslash() -> TestResult {
    let name = "future\\path\\cf";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_065_clone_preserves_name_with_colon() -> TestResult {
    let name = "future:cf:name";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_066_clone_preserves_emoji_unknown_name() -> TestResult {
    let name = "future_cf_🚀";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_067_clone_does_not_normalize_uppercase_production_name() -> TestResult {
    let name = GlobalConfiguration::META_DATA_COLUMN_NAME.to_ascii_uppercase();

    assert_eq!(clone_name(&name), name);
    assert_ne!(name, GlobalConfiguration::META_DATA_COLUMN_NAME);

    Ok(())
}

#[test]
fn cf_descriptors_068_clone_does_not_normalize_prefixed_production_name() -> TestResult {
    let name = format!("x_{}", GlobalConfiguration::NETWORK_COLUMN_NAME);

    assert_eq!(clone_name(&name), name);

    Ok(())
}

#[test]
fn cf_descriptors_069_clone_does_not_normalize_suffixed_production_name() -> TestResult {
    let name = format!("{}_x", GlobalConfiguration::NETWORK_COLUMN_NAME);

    assert_eq!(clone_name(&name), name);

    Ok(())
}

#[test]
fn cf_descriptors_070_clone_does_not_trim_newline_suffix() -> TestResult {
    let name = format!("{}\n", GlobalConfiguration::LOGS_COLUMN_NAME);

    assert_eq!(clone_name(&name), name);

    Ok(())
}

#[test]
fn cf_descriptors_071_custom_out_of_order_descriptor_list_clones_in_same_order() -> TestResult {
    let names = [
        GlobalConfiguration::LOGS_COLUMN_NAME,
        "default",
        GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME,
        GlobalConfiguration::TRANSACTION_COLUMN_NAME,
        "future_unknown_cf",
    ];

    let descriptors = names
        .into_iter()
        .map(descriptor_with_name)
        .collect::<Vec<_>>();

    let cloned_names = descriptors
        .iter()
        .map(|descriptor| {
            CFDescriptors::clone_column_family_descriptor(descriptor)
                .name()
                .to_owned()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        cloned_names,
        names.into_iter().map(str::to_owned).collect::<Vec<_>>()
    );

    Ok(())
}

#[test]
fn cf_descriptors_072_duplicate_input_descriptors_remain_duplicate_after_clone() -> TestResult {
    let descriptors = [
        descriptor_with_name(GlobalConfiguration::STATE_COLUMN_NAME),
        descriptor_with_name(GlobalConfiguration::STATE_COLUMN_NAME),
        descriptor_with_name(GlobalConfiguration::STATE_COLUMN_NAME),
    ];

    let cloned_names = descriptors
        .iter()
        .map(|descriptor| {
            CFDescriptors::clone_column_family_descriptor(descriptor)
                .name()
                .to_owned()
        })
        .collect::<Vec<_>>();

    assert_eq!(cloned_names.len(), 3);
    assert!(
        cloned_names
            .iter()
            .all(|name| name == GlobalConfiguration::STATE_COLUMN_NAME)
    );

    Ok(())
}

#[test]
fn cf_descriptors_073_fuzz_generated_names_are_unique_for_test_range() -> TestResult {
    let names = (0..256).map(deterministic_cf_name).collect::<Vec<String>>();
    let unique = names.iter().cloned().collect::<BTreeSet<_>>();

    assert_eq!(unique.len(), names.len());

    Ok(())
}

#[test]
fn cf_descriptors_074_fuzz_generated_names_have_expected_prefix() -> TestResult {
    for seed in 0..256 {
        let name = deterministic_cf_name(seed);

        assert!(name.starts_with("generated_cf_"));
    }

    Ok(())
}

#[test]
fn cf_descriptors_075_fuzz_generated_names_are_ascii_identifier_like() -> TestResult {
    for seed in 0..256 {
        let name = deterministic_cf_name(seed);

        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        );
    }

    Ok(())
}

#[test]
fn cf_descriptors_076_fuzz_generated_name_clone_round_trip_twice() -> TestResult {
    for seed in 0..128 {
        let name = deterministic_cf_name(seed);
        let first = CFDescriptors::clone_column_family_descriptor(&descriptor_with_name(&name));
        let second = CFDescriptors::clone_column_family_descriptor(&first);

        assert_eq!(first.name(), name);
        assert_eq!(second.name(), name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_077_load_generate_descriptors_one_thousand_times() -> TestResult {
    let expected = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    for _ in 0..1_000 {
        let descriptors = CFDescriptors::get_cf_descriptors();

        assert_eq!(descriptor_names(&descriptors), expected);
    }

    Ok(())
}

#[test]
fn cf_descriptors_078_load_clone_all_descriptors_one_thousand_times() -> TestResult {
    let baseline = descriptor_names(&CFDescriptors::get_cf_descriptors());

    for _ in 0..1_000 {
        let descriptors = CFDescriptors::get_cf_descriptors();
        let cloned = descriptors
            .iter()
            .map(CFDescriptors::clone_column_family_descriptor)
            .collect::<Vec<_>>();

        assert_eq!(descriptor_names(&cloned), baseline);
    }

    Ok(())
}

#[test]
fn cf_descriptors_079_load_clone_unknown_descriptors_keeps_expected_count() -> TestResult {
    let unknown_names = (0..512).map(deterministic_cf_name).collect::<Vec<_>>();

    let cloned_names = unknown_names
        .iter()
        .map(|name| clone_name(name))
        .collect::<Vec<_>>();

    assert_eq!(cloned_names.len(), unknown_names.len());
    assert_eq!(cloned_names, unknown_names);

    Ok(())
}

#[test]
fn cf_descriptors_080_adversarial_clone_many_long_unknown_names() -> TestResult {
    for seed in 0..64 {
        let name = format!(
            "{}_{}",
            deterministic_cf_name(seed),
            "x".repeat(1_024 + seed)
        );

        assert_eq!(clone_name(&name), name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_081_vector_default_name_is_not_in_global_column_constants() -> TestResult {
    let configured_names = expected_cf_names()
        .into_iter()
        .skip(1)
        .collect::<BTreeSet<_>>();

    assert!(!configured_names.contains("default"));

    Ok(())
}

#[test]
fn cf_descriptors_082_vector_configured_names_exclude_empty_string() -> TestResult {
    let configured_names = expected_cf_names();

    for name in configured_names {
        assert_ne!(name, "");
    }

    Ok(())
}

#[test]
fn cf_descriptors_083_vector_all_expected_names_are_found_by_index_lookup() -> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let names = descriptor_names(&descriptors);

    for expected_name in expected_cf_names() {
        let index = names
            .iter()
            .position(|name| name == expected_name)
            .ok_or_else(|| format!("expected descriptor missing: {expected_name}"))?;

        assert_eq!(names[index], expected_name);
    }

    Ok(())
}

#[test]
fn cf_descriptors_084_vector_state_descriptor_position_is_after_sidechain() -> TestResult {
    let names = descriptor_names(&CFDescriptors::get_cf_descriptors());

    let sidechain_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::SIDECHAIN_COLUMN_NAME)
        .ok_or_else(|| "sidechain descriptor missing".to_string())?;

    let state_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::STATE_COLUMN_NAME)
        .ok_or_else(|| "state descriptor missing".to_string())?;

    assert!(sidechain_index < state_index);

    Ok(())
}

#[test]
fn cf_descriptors_085_vector_transaction_batch_position_is_after_transaction() -> TestResult {
    let names = descriptor_names(&CFDescriptors::get_cf_descriptors());

    let tx_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::TRANSACTION_COLUMN_NAME)
        .ok_or_else(|| "transaction descriptor missing".to_string())?;

    let tx_batch_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME)
        .ok_or_else(|| "transaction batch descriptor missing".to_string())?;

    assert!(tx_index < tx_batch_index);

    Ok(())
}

#[test]
fn cf_descriptors_086_vector_reward_batch_position_is_after_reward() -> TestResult {
    let names = descriptor_names(&CFDescriptors::get_cf_descriptors());

    let reward_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::REWARD_COLUMN_NAME)
        .ok_or_else(|| "reward descriptor missing".to_string())?;

    let reward_batch_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::REWARD_BATCH_COLUMN_NAME)
        .ok_or_else(|| "reward batch descriptor missing".to_string())?;

    assert!(reward_index < reward_batch_index);

    Ok(())
}

#[test]
fn cf_descriptors_087_vector_identity_descriptor_is_after_tx_hash_descriptor() -> TestResult {
    let names = descriptor_names(&CFDescriptors::get_cf_descriptors());

    let tx_hash_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::TX_TO_HASH_COLUMN_NAME)
        .ok_or_else(|| "tx hash descriptor missing".to_string())?;

    let identity_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::IDENTITY_COLUMN_NAME)
        .ok_or_else(|| "identity descriptor missing".to_string())?;

    assert!(tx_hash_index < identity_index);

    Ok(())
}

#[test]
fn cf_descriptors_088_vector_batch_by_block_hash_is_after_block_meta() -> TestResult {
    let names = descriptor_names(&CFDescriptors::get_cf_descriptors());

    let block_meta_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::BLOCK_META_BY_HASH_COLUMN_NAME)
        .ok_or_else(|| "block meta descriptor missing".to_string())?;

    let batch_by_block_hash_index = names
        .iter()
        .position(|name| name == GlobalConfiguration::BATCH_BY_BLOCK_HASH_COLUMN_NAME)
        .ok_or_else(|| "batch by block hash descriptor missing".to_string())?;

    assert!(block_meta_index < batch_by_block_hash_index);

    Ok(())
}

#[test]
fn cf_descriptors_089_edge_clone_name_with_only_newline_is_preserved() -> TestResult {
    let name = "\n";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_090_edge_clone_name_with_tabs_is_preserved() -> TestResult {
    let name = "\t\tfuture_cf\t";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_091_edge_clone_name_with_spaces_around_known_name_is_not_trimmed() -> TestResult {
    let name = format!(" {} ", GlobalConfiguration::STATE_COLUMN_NAME);

    assert_eq!(clone_name(&name), name);
    assert_ne!(clone_name(&name), GlobalConfiguration::STATE_COLUMN_NAME);

    Ok(())
}

#[test]
fn cf_descriptors_092_edge_clone_name_with_dot_components_is_preserved() -> TestResult {
    let name = "../future_cf/./name";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_093_edge_clone_name_with_windows_drive_like_prefix_is_preserved() -> TestResult {
    let name = "C:\\future\\column_family";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_094_edge_clone_name_with_null_like_text_is_preserved() -> TestResult {
    let name = "future_cf_NULL_0";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_095_edge_clone_name_with_punctuation_is_preserved() -> TestResult {
    let name = "future.cf-name:v2@network#1";

    assert_eq!(clone_name(name), name);

    Ok(())
}

#[test]
fn cf_descriptors_096_vector_known_name_case_variants_do_not_collapse() -> TestResult {
    let lowercase = GlobalConfiguration::LOGS_COLUMN_NAME;
    let uppercase = lowercase.to_ascii_uppercase();

    assert_eq!(clone_name(lowercase), lowercase);
    assert_eq!(clone_name(&uppercase), uppercase);
    assert_ne!(clone_name(&uppercase), lowercase);

    Ok(())
}

#[test]
fn cf_descriptors_097_vector_known_name_prefix_suffix_variants_remain_distinct() -> TestResult {
    let exact = GlobalConfiguration::NETWORK_COLUMN_NAME;
    let prefixed = format!("prefix_{exact}");
    let suffixed = format!("{exact}_suffix");

    assert_eq!(clone_name(exact), exact);
    assert_eq!(clone_name(&prefixed), prefixed);
    assert_eq!(clone_name(&suffixed), suffixed);
    assert_ne!(prefixed, exact);
    assert_ne!(suffixed, exact);

    Ok(())
}

#[test]
fn cf_descriptors_098_vector_descriptor_generation_does_not_mutate_expected_name_helper()
-> TestResult {
    let before = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let _descriptors = CFDescriptors::get_cf_descriptors();

    let after = expected_cf_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert_eq!(before, after);

    Ok(())
}

#[test]
fn cf_descriptors_099_vector_clone_does_not_change_original_descriptor_name() -> TestResult {
    let original = descriptor_with_name(GlobalConfiguration::BLOCKMINT_DATA_COLUMN_NAME);
    let original_name_before = original.name().to_owned();

    let cloned = CFDescriptors::clone_column_family_descriptor(&original);

    assert_eq!(original.name(), original_name_before);
    assert_eq!(cloned.name(), original_name_before);

    Ok(())
}

#[test]
fn cf_descriptors_100_vector_final_descriptor_list_matches_exact_expected_joined_string()
-> TestResult {
    let descriptors = CFDescriptors::get_cf_descriptors();
    let actual = descriptor_names(&descriptors).join("|");
    let expected = expected_cf_names()
        .into_iter()
        .collect::<Vec<_>>()
        .join("|");

    assert_eq!(actual, expected);

    Ok(())
}
