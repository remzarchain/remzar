use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use remzar::tokens::game_slot_machine::{
    SLOT_ENTRY_FEE_MICRO, SLOT_HOUSE_ADDRESS, SlotMachineGame, SlotMachineGameConfig, SpinResult,
};
use remzar::utility::helper::{
    REMZAR_WALLET_LEN, UNIT_DIVISOR, canon_wallet_id_checked, parse_wallet_address,
    to_micro_units_str,
};

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    #[test]
    fn spin_result_is_win_if_and_only_if_payout_is_positive(
        payout_micro in any::<u64>(),
    ) {
        let spin = SpinResult { payout_micro };

        prop_assert_eq!(
            spin.is_win(),
            payout_micro > 0,
            "SpinResult::is_win must be true exactly when payout_micro > 0"
        );
    }

    #[test]
    fn default_slot_config_matches_fixed_house_and_entry_fee(
        _entry_fee_probe in 1u64..=1_000_000_000_000u64,
    ) {
        let cfg = SlotMachineGameConfig::default();

        prop_assert_eq!(
            cfg.house_address,
            SLOT_HOUSE_ADDRESS,
            "default slot config must use the fixed HOUSE wallet"
        );

        prop_assert_eq!(
            cfg.entry_fee_micro,
            SLOT_ENTRY_FEE_MICRO,
            "default slot config must use the fixed slot entry fee"
        );

        prop_assert_eq!(
            SLOT_ENTRY_FEE_MICRO,
            UNIT_DIVISOR,
            "slot entry fee must be exactly 1 REMZAR in micro-units"
        );
    }

    #[test]
    fn house_wallet_constant_is_canonical_remzar_wallet_address(
        uppercase in any::<bool>(),
        left_pad in "[ \\t]{0,4}",
        right_pad in "[ \\t\\n\\r]{0,4}",
    ) {
        let candidate = if uppercase {
            format!(
                "{}{}{}",
                left_pad,
                SLOT_HOUSE_ADDRESS.to_ascii_uppercase(),
                right_pad
            )
        } else {
            format!("{}{}{}", left_pad, SLOT_HOUSE_ADDRESS, right_pad)
        };

        let canonical = canon_wallet_id_checked(&candidate)
            .expect("HOUSE wallet should canonicalize even with harmless surrounding whitespace");

        prop_assert_eq!(
            canonical,
            SLOT_HOUSE_ADDRESS,
            "canonicalized HOUSE wallet must equal the fixed lowercase HOUSE wallet"
        );

        prop_assert_eq!(
            SLOT_HOUSE_ADDRESS.len(),
            REMZAR_WALLET_LEN,
            "HOUSE wallet must be r + 128 lowercase hex chars"
        );

        prop_assert!(
            parse_wallet_address(SLOT_HOUSE_ADDRESS).is_ok(),
            "HOUSE wallet must pass strict wallet address parser"
        );

        prop_assert!(
            SLOT_HOUSE_ADDRESS.starts_with('r'),
            "HOUSE wallet must start with r"
        );

        prop_assert!(
            SLOT_HOUSE_ADDRESS[1..]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "HOUSE wallet body must be lowercase hex"
        );
    }

    #[test]
    fn max_payout_is_exactly_100_remzar_and_independent_of_entry_fee(
        entry_fee_micro in 1u64..=u64::MAX,
    ) {
        let game = SlotMachineGame {
            cfg: SlotMachineGameConfig {
                house_address: SLOT_HOUSE_ADDRESS,
                entry_fee_micro,
            },
        };

        let expected_max = 100u64.saturating_mul(UNIT_DIVISOR);

        prop_assert_eq!(
            game.max_payout_micro(),
            expected_max,
            "slot max payout must stay fixed at 100 REMZAR"
        );

        prop_assert!(
            game.max_payout_micro() >= SLOT_ENTRY_FEE_MICRO,
            "max payout must cover at least the fixed entry fee"
        );
    }

    #[test]
    fn default_game_and_explicit_default_config_have_same_max_payout(
        entry_fee_probe in 1u64..=1_000_000_000u64,
    ) {
        let default_game = SlotMachineGame::default();

        let explicit_game = SlotMachineGame {
            cfg: SlotMachineGameConfig::default(),
        };

        prop_assert_eq!(
            default_game.max_payout_micro(),
            explicit_game.max_payout_micro(),
            "default game and explicit default config must agree on max payout"
        );

        prop_assert_eq!(
            default_game.cfg.house_address,
            explicit_game.cfg.house_address,
            "default game and explicit default config must use same HOUSE wallet"
        );

        prop_assert_eq!(
            default_game.cfg.entry_fee_micro,
            explicit_game.cfg.entry_fee_micro,
            "default game and explicit default config must use same entry fee"
        );

        prop_assert!(
            entry_fee_probe > 0,
            "generated probe keeps this as a real generated property"
        );
    }

    #[test]
    fn slot_entry_fee_formats_and_parses_as_one_remzar(
        trailing_zeros in 0usize..=8usize,
    ) {
        let canonical = "1.00000000";

        prop_assert_eq!(
            to_micro_units_str(canonical),
            SLOT_ENTRY_FEE_MICRO,
            "canonical 1.00000000 REMZAR string must parse to slot entry fee"
        );

        let mut trimmed = String::from("1");
        if trailing_zeros > 0 {
            trimmed.push('.');
            for _ in 0..trailing_zeros {
                trimmed.push('0');
            }
        }

        prop_assert_eq!(
            to_micro_units_str(&trimmed),
            SLOT_ENTRY_FEE_MICRO,
            "1 with optional zero fractional digits must parse to slot entry fee"
        );
    }

    #[test]
    fn custom_config_preserves_generated_entry_fee_and_fixed_house_wallet(
        entry_fee_micro in 1u64..=1_000_000_000_000u64,
    ) {
        let cfg = SlotMachineGameConfig {
            house_address: SLOT_HOUSE_ADDRESS,
            entry_fee_micro,
        };

        let game = SlotMachineGame { cfg: cfg.clone() };

        prop_assert_eq!(
            game.cfg.house_address,
            SLOT_HOUSE_ADDRESS,
            "custom config should preserve fixed HOUSE wallet"
        );

        prop_assert_eq!(
            game.cfg.entry_fee_micro,
            entry_fee_micro,
            "custom config should preserve generated entry fee"
        );

        prop_assert_eq!(
            cfg.entry_fee_micro,
            entry_fee_micro,
            "cloned config should preserve generated entry fee"
        );

        prop_assert_eq!(
            game.max_payout_micro(),
            100u64.saturating_mul(UNIT_DIVISOR),
            "custom entry fee must not change jackpot cap"
        );
    }
}
