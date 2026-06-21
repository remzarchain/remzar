use anyhow::anyhow;
use remzar::utility::alpha_002_error_detection_system::{
    ErrorDetection, GenericError, NetworkErrorKind,
};
use std::error::Error as StdError;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::time::{Duration, SystemTime};
type TestResult = Result<(), String>;

fn to_json(error: &ErrorDetection) -> Result<String, String> {
    serde_json::to_string(error).map_err(|e| e.to_string())
}

fn from_json(s: &str) -> Result<ErrorDetection, String> {
    serde_json::from_str::<ErrorDetection>(s).map_err(|e| e.to_string())
}

fn roundtrip(error: &ErrorDetection) -> Result<ErrorDetection, String> {
    let json = to_json(error)?;
    from_json(&json)
}

fn network_kind_roundtrip(kind: &NetworkErrorKind) -> Result<NetworkErrorKind, String> {
    let json = serde_json::to_string(kind).map_err(|e| e.to_string())?;
    serde_json::from_str::<NetworkErrorKind>(&json).map_err(|e| e.to_string())
}

fn assert_display_contains(error: &ErrorDetection, expected: &str) {
    let rendered = error.to_string();
    assert!(
        rendered.contains(expected),
        "display `{rendered}` did not contain `{expected}`"
    );
}

#[test]
fn error_detection_001_generic_error_display_vector() -> TestResult {
    let error = GenericError("generic failure".to_string());

    assert_eq!(error.to_string(), "generic failure");
    Ok(())
}

#[test]
fn error_detection_002_network_error_kind_named_variants_roundtrip() -> TestResult {
    let variants = [
        NetworkErrorKind::Transient,
        NetworkErrorKind::Permanent,
        NetworkErrorKind::DnsResolution,
        NetworkErrorKind::ConnectionRefused,
        NetworkErrorKind::Timeout,
    ];

    for variant in variants {
        let decoded = network_kind_roundtrip(&variant)?;
        assert_eq!(decoded, variant);
    }

    Ok(())
}

#[test]
fn error_detection_003_network_error_kind_other_preserves_payload() -> TestResult {
    let kind = NetworkErrorKind::Other("peer disconnected mid-frame".to_string());
    let decoded = network_kind_roundtrip(&kind)?;

    assert_eq!(decoded, kind);
    Ok(())
}

#[test]
fn error_detection_004_validation_error_status_display_and_raw_os_code() -> TestResult {
    let error = ErrorDetection::ValidationError {
        message: "bad signature domain".to_string(),
        tx_id: Some("tx-001".to_string()),
    };

    assert_eq!(error.to_http_status_code(), 400);
    assert_eq!(error.raw_os_error(), None);
    assert_display_contains(&error, "Validation error");
    assert_display_contains(&error, "bad signature domain");
    assert_display_contains(&error, "tx-001");
    Ok(())
}

#[test]
fn error_detection_005_timeout_error_maps_to_408() -> TestResult {
    let error = ErrorDetection::TimeoutError {
        message: "mempool flush exceeded deadline".to_string(),
        operation: Some("flush".to_string()),
    };

    assert_eq!(error.to_http_status_code(), 408);
    assert_display_contains(&error, "Timeout error");
    assert_display_contains(&error, "flush");
    Ok(())
}

#[test]
fn error_detection_006_custom_error_maps_to_400_and_preserves_context() -> TestResult {
    let error = ErrorDetection::CustomError {
        details: "invalid rpc argument".to_string(),
        context: Some("rpc.submit_transaction".to_string()),
    };

    assert_eq!(error.to_http_status_code(), 400);
    assert_display_contains(&error, "Custom error");
    assert_display_contains(&error, "invalid rpc argument");
    assert_display_contains(&error, "rpc.submit_transaction");
    Ok(())
}

#[test]
fn error_detection_007_permission_denied_maps_to_403() -> TestResult {
    let error = ErrorDetection::PermissionDenied {
        message: "wallet is locked".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 403);
    assert_display_contains(&error, "Permission denied");
    assert_display_contains(&error, "wallet is locked");
    Ok(())
}

#[test]
fn error_detection_008_insufficient_balance_maps_to_402() -> TestResult {
    let error = ErrorDetection::InsufficientBalance {
        details: "needed 100, available 99".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 402);
    assert_display_contains(&error, "Insufficient balance");
    assert_display_contains(&error, "needed 100");
    Ok(())
}

#[test]
fn error_detection_009_not_found_maps_to_404() -> TestResult {
    let error = ErrorDetection::NotFound {
        resource: "block:42".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 404);
    assert_display_contains(&error, "Resource not found");
    assert_display_contains(&error, "block:42");
    Ok(())
}

#[test]
fn error_detection_010_version_compatibility_maps_to_409() -> TestResult {
    let error = ErrorDetection::VersionCompatibilityError {
        details: "wire protocol v2 required".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 409);
    assert_display_contains(&error, "Version compatibility error");
    assert_display_contains(&error, "wire protocol v2 required");
    Ok(())
}

#[test]
fn error_detection_011_rate_limit_retry_maps_to_429() -> TestResult {
    let error = ErrorDetection::RateLimitRetryError {
        message: "too many gossip requests".to_string(),
        retry_after: Some(30),
    };

    assert_eq!(error.to_http_status_code(), 429);
    assert_display_contains(&error, "Rate-limited");
    assert_display_contains(&error, "too many gossip requests");
    assert_display_contains(&error, "30");
    Ok(())
}

#[test]
fn error_detection_012_service_unavailable_maps_to_503() -> TestResult {
    let error = ErrorDetection::ServiceUnavailableError {
        message: "bootstrap peers unavailable".to_string(),
        retry_after: None,
    };

    assert_eq!(error.to_http_status_code(), 503);
    assert_display_contains(&error, "Service unavailable");
    assert_display_contains(&error, "bootstrap peers unavailable");
    Ok(())
}

#[test]
fn error_detection_013_warning_error_maps_to_200() -> TestResult {
    let error = ErrorDetection::WarningError {
        details: "non-fatal peer lag".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 200);
    assert_display_contains(&error, "Warning");
    error.log();
    Ok(())
}

#[test]
fn error_detection_014_unknown_error_defaults_to_500() -> TestResult {
    let error = ErrorDetection::UnknownError;

    assert_eq!(error.to_http_status_code(), 500);
    assert_eq!(error.raw_os_error(), None);
    assert_eq!(error.to_string(), "Unknown error occurred");
    error.log();
    Ok(())
}

#[test]
fn error_detection_015_io_error_from_std_io_preserves_raw_os_code_and_source() -> TestResult {
    let error: ErrorDetection = IoError::from_raw_os_error(13).into();

    assert_eq!(error.raw_os_error(), Some(13));
    assert_eq!(error.to_http_status_code(), 500);
    assert!(StdError::source(&error).is_some());

    match error {
        ErrorDetection::IoError { code, source, .. } => {
            assert_eq!(code, Some(13));
            assert!(source.is_some());
        }
        _ => return Err("expected IoError variant".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_016_io_error_serde_skips_source_but_preserves_message_and_code() -> TestResult {
    let error: ErrorDetection = IoError::from_raw_os_error(22).into();
    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::IoError {
            message,
            code,
            source,
        } => {
            assert!(!message.is_empty());
            assert_eq!(code, Some(22));
            assert!(source.is_none());
        }
        _ => return Err("expected IoError after roundtrip".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_017_system_time_error_conversion_sets_timestamp_error_source() -> TestResult {
    let later = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let source = match SystemTime::UNIX_EPOCH.duration_since(later) {
        Ok(_) => return Err("expected SystemTimeError".to_string()),
        Err(error) => error,
    };

    let error: ErrorDetection = source.into();

    assert_eq!(error.to_http_status_code(), 500);
    assert!(StdError::source(&error).is_some());

    match error {
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            assert_eq!(message, "Timestamp error occurred");
            assert!(!details.is_empty());
            assert!(source.is_some());
        }
        _ => return Err("expected TimestampError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_018_serde_json_error_conversion_preserves_details_and_source() -> TestResult {
    let serde_err = match serde_json::from_str::<serde_json::Value>("{") {
        Ok(_) => return Err("expected serde_json error".to_string()),
        Err(error) => error,
    };

    let error: ErrorDetection = serde_err.into();

    assert_eq!(error.to_http_status_code(), 500);
    assert!(StdError::source(&error).is_some());

    match error {
        ErrorDetection::SerdeJsonError { details, source } => {
            assert!(!details.is_empty());
            assert!(source.is_some());
        }
        _ => return Err("expected SerdeJsonError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_019_anyhow_conversion_maps_to_protocol_error() -> TestResult {
    let error: ErrorDetection = anyhow!("handshake transcript mismatch").into();

    assert_eq!(error.to_http_status_code(), 500);

    match error {
        ErrorDetection::ProtocolError { message } => {
            assert_eq!(message, "handshake transcript mismatch");
        }
        _ => return Err("expected ProtocolError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_020_string_conversion_maps_to_custom_error_without_context() -> TestResult {
    let error: ErrorDetection = String::from("string converted failure").into();

    assert_eq!(error.to_http_status_code(), 400);

    match error {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "string converted failure");
            assert_eq!(context, None);
        }
        _ => return Err("expected CustomError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_021_str_conversion_maps_to_custom_error_without_context() -> TestResult {
    let error: ErrorDetection = "str converted failure".into();

    assert_eq!(error.to_http_status_code(), 400);

    match error {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "str converted failure");
            assert_eq!(context, None);
        }
        _ => return Err("expected CustomError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_022_boxed_error_conversion_preserves_box_context() -> TestResult {
    let boxed: Box<dyn std::error::Error> = Box::new(GenericError("boxed diagnostic".to_string()));
    let error: ErrorDetection = boxed.into();

    assert_eq!(error.to_http_status_code(), 400);

    match error {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "boxed diagnostic");
            assert_eq!(context, Some("Box<dyn Error>".to_string()));
        }
        _ => return Err("expected CustomError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_023_wallet_initialization_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::WalletInitializationError {
        wallet: "rabc".to_string(),
        details: "seed phrase rejected".to_string(),
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::WalletInitializationError { wallet, details } => {
            assert_eq!(wallet, "rabc");
            assert_eq!(details, "seed phrase rejected");
        }
        _ => return Err("expected WalletInitializationError".to_string()),
    }

    assert_display_contains(&error, "Wallet initialization error");
    Ok(())
}

#[test]
fn error_detection_024_initialization_configuration_and_concurrency_default_to_500() -> TestResult {
    let errors = [
        ErrorDetection::InitializationError {
            message: "db bootstrap failed".to_string(),
        },
        ErrorDetection::ConfigurationError {
            message: "missing chain id".to_string(),
        },
        ErrorDetection::ConcurrencyError {
            message: "lock poisoned".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.to_http_status_code(), 500);
        assert!(!error.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_025_transaction_double_spend_and_stack_underflow_vectors() -> TestResult {
    let tx_error = ErrorDetection::TransactionError {
        message: "nonce mismatch".to_string(),
        tx_id: Some("tx-abc".to_string()),
    };
    let double_spend = ErrorDetection::DoubleSpending {
        tx_id: Some("tx-abc".to_string()),
    };
    let stack_underflow = ErrorDetection::StackUnderflow;

    assert_eq!(tx_error.to_http_status_code(), 500);
    assert_eq!(double_spend.to_http_status_code(), 500);
    assert_eq!(stack_underflow.to_http_status_code(), 500);

    assert_display_contains(&tx_error, "nonce mismatch");
    assert_display_contains(&double_spend, "tx-abc");
    assert_eq!(
        stack_underflow.to_string(),
        "Stack underflow error occurred"
    );
    Ok(())
}

#[test]
fn error_detection_026_crypto_and_security_variant_display_vectors() -> TestResult {
    let errors = [
        ErrorDetection::MerkleProofGenerationError {
            reason: "missing sibling".to_string(),
        },
        ErrorDetection::CryptographicError {
            message: "hash mismatch".to_string(),
        },
        ErrorDetection::TlsError {
            message: "cert rejected".to_string(),
            details: "expired".to_string(),
        },
        ErrorDetection::SignatureVerificationFailed {
            message: "bad mldsa signature".to_string(),
        },
        ErrorDetection::EncryptionError {
            message: "aes-gcm seal failed".to_string(),
        },
        ErrorDetection::CompressionError {
            message: "frame too large".to_string(),
        },
        ErrorDetection::InvalidSignature {
            reason: "wrong signer".to_string(),
        },
        ErrorDetection::DecryptionError {
            message: "tag mismatch".to_string(),
        },
        ErrorDetection::InvalidSignatureFormat {
            format: "wrong length".to_string(),
        },
        ErrorDetection::BackupFailed {
            message: "snapshot copy failed".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.to_http_status_code(), 500);
        assert!(!error.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_027_network_error_variant_roundtrip_preserves_kind_and_message() -> TestResult {
    let error = ErrorDetection::NetworkError {
        message: "dial failed".to_string(),
        kind: NetworkErrorKind::ConnectionRefused,
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::NetworkError { message, kind } => {
            assert_eq!(message, "dial failed");
            assert_eq!(kind, NetworkErrorKind::ConnectionRefused);
        }
        _ => return Err("expected NetworkError".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 500);
    Ok(())
}

#[test]
fn error_detection_028_rate_limit_and_service_retry_after_options_roundtrip() -> TestResult {
    let rate_limited = ErrorDetection::RateLimitRetryError {
        message: "burst exceeded".to_string(),
        retry_after: Some(9),
    };
    let unavailable = ErrorDetection::ServiceUnavailableError {
        message: "maintenance".to_string(),
        retry_after: None,
    };

    match roundtrip(&rate_limited)? {
        ErrorDetection::RateLimitRetryError {
            message,
            retry_after,
        } => {
            assert_eq!(message, "burst exceeded");
            assert_eq!(retry_after, Some(9));
        }
        _ => return Err("expected RateLimitRetryError".to_string()),
    }

    match roundtrip(&unavailable)? {
        ErrorDetection::ServiceUnavailableError {
            message,
            retry_after,
        } => {
            assert_eq!(message, "maintenance");
            assert_eq!(retry_after, None);
        }
        _ => return Err("expected ServiceUnavailableError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_029_data_and_storage_variant_display_vectors() -> TestResult {
    let errors = [
        ErrorDetection::AlreadyExists {
            message: "wallet exists".to_string(),
        },
        ErrorDetection::InvalidInput {
            message: "empty block hash".to_string(),
        },
        ErrorDetection::WalletNotFound {
            wallet_id: "rmissing".to_string(),
        },
        ErrorDetection::StorageError {
            message: "cf missing".to_string(),
        },
        ErrorDetection::BincodeError {
            details: "decode failed".to_string(),
        },
        ErrorDetection::ParityDbError {
            details: "parity unavailable".to_string(),
        },
        ErrorDetection::SnapError {
            details: "snap decode failed".to_string(),
        },
        ErrorDetection::DatabaseError {
            details: "rocks handle closed".to_string(),
        },
        ErrorDetection::SerializationError {
            details: "postcard encode failed".to_string(),
        },
        ErrorDetection::InvalidNumberFormat {
            format: "1e9".to_string(),
        },
        ErrorDetection::BlockchainError {
            details: "parent missing".to_string(),
        },
        ErrorDetection::ZstdError {
            details: "zstd frame failed".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.to_http_status_code(), 500);
        assert!(!error.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_030_conflict_authorization_and_capacity_vectors() -> TestResult {
    let errors = [
        ErrorDetection::TxConflict {
            key: "account:r1".to_string(),
        },
        ErrorDetection::ReplicationError {
            details: "follower rejected append".to_string(),
        },
        ErrorDetection::GenericDbError {
            details: "db generic".to_string(),
        },
        ErrorDetection::Unauthorized {
            message: "not committee member".to_string(),
        },
        ErrorDetection::VersionConflict {
            key: "height:10".to_string(),
        },
        ErrorDetection::CapacityError {
            message: "batch too large".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.to_http_status_code(), 500);
        assert!(!error.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_031_operational_variant_display_vectors() -> TestResult {
    let errors = [
        ErrorDetection::AnomalyDetectionError {
            details: "fork depth spike".to_string(),
        },
        ErrorDetection::ExecutionError {
            details: "state transition failed".to_string(),
        },
        ErrorDetection::LockError {
            details: "db lock busy".to_string(),
        },
        ErrorDetection::CriticalError {
            details: "consensus halted".to_string(),
        },
        ErrorDetection::RocksDbError {
            details: "rocksdb open failed".to_string(),
        },
        ErrorDetection::AsyncRuntimeError {
            details: "task join failed".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.to_http_status_code(), 500);
        assert!(!error.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_032_batch_error_nested_roundtrip_preserves_child_count() -> TestResult {
    let error = ErrorDetection::BatchError {
        errors: vec![
            ErrorDetection::ValidationError {
                message: "bad tx".to_string(),
                tx_id: Some("tx-1".to_string()),
            },
            ErrorDetection::NotFound {
                resource: "parent block".to_string(),
            },
        ],
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::BatchError { errors } => {
            assert_eq!(errors.len(), 2);
            assert_eq!(errors[0].to_http_status_code(), 400);
            assert_eq!(errors[1].to_http_status_code(), 404);
        }
        _ => return Err("expected BatchError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_033_batch_processing_error_preserves_optional_index() -> TestResult {
    let error = ErrorDetection::BatchProcessingError {
        batch_type: "transaction_batch".to_string(),
        details: "operation rejected".to_string(),
        operation_index: Some(7),
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::BatchProcessingError {
            batch_type,
            details,
            operation_index,
        } => {
            assert_eq!(batch_type, "transaction_batch");
            assert_eq!(details, "operation rejected");
            assert_eq!(operation_index, Some(7));
        }
        _ => return Err("expected BatchProcessingError".to_string()),
    }

    assert_display_contains(&error, "operation index");
    Ok(())
}

#[test]
fn error_detection_034_snapshot_and_async_runtime_errors_roundtrip() -> TestResult {
    let snapshot = ErrorDetection::SnapshotError {
        snapshot_type: "account_state".to_string(),
        details: "checksum mismatch".to_string(),
    };
    let async_runtime = ErrorDetection::AsyncRuntimeError {
        details: "join handle failed".to_string(),
    };

    match roundtrip(&snapshot)? {
        ErrorDetection::SnapshotError {
            snapshot_type,
            details,
        } => {
            assert_eq!(snapshot_type, "account_state");
            assert_eq!(details, "checksum mismatch");
        }
        _ => return Err("expected SnapshotError".to_string()),
    }

    match roundtrip(&async_runtime)? {
        ErrorDetection::AsyncRuntimeError { details } => {
            assert_eq!(details, "join handle failed");
        }
        _ => return Err("expected AsyncRuntimeError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_035_serde_tag_names_are_snake_case_vectors() -> TestResult {
    let validation = ErrorDetection::ValidationError {
        message: "bad input".to_string(),
        tx_id: None,
    };
    let not_found = ErrorDetection::NotFound {
        resource: "header".to_string(),
    };
    let rocks = ErrorDetection::RocksDbError {
        details: "open failed".to_string(),
    };

    assert!(to_json(&validation)?.contains("\"error_type\":\"validation_error\""));
    assert!(to_json(&not_found)?.contains("\"error_type\":\"not_found\""));
    assert!(to_json(&rocks)?.contains("\"error_type\":\"rocks_db_error\""));
    Ok(())
}

#[test]
fn error_detection_036_network_kind_json_uses_snake_case_vectors() -> TestResult {
    let dns = serde_json::to_string(&NetworkErrorKind::DnsResolution).map_err(|e| e.to_string())?;
    let refused =
        serde_json::to_string(&NetworkErrorKind::ConnectionRefused).map_err(|e| e.to_string())?;
    let timeout = serde_json::to_string(&NetworkErrorKind::Timeout).map_err(|e| e.to_string())?;

    assert_eq!(dns, "\"dns_resolution\"");
    assert_eq!(refused, "\"connection_refused\"");
    assert_eq!(timeout, "\"timeout\"");
    Ok(())
}

#[test]
fn error_detection_037_raw_os_error_returns_none_for_non_io_variants() -> TestResult {
    let errors = [
        ErrorDetection::ValidationError {
            message: "bad input".to_string(),
            tx_id: None,
        },
        ErrorDetection::NotFound {
            resource: "missing".to_string(),
        },
        ErrorDetection::UnknownError,
        ErrorDetection::WarningError {
            details: "warn".to_string(),
        },
    ];

    for error in errors {
        assert_eq!(error.raw_os_error(), None);
    }

    Ok(())
}

#[test]
fn error_detection_038_log_covers_specific_and_fallback_paths_without_panicking() -> TestResult {
    let errors = [
        ErrorDetection::IoError {
            message: "io".to_string(),
            code: Some(1),
            source: None,
        },
        ErrorDetection::ServiceUnavailableError {
            message: "down".to_string(),
            retry_after: Some(1),
        },
        ErrorDetection::RateLimitRetryError {
            message: "slow down".to_string(),
            retry_after: Some(2),
        },
        ErrorDetection::ValidationError {
            message: "bad".to_string(),
            tx_id: Some("tx".to_string()),
        },
        ErrorDetection::BatchProcessingError {
            batch_type: "tx".to_string(),
            details: "bad op".to_string(),
            operation_index: Some(0),
        },
        ErrorDetection::SnapshotError {
            snapshot_type: "state".to_string(),
            details: "bad root".to_string(),
        },
        ErrorDetection::CustomError {
            details: "custom".to_string(),
            context: Some("ctx".to_string()),
        },
        ErrorDetection::CriticalError {
            details: "critical".to_string(),
        },
        ErrorDetection::WarningError {
            details: "warning".to_string(),
        },
        ErrorDetection::UnknownError,
        ErrorDetection::SerdeJsonError {
            details: "serde".to_string(),
            source: None,
        },
        ErrorDetection::AsyncRuntimeError {
            details: "async".to_string(),
        },
        ErrorDetection::ProtocolError {
            message: "fallback branch".to_string(),
        },
    ];

    for error in errors {
        error.log();
    }

    let batch = ErrorDetection::BatchError {
        errors: vec![ErrorDetection::ValidationError {
            message: "child".to_string(),
            tx_id: None,
        }],
    };
    batch.log();

    Ok(())
}

#[test]
fn error_detection_039_adversarial_nested_batch_serde_preserves_deep_errors() -> TestResult {
    let nested = ErrorDetection::BatchError {
        errors: vec![
            ErrorDetection::BatchError {
                errors: vec![ErrorDetection::CustomError {
                    details: "inner custom".to_string(),
                    context: Some("inner context".to_string()),
                }],
            },
            ErrorDetection::NetworkError {
                message: "peer stalled".to_string(),
                kind: NetworkErrorKind::Other("slowloris".to_string()),
            },
        ],
    };

    let decoded = roundtrip(&nested)?;

    match decoded {
        ErrorDetection::BatchError { errors } => {
            assert_eq!(errors.len(), 2);

            match &errors[0] {
                ErrorDetection::BatchError { errors: inner } => {
                    assert_eq!(inner.len(), 1);
                    assert_eq!(inner[0].to_http_status_code(), 400);
                }
                _ => return Err("expected nested BatchError".to_string()),
            }

            match &errors[1] {
                ErrorDetection::NetworkError { message, kind } => {
                    assert_eq!(message, "peer stalled");
                    assert_eq!(kind, &NetworkErrorKind::Other("slowloris".to_string()));
                }
                _ => return Err("expected nested NetworkError".to_string()),
            }
        }
        _ => return Err("expected outer BatchError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_040_load_many_roundtrips_keep_status_codes_stable() -> TestResult {
    let errors = [
        ErrorDetection::ValidationError {
            message: "v".to_string(),
            tx_id: None,
        },
        ErrorDetection::PermissionDenied {
            message: "p".to_string(),
        },
        ErrorDetection::NotFound {
            resource: "n".to_string(),
        },
        ErrorDetection::RateLimitRetryError {
            message: "r".to_string(),
            retry_after: Some(1),
        },
        ErrorDetection::ServiceUnavailableError {
            message: "s".to_string(),
            retry_after: None,
        },
        ErrorDetection::WarningError {
            details: "w".to_string(),
        },
        ErrorDetection::ProtocolError {
            message: "fallback".to_string(),
        },
    ];

    for _ in 0..1_000 {
        for error in &errors {
            let before = error.to_http_status_code();
            let decoded = roundtrip(error)?;
            let after = decoded.to_http_status_code();

            assert_eq!(after, before);
        }
    }

    Ok(())
}

#[test]
fn error_detection_041_manual_validation_json_deserializes_with_null_tx_id() -> TestResult {
    let json =
        r#"{"error_type":"validation_error","details":{"message":"bad input","tx_id":null}}"#;
    let decoded = from_json(json)?;

    match decoded {
        ErrorDetection::ValidationError { message, tx_id } => {
            assert_eq!(message, "bad input");
            assert_eq!(tx_id, None);
        }
        _ => return Err("expected ValidationError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_042_custom_error_json_preserves_null_context() -> TestResult {
    let error = ErrorDetection::CustomError {
        details: "custom edge".to_string(),
        context: None,
    };

    let json = to_json(&error)?;
    assert!(json.contains("\"error_type\":\"custom_error\""));
    assert!(json.contains("\"context\":null"));

    match from_json(&json)? {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "custom edge");
            assert_eq!(context, None);
        }
        _ => return Err("expected CustomError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_043_rate_limit_retry_none_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::RateLimitRetryError {
        message: "retry later".to_string(),
        retry_after: None,
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::RateLimitRetryError {
            message,
            retry_after,
        } => {
            assert_eq!(message, "retry later");
            assert_eq!(retry_after, None);
        }
        _ => return Err("expected RateLimitRetryError".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 429);
    Ok(())
}

#[test]
fn error_detection_044_service_unavailable_some_retry_after_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::ServiceUnavailableError {
        message: "node draining".to_string(),
        retry_after: Some(120),
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::ServiceUnavailableError {
            message,
            retry_after,
        } => {
            assert_eq!(message, "node draining");
            assert_eq!(retry_after, Some(120));
        }
        _ => return Err("expected ServiceUnavailableError".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 503);
    Ok(())
}

#[test]
fn error_detection_045_timeout_error_none_operation_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::TimeoutError {
        message: "deadline exceeded".to_string(),
        operation: None,
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::TimeoutError { message, operation } => {
            assert_eq!(message, "deadline exceeded");
            assert_eq!(operation, None);
        }
        _ => return Err("expected TimeoutError".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 408);
    Ok(())
}

#[test]
fn error_detection_046_double_spending_none_tx_id_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::DoubleSpending { tx_id: None };
    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::DoubleSpending { tx_id } => {
            assert_eq!(tx_id, None);
        }
        _ => return Err("expected DoubleSpending".to_string()),
    }

    assert_display_contains(&error, "Double spending detected");
    Ok(())
}

#[test]
fn error_detection_047_timestamp_error_roundtrip_skips_source_to_none() -> TestResult {
    let error = ErrorDetection::TimestampError {
        message: "clock moved backward".to_string(),
        details: "system clock underflow".to_string(),
        source: None,
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::TimestampError {
            message,
            details,
            source,
        } => {
            assert_eq!(message, "clock moved backward");
            assert_eq!(details, "system clock underflow");
            assert!(source.is_none());
        }
        _ => return Err("expected TimestampError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_048_serde_json_error_roundtrip_skips_source_to_none() -> TestResult {
    let error = ErrorDetection::SerdeJsonError {
        details: "json parse failed".to_string(),
        source: None,
    };

    let decoded = roundtrip(&error)?;

    match decoded {
        ErrorDetection::SerdeJsonError { details, source } => {
            assert_eq!(details, "json parse failed");
            assert!(source.is_none());
        }
        _ => return Err("expected SerdeJsonError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_049_io_error_from_error_kind_has_no_raw_os_code_but_has_source() -> TestResult {
    let error: ErrorDetection = IoError::new(ErrorKind::PermissionDenied, "denied").into();

    assert_eq!(error.raw_os_error(), None);
    assert!(StdError::source(&error).is_some());

    match error {
        ErrorDetection::IoError {
            message,
            code,
            source,
        } => {
            assert_eq!(message, "denied");
            assert_eq!(code, None);
            assert!(source.is_some());
        }
        _ => return Err("expected IoError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_050_io_error_json_omits_source_field() -> TestResult {
    let error: ErrorDetection = IoError::new(ErrorKind::Other, "hidden source").into();
    let json = to_json(&error)?;

    assert!(json.contains("\"error_type\":\"io_error\""));
    assert!(json.contains("\"message\":\"hidden source\""));
    assert!(!json.contains("\"source\""));
    Ok(())
}

#[test]
fn error_detection_051_unknown_error_json_is_unit_tag_vector() -> TestResult {
    let error = ErrorDetection::UnknownError;
    let json_value: serde_json::Value =
        serde_json::from_str(&to_json(&error)?).map_err(|e| e.to_string())?;

    assert_eq!(json_value["error_type"], "unknown_error");
    assert!(json_value.get("details").is_none());
    Ok(())
}

#[test]
fn error_detection_052_network_kind_other_json_shape_preserves_payload() -> TestResult {
    let kind = NetworkErrorKind::Other("custom transport".to_string());
    let json = serde_json::to_string(&kind).map_err(|e| e.to_string())?;

    assert!(json.contains("other"));
    assert!(json.contains("custom transport"));
    assert_eq!(network_kind_roundtrip(&kind)?, kind);
    Ok(())
}

#[test]
fn error_detection_053_all_network_kinds_work_inside_network_error_roundtrip() -> TestResult {
    let kinds = [
        NetworkErrorKind::Transient,
        NetworkErrorKind::Permanent,
        NetworkErrorKind::DnsResolution,
        NetworkErrorKind::ConnectionRefused,
        NetworkErrorKind::Timeout,
        NetworkErrorKind::Other("custom".to_string()),
    ];

    for kind in kinds {
        let error = ErrorDetection::NetworkError {
            message: "network edge".to_string(),
            kind,
        };

        match roundtrip(&error)? {
            ErrorDetection::NetworkError { message, kind } => {
                assert_eq!(message, "network edge");
                assert!(!format!("{kind:?}").is_empty());
            }
            _ => return Err("expected NetworkError".to_string()),
        }
    }

    Ok(())
}

#[test]
fn error_detection_054_network_error_display_includes_debug_kind() -> TestResult {
    let error = ErrorDetection::NetworkError {
        message: "read timed out".to_string(),
        kind: NetworkErrorKind::Timeout,
    };

    assert_display_contains(&error, "Network error");
    assert_display_contains(&error, "read timed out");
    assert_display_contains(&error, "Timeout");
    Ok(())
}

#[test]
fn error_detection_055_permission_denied_roundtrip_preserves_message() -> TestResult {
    let error = ErrorDetection::PermissionDenied {
        message: "operator key required".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::PermissionDenied { message } => {
            assert_eq!(message, "operator key required");
        }
        _ => return Err("expected PermissionDenied".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 403);
    Ok(())
}

#[test]
fn error_detection_056_not_found_roundtrip_preserves_resource() -> TestResult {
    let error = ErrorDetection::NotFound {
        resource: "canonical tip".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::NotFound { resource } => {
            assert_eq!(resource, "canonical tip");
        }
        _ => return Err("expected NotFound".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 404);
    Ok(())
}

#[test]
fn error_detection_057_invalid_operation_display_and_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::InvalidOperation {
        operation: "rollback finalized block".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::InvalidOperation { operation } => {
            assert_eq!(operation, "rollback finalized block");
        }
        _ => return Err("expected InvalidOperation".to_string()),
    }

    assert_display_contains(&error, "Invalid operation");
    assert_eq!(error.to_http_status_code(), 500);
    Ok(())
}

#[test]
fn error_detection_058_rate_limit_error_without_retry_defaults_to_500() -> TestResult {
    let error = ErrorDetection::RateLimitError {
        message: "plain limiter tripped".to_string(),
    };

    assert_eq!(error.to_http_status_code(), 500);
    assert_display_contains(&error, "Rate limit exceeded");
    assert_display_contains(&error, "plain limiter tripped");
    Ok(())
}

#[test]
fn error_detection_059_broadcast_and_protocol_errors_roundtrip_as_500() -> TestResult {
    let broadcast = ErrorDetection::BroadcastError {
        details: "gossipsub publish failed".to_string(),
    };
    let protocol = ErrorDetection::ProtocolError {
        message: "invalid frame".to_string(),
    };

    assert_eq!(broadcast.to_http_status_code(), 500);
    assert_eq!(protocol.to_http_status_code(), 500);

    match roundtrip(&broadcast)? {
        ErrorDetection::BroadcastError { details } => {
            assert_eq!(details, "gossipsub publish failed");
        }
        _ => return Err("expected BroadcastError".to_string()),
    }

    match roundtrip(&protocol)? {
        ErrorDetection::ProtocolError { message } => {
            assert_eq!(message, "invalid frame");
        }
        _ => return Err("expected ProtocolError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_060_already_exists_roundtrip_preserves_message() -> TestResult {
    let error = ErrorDetection::AlreadyExists {
        message: "wallet already registered".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::AlreadyExists { message } => {
            assert_eq!(message, "wallet already registered");
        }
        _ => return Err("expected AlreadyExists".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_061_invalid_input_roundtrip_preserves_message() -> TestResult {
    let error = ErrorDetection::InvalidInput {
        message: "empty public key".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::InvalidInput { message } => {
            assert_eq!(message, "empty public key");
        }
        _ => return Err("expected InvalidInput".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_062_wallet_not_found_roundtrip_preserves_wallet_id() -> TestResult {
    let error = ErrorDetection::WalletNotFound {
        wallet_id: "rmissing000".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::WalletNotFound { wallet_id } => {
            assert_eq!(wallet_id, "rmissing000");
        }
        _ => return Err("expected WalletNotFound".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_063_invalid_number_format_roundtrip_preserves_format() -> TestResult {
    let error = ErrorDetection::InvalidNumberFormat {
        format: "1e999999".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::InvalidNumberFormat { format } => {
            assert_eq!(format, "1e999999");
        }
        _ => return Err("expected InvalidNumberFormat".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_064_tx_conflict_and_version_conflict_have_distinct_display_text() -> TestResult {
    let tx_conflict = ErrorDetection::TxConflict {
        key: "account:r1".to_string(),
    };
    let version_conflict = ErrorDetection::VersionConflict {
        key: "account:r1".to_string(),
    };

    assert_display_contains(&tx_conflict, "Transaction conflict");
    assert_display_contains(&version_conflict, "Version conflict");
    assert_ne!(tx_conflict.to_string(), version_conflict.to_string());
    Ok(())
}

#[test]
fn error_detection_065_batch_processing_error_none_index_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::BatchProcessingError {
        batch_type: "reward_batch".to_string(),
        details: "empty operation list".to_string(),
        operation_index: None,
    };

    match roundtrip(&error)? {
        ErrorDetection::BatchProcessingError {
            batch_type,
            details,
            operation_index,
        } => {
            assert_eq!(batch_type, "reward_batch");
            assert_eq!(details, "empty operation list");
            assert_eq!(operation_index, None);
        }
        _ => return Err("expected BatchProcessingError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_066_snapshot_error_preserves_empty_edge_fields() -> TestResult {
    let error = ErrorDetection::SnapshotError {
        snapshot_type: String::new(),
        details: String::new(),
    };

    match roundtrip(&error)? {
        ErrorDetection::SnapshotError {
            snapshot_type,
            details,
        } => {
            assert_eq!(snapshot_type, "");
            assert_eq!(details, "");
        }
        _ => return Err("expected SnapshotError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_067_custom_error_none_context_roundtrip_vector() -> TestResult {
    let error = ErrorDetection::CustomError {
        details: "boundary custom".to_string(),
        context: None,
    };

    match roundtrip(&error)? {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "boundary custom");
            assert_eq!(context, None);
        }
        _ => return Err("expected CustomError".to_string()),
    }

    assert_eq!(error.to_http_status_code(), 400);
    Ok(())
}

#[test]
fn error_detection_068_empty_batch_error_roundtrip_preserves_empty_vec() -> TestResult {
    let error = ErrorDetection::BatchError { errors: Vec::new() };

    match roundtrip(&error)? {
        ErrorDetection::BatchError { errors } => {
            assert!(errors.is_empty());
        }
        _ => return Err("expected BatchError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_069_batch_error_display_includes_child_error_debug_text() -> TestResult {
    let error = ErrorDetection::BatchError {
        errors: vec![
            ErrorDetection::UnknownError,
            ErrorDetection::WarningError {
                details: "child warning".to_string(),
            },
        ],
    };

    assert_display_contains(&error, "Batch error occurred");
    assert_display_contains(&error, "UnknownError");
    assert_display_contains(&error, "WarningError");
    Ok(())
}

#[test]
fn error_detection_070_known_http_status_mapping_table_vectors() -> TestResult {
    let cases = [
        (
            ErrorDetection::TimeoutError {
                message: "timeout".to_string(),
                operation: None,
            },
            408,
        ),
        (
            ErrorDetection::ValidationError {
                message: "validation".to_string(),
                tx_id: None,
            },
            400,
        ),
        (
            ErrorDetection::CustomError {
                details: "custom".to_string(),
                context: None,
            },
            400,
        ),
        (
            ErrorDetection::PermissionDenied {
                message: "denied".to_string(),
            },
            403,
        ),
        (
            ErrorDetection::InsufficientBalance {
                details: "low".to_string(),
            },
            402,
        ),
        (
            ErrorDetection::NotFound {
                resource: "missing".to_string(),
            },
            404,
        ),
        (
            ErrorDetection::VersionCompatibilityError {
                details: "version".to_string(),
            },
            409,
        ),
        (
            ErrorDetection::RateLimitRetryError {
                message: "retry".to_string(),
                retry_after: None,
            },
            429,
        ),
        (
            ErrorDetection::ServiceUnavailableError {
                message: "down".to_string(),
                retry_after: None,
            },
            503,
        ),
        (
            ErrorDetection::WarningError {
                details: "warning".to_string(),
            },
            200,
        ),
    ];

    for (error, expected_status) in cases {
        assert_eq!(error.to_http_status_code(), expected_status);
    }

    Ok(())
}

#[test]
fn error_detection_071_default_http_status_is_500_for_unmapped_representative_variants()
-> TestResult {
    let cases = [
        ErrorDetection::ConfigurationError {
            message: "bad config".to_string(),
        },
        ErrorDetection::ProtocolError {
            message: "bad protocol".to_string(),
        },
        ErrorDetection::DatabaseError {
            details: "db failed".to_string(),
        },
        ErrorDetection::CriticalError {
            details: "critical".to_string(),
        },
        ErrorDetection::AsyncRuntimeError {
            details: "async failed".to_string(),
        },
    ];

    for error in cases {
        assert_eq!(error.to_http_status_code(), 500);
    }

    Ok(())
}

#[test]
fn error_detection_072_serde_rejects_unknown_error_type() -> TestResult {
    let json = r#"{"error_type":"does_not_exist","details":{"message":"bad"}}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_073_serde_rejects_malformed_details_shape() -> TestResult {
    let json = r#"{"error_type":"validation_error","details":"not-an-object"}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_074_serde_rejects_unknown_network_kind_string() -> TestResult {
    let json = r#""not_a_real_network_kind""#;
    let decoded = serde_json::from_str::<NetworkErrorKind>(json);

    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn error_detection_075_manual_network_kind_other_json_deserializes() -> TestResult {
    let json = r#"{"other":"custom-network-kind"}"#;
    let decoded: NetworkErrorKind = serde_json::from_str(json).map_err(|e| e.to_string())?;

    assert_eq!(
        decoded,
        NetworkErrorKind::Other("custom-network-kind".to_string())
    );
    Ok(())
}

#[test]
fn error_detection_076_manual_network_error_with_other_kind_json_deserializes() -> TestResult {
    let json = r#"{"error_type":"network_error","details":{"message":"custom net","kind":{"other":"slowloris"}}}"#;
    let decoded = from_json(json)?;

    match decoded {
        ErrorDetection::NetworkError { message, kind } => {
            assert_eq!(message, "custom net");
            assert_eq!(kind, NetworkErrorKind::Other("slowloris".to_string()));
        }
        _ => return Err("expected NetworkError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_077_source_backed_variants_do_not_serialize_source_field() -> TestResult {
    let io_error: ErrorDetection = IoError::new(ErrorKind::Other, "io hidden").into();

    let timestamp_error = ErrorDetection::TimestampError {
        message: "time".to_string(),
        details: "details".to_string(),
        source: None,
    };

    let serde_error = ErrorDetection::SerdeJsonError {
        details: "serde hidden".to_string(),
        source: None,
    };

    for error in [io_error, timestamp_error, serde_error] {
        let json = to_json(&error)?;
        assert!(!json.contains("\"source\""));
    }

    Ok(())
}

#[test]
fn error_detection_078_log_empty_and_nested_batch_errors_without_panicking() -> TestResult {
    let empty_batch = ErrorDetection::BatchError { errors: Vec::new() };

    let nested_batch = ErrorDetection::BatchError {
        errors: vec![ErrorDetection::BatchError {
            errors: vec![ErrorDetection::CriticalError {
                details: "inner critical".to_string(),
            }],
        }],
    };

    empty_batch.log();
    nested_batch.log();
    Ok(())
}

#[test]
fn error_detection_079_load_roundtrip_serialization_for_representative_variants() -> TestResult {
    let errors = [
        ErrorDetection::WalletInitializationError {
            wallet: "rw".to_string(),
            details: "d".to_string(),
        },
        ErrorDetection::NetworkError {
            message: "m".to_string(),
            kind: NetworkErrorKind::Transient,
        },
        ErrorDetection::BatchProcessingError {
            batch_type: "b".to_string(),
            details: "d".to_string(),
            operation_index: Some(1),
        },
        ErrorDetection::SnapshotError {
            snapshot_type: "s".to_string(),
            details: "d".to_string(),
        },
        ErrorDetection::RocksDbError {
            details: "r".to_string(),
        },
    ];

    for _ in 0..1_000 {
        for error in &errors {
            let decoded = roundtrip(error)?;
            assert_eq!(decoded.to_http_status_code(), error.to_http_status_code());
            assert!(!decoded.to_string().is_empty());
        }
    }

    Ok(())
}

#[test]
fn error_detection_080_io_error_kind_vectors_convert_to_io_error_without_os_code() -> TestResult {
    let kinds = [
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::ConnectionRefused,
        ErrorKind::TimedOut,
        ErrorKind::InvalidInput,
        ErrorKind::Other,
    ];

    for kind in kinds {
        let error: ErrorDetection = IoError::new(kind, "kind vector").into();

        match error {
            ErrorDetection::IoError {
                message,
                code,
                source,
            } => {
                assert_eq!(message, "kind vector");
                assert_eq!(code, None);
                assert!(source.is_some());
            }
            _ => return Err("expected IoError".to_string()),
        }
    }

    Ok(())
}

#[test]
fn error_detection_081_generic_error_is_std_error_with_no_source() -> TestResult {
    let error = GenericError("generic source check".to_string());

    assert_eq!(error.to_string(), "generic source check");
    assert!(StdError::source(&error).is_none());
    Ok(())
}

#[test]
fn error_detection_082_non_source_variants_report_no_std_error_source() -> TestResult {
    let errors = [
        ErrorDetection::ValidationError {
            message: "bad input".to_string(),
            tx_id: None,
        },
        ErrorDetection::ProtocolError {
            message: "bad protocol".to_string(),
        },
        ErrorDetection::DatabaseError {
            details: "db failed".to_string(),
        },
        ErrorDetection::UnknownError,
    ];

    for error in errors {
        assert!(StdError::source(&error).is_none());
    }

    Ok(())
}

#[test]
fn error_detection_083_source_backed_variants_with_none_report_no_std_error_source() -> TestResult {
    let errors = [
        ErrorDetection::IoError {
            message: "io without source".to_string(),
            code: None,
            source: None,
        },
        ErrorDetection::TimestampError {
            message: "time without source".to_string(),
            details: "no source".to_string(),
            source: None,
        },
        ErrorDetection::SerdeJsonError {
            details: "serde without source".to_string(),
            source: None,
        },
    ];

    for error in errors {
        assert!(StdError::source(&error).is_none());
    }

    Ok(())
}

#[test]
fn error_detection_084_missing_required_details_field_is_rejected() -> TestResult {
    let json = r#"{"error_type":"validation_error"}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_085_missing_required_payload_field_is_rejected() -> TestResult {
    let json = r#"{"error_type":"not_found","details":{}}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_086_null_details_for_struct_variant_is_rejected() -> TestResult {
    let json = r#"{"error_type":"database_error","details":null}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_087_unknown_error_rejects_unexpected_details_payload() -> TestResult {
    let json = r#"{"error_type":"unknown_error","details":{"extra":"field"}}"#;

    assert!(from_json(json).is_err());
    Ok(())
}

#[test]
fn error_detection_088_storage_extension_tag_vectors_are_stable() -> TestResult {
    let rocks = ErrorDetection::RocksDbError {
        details: "rocks".to_string(),
    };
    let batch = ErrorDetection::BatchProcessingError {
        batch_type: "tx".to_string(),
        details: "bad".to_string(),
        operation_index: Some(1),
    };
    let snapshot = ErrorDetection::SnapshotError {
        snapshot_type: "state".to_string(),
        details: "root".to_string(),
    };
    let async_error = ErrorDetection::AsyncRuntimeError {
        details: "join".to_string(),
    };

    assert!(to_json(&rocks)?.contains("\"error_type\":\"rocks_db_error\""));
    assert!(to_json(&batch)?.contains("\"error_type\":\"batch_processing_error\""));
    assert!(to_json(&snapshot)?.contains("\"error_type\":\"snapshot_error\""));
    assert!(to_json(&async_error)?.contains("\"error_type\":\"async_runtime_error\""));
    Ok(())
}

#[test]
fn error_detection_089_security_error_tag_vectors_are_stable() -> TestResult {
    let invalid_signature = ErrorDetection::InvalidSignature {
        reason: "wrong key".to_string(),
    };
    let invalid_format = ErrorDetection::InvalidSignatureFormat {
        format: "short".to_string(),
    };
    let signature_failed = ErrorDetection::SignatureVerificationFailed {
        message: "verify failed".to_string(),
    };
    let crypto = ErrorDetection::CryptographicError {
        message: "hash failed".to_string(),
    };

    assert!(to_json(&invalid_signature)?.contains("\"error_type\":\"invalid_signature\""));
    assert!(to_json(&invalid_format)?.contains("\"error_type\":\"invalid_signature_format\""));
    assert!(
        to_json(&signature_failed)?.contains("\"error_type\":\"signature_verification_failed\"")
    );
    assert!(to_json(&crypto)?.contains("\"error_type\":\"cryptographic_error\""));
    Ok(())
}

#[test]
fn error_detection_090_tls_error_roundtrip_preserves_message_and_details() -> TestResult {
    let error = ErrorDetection::TlsError {
        message: "certificate rejected".to_string(),
        details: "expired root".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::TlsError { message, details } => {
            assert_eq!(message, "certificate rejected");
            assert_eq!(details, "expired root");
        }
        _ => return Err("expected TlsError".to_string()),
    }

    assert_display_contains(&error, "TLS error occurred");
    assert_display_contains(&error, "certificate rejected");
    Ok(())
}

#[test]
fn error_detection_091_long_payload_roundtrip_preserves_full_details() -> TestResult {
    let long_details = "x".repeat(8_192);
    let error = ErrorDetection::DatabaseError {
        details: long_details.clone(),
    };

    match roundtrip(&error)? {
        ErrorDetection::DatabaseError { details } => {
            assert_eq!(details.len(), 8_192);
            assert_eq!(details, long_details);
        }
        _ => return Err("expected DatabaseError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_092_unicode_payload_roundtrip_preserves_text() -> TestResult {
    let error = ErrorDetection::CustomError {
        details: "unicode diagnostic: 鎖 🔐 блок".to_string(),
        context: Some("ctx: 同步".to_string()),
    };

    match roundtrip(&error)? {
        ErrorDetection::CustomError { details, context } => {
            assert_eq!(details, "unicode diagnostic: 鎖 🔐 блок");
            assert_eq!(context, Some("ctx: 同步".to_string()));
        }
        _ => return Err("expected CustomError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_093_newline_payload_roundtrip_preserves_text() -> TestResult {
    let error = ErrorDetection::ExecutionError {
        details: "line one\nline two\nline three".to_string(),
    };

    match roundtrip(&error)? {
        ErrorDetection::ExecutionError { details } => {
            assert_eq!(details, "line one\nline two\nline three");
        }
        _ => return Err("expected ExecutionError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_094_batch_error_roundtrip_preserves_child_order() -> TestResult {
    let error = ErrorDetection::BatchError {
        errors: vec![
            ErrorDetection::NotFound {
                resource: "first".to_string(),
            },
            ErrorDetection::PermissionDenied {
                message: "second".to_string(),
            },
            ErrorDetection::WarningError {
                details: "third".to_string(),
            },
        ],
    };

    match roundtrip(&error)? {
        ErrorDetection::BatchError { errors } => {
            assert_eq!(errors.len(), 3);
            assert!(matches!(
                errors.first(),
                Some(ErrorDetection::NotFound { .. })
            ));
            assert!(matches!(
                errors.get(1),
                Some(ErrorDetection::PermissionDenied { .. })
            ));
            assert!(matches!(
                errors.get(2),
                Some(ErrorDetection::WarningError { .. })
            ));
        }
        _ => return Err("expected BatchError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_095_all_network_kind_json_vectors_are_exact() -> TestResult {
    let cases = [
        (NetworkErrorKind::Transient, "\"transient\""),
        (NetworkErrorKind::Permanent, "\"permanent\""),
        (NetworkErrorKind::DnsResolution, "\"dns_resolution\""),
        (
            NetworkErrorKind::ConnectionRefused,
            "\"connection_refused\"",
        ),
        (NetworkErrorKind::Timeout, "\"timeout\""),
    ];

    for (kind, expected_json) in cases {
        let json = serde_json::to_string(&kind).map_err(|e| e.to_string())?;
        assert_eq!(json, expected_json);
    }

    Ok(())
}

#[test]
fn error_detection_096_http_status_codes_are_valid_http_range_for_representative_variants()
-> TestResult {
    let errors = [
        ErrorDetection::TimeoutError {
            message: "timeout".to_string(),
            operation: None,
        },
        ErrorDetection::ValidationError {
            message: "validation".to_string(),
            tx_id: None,
        },
        ErrorDetection::PermissionDenied {
            message: "denied".to_string(),
        },
        ErrorDetection::InsufficientBalance {
            details: "low".to_string(),
        },
        ErrorDetection::NotFound {
            resource: "missing".to_string(),
        },
        ErrorDetection::VersionCompatibilityError {
            details: "version".to_string(),
        },
        ErrorDetection::RateLimitRetryError {
            message: "retry".to_string(),
            retry_after: None,
        },
        ErrorDetection::ServiceUnavailableError {
            message: "down".to_string(),
            retry_after: None,
        },
        ErrorDetection::WarningError {
            details: "warning".to_string(),
        },
        ErrorDetection::UnknownError,
    ];

    for error in errors {
        let status = error.to_http_status_code();
        assert!((100..=599).contains(&status));
    }

    Ok(())
}

#[test]
fn error_detection_097_empty_string_payloads_do_not_break_display_or_serde() -> TestResult {
    let errors = [
        ErrorDetection::ConfigurationError {
            message: String::new(),
        },
        ErrorDetection::StorageError {
            message: String::new(),
        },
        ErrorDetection::SerializationError {
            details: String::new(),
        },
        ErrorDetection::CriticalError {
            details: String::new(),
        },
    ];

    for error in errors {
        let decoded = roundtrip(&error)?;
        assert!(!decoded.to_string().is_empty());
    }

    Ok(())
}

#[test]
fn error_detection_098_serde_json_error_details_survive_manual_roundtrip() -> TestResult {
    let json = r#"{"error_type":"serde_json_error","details":{"details":"expected value at line 1 column 1"}}"#;
    let decoded = from_json(json)?;

    match decoded {
        ErrorDetection::SerdeJsonError { details, source } => {
            assert_eq!(details, "expected value at line 1 column 1");
            assert!(source.is_none());
        }
        _ => return Err("expected SerdeJsonError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_099_io_error_manual_json_deserializes_with_no_source() -> TestResult {
    let json = r#"{"error_type":"io_error","details":{"message":"manual io","code":5}}"#;
    let decoded = from_json(json)?;

    match decoded {
        ErrorDetection::IoError {
            message,
            code,
            source,
        } => {
            assert_eq!(message, "manual io");
            assert_eq!(code, Some(5));
            assert!(source.is_none());
        }
        _ => return Err("expected IoError".to_string()),
    }

    Ok(())
}

#[test]
fn error_detection_100_load_all_http_mapped_variants_repeatedly_without_status_drift() -> TestResult
{
    let errors = [
        (
            ErrorDetection::TimeoutError {
                message: "timeout".to_string(),
                operation: None,
            },
            408,
        ),
        (
            ErrorDetection::ValidationError {
                message: "validation".to_string(),
                tx_id: Some("tx".to_string()),
            },
            400,
        ),
        (
            ErrorDetection::CustomError {
                details: "custom".to_string(),
                context: Some("ctx".to_string()),
            },
            400,
        ),
        (
            ErrorDetection::PermissionDenied {
                message: "denied".to_string(),
            },
            403,
        ),
        (
            ErrorDetection::InsufficientBalance {
                details: "low".to_string(),
            },
            402,
        ),
        (
            ErrorDetection::NotFound {
                resource: "missing".to_string(),
            },
            404,
        ),
        (
            ErrorDetection::VersionCompatibilityError {
                details: "version".to_string(),
            },
            409,
        ),
        (
            ErrorDetection::RateLimitRetryError {
                message: "retry".to_string(),
                retry_after: Some(1),
            },
            429,
        ),
        (
            ErrorDetection::ServiceUnavailableError {
                message: "down".to_string(),
                retry_after: Some(1),
            },
            503,
        ),
        (
            ErrorDetection::WarningError {
                details: "warn".to_string(),
            },
            200,
        ),
    ];

    for _ in 0..2_000 {
        for (error, expected_status) in &errors {
            assert_eq!(error.to_http_status_code(), *expected_status);
        }
    }

    Ok(())
}
