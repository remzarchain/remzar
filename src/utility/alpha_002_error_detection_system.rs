//! # ErrorDetection — Unified Error Handling for the Remzar Blockchain

use anyhow::Error as AnyhowErr;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::time::SystemTimeError;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
pub struct GenericError(pub String);

/// Represents different categories of network errors.

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkErrorKind {
    /// A transient network failure.
    Transient,
    /// A permanent network failure.
    Permanent,
    /// DNS resolution failure.
    DnsResolution,
    /// Connection refused.
    ConnectionRefused,
    /// Timeout during network operation.
    Timeout,
    /// Any other network-related error not covered above.
    Other(String),
}

#[derive(Debug, Error, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "error_type", content = "details", rename_all = "snake_case")]
pub enum ErrorDetection {
    // ─────────────────────────────────────────────────────────────────────────────
    // Wallet & Initialization Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// A wallet initialization error occurred.
    #[error("Wallet initialization error for '{wallet}': {details}")]
    WalletInitializationError { wallet: String, details: String },

    /// An error occurred during database initialization.
    #[error("Initialization error: {message}")]
    InitializationError { message: String },

    // ─────────────────────────────────────────────────────────────────────────────
    // I/O & System-level Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// An I/O error occurred (file, disk, network I/O, etc.).
    #[error("I/O error occurred: {message} (code: {code:?})")]
    IoError {
        message: String,
        code: Option<i32>,
        /// The underlying I/O error.
        #[source]
        #[serde(skip)]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    /// A configuration error occurred.
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },

    /// A concurrency-related error occurred (e.g., lock contention).
    #[error("Concurrency error: {message}")]
    ConcurrencyError { message: String },

    /// A validation error occurred, e.g., invalid input or parameters.
    #[error("Validation error: {message}, Transaction ID: {tx_id:?}")]
    ValidationError {
        message: String,
        tx_id: Option<String>,
    },

    /// A timeout error occurred during a particular operation.
    #[error("Timeout error during {operation:?}: {message}")]
    TimeoutError {
        message: String,
        operation: Option<String>,
    },

    /// A transaction error occurred, possibly related to the blockchain or database.
    #[error("Transaction error: {message}, Transaction ID: {tx_id:?}")]
    TransactionError {
        message: String,
        tx_id: Option<String>,
    },

    /// Double spending detected for a particular transaction ID.
    #[error("Double spending detected for Transaction ID: {tx_id:?}")]
    DoubleSpending { tx_id: Option<String> },

    /// A stack underflow error occurred.
    #[error("Stack underflow error occurred")]
    StackUnderflow,

    /// A permission denied error occurred.
    #[error("Permission denied: {message}")]
    PermissionDenied { message: String },

    /// The requested resource was not found.
    #[error("Resource not found: {resource}")]
    NotFound { resource: String },

    /// An invalid operation was requested.
    #[error("Invalid operation: {operation}")]
    InvalidOperation { operation: String },

    /// A timestamp-related error occurred.
    #[error("Timestamp error: {message}")]
    TimestampError {
        message: String,
        details: String,
        /// The underlying system time error.
        #[source]
        #[serde(skip)]
        source: Option<SystemTimeError>,
    },

    /// A Serde JSON serialization/deserialization error.
    #[error("Serde JSON error occurred: {details}")]
    SerdeJsonError {
        details: String,
        /// The underlying serde_json error.
        #[source]
        #[serde(skip)]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },

    // ─────────────────────────────────────────────────────────────────────────────
    // Cryptographic & Security Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// Error encountered while generating a Merkle proof.
    #[error("Merkle Proof generation failed: {reason}")]
    MerkleProofGenerationError { reason: String },

    /// A cryptographic error occurred.
    #[error("Cryptographic error: {message}")]
    CryptographicError { message: String },

    /// A TLS-related error occurred.
    #[error("TLS error occurred: {message}")]
    TlsError { message: String, details: String },

    /// A signature verification failure occurred.
    #[error("Signature verification failed: {message}")]
    SignatureVerificationFailed { message: String },

    /// An encryption error occurred.
    #[error("Encryption error: {message}")]
    EncryptionError { message: String },

    /// A compression error occurred.
    #[error("Compression error: {message}")]
    CompressionError { message: String },

    /// An invalid signature error occurred.
    #[error("Invalid signature error: {reason}")]
    InvalidSignature { reason: String },

    /// A decryption error occurred.
    #[error("Decryption error: {message}")]
    DecryptionError { message: String },

    /// An invalid signature format error occurred.
    #[error("Invalid signature format: {format}")]
    InvalidSignatureFormat { format: String },

    /// A backup operation failed.
    #[error("Backup failed: {message}")]
    BackupFailed { message: String },

    // ─────────────────────────────────────────────────────────────────────────────
    // Networking & Protocol Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// Failed to broadcast a transaction over the P2P network.
    #[error("Broadcast error: {details}")]
    BroadcastError { details: String },

    /// A protocol-related error occurred.
    #[error("Protocol error: {message}")]
    ProtocolError { message: String },

    /// A network error occurred.
    #[error("Network error: {message}, Kind: {kind:?}")]
    NetworkError {
        message: String,
        kind: NetworkErrorKind,
    },

    /// A rate-limiting error occurred.
    #[error("Rate limit exceeded: {message}")]
    RateLimitError { message: String },

    /// A rate-limit retry error occurred.
    #[error("Rate-limited: {message}, Retry-After: {retry_after:?} seconds")]
    RateLimitRetryError {
        message: String,
        retry_after: Option<u64>,
    },

    /// The service is unavailable.
    #[error("Service unavailable: {message}, Retry-After: {retry_after:?} seconds")]
    ServiceUnavailableError {
        message: String,
        retry_after: Option<u64>,
    },

    // ─────────────────────────────────────────────────────────────────────────────
    // Data & Storage Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// Indicates that an entity or resource already exists.
    #[error("Resource already exists: {message}")]
    AlreadyExists { message: String },

    /// An input validation error occurred.
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    /// A wallet was not found by the given identifier.
    #[error("Wallet not found: {wallet_id}")]
    WalletNotFound { wallet_id: String },

    /// A storage-related error occurred.
    #[error("Storage error: {message}")]
    StorageError { message: String },

    /// Bincode serialization/deserialization error.
    #[error("Bincode error occurred: {details}")]
    BincodeError { details: String },

    /// A ParityDb error occurred.
    #[error("ParityDb error occurred: {details}")]
    ParityDbError { details: String },

    /// A Snap compression/decompression error occurred.
    #[error("Snap error occurred: {details}")]
    SnapError { details: String },

    /// A database-related error.
    #[error("Database error: {details}")]
    DatabaseError { details: String },

    /// A serialization error occurred.
    #[error("Serialization error: {details}")]
    SerializationError { details: String },

    /// Invalid number format encountered.
    #[error("Invalid number format: {format}")]
    InvalidNumberFormat { format: String },

    /// A blockchain-related error occurred.
    #[error("Blockchain error: {details}")]
    BlockchainError { details: String },

    /// A Zstd compression/decompression error occurred.
    #[error("Zstd error occurred: {details}")]
    ZstdError { details: String },

    /// A transaction conflict occurred due to version mismatch for a specific key.
    #[error("Transaction conflict: version mismatch for key: {key}")]
    TxConflict { key: String },

    /// A replication error occurred.
    #[error("Replication error occurred: {details}")]
    ReplicationError { details: String },

    /// A generic database-related error occurred.
    #[error("Generic database error: {details}")]
    GenericDbError { details: String },

    /// Unauthorized access error occurred.
    #[error("Unauthorized access: {message}")]
    Unauthorized { message: String },

    /// A transaction conflict occurred due to version mismatch for a specific key.
    #[error("Version conflict: version mismatch for key: {key}")]
    VersionConflict { key: String },

    /// Capacity error, such as exceeding the storage or memory limit.
    #[error("Capacity error: {message}")]
    CapacityError { message: String },

    // ─────────────────────────────────────────────────────────────────────────────
    // Operational Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// Insufficient balance for a transaction or operation.
    #[error("Insufficient balance: {details}")]
    InsufficientBalance { details: String },

    /// A version compatibility error occurred.
    #[error("Version compatibility error: {details}")]
    VersionCompatibilityError { details: String },

    /// An anomaly detection error occurred.
    #[error("Anomaly detection error: {details}")]
    AnomalyDetectionError { details: String },

    /// An execution error occurred.
    #[error("Execution error: {details}")]
    ExecutionError { details: String },

    /// A lock-related error occurred.
    #[error("Lock error: {details}")]
    LockError { details: String },

    /// A warning-level error that does not necessarily require failure.
    #[error("Warning: {details}")]
    WarningError { details: String },

    /// A critical error that might require urgent attention.
    #[error("Critical error: {details}")]
    CriticalError { details: String },

    /// Multiple errors occurred in a batch operation.
    #[error("Batch error occurred with the following errors: {errors:?}")]
    BatchError { errors: Vec<ErrorDetection> },

    /// A custom error with additional context.
    #[error("Custom error: {details}, context: {context:?}")]
    CustomError {
        details: String,
        context: Option<String>,
    },

    /// An unknown or fallback error type.
    #[error("Unknown error occurred")]
    UnknownError,

    // ─────────────────────────────────────────────────────────────────────────────
    // Data & Storage Extensions
    // ─────────────────────────────────────────────────────────────────────────────
    /// A RocksDB error occurred.
    #[error("RocksDB error: {details}")]
    RocksDbError { details: String },

    // ─────────────────────────────────────────────────────────────────────────────
    // Batch and Snapshot Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// A batch processing error occurred with additional context.
    #[error(
        "Batch processing error in {batch_type}: {details} at operation index: {operation_index:?}"
    )]
    BatchProcessingError {
        batch_type: String,
        details: String,
        operation_index: Option<usize>,
    },

    /// A snapshot error occurred for the specified entity (e.g., transactions, blocks).
    #[error("Snapshot error for {snapshot_type}: {details}")]
    SnapshotError {
        snapshot_type: String,
        details: String,
    },

    // ─────────────────────────────────────────────────────────────────────────────
    // Extended Operational Errors
    // ─────────────────────────────────────────────────────────────────────────────
    /// An asynchronous runtime error occurred.
    #[error("Asynchronous runtime error: {details}")]
    AsyncRuntimeError { details: String },
}

impl ErrorDetection {
    /// Returns the raw OS error code if available (primarily for I/O errors).
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            ErrorDetection::IoError { code, .. } => *code,
            _ => None,
        }
    }

    /// Logs the error details using `tracing`.
    /// **Note:** Ensure that logged messages are sanitized.
    pub fn log(&self) {
        match self {
            ErrorDetection::IoError { message, code, .. } => {
                tracing::error!(%message, ?code, "I/O error occurred");
            }
            ErrorDetection::ServiceUnavailableError {
                message,
                retry_after,
            } => {
                tracing::error!(%message, ?retry_after, "Service unavailable error occurred");
            }
            ErrorDetection::RateLimitRetryError {
                message,
                retry_after,
            } => {
                tracing::warn!(%message, ?retry_after, "Rate limit exceeded");
            }
            ErrorDetection::ValidationError { message, tx_id } => {
                tracing::warn!(%message, ?tx_id, "Validation error occurred");
            }
            ErrorDetection::BatchError { errors } => {
                for (index, error) in errors.iter().enumerate() {
                    tracing::error!(?error, index, "Batch error occurred");
                }
            }
            ErrorDetection::BatchProcessingError {
                batch_type,
                details,
                operation_index,
            } => {
                tracing::error!(batch_type, %details, ?operation_index, "Batch processing error occurred");
            }
            ErrorDetection::SnapshotError {
                snapshot_type,
                details,
            } => {
                tracing::error!(snapshot_type, %details, "Snapshot error occurred");
            }
            ErrorDetection::CustomError { details, context } => {
                tracing::error!(%details, ?context, "Custom error occurred");
            }
            ErrorDetection::CriticalError { details } => {
                tracing::error!(%details, "Critical error occurred");
            }
            ErrorDetection::WarningError { details } => {
                tracing::warn!(%details, "Warning: potential issue detected");
            }
            ErrorDetection::UnknownError => {
                tracing::error!("Unknown error occurred");
            }
            ErrorDetection::SerdeJsonError { details, .. } => {
                tracing::error!(%details, "Serde JSON error occurred");
            }
            ErrorDetection::AsyncRuntimeError { details } => {
                tracing::error!(%details, "Asynchronous runtime error occurred");
            }
            _ => {
                tracing::error!(error = ?self, "Unhandled error occurred");
            }
        }
    }

    /// Maps this error to an appropriate HTTP status code.
    pub fn to_http_status_code(&self) -> u16 {
        match self {
            ErrorDetection::TimeoutError { .. } => 408,
            ErrorDetection::ValidationError { .. } | ErrorDetection::CustomError { .. } => 400,
            ErrorDetection::PermissionDenied { .. } => 403,
            ErrorDetection::InsufficientBalance { .. } => 402, // Payment required use case.
            ErrorDetection::NotFound { .. } => 404,
            ErrorDetection::VersionCompatibilityError { .. } => 409,
            ErrorDetection::RateLimitRetryError { .. } => 429,
            ErrorDetection::ServiceUnavailableError { .. } => 503,
            ErrorDetection::WarningError { .. } => 200,

            _ => 500,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// From Implementations
// ─────────────────────────────────────────────────────────────────────────────

impl From<std::io::Error> for ErrorDetection {
    fn from(err: std::io::Error) -> Self {
        ErrorDetection::IoError {
            message: err.to_string(),
            code: err.raw_os_error(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<SystemTimeError> for ErrorDetection {
    fn from(err: SystemTimeError) -> Self {
        ErrorDetection::TimestampError {
            message: "Timestamp error occurred".to_string(),
            details: err.to_string(),
            source: Some(err),
        }
    }
}

impl From<serde_json::Error> for ErrorDetection {
    fn from(err: serde_json::Error) -> Self {
        ErrorDetection::SerdeJsonError {
            details: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<Infallible> for ErrorDetection {
    fn from(_: Infallible) -> Self {
        // This branch is literally unreachable
        ErrorDetection::UnknownError
    }
}

impl From<AnyhowErr> for ErrorDetection {
    fn from(e: AnyhowErr) -> Self {
        ErrorDetection::ProtocolError {
            message: e.to_string(),
        }
    }
}

// From String
impl From<String> for ErrorDetection {
    fn from(e: String) -> Self {
        ErrorDetection::CustomError {
            details: e,
            context: None,
        }
    }
}

// From &str (optional, for ergonomics)
impl From<&str> for ErrorDetection {
    fn from(e: &str) -> Self {
        ErrorDetection::CustomError {
            details: e.to_owned(),
            context: None,
        }
    }
}

// From Box<dyn std::error::Error>
impl From<Box<dyn std::error::Error>> for ErrorDetection {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        ErrorDetection::CustomError {
            details: e.to_string(),
            context: Some("Box<dyn Error>".to_string()),
        }
    }
}

pub async fn wait_for_shutdown_signal() -> Result<(), ErrorDetection> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).map_err(ErrorDetection::from)?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                // ctrl_c future completed
            }
            _ = term.recv() => {
                // SIGTERM received
            }
        }

        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(ErrorDetection::from)?;
        Ok(())
    }
}
