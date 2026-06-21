//! src/privacy/privacy_002_private_receive_invoice.rs

use crate::privacy::privacy_001_private_receive_wallet::{
    MAX_PRIVATE_RECEIVE_INVOICE_LEN, PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION,
    PrivateRW, PrivateReceiveWalletReceipt, PrivateReceiveWalletRecord,
};
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Human-readable type marker for JSON/export/debug contexts.
pub const PRIVATE_RECEIVE_INVOICE_KIND: &str = "remzar_private_receive_invoice";

/// Hard cap for user-facing label/note fields if later used by CLI/QR displays.
pub const MAX_PRIVATE_RECEIVE_LABEL_LEN: usize = 96;

/// Hard cap for optional caller-provided context.
pub const MAX_PRIVATE_RECEIVE_CONTEXT_LEN: usize = 256;

/// A validated private receive invoice.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReceiveInvoice {
    pub kind: String,
    pub version: u16,
    pub one_time_wallet: String,
    pub invoice: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Result of parsing sender input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReceiveInvoiceParseResult {
    pub source: PrivateReceiveInvoiceSource,
    pub one_time_wallet: String,
    pub canonical_invoice: String,
}

/// How the recipient target was supplied.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrivateReceiveInvoiceSource {
    Invoice,
    RawOneTimeWallet,
}

/// Request for building a user-facing invoice object.
#[derive(Debug, Clone)]
pub struct PrivateReceiveInvoiceBuildRequest<'a> {
    pub one_time_wallet: &'a str,
    pub label: Option<&'a str>,
    pub context: Option<&'a str>,
}

/// Owned version for CLI/UI workflows.
#[derive(Debug, Clone)]
pub struct PrivateReceiveInvoiceBuildOwnedRequest {
    pub one_time_wallet: String,
    pub label: Option<String>,
    pub context: Option<String>,
}

/// Public API facade.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrivateRI;

impl PrivateRI {
    // ─────────────────────────────────────────────────────────────────────
    // Constructors
    // ─────────────────────────────────────────────────────────────────────

    pub fn new() -> Self {
        Self
    }

    /// Build a validated private receive invoice object from a one-time wallet.
    pub fn build(
        &self,
        request: PrivateReceiveInvoiceBuildRequest<'_>,
    ) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        Self::maybe_fault("PRIVATE_RI_BUILD_PRE")?;

        let one_time_wallet = Self::canonical_wallet(request.one_time_wallet)?;
        let invoice = PrivateRW::make_invoice(&one_time_wallet)?;

        let label = match request.label {
            Some(v) => Some(Self::validate_optional_label(v)?),
            None => None,
        };

        let context = match request.context {
            Some(v) => Some(Self::validate_optional_context(v)?),
            None => None,
        };

        let out = PrivateReceiveInvoice {
            kind: PRIVATE_RECEIVE_INVOICE_KIND.to_string(),
            version: PRIVATE_RECEIVE_VERSION,
            one_time_wallet,
            invoice,
            label,
            context,
        };

        Self::validate_invoice_object(&out)?;

        Self::maybe_fault("PRIVATE_RI_BUILD_POST")?;
        Ok(out)
    }

    /// Build using owned request values.
    pub fn build_owned(
        &self,
        request: PrivateReceiveInvoiceBuildOwnedRequest,
    ) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        self.build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &request.one_time_wallet,
            label: request.label.as_deref(),
            context: request.context.as_deref(),
        })
    }

    /// Build directly from the receipt returned by `PrivateRW`.
    pub fn from_wallet_receipt(
        &self,
        receipt: &PrivateReceiveWalletReceipt,
    ) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        PrivateRW::validate_receipt(receipt)?;

        let out = self.build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &receipt.one_time_wallet,
            label: None,
            context: Some("created_from_private_receive_wallet_receipt"),
        })?;

        if out.invoice != receipt.invoice {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice mismatch between receipt and invoice builder"
                    .into(),
                tx_id: None,
            });
        }

        Ok(out)
    }

    /// Build directly from a local private receive record.
    pub fn from_wallet_record(
        &self,
        record: &PrivateReceiveWalletRecord,
    ) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        PrivateRW::validate_record(record)?;

        let out = self.build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &record.one_time_wallet,
            label: None,
            context: Some("created_from_private_receive_wallet_record"),
        })?;

        if out.invoice != record.invoice {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice mismatch between record and invoice builder"
                    .into(),
                tx_id: None,
            });
        }

        Ok(out)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Canonical string helpers
    // ─────────────────────────────────────────────────────────────────────

    /// Return the canonical invoice string for a one-time wallet.
    pub fn encode(one_time_wallet: &str) -> Result<String, ErrorDetection> {
        let one_time_wallet = Self::canonical_wallet(one_time_wallet)?;
        PrivateRW::make_invoice(&one_time_wallet)
    }

    /// Parse only a full invoice.
    pub fn parse_invoice_only(input: &str) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        let s = Self::normalize_input(input)?;

        if !Self::looks_like_private_receive_invoice(s) {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Expected private receive invoice '{}:v{}:<wallet>'",
                    PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
                ),
                tx_id: None,
            });
        }

        let one_time_wallet = Self::parse_invoice_to_wallet_strict(s)?;
        PrivateRI::new().build(PrivateReceiveInvoiceBuildRequest {
            one_time_wallet: &one_time_wallet,
            label: None,
            context: None,
        })
    }

    /// Parse either a full private receive invoice or a raw one-time wallet address.
    pub fn parse_invoice_or_address(
        input: &str,
    ) -> Result<PrivateReceiveInvoiceParseResult, ErrorDetection> {
        let s = Self::normalize_input(input)?;

        let source = if Self::looks_like_private_receive_invoice(s) {
            PrivateReceiveInvoiceSource::Invoice
        } else {
            PrivateReceiveInvoiceSource::RawOneTimeWallet
        };

        let one_time_wallet = match source {
            PrivateReceiveInvoiceSource::Invoice => Self::parse_invoice_to_wallet_strict(s)?,
            PrivateReceiveInvoiceSource::RawOneTimeWallet => {
                if s.contains(':') {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Invalid private receive target. Expected '{}:v{}:<wallet>' or raw one-time wallet address",
                            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
                        ),
                        tx_id: None,
                    });
                }

                Self::canonical_wallet(s)?
            }
        };

        let canonical_invoice = PrivateRW::make_invoice(&one_time_wallet)?;

        Ok(PrivateReceiveInvoiceParseResult {
            source,
            one_time_wallet,
            canonical_invoice,
        })
    }

    /// Parse either a full invoice or a raw one-time wallet address and return only the wallet.
    pub fn recipient_wallet_from_input(input: &str) -> Result<String, ErrorDetection> {
        Ok(Self::parse_invoice_or_address(input)?.one_time_wallet)
    }

    /// True if the string has the exact private receive invoice prefix/version shape.
    pub fn looks_like_private_receive_invoice(input: &str) -> bool {
        let s = input.trim();
        s.starts_with(&format!(
            "{}:v{}:",
            PRIVATE_RECEIVE_INVOICE_PREFIX, PRIVATE_RECEIVE_VERSION
        ))
    }

    /// Return a QR-safe string.
    pub fn qr_payload(invoice: &PrivateReceiveInvoice) -> Result<String, ErrorDetection> {
        Self::validate_invoice_object(invoice)?;
        Ok(invoice.invoice.clone())
    }

    /// Return a short display preview that does not dump the full 129-char wallet.
    pub fn display_preview(invoice_or_address: &str) -> Result<String, ErrorDetection> {
        let parsed = Self::parse_invoice_or_address(invoice_or_address)?;
        Ok(format!(
            "{}:v{}:{}",
            PRIVATE_RECEIVE_INVOICE_PREFIX,
            PRIVATE_RECEIVE_VERSION,
            Self::short_wallet(&parsed.one_time_wallet)?
        ))
    }

    /// Return short wallet display form:
    pub fn short_wallet(wallet: &str) -> Result<String, ErrorDetection> {
        let wallet = Self::canonical_wallet(wallet)?;

        if wallet.len() < 18 {
            return Err(ErrorDetection::ValidationError {
                message: "Wallet address too short for display preview".into(),
                tx_id: None,
            });
        }

        let start = wallet
            .get(..9)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Failed to read wallet display prefix".into(),
                tx_id: None,
            })?;

        let end = wallet
            .get(wallet.len().saturating_sub(8)..)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Failed to read wallet display suffix".into(),
                tx_id: None,
            })?;

        Ok(format!("{start}...{end}"))
    }

    /// Serialize invoice object as pretty JSON for local debug/export.
    pub fn to_pretty_json(invoice: &PrivateReceiveInvoice) -> Result<String, ErrorDetection> {
        Self::validate_invoice_object(invoice)?;

        serde_json::to_string_pretty(invoice).map_err(|e| ErrorDetection::SerializationError {
            details: format!("Failed to serialize private receive invoice JSON: {e}"),
        })
    }

    /// Decode invoice object from JSON and validate it.
    pub fn from_json(json: &str) -> Result<PrivateReceiveInvoice, ErrorDetection> {
        let s = json.trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice JSON cannot be empty".into(),
                tx_id: None,
            });
        }

        if s.len() > 4096 {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice JSON is too large".into(),
                tx_id: None,
            });
        }

        let invoice: PrivateReceiveInvoice =
            serde_json::from_str(s).map_err(|e| ErrorDetection::SerializationError {
                details: format!("Failed to parse private receive invoice JSON: {e}"),
            })?;

        Self::validate_invoice_object(&invoice)?;
        Ok(invoice)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Validation
    // ─────────────────────────────────────────────────────────────────────

    pub fn validate_invoice_object(invoice: &PrivateReceiveInvoice) -> Result<(), ErrorDetection> {
        if invoice.kind != PRIVATE_RECEIVE_INVOICE_KIND {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid private receive invoice kind '{}'; expected '{}'",
                    invoice.kind, PRIVATE_RECEIVE_INVOICE_KIND
                ),
                tx_id: None,
            });
        }

        if invoice.version != PRIVATE_RECEIVE_VERSION {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid private receive invoice version {}; expected {}",
                    invoice.version, PRIVATE_RECEIVE_VERSION
                ),
                tx_id: None,
            });
        }

        let one_time_wallet = Self::canonical_wallet(&invoice.one_time_wallet)?;
        let parsed_wallet = Self::parse_invoice_to_wallet_strict(&invoice.invoice)?;

        if parsed_wallet != one_time_wallet {
            return Err(ErrorDetection::ValidationError {
                message:
                    "Private receive invoice object mismatch: invoice wallet != one_time_wallet"
                        .into(),
                tx_id: None,
            });
        }

        let canonical_invoice = PrivateRW::make_invoice(&one_time_wallet)?;
        if invoice.invoice != canonical_invoice {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice object is not canonical".into(),
                tx_id: None,
            });
        }

        if let Some(label) = invoice.label.as_deref() {
            Self::validate_optional_label(label)?;
        }

        if let Some(context) = invoice.context.as_deref() {
            Self::validate_optional_context(context)?;
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────

    #[inline]
    fn maybe_fault(op: &'static str) -> Result<(), ErrorDetection> {
        if std::env::var_os(format!("REMZAR_FAIL_{op}")).is_some() {
            return Err(ErrorDetection::CryptographicError {
                message: format!("Fault injection triggered at operation: {op}"),
            });
        }

        Ok(())
    }

    fn normalize_input(input: &str) -> Result<&str, ErrorDetection> {
        let s = input.trim();

        if s.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice/address cannot be empty".into(),
                tx_id: None,
            });
        }

        if s.len() > MAX_PRIVATE_RECEIVE_INVOICE_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive invoice/address too long: {} > {}",
                    s.len(),
                    MAX_PRIVATE_RECEIVE_INVOICE_LEN
                ),
                tx_id: None,
            });
        }

        if !s.is_ascii() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice/address must be ASCII".into(),
                tx_id: None,
            });
        }

        if s.bytes().any(|b| b.is_ascii_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice/address contains control characters".into(),
                tx_id: None,
            });
        }

        if s.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice/address contains internal whitespace".into(),
                tx_id: None,
            });
        }

        Ok(s)
    }

    fn canonical_wallet(wallet: &str) -> Result<String, ErrorDetection> {
        canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
            message: format!("Invalid Remzar wallet address for private receive invoice: {e}"),
            tx_id: None,
        })
    }

    fn parse_invoice_to_wallet_strict(invoice: &str) -> Result<String, ErrorDetection> {
        let s = Self::normalize_input(invoice)?;

        let mut parts = s.split(':');

        let prefix = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        let wallet = parts.next().unwrap_or_default();

        if parts.next().is_some() {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid private receive invoice: too many ':' separators".into(),
                tx_id: None,
            });
        }

        if prefix != PRIVATE_RECEIVE_INVOICE_PREFIX {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invalid private receive invoice prefix '{}'; expected '{}'",
                    prefix, PRIVATE_RECEIVE_INVOICE_PREFIX
                ),
                tx_id: None,
            });
        }

        let expected_version = format!("v{}", PRIVATE_RECEIVE_VERSION);
        if version != expected_version {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Unsupported private receive invoice version '{}'; expected '{}'",
                    version, expected_version
                ),
                tx_id: None,
            });
        }

        if wallet.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice wallet address is empty".into(),
                tx_id: None,
            });
        }

        Self::canonical_wallet(wallet)
    }

    fn validate_optional_label(label: &str) -> Result<String, ErrorDetection> {
        let label = label.trim();

        if label.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice label cannot be empty when provided".into(),
                tx_id: None,
            });
        }

        if label.len() > MAX_PRIVATE_RECEIVE_LABEL_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive invoice label too long: {} > {}",
                    label.len(),
                    MAX_PRIVATE_RECEIVE_LABEL_LEN
                ),
                tx_id: None,
            });
        }

        if label.bytes().any(|b| b.is_ascii_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice label contains control characters".into(),
                tx_id: None,
            });
        }

        Ok(label.to_string())
    }

    fn validate_optional_context(context: &str) -> Result<String, ErrorDetection> {
        let context = context.trim();

        if context.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice context cannot be empty when provided".into(),
                tx_id: None,
            });
        }

        if context.len() > MAX_PRIVATE_RECEIVE_CONTEXT_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Private receive invoice context too long: {} > {}",
                    context.len(),
                    MAX_PRIVATE_RECEIVE_CONTEXT_LEN
                ),
                tx_id: None,
            });
        }

        if context.bytes().any(|b| b.is_ascii_control()) {
            return Err(ErrorDetection::ValidationError {
                message: "Private receive invoice context contains control characters".into(),
                tx_id: None,
            });
        }

        Ok(context.to_string())
    }
}

impl PrivateReceiveInvoice {
    /// Return the canonical invoice string.
    pub fn as_str(&self) -> &str {
        &self.invoice
    }

    /// Validate this object using `PrivateRI`.
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        PrivateRI::validate_invoice_object(self)
    }

    /// Return the one-time wallet address.
    pub fn recipient_wallet(&self) -> &str {
        &self.one_time_wallet
    }
}

impl fmt::Display for PrivateReceiveInvoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.invoice)
    }
}
