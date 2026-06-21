//! src/tokens/rwa_asset_certificate.rs
//!
//! Remzar RWA (Real-World Asset) certificate domain model.

use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{canon_wallet_id_checked, serde_u8_array_64};
use crate::utility::time_policy::TimePolicy;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const RWA_SCHEMA: &str = "rwa-asset-certificate-v1";
pub const RWA_KIND: &str = "RealWorldAsset";
pub const RWA_NFT_TITLE_PREFIX: &str = "Remzar RWA Certificate";

pub const RWA_ID_BYTES: usize = 64;
pub const RWA_ID_HEX_LEN: usize = 128;

pub const MAX_SHORT_TEXT_BYTES: usize = 256;
pub const MAX_MEDIUM_TEXT_BYTES: usize = 1_024;
pub const MAX_LONG_TEXT_BYTES: usize = 4 * 1_024;
pub const MAX_URI_BYTES: usize = 2 * 1_024;
pub const MAX_DOCUMENTS: usize = 64;
pub const MAX_AUDITOR_STAMPS: usize = 32;
pub const MAX_JURISDICTIONS: usize = 256;
pub const MAX_RULES: usize = 128;
pub const MAX_YIELD_BPS: u32 = 100_000;
pub const MAX_DECIMALS: u8 = 18;
pub const MAX_INVESTORS_HARD_CAP: u32 = 1_000_000;

pub type RwaUnits = u128;
pub type UsdCents = u128;
pub type BasisPoints = u32;
pub type UnixTimestampSecs = u64;

/// 64-byte Remzar hash wrapper.
///
/// Uses the existing `serde_u8_array_64` helper so this module stays aligned
/// with Remzar's "64-byte hash / 128 hex chars" rule.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RwaHash64(#[serde(with = "serde_u8_array_64")] pub [u8; RWA_ID_BYTES]);

impl RwaHash64 {
    pub const ZERO: Self = Self([0u8; RWA_ID_BYTES]);

    #[must_use]
    pub fn from_bytes(bytes: [u8; RWA_ID_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, ErrorDetection> {
        let s = hex_str.trim();

        if s.len() != RWA_ID_HEX_LEN {
            return Err(validation_err(format!(
                "Expected 64-byte hash as {} hex chars, got {} chars",
                RWA_ID_HEX_LEN,
                s.len()
            )));
        }

        let decoded = hex::decode(s).map_err(|e| {
            validation_err(format!(
                "Invalid 64-byte hash hex string in RWA certificate: {e}"
            ))
        })?;

        if decoded.len() != RWA_ID_BYTES {
            return Err(validation_err(format!(
                "Expected {} decoded hash bytes, got {}",
                RWA_ID_BYTES,
                decoded.len()
            )));
        }

        let mut out = [0u8; RWA_ID_BYTES];
        out.copy_from_slice(&decoded);
        Ok(Self(out))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    #[must_use]
    pub fn compute_from_bytes(bytes: &[u8]) -> Self {
        Self(RemzarHash::compute_bytes_hash(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaAssetClass {
    RealEstate,
    Treasury,
    MoneyMarket,
    PrivateCredit,
    Invoice,
    Commodity,
    PreciousMetal,
    CashEquivalent,
    Equity,
    FundShare,
    Bond,
    CarbonCredit,
    IntellectualProperty,
    Equipment,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaPayoutFrequency {
    None,
    PerSecond,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    SemiAnnual,
    Annual,
    AtMaturity,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaLifecycleStatus {
    Draft,
    MintSubmitted,
    Active,
    Frozen,
    Matured,
    Redeemed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaDocumentKind {
    AssetDeed,
    TitleInsurance,
    Appraisal,
    CustodyStatement,
    SpvFiling,
    TrustAgreement,
    OfferingMemorandum,
    SubscriptionAgreement,
    AuditReport,
    ProofOfReserve,
    InsurancePolicy,
    CourtOrder,
    LegalOpinion,
    CompliancePolicy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaTokenStandard {
    RemzarNativeRwa,
    RemzarNftBacked,
    Erc3643Inspired,
    Erc1400Inspired,
    Erc1155Inspired,
    Other,
}

/// Core financial variables that automated software can read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaCoreFinancialData {
    pub asset_class: RwaAssetClass,
    pub asset_name: String,

    /// Hash of the issuer's private asset reference or internal deal id.
    /// This avoids leaking real-world registry numbers if the issuer wants privacy.
    pub asset_reference_hash: RwaHash64,

    /// Current appraised value of the underlying asset.
    pub asset_valuation_usd_cents: UsdCents,
    pub valuation_timestamp_unix: UnixTimestampSecs,
    pub valuation_source_hash: RwaHash64,

    /// Annual yield in basis points. Example: 450 = 4.50%.
    pub yield_bps: BasisPoints,
    pub payout_frequency: RwaPayoutFrequency,

    /// None means no contractual maturity / perpetual certificate.
    pub maturity_timestamp_unix: Option<UnixTimestampSecs>,

    /// Total fractional units minted for this RWA.
    pub total_supply: RwaUnits,

    /// Number of decimal places used by the fractional unit accounting.
    pub decimals: u8,

    /// Face value per unit, if the instrument has one.
    pub face_value_usd_cents_per_unit: Option<UsdCents>,

    /// Optional minimum transfer size in RWA units.
    pub minimum_transfer_units: Option<RwaUnits>,
}

/// Off-chain legal document pointer. The URI can be IPFS, Arweave, HTTPS,
/// or a future Remzar document storage scheme. The hash must be over the exact
/// bytes of the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaDocumentLink {
    pub kind: RwaDocumentKind,
    pub label: String,
    pub uri: String,
    pub content_hash: RwaHash64,
    pub version: u32,
    pub issued_at_unix: Option<UnixTimestampSecs>,
    pub expires_at_unix: Option<UnixTimestampSecs>,

    /// Hash of the legal issuer/appraiser/custodian name or identifier.
    pub issuer_identity_hash: Option<RwaHash64>,
}

/// Independent verification stamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaAuditorVerification {
    pub auditor_wallet: Option<String>,
    pub auditor_identity_hash: RwaHash64,
    pub statement_hash: RwaHash64,
    pub verified_at_unix: UnixTimestampSecs,
    pub expires_at_unix: Option<UnixTimestampSecs>,
    pub proof_uri: Option<String>,
}

/// Legal ownership and court-linking data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaLegalOwnershipData {
    /// Example: "US-DE", "CA-ON", "SG".
    pub legal_jurisdiction: String,

    /// Hash of the SPV/trustee/custodian legal name or registration identity.
    pub spv_or_trustee_identity_hash: RwaHash64,

    /// Optional trustee/custodian wallet authorized to operate legal actions.
    pub trustee_wallet: Option<String>,

    /// Optional issuer-facing natural-language note. Do not put private data here.
    pub legal_summary: Option<String>,

    pub documents: Vec<RwaDocumentLink>,
    pub auditor_stamps: Vec<RwaAuditorVerification>,
}

/// Transfer/compliance rules that make the RWA different from a normal NFT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaComplianceRules {
    /// Optional on-chain/off-chain registry contract/module reference.
    pub kyc_registry_wallet: Option<String>,
    pub kyc_registry_reference: Option<String>,

    /// Empty allowed list means "not restricted by allow-list".
    pub allowed_jurisdictions: Vec<String>,

    /// Blocked list always wins over allowed list.
    pub blocked_jurisdictions: Vec<String>,

    pub accredited_investor_required: bool,
    pub max_investors: Option<u32>,
    pub transfer_lock_until_unix: Option<UnixTimestampSecs>,

    /// Global pause for transfers.
    pub transfers_paused: bool,

    /// Authority wallets must be canonical Remzar wallet addresses.
    pub freeze_authority_wallet: Option<String>,
    pub clawback_authority_wallet: Option<String>,

    /// True when issuer/legal trustee can move/burn/re-mint under a legal order.
    pub clawback_enabled: bool,

    /// Human-readable rules for UI/logging only. Compliance code should still be
    /// enforced by structured fields above.
    pub rule_notes: Vec<String>,
}

/// Technical chain data known at or after mint time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaTechnicalBlockchainData {
    pub token_standard: RwaTokenStandard,

    /// Contract/module/account address, if already deployed/known.
    pub contract_address: Option<String>,

    pub minting_timestamp_unix: Option<UnixTimestampSecs>,
    pub minting_block: Option<u64>,

    /// Hash of the transaction that minted this certificate, if known later.
    pub mint_tx_hash: Option<RwaHash64>,
}

/// Wallet-level compliance snapshot used by `can_transfer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaHolderCompliance {
    pub wallet: String,
    pub kyc_approved: bool,
    pub jurisdiction: String,
    pub accredited_investor: bool,
    pub expires_at_unix: Option<UnixTimestampSecs>,
    pub frozen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaTransferCheck {
    pub from_wallet: String,
    pub to_wallet: String,
    pub amount_units: RwaUnits,
    pub from_balance_units: RwaUnits,
    pub to_balance_units: RwaUnits,
    pub current_holder_count: u32,
    pub now_unix: UnixTimestampSecs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwaAssetCertificate {
    pub schema: String,
    pub kind: String,

    /// 64-byte id. This can be reused as the `nft_id` when the RWA is wrapped
    pub certificate_id: RwaHash64,

    pub issuer_wallet: String,
    pub owner_wallet: String,
    pub status: RwaLifecycleStatus,

    pub core: RwaCoreFinancialData,
    pub legal: RwaLegalOwnershipData,
    pub compliance: RwaComplianceRules,
    pub technical: RwaTechnicalBlockchainData,

    pub created_at_unix: UnixTimestampSecs,
    pub updated_at_unix: UnixTimestampSecs,

    /// Hash of the canonical certificate payload with this field zeroed.
    pub metadata_hash: RwaHash64,
}

impl RwaAssetCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_id: [u8; RWA_ID_BYTES],
        issuer_wallet: impl AsRef<str>,
        owner_wallet: impl AsRef<str>,
        core: RwaCoreFinancialData,
        legal: RwaLegalOwnershipData,
        compliance: RwaComplianceRules,
        technical: RwaTechnicalBlockchainData,
        created_at_unix: UnixTimestampSecs,
    ) -> Result<Self, ErrorDetection> {
        TimePolicy::validate_unix_secs_structural("rwa.created_at_unix", created_at_unix)?;

        let issuer_wallet = canonical_wallet(issuer_wallet.as_ref(), "issuer_wallet")?;
        let owner_wallet = canonical_wallet(owner_wallet.as_ref(), "owner_wallet")?;

        let mut out = Self {
            schema: RWA_SCHEMA.to_string(),
            kind: RWA_KIND.to_string(),
            certificate_id: RwaHash64::from_bytes(certificate_id),
            issuer_wallet,
            owner_wallet,
            status: RwaLifecycleStatus::Draft,
            core,
            legal,
            compliance,
            technical,
            created_at_unix,
            updated_at_unix: created_at_unix,
            metadata_hash: RwaHash64::ZERO,
        };

        out.validate_without_metadata_hash()?;
        let hash = out.recompute_metadata_hash()?;
        out.metadata_hash = hash;
        out.validate()?;
        Ok(out)
    }

    /// Runtime helper for CLI/off-chain construction.
    ///
    /// Consensus replay should pass block-derived timestamps explicitly instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new_runtime(
        certificate_id: [u8; RWA_ID_BYTES],
        issuer_wallet: impl AsRef<str>,
        owner_wallet: impl AsRef<str>,
        core: RwaCoreFinancialData,
        legal: RwaLegalOwnershipData,
        compliance: RwaComplianceRules,
        technical: RwaTechnicalBlockchainData,
    ) -> Result<Self, ErrorDetection> {
        let now = TimePolicy::now_unix_secs_runtime()?;
        Self::new(
            certificate_id,
            issuer_wallet,
            owner_wallet,
            core,
            legal,
            compliance,
            technical,
            now,
        )
    }

    #[must_use]
    pub fn certificate_id_hex(&self) -> String {
        self.certificate_id.to_hex()
    }

    #[must_use]
    pub fn metadata_hash_hex(&self) -> String {
        self.metadata_hash.to_hex()
    }

    #[must_use]
    pub fn nft_title(&self) -> String {
        format!("{RWA_NFT_TITLE_PREFIX}: {}", self.core.asset_name)
    }

    #[must_use]
    pub fn nft_description(&self) -> String {
        let maturity = self
            .core
            .maturity_timestamp_unix
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());

        format!(
            "Kind: {} | Schema: {} | Asset class: {:?} | Jurisdiction: {} | Issuer: {} | Owner: {} | Valuation USD cents: {} | Yield bps: {} | Supply: {} | Decimals: {} | Maturity unix: {} | Metadata hash: {}",
            self.kind,
            self.schema,
            self.core.asset_class,
            self.legal.legal_jurisdiction,
            self.issuer_wallet,
            self.owner_wallet,
            self.core.asset_valuation_usd_cents,
            self.core.yield_bps,
            self.core.total_supply,
            self.core.decimals,
            maturity,
            self.metadata_hash_hex()
        )
    }

    /// Bytes to pass into `NftMintTx::from_content_bytes(...)`.
    pub fn to_nft_content_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ErrorDetection::SerializationError {
            details: format!("serialize RWA NFT content bytes: {e}"),
        })
    }

    pub fn content_hash(&self) -> Result<RwaHash64, ErrorDetection> {
        Ok(RwaHash64::compute_from_bytes(&self.to_nft_content_bytes()?))
    }

    pub fn content_hash_hex(&self) -> Result<String, ErrorDetection> {
        Ok(self.content_hash()?.to_hex())
    }

    /// Canonical bytes for certificate metadata hashing.
    ///
    /// `metadata_hash` is set to zero before serialization to avoid a circular hash.
    pub fn canonical_metadata_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        let mut clone = self.clone();
        clone.metadata_hash = RwaHash64::ZERO;

        serde_json::to_vec(&clone).map_err(|e| ErrorDetection::SerializationError {
            details: format!("serialize RWA canonical metadata bytes: {e}"),
        })
    }

    pub fn recompute_metadata_hash(&self) -> Result<RwaHash64, ErrorDetection> {
        Ok(RwaHash64::compute_from_bytes(
            &self.canonical_metadata_bytes()?,
        ))
    }

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        self.validate_without_metadata_hash()?;

        if self.metadata_hash.is_zero() {
            return Err(validation_err("RWA metadata_hash cannot be zero"));
        }

        let expected = self.recompute_metadata_hash()?;
        if expected != self.metadata_hash {
            return Err(validation_err(format!(
                "RWA metadata_hash mismatch: expected {}, got {}",
                expected.to_hex(),
                self.metadata_hash.to_hex()
            )));
        }

        Ok(())
    }

    pub fn validate_without_metadata_hash(&self) -> Result<(), ErrorDetection> {
        validate_short_text("schema", &self.schema)?;
        validate_short_text("kind", &self.kind)?;

        if self.schema != RWA_SCHEMA {
            return Err(validation_err(format!(
                "Invalid RWA schema: expected {RWA_SCHEMA}, got {}",
                self.schema
            )));
        }

        if self.kind != RWA_KIND {
            return Err(validation_err(format!(
                "Invalid RWA kind: expected {RWA_KIND}, got {}",
                self.kind
            )));
        }

        if self.certificate_id.is_zero() {
            return Err(validation_err("RWA certificate_id cannot be zero"));
        }

        canonical_wallet(&self.issuer_wallet, "issuer_wallet")?;
        canonical_wallet(&self.owner_wallet, "owner_wallet")?;

        TimePolicy::validate_unix_secs_structural("rwa.created_at_unix", self.created_at_unix)?;
        TimePolicy::validate_unix_secs_structural("rwa.updated_at_unix", self.updated_at_unix)?;

        if self.updated_at_unix < self.created_at_unix {
            return Err(validation_err(
                "RWA updated_at_unix cannot be earlier than created_at_unix",
            ));
        }

        self.core.validate(self.created_at_unix)?;
        self.legal.validate()?;
        self.compliance.validate(&self.legal)?;
        self.technical.validate()?;

        Ok(())
    }

    pub fn refresh_metadata_hash(
        &mut self,
        updated_at_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        TimePolicy::validate_unix_secs_structural("rwa.updated_at_unix", updated_at_unix)?;

        if updated_at_unix < self.created_at_unix {
            return Err(validation_err(
                "RWA updated_at_unix cannot be earlier than created_at_unix",
            ));
        }

        self.updated_at_unix = updated_at_unix;
        self.validate_without_metadata_hash()?;
        self.metadata_hash = self.recompute_metadata_hash()?;
        self.validate()
    }

    pub fn mark_mint_submitted(
        &mut self,
        minting_timestamp_unix: UnixTimestampSecs,
        minting_block: Option<u64>,
        mint_tx_hash: Option<RwaHash64>,
    ) -> Result<(), ErrorDetection> {
        TimePolicy::validate_unix_secs_structural(
            "rwa.minting_timestamp_unix",
            minting_timestamp_unix,
        )?;

        self.status = RwaLifecycleStatus::MintSubmitted;
        self.technical.minting_timestamp_unix = Some(minting_timestamp_unix);
        self.technical.minting_block = minting_block;
        self.technical.mint_tx_hash = mint_tx_hash;
        self.refresh_metadata_hash(minting_timestamp_unix)
    }

    pub fn activate(&mut self, now_unix: UnixTimestampSecs) -> Result<(), ErrorDetection> {
        self.status = RwaLifecycleStatus::Active;
        self.refresh_metadata_hash(now_unix)
    }

    pub fn freeze(
        &mut self,
        caller_wallet: &str,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_freeze_authority(caller_wallet)?;
        self.status = RwaLifecycleStatus::Frozen;
        self.refresh_metadata_hash(now_unix)
    }

    pub fn unfreeze(
        &mut self,
        caller_wallet: &str,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_freeze_authority(caller_wallet)?;
        self.status = RwaLifecycleStatus::Active;
        self.refresh_metadata_hash(now_unix)
    }

    pub fn pause_transfers(
        &mut self,
        caller_wallet: &str,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_freeze_authority(caller_wallet)?;
        self.compliance.transfers_paused = true;
        self.refresh_metadata_hash(now_unix)
    }

    pub fn unpause_transfers(
        &mut self,
        caller_wallet: &str,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_freeze_authority(caller_wallet)?;
        self.compliance.transfers_paused = false;
        self.refresh_metadata_hash(now_unix)
    }

    pub fn update_valuation(
        &mut self,
        caller_wallet: &str,
        asset_valuation_usd_cents: UsdCents,
        valuation_timestamp_unix: UnixTimestampSecs,
        valuation_source_hash: RwaHash64,
    ) -> Result<(), ErrorDetection> {
        self.assert_issuer_or_trustee(caller_wallet)?;

        if asset_valuation_usd_cents == 0 {
            return Err(validation_err("RWA valuation must be > 0"));
        }

        if valuation_source_hash.is_zero() {
            return Err(validation_err("RWA valuation_source_hash cannot be zero"));
        }

        TimePolicy::validate_unix_secs_structural(
            "rwa.valuation_timestamp_unix",
            valuation_timestamp_unix,
        )?;

        self.core.asset_valuation_usd_cents = asset_valuation_usd_cents;
        self.core.valuation_timestamp_unix = valuation_timestamp_unix;
        self.core.valuation_source_hash = valuation_source_hash;

        self.refresh_metadata_hash(valuation_timestamp_unix)
    }

    pub fn add_document(
        &mut self,
        caller_wallet: &str,
        document: RwaDocumentLink,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_issuer_or_trustee(caller_wallet)?;

        if self.legal.documents.len() >= MAX_DOCUMENTS {
            return Err(validation_err(format!(
                "RWA documents exceed max {MAX_DOCUMENTS}"
            )));
        }

        document.validate()?;
        self.legal.documents.push(document);
        self.refresh_metadata_hash(now_unix)
    }

    pub fn add_auditor_stamp(
        &mut self,
        caller_wallet: &str,
        stamp: RwaAuditorVerification,
        now_unix: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        self.assert_issuer_or_trustee(caller_wallet)?;

        if self.legal.auditor_stamps.len() >= MAX_AUDITOR_STAMPS {
            return Err(validation_err(format!(
                "RWA auditor stamps exceed max {MAX_AUDITOR_STAMPS}"
            )));
        }

        stamp.validate()?;
        self.legal.auditor_stamps.push(stamp);
        self.refresh_metadata_hash(now_unix)
    }

    pub fn can_transfer(
        &self,
        check: &RwaTransferCheck,
        from_compliance: &RwaHolderCompliance,
        to_compliance: &RwaHolderCompliance,
    ) -> Result<(), ErrorDetection> {
        self.validate()?;
        check.validate()?;
        from_compliance.validate()?;
        to_compliance.validate()?;

        let from_wallet = canonical_wallet(&check.from_wallet, "transfer.from_wallet")?;
        let to_wallet = canonical_wallet(&check.to_wallet, "transfer.to_wallet")?;

        if from_wallet == to_wallet {
            return Err(validation_err(
                "RWA transfer sender and receiver are the same",
            ));
        }

        if canonical_wallet(&from_compliance.wallet, "from_compliance.wallet")? != from_wallet {
            return Err(validation_err(
                "RWA transfer sender compliance wallet does not match sender",
            ));
        }

        if canonical_wallet(&to_compliance.wallet, "to_compliance.wallet")? != to_wallet {
            return Err(validation_err(
                "RWA transfer receiver compliance wallet does not match receiver",
            ));
        }

        if !matches!(self.status, RwaLifecycleStatus::Active) {
            return Err(validation_err(format!(
                "RWA transfer rejected: certificate status is {:?}",
                self.status
            )));
        }

        if self.compliance.transfers_paused {
            return Err(validation_err(
                "RWA transfer rejected: transfers are paused",
            ));
        }

        if let Some(lock_until) = self.compliance.transfer_lock_until_unix
            && check.now_unix < lock_until
        {
            return Err(validation_err(format!(
                "RWA transfer rejected: locked until unix {lock_until}"
            )));
        }

        if check.amount_units == 0 {
            return Err(validation_err("RWA transfer amount must be > 0"));
        }

        if let Some(min) = self.core.minimum_transfer_units
            && check.amount_units < min
        {
            return Err(validation_err(format!(
                "RWA transfer amount below minimum units: min={min}"
            )));
        }

        if check.from_balance_units < check.amount_units {
            return Err(validation_err(
                "RWA transfer rejected: insufficient balance",
            ));
        }

        if from_compliance.frozen || to_compliance.frozen {
            return Err(validation_err(
                "RWA transfer rejected: sender or receiver wallet is frozen",
            ));
        }

        validate_holder_active("sender", from_compliance, check.now_unix)?;
        validate_holder_active("receiver", to_compliance, check.now_unix)?;

        if self.compliance.accredited_investor_required && !to_compliance.accredited_investor {
            return Err(validation_err(
                "RWA transfer rejected: receiver must be accredited investor",
            ));
        }

        let receiver_jurisdiction = normalize_jurisdiction(&to_compliance.jurisdiction)?;

        if self
            .compliance
            .blocked_jurisdictions
            .iter()
            .any(|j| normalize_jurisdiction_lossy(j) == receiver_jurisdiction)
        {
            return Err(validation_err(format!(
                "RWA transfer rejected: receiver jurisdiction is blocked: {receiver_jurisdiction}"
            )));
        }

        if !self.compliance.allowed_jurisdictions.is_empty()
            && !self
                .compliance
                .allowed_jurisdictions
                .iter()
                .any(|j| normalize_jurisdiction_lossy(j) == receiver_jurisdiction)
        {
            return Err(validation_err(format!(
                "RWA transfer rejected: receiver jurisdiction is not allowed: {receiver_jurisdiction}"
            )));
        }

        if check.to_balance_units == 0
            && let Some(max) = self.compliance.max_investors
            && check.current_holder_count >= max
        {
            return Err(validation_err(format!(
                "RWA transfer rejected: max investor count reached ({max})"
            )));
        }

        Ok(())
    }

    pub fn can_clawback(
        &self,
        caller_wallet: &str,
        from_wallet: &str,
        to_wallet: &str,
        amount_units: RwaUnits,
        legal_order_hash: RwaHash64,
    ) -> Result<(), ErrorDetection> {
        self.validate()?;

        if !self.compliance.clawback_enabled {
            return Err(validation_err("RWA clawback is disabled for this asset"));
        }

        let caller = canonical_wallet(caller_wallet, "clawback.caller_wallet")?;
        let authority = self
            .compliance
            .clawback_authority_wallet
            .as_ref()
            .ok_or_else(|| validation_err("RWA clawback authority wallet is not configured"))?;

        if caller != canonical_wallet(authority, "clawback.authority_wallet")? {
            return Err(validation_err(
                "RWA clawback rejected: caller is not authority",
            ));
        }

        let from = canonical_wallet(from_wallet, "clawback.from_wallet")?;
        let to = canonical_wallet(to_wallet, "clawback.to_wallet")?;

        if from == to {
            return Err(validation_err(
                "RWA clawback source and destination are the same",
            ));
        }

        if amount_units == 0 {
            return Err(validation_err("RWA clawback amount must be > 0"));
        }

        if legal_order_hash.is_zero() {
            return Err(validation_err(
                "RWA clawback requires non-zero legal_order_hash",
            ));
        }

        Ok(())
    }

    fn assert_issuer_or_trustee(&self, caller_wallet: &str) -> Result<(), ErrorDetection> {
        let caller = canonical_wallet(caller_wallet, "caller_wallet")?;

        if caller == self.issuer_wallet {
            return Ok(());
        }

        if let Some(trustee_wallet) = &self.legal.trustee_wallet
            && caller == canonical_wallet(trustee_wallet, "trustee_wallet")?
        {
            return Ok(());
        }

        Err(validation_err(
            "RWA operation rejected: caller is not issuer or trustee",
        ))
    }

    fn assert_freeze_authority(&self, caller_wallet: &str) -> Result<(), ErrorDetection> {
        let caller = canonical_wallet(caller_wallet, "caller_wallet")?;

        if caller == self.issuer_wallet {
            return Ok(());
        }

        if let Some(authority) = &self.compliance.freeze_authority_wallet
            && caller == canonical_wallet(authority, "freeze_authority_wallet")?
        {
            return Ok(());
        }

        Err(validation_err(
            "RWA operation rejected: caller is not freeze authority",
        ))
    }
}

impl RwaCoreFinancialData {
    pub fn validate(
        &self,
        certificate_created_at: UnixTimestampSecs,
    ) -> Result<(), ErrorDetection> {
        validate_short_text("asset_name", &self.asset_name)?;

        if self.asset_reference_hash.is_zero() {
            return Err(validation_err("RWA asset_reference_hash cannot be zero"));
        }

        if self.asset_valuation_usd_cents == 0 {
            return Err(validation_err("RWA asset_valuation_usd_cents must be > 0"));
        }

        TimePolicy::validate_unix_secs_structural(
            "rwa.valuation_timestamp_unix",
            self.valuation_timestamp_unix,
        )?;

        if self.valuation_timestamp_unix < certificate_created_at.saturating_sub(31_536_000 * 50) {
            return Err(validation_err(
                "RWA valuation timestamp is implausibly older than certificate creation",
            ));
        }

        if self.valuation_source_hash.is_zero() {
            return Err(validation_err("RWA valuation_source_hash cannot be zero"));
        }

        if self.yield_bps > MAX_YIELD_BPS {
            return Err(validation_err(format!(
                "RWA yield_bps exceeds max sanity cap {MAX_YIELD_BPS}"
            )));
        }

        if let Some(maturity) = self.maturity_timestamp_unix {
            TimePolicy::validate_unix_secs_structural("rwa.maturity_timestamp_unix", maturity)?;

            if maturity <= certificate_created_at {
                return Err(validation_err(
                    "RWA maturity_timestamp_unix must be after created_at_unix",
                ));
            }
        }

        if self.total_supply == 0 {
            return Err(validation_err("RWA total_supply must be > 0"));
        }

        if self.decimals > MAX_DECIMALS {
            return Err(validation_err(format!(
                "RWA decimals exceeds max {MAX_DECIMALS}"
            )));
        }

        if let Some(face_value) = self.face_value_usd_cents_per_unit
            && face_value == 0
        {
            return Err(validation_err(
                "RWA face_value_usd_cents_per_unit must be > 0 when present",
            ));
        }

        if let Some(min_transfer) = self.minimum_transfer_units {
            if min_transfer == 0 {
                return Err(validation_err(
                    "RWA minimum_transfer_units must be > 0 when present",
                ));
            }

            if min_transfer > self.total_supply {
                return Err(validation_err(
                    "RWA minimum_transfer_units cannot exceed total_supply",
                ));
            }
        }

        Ok(())
    }
}

impl RwaDocumentLink {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        validate_short_text("document.label", &self.label)?;
        validate_uri("document.uri", &self.uri)?;

        if self.content_hash.is_zero() {
            return Err(validation_err("RWA document content_hash cannot be zero"));
        }

        if self.version == 0 {
            return Err(validation_err("RWA document version must be >= 1"));
        }

        if let Some(ts) = self.issued_at_unix {
            TimePolicy::validate_unix_secs_structural("rwa.document.issued_at_unix", ts)?;
        }

        if let Some(ts) = self.expires_at_unix {
            TimePolicy::validate_unix_secs_structural("rwa.document.expires_at_unix", ts)?;
        }

        if let (Some(issued), Some(expires)) = (self.issued_at_unix, self.expires_at_unix)
            && expires <= issued
        {
            return Err(validation_err(
                "RWA document expires_at_unix must be after issued_at_unix",
            ));
        }

        if let Some(hash) = self.issuer_identity_hash
            && hash.is_zero()
        {
            return Err(validation_err(
                "RWA document issuer_identity_hash cannot be zero when present",
            ));
        }

        Ok(())
    }
}

impl RwaAuditorVerification {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        if let Some(wallet) = &self.auditor_wallet {
            canonical_wallet(wallet, "auditor_wallet")?;
        }

        if self.auditor_identity_hash.is_zero() {
            return Err(validation_err("RWA auditor_identity_hash cannot be zero"));
        }

        if self.statement_hash.is_zero() {
            return Err(validation_err("RWA auditor statement_hash cannot be zero"));
        }

        TimePolicy::validate_unix_secs_structural(
            "rwa.auditor.verified_at_unix",
            self.verified_at_unix,
        )?;

        if let Some(expires) = self.expires_at_unix {
            TimePolicy::validate_unix_secs_structural("rwa.auditor.expires_at_unix", expires)?;

            if expires <= self.verified_at_unix {
                return Err(validation_err(
                    "RWA auditor expires_at_unix must be after verified_at_unix",
                ));
            }
        }

        if let Some(uri) = &self.proof_uri {
            validate_uri("auditor.proof_uri", uri)?;
        }

        Ok(())
    }
}

impl RwaLegalOwnershipData {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        normalize_jurisdiction(&self.legal_jurisdiction)?;

        if self.spv_or_trustee_identity_hash.is_zero() {
            return Err(validation_err(
                "RWA spv_or_trustee_identity_hash cannot be zero",
            ));
        }

        if let Some(trustee_wallet) = &self.trustee_wallet {
            canonical_wallet(trustee_wallet, "trustee_wallet")?;
        }

        if let Some(summary) = &self.legal_summary {
            validate_long_text("legal_summary", summary)?;
        }

        if self.documents.is_empty() {
            return Err(validation_err(
                "RWA must include at least one off-chain legal document pointer",
            ));
        }

        if self.documents.len() > MAX_DOCUMENTS {
            return Err(validation_err(format!(
                "RWA documents exceed max {MAX_DOCUMENTS}"
            )));
        }

        let mut doc_keys = BTreeSet::new();
        for doc in &self.documents {
            doc.validate()?;
            let key = format!(
                "{:?}:{}:{}",
                doc.kind,
                doc.version,
                doc.content_hash.to_hex()
            );
            if !doc_keys.insert(key) {
                return Err(validation_err("Duplicate RWA legal document detected"));
            }
        }

        if self.auditor_stamps.len() > MAX_AUDITOR_STAMPS {
            return Err(validation_err(format!(
                "RWA auditor stamps exceed max {MAX_AUDITOR_STAMPS}"
            )));
        }

        for stamp in &self.auditor_stamps {
            stamp.validate()?;
        }

        Ok(())
    }
}

impl RwaComplianceRules {
    pub fn validate(&self, legal: &RwaLegalOwnershipData) -> Result<(), ErrorDetection> {
        if let Some(wallet) = &self.kyc_registry_wallet {
            canonical_wallet(wallet, "kyc_registry_wallet")?;
        }

        if let Some(reference) = &self.kyc_registry_reference {
            validate_medium_text("kyc_registry_reference", reference)?;
        }

        validate_jurisdiction_list("allowed_jurisdictions", &self.allowed_jurisdictions)?;
        validate_jurisdiction_list("blocked_jurisdictions", &self.blocked_jurisdictions)?;

        let allowed: BTreeSet<String> = self
            .allowed_jurisdictions
            .iter()
            .map(|j| normalize_jurisdiction_lossy(j))
            .collect();

        for blocked in &self.blocked_jurisdictions {
            let normalized = normalize_jurisdiction(blocked)?;
            if allowed.contains(&normalized) {
                return Err(validation_err(format!(
                    "Jurisdiction {normalized} cannot be both allowed and blocked"
                )));
            }
        }

        if let Some(max) = self.max_investors {
            if max == 0 {
                return Err(validation_err("RWA max_investors must be > 0 when present"));
            }

            if max > MAX_INVESTORS_HARD_CAP {
                return Err(validation_err(format!(
                    "RWA max_investors exceeds hard cap {MAX_INVESTORS_HARD_CAP}"
                )));
            }
        }

        if let Some(lock_until) = self.transfer_lock_until_unix {
            TimePolicy::validate_unix_secs_structural("rwa.transfer_lock_until_unix", lock_until)?;
        }

        if let Some(wallet) = &self.freeze_authority_wallet {
            canonical_wallet(wallet, "freeze_authority_wallet")?;
        }

        if let Some(wallet) = &self.clawback_authority_wallet {
            canonical_wallet(wallet, "clawback_authority_wallet")?;
        }

        if self.clawback_enabled && self.clawback_authority_wallet.is_none() {
            return Err(validation_err(
                "RWA clawback_enabled requires clawback_authority_wallet",
            ));
        }

        if self.rule_notes.len() > MAX_RULES {
            return Err(validation_err(format!(
                "RWA rule_notes exceed max {MAX_RULES}"
            )));
        }

        for note in &self.rule_notes {
            validate_medium_text("rule_note", note)?;
        }

        if let Some(trustee) = &legal.trustee_wallet {
            canonical_wallet(trustee, "legal.trustee_wallet")?;
        }

        Ok(())
    }
}

impl RwaTechnicalBlockchainData {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        if let Some(contract_address) = &self.contract_address {
            validate_medium_text("contract_address", contract_address)?;
        }

        if let Some(ts) = self.minting_timestamp_unix {
            TimePolicy::validate_unix_secs_structural("rwa.minting_timestamp_unix", ts)?;
        }

        if let Some(hash) = self.mint_tx_hash
            && hash.is_zero()
        {
            return Err(validation_err(
                "RWA mint_tx_hash cannot be zero when present",
            ));
        }

        Ok(())
    }
}

impl RwaHolderCompliance {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        canonical_wallet(&self.wallet, "holder.wallet")?;
        normalize_jurisdiction(&self.jurisdiction)?;

        if let Some(expires) = self.expires_at_unix {
            TimePolicy::validate_unix_secs_structural("holder.expires_at_unix", expires)?;
        }

        Ok(())
    }
}

impl RwaTransferCheck {
    pub fn validate(&self) -> Result<(), ErrorDetection> {
        canonical_wallet(&self.from_wallet, "transfer.from_wallet")?;
        canonical_wallet(&self.to_wallet, "transfer.to_wallet")?;
        TimePolicy::validate_unix_secs_structural("transfer.now_unix", self.now_unix)?;

        if self.amount_units == 0 {
            return Err(validation_err("RWA transfer amount_units must be > 0"));
        }

        if self.from_balance_units < self.amount_units {
            return Err(validation_err(
                "RWA transfer from_balance_units is below amount_units",
            ));
        }

        Ok(())
    }
}

/// Convenience builder for the most common "legal document hash + URI" case.
pub fn document_from_bytes(
    kind: RwaDocumentKind,
    label: impl Into<String>,
    uri: impl Into<String>,
    document_bytes: &[u8],
    version: u32,
    issued_at_unix: Option<UnixTimestampSecs>,
) -> Result<RwaDocumentLink, ErrorDetection> {
    let doc = RwaDocumentLink {
        kind,
        label: label.into(),
        uri: uri.into(),
        content_hash: RwaHash64::compute_from_bytes(document_bytes),
        version,
        issued_at_unix,
        expires_at_unix: None,
        issuer_identity_hash: None,
    };

    doc.validate()?;
    Ok(doc)
}

/// Builds a deterministic 64-byte certificate id from caller-supplied entropy.
///
/// Recommended entropy:
/// - issuer wallet
/// - owner wallet
/// - asset reference hash
/// - user/node random 64 bytes
/// - runtime timestamp
pub fn derive_certificate_id_from_entropy(
    entropy: &[u8],
) -> Result<[u8; RWA_ID_BYTES], ErrorDetection> {
    if entropy.len() < 32 {
        return Err(validation_err(
            "RWA certificate id entropy must be at least 32 bytes",
        ));
    }

    Ok(RemzarHash::compute_bytes_hash(entropy))
}

/// Human-friendly JSON export for audit files.
pub fn to_pretty_json(certificate: &RwaAssetCertificate) -> Result<Vec<u8>, ErrorDetection> {
    certificate.validate()?;
    serde_json::to_vec_pretty(certificate).map_err(|e| ErrorDetection::SerializationError {
        details: format!("serialize RWA pretty JSON: {e}"),
    })
}

/// Parse and validate an exported RWA certificate JSON.
pub fn from_json_slice(bytes: &[u8]) -> Result<RwaAssetCertificate, ErrorDetection> {
    if bytes.is_empty() {
        return Err(validation_err("RWA JSON cannot be empty"));
    }

    if bytes.len() > 5 * 1024 * 1024 {
        return Err(validation_err("RWA JSON exceeds 5 MiB limit"));
    }

    let cert: RwaAssetCertificate =
        serde_json::from_slice(bytes).map_err(|e| ErrorDetection::SerializationError {
            details: format!("parse RWA certificate JSON: {e}"),
        })?;

    cert.validate()?;
    Ok(cert)
}

fn validate_holder_active(
    label: &'static str,
    holder: &RwaHolderCompliance,
    now_unix: UnixTimestampSecs,
) -> Result<(), ErrorDetection> {
    if !holder.kyc_approved {
        return Err(validation_err(format!(
            "RWA transfer rejected: {label} is not KYC approved"
        )));
    }

    if let Some(expires) = holder.expires_at_unix
        && now_unix > expires
    {
        return Err(validation_err(format!(
            "RWA transfer rejected: {label} KYC has expired"
        )));
    }

    Ok(())
}

#[inline]
fn canonical_wallet(wallet: &str, label: &'static str) -> Result<String, ErrorDetection> {
    canon_wallet_id_checked(wallet).map_err(|e| {
        validation_err(format!(
            "Invalid RWA wallet field {label}: wallet address is invalid or incomplete: {e:?}"
        ))
    })
}

fn normalize_jurisdiction(value: &str) -> Result<String, ErrorDetection> {
    let s = value.trim();

    if s.is_empty() {
        return Err(validation_err("RWA jurisdiction cannot be empty"));
    }

    if s.len() > 64 {
        return Err(validation_err("RWA jurisdiction exceeds 64 chars"));
    }

    if !s
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
    {
        return Err(validation_err(format!(
            "RWA jurisdiction contains invalid characters: {s}"
        )));
    }

    Ok(s.to_ascii_uppercase())
}

#[inline]
fn normalize_jurisdiction_lossy(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn validate_jurisdiction_list(label: &'static str, list: &[String]) -> Result<(), ErrorDetection> {
    if list.len() > MAX_JURISDICTIONS {
        return Err(validation_err(format!(
            "RWA {label} exceeds max {MAX_JURISDICTIONS}"
        )));
    }

    let mut seen = BTreeSet::new();
    for item in list {
        let normalized = normalize_jurisdiction(item)?;
        if !seen.insert(normalized.clone()) {
            return Err(validation_err(format!(
                "Duplicate RWA jurisdiction in {label}: {normalized}"
            )));
        }
    }

    Ok(())
}

fn validate_short_text(label: &'static str, value: &str) -> Result<(), ErrorDetection> {
    validate_text(label, value, 1, MAX_SHORT_TEXT_BYTES)
}

fn validate_medium_text(label: &'static str, value: &str) -> Result<(), ErrorDetection> {
    validate_text(label, value, 1, MAX_MEDIUM_TEXT_BYTES)
}

fn validate_long_text(label: &'static str, value: &str) -> Result<(), ErrorDetection> {
    validate_text(label, value, 1, MAX_LONG_TEXT_BYTES)
}

fn validate_text(
    label: &'static str,
    value: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<(), ErrorDetection> {
    let s = value.trim();

    if s.len() < min_bytes {
        return Err(validation_err(format!("RWA {label} cannot be empty")));
    }

    if s.len() > max_bytes {
        return Err(validation_err(format!(
            "RWA {label} exceeds max {max_bytes} bytes"
        )));
    }

    if s.chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(validation_err(format!(
            "RWA {label} contains unsupported control characters"
        )));
    }

    Ok(())
}

fn validate_uri(label: &'static str, value: &str) -> Result<(), ErrorDetection> {
    validate_text(label, value, 1, MAX_URI_BYTES)?;

    let s = value.trim();

    if s.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(validation_err(format!(
            "RWA {label} cannot contain whitespace"
        )));
    }

    let ok_scheme = s.starts_with("ipfs://")
        || s.starts_with("ar://")
        || s.starts_with("https://")
        || s.starts_with("remzar://");

    if !ok_scheme {
        return Err(validation_err(format!(
            "RWA {label} must start with ipfs://, ar://, https://, or remzar://"
        )));
    }

    Ok(())
}

#[inline]
fn validation_err(message: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: message.into(),
        tx_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(ch: char) -> String {
        format!("r{}", ch.to_string().repeat(128))
    }

    fn hash(byte: u8) -> RwaHash64 {
        RwaHash64::from_bytes([byte; RWA_ID_BYTES])
    }

    fn sample_core() -> RwaCoreFinancialData {
        RwaCoreFinancialData {
            asset_class: RwaAssetClass::RealEstate,
            asset_name: "Example Property RWA".to_string(),
            asset_reference_hash: hash(1),
            asset_valuation_usd_cents: 10_000_000_00,
            valuation_timestamp_unix: 1_800_000_000,
            valuation_source_hash: hash(2),
            yield_bps: 450,
            payout_frequency: RwaPayoutFrequency::Monthly,
            maturity_timestamp_unix: Some(1_900_000_000),
            total_supply: 1_000_000,
            decimals: 0,
            face_value_usd_cents_per_unit: Some(100),
            minimum_transfer_units: Some(1),
        }
    }

    fn sample_legal() -> RwaLegalOwnershipData {
        RwaLegalOwnershipData {
            legal_jurisdiction: "US-DE".to_string(),
            spv_or_trustee_identity_hash: hash(3),
            trustee_wallet: Some(wallet('b')),
            legal_summary: Some(
                "Off-chain legal documents are referenced by hash only.".to_string(),
            ),
            documents: vec![RwaDocumentLink {
                kind: RwaDocumentKind::SpvFiling,
                label: "SPV filing".to_string(),
                uri: "ipfs://example-cid".to_string(),
                content_hash: hash(4),
                version: 1,
                issued_at_unix: Some(1_800_000_000),
                expires_at_unix: None,
                issuer_identity_hash: Some(hash(5)),
            }],
            auditor_stamps: vec![RwaAuditorVerification {
                auditor_wallet: Some(wallet('c')),
                auditor_identity_hash: hash(6),
                statement_hash: hash(7),
                verified_at_unix: 1_800_000_000,
                expires_at_unix: Some(1_850_000_000),
                proof_uri: Some("https://example.com/audit.pdf".to_string()),
            }],
        }
    }

    fn sample_compliance() -> RwaComplianceRules {
        RwaComplianceRules {
            kyc_registry_wallet: Some(wallet('d')),
            kyc_registry_reference: Some("remzar://kyc/registry/v1".to_string()),
            allowed_jurisdictions: vec!["US-DE".to_string(), "CA-ON".to_string()],
            blocked_jurisdictions: vec!["KP".to_string()],
            accredited_investor_required: true,
            max_investors: Some(99),
            transfer_lock_until_unix: None,
            transfers_paused: false,
            freeze_authority_wallet: Some(wallet('e')),
            clawback_authority_wallet: Some(wallet('f')),
            clawback_enabled: true,
            rule_notes: vec!["Transfers require KYC and jurisdiction checks.".to_string()],
        }
    }

    fn sample_technical() -> RwaTechnicalBlockchainData {
        RwaTechnicalBlockchainData {
            token_standard: RwaTokenStandard::RemzarNativeRwa,
            contract_address: Some("remzar://tokens/rwa_asset_certificate".to_string()),
            minting_timestamp_unix: None,
            minting_block: None,
            mint_tx_hash: None,
        }
    }

    #[test]
    fn builds_and_validates_rwa_certificate() {
        let cert = RwaAssetCertificate::new(
            [9u8; RWA_ID_BYTES],
            wallet('a'),
            wallet('a'),
            sample_core(),
            sample_legal(),
            sample_compliance(),
            sample_technical(),
            1_800_000_000,
        )
        .expect("valid RWA certificate");

        assert_eq!(cert.schema, RWA_SCHEMA);
        assert!(!cert.metadata_hash.is_zero());
        assert!(cert.validate().is_ok());
        assert!(cert.to_nft_content_bytes().is_ok());
    }

    #[test]
    fn rejects_zero_document_hash() {
        let mut legal = sample_legal();
        legal.documents[0].content_hash = RwaHash64::ZERO;

        let err = legal.validate().expect_err("zero document hash must fail");
        match err {
            ErrorDetection::ValidationError { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn transfer_gate_rejects_blocked_jurisdiction() {
        let cert = RwaAssetCertificate::new(
            [9u8; RWA_ID_BYTES],
            wallet('a'),
            wallet('a'),
            sample_core(),
            sample_legal(),
            sample_compliance(),
            sample_technical(),
            1_800_000_000,
        )
        .expect("valid RWA certificate");

        let check = RwaTransferCheck {
            from_wallet: wallet('a'),
            to_wallet: wallet('b'),
            amount_units: 1,
            from_balance_units: 10,
            to_balance_units: 0,
            current_holder_count: 1,
            now_unix: 1_810_000_000,
        };

        let from = RwaHolderCompliance {
            wallet: wallet('a'),
            kyc_approved: true,
            jurisdiction: "US-DE".to_string(),
            accredited_investor: true,
            expires_at_unix: Some(1_900_000_000),
            frozen: false,
        };

        let to = RwaHolderCompliance {
            wallet: wallet('b'),
            kyc_approved: true,
            jurisdiction: "KP".to_string(),
            accredited_investor: true,
            expires_at_unix: Some(1_900_000_000),
            frozen: false,
        };

        assert!(cert.can_transfer(&check, &from, &to).is_err());
    }
}
