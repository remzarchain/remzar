//! src/utility/digital_id_receipt.rs
//!
//! Local-only Digital I.D. / Digital Passport receipt support.
//!
//! Intended CLI flow:
//! 1. Prompt Digital I.D. fields.
//! 2. Prompt wallet address.
//! 3. Prompt hidden passphrase + hidden confirmation using dialoguer::Password.
//! 4. Load/construct the real MLDSA65Wallet for that wallet.
//! 5. Call DigitalPassport::new_signed(...).
//! 6. Mint NftMintTx from passport.content_bytes_for_nft()?.
//! 7. Write local JSON/PDF/QR via passport.write_receipt_files(...).

use crate::cryptography::ml_dsa_65_006_edwallet::MLDSA65Wallet;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::hash_system_remzarhash::RemzarHash;
use crate::utility::helper::{
    REMZAR_WALLET_LEN, canon_wallet_id_checked, parse_wallet_address,
    wallet_id_matches_pubkey_bytes_checked,
};

use chrono::{DateTime, SecondsFormat, Utc};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use image::{DynamicImage, ImageFormat, Luma};
use pdf_writer::{Content, Name, Pdf, Rect, Ref, Str};
use qrcode::{EcLevel, QrCode};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const DIGITAL_PASSPORT_KIND: &str = "DigitalID";
pub const DIGITAL_PASSPORT_SCHEMA: &str = "digital-id-v1";

const CONSENSUS_CTX: &[u8] = b"";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigitalPassportReceiptFiles {
    pub json_path: PathBuf,
    pub pdf_path: PathBuf,
    pub qr_png_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigitalPassportFields {
    pub name: Option<String>,
    pub birth: Option<String>,
    pub sex: Option<String>,
    pub height: Option<String>,
    pub nationality: Option<String>,
    pub country: Option<String>,
    pub address: Option<String>,
    pub job: Option<String>,
}

impl DigitalPassportFields {
    #[allow(clippy::too_many_arguments)]
    pub fn from_raw(
        name: String,
        birth: String,
        sex: String,
        height: String,
        nationality: String,
        country: String,
        address: String,
        job: String,
    ) -> Result<Self, ErrorDetection> {
        let fields = Self {
            name: Self::blank_to_none(name),
            birth: Self::blank_to_none(birth),
            sex: Self::blank_to_none(sex),
            height: Self::blank_to_none(height),
            nationality: Self::blank_to_none(nationality),
            country: Self::blank_to_none(country),
            address: Self::blank_to_none(address),
            job: Self::blank_to_none(job),
        };

        DigitalPassport::validate_fields(&fields)?;
        Ok(fields)
    }

    fn blank_to_none(s: String) -> Option<String> {
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    fn has_any_identity_field(&self) -> bool {
        self.name.is_some()
            || self.birth.is_some()
            || self.sex.is_some()
            || self.height.is_some()
            || self.nationality.is_some()
            || self.country.is_some()
            || self.address.is_some()
            || self.job.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigitalPassport {
    pub kind: String,
    pub schema: String,

    /// 64-byte id encoded as 128 lowercase hex chars.
    /// Usually this should be the same id as the NFT id.
    pub passport_id_hex: String,

    /// Canonical wallet address: "r" + 128 lowercase hex chars.
    pub wallet_address: String,

    /// ML-DSA-65 public key hex for local signature verification.
    pub wallet_public_key_hex: String,

    /// Local identity fields.
    pub fields: DigitalPassportFields,

    /// RFC3339 UTC creation time.
    pub created_at_utc: String,

    /// 64-byte BLAKE3-XOF/RemzarHash over the deterministic proof payload.
    pub digital_fingerprint_hex: String,

    /// ML-DSA-65 signature over the deterministic proof payload bytes.
    ///
    /// Created using MLDSA65Wallet::sign(passphrase, proof_payload_bytes).
    pub wallet_signature_hex: String,
}

#[derive(Debug, Serialize)]
struct DigitalPassportProofPayload<'a> {
    kind: &'a str,
    schema: &'a str,
    passport_id_hex: &'a str,
    wallet_address: &'a str,
    wallet_public_key_hex: &'a str,
    fields: &'a DigitalPassportFields,
    created_at_utc: &'a str,
}

impl DigitalPassport {
    const HEX_64_LEN: usize = 128;
    const MAX_HEX_LEN: usize = 16_384;

    const PUBLIC_KEY_HEX_LEN: usize = ml_dsa_65::PK_LEN * 2;
    const SIGNATURE_HEX_LEN: usize = ml_dsa_65::SIG_LEN * 2;

    const MAX_NAME_BYTES: usize = 128;
    const MAX_SHORT_FIELD_BYTES: usize = 128;
    const MAX_ADDRESS_BYTES: usize = 512;
    const MAX_JOB_BYTES: usize = 128;

    const MAX_JSON_BYTES: usize = 64 * 1024;
    const MAX_PDF_BYTES: usize = 10 * 1024 * 1024;
    const MAX_QR_PNG_BYTES: usize = 2 * 1024 * 1024;

    const MAX_PASSPHRASE_BYTES: usize = 16 * 1024;

    /// Create a fully signed Digital Passport.
    pub fn new_signed(
        passport_id_hex: String,
        expected_wallet_address: String,
        wallet: &MLDSA65Wallet,
        mut passphrase: String,
        mut confirm_passphrase: String,
        fields: DigitalPassportFields,
    ) -> Result<Self, ErrorDetection> {
        let result = Self::new_signed_inner(
            passport_id_hex,
            expected_wallet_address,
            wallet,
            &passphrase,
            &confirm_passphrase,
            fields,
        );

        passphrase.zeroize();
        confirm_passphrase.zeroize();

        result
    }

    fn new_signed_inner(
        passport_id_hex: String,
        expected_wallet_address: String,
        wallet: &MLDSA65Wallet,
        passphrase: &str,
        confirm_passphrase: &str,
        fields: DigitalPassportFields,
    ) -> Result<Self, ErrorDetection> {
        Self::validate_passphrase_confirmation(passphrase, confirm_passphrase)?;

        wallet
            .validate_self()
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Digital I.D. wallet self-validation failed: {e}"),
                tx_id: None,
            })?;

        let expected_wallet_address = canon_wallet_id_checked(expected_wallet_address.trim())
            .map_err(|e| ErrorDetection::ValidationError {
                message: format!("Digital I.D. wallet address invalid: {e}"),
                tx_id: None,
            })?;

        let wallet_address = canon_wallet_id_checked(wallet.address.trim()).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Loaded wallet address invalid: {e}"),
                tx_id: None,
            }
        })?;

        if expected_wallet_address != wallet_address {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Wallet address mismatch: entered {} but loaded wallet is {}",
                    expected_wallet_address, wallet_address
                ),
                tx_id: None,
            });
        }

        wallet_id_matches_pubkey_bytes_checked(&wallet_address, &wallet.public).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Wallet address does not match wallet public key: {e}"),
                tx_id: None,
            }
        })?;

        let passport_id_hex = passport_id_hex.trim().to_ascii_lowercase();
        Self::validate_hex_exact("passport_id_hex", &passport_id_hex, Self::HEX_64_LEN)?;

        let wallet_public_key_hex = hex::encode(wallet.public);
        Self::validate_hex_exact(
            "wallet_public_key_hex",
            &wallet_public_key_hex,
            Self::PUBLIC_KEY_HEX_LEN,
        )?;

        Self::validate_fields(&fields)?;

        let created_at_utc = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        let mut passport = Self {
            kind: DIGITAL_PASSPORT_KIND.to_string(),
            schema: DIGITAL_PASSPORT_SCHEMA.to_string(),
            passport_id_hex,
            wallet_address,
            wallet_public_key_hex,
            fields,
            created_at_utc,
            digital_fingerprint_hex: String::new(),
            wallet_signature_hex: String::new(),
        };

        let proof_bytes = passport.proof_payload_json_bytes_unchecked()?;
        let fingerprint = RemzarHash::compute_bytes_hash_hex(&proof_bytes);
        Self::validate_hex_exact("digital_fingerprint_hex", &fingerprint, Self::HEX_64_LEN)?;
        passport.digital_fingerprint_hex = fingerprint;

        let signature = wallet.sign(passphrase, &proof_bytes).map_err(|e| {
            ErrorDetection::CryptographicError {
                message: format!("Digital I.D. wallet signing failed: {e}"),
            }
        })?;

        if signature.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::CryptographicError {
                message: format!(
                    "Digital I.D. signature length invalid: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    signature.len()
                ),
            });
        }

        passport.wallet_signature_hex = hex::encode(signature);

        passport.validate()?;
        Ok(passport)
    }

    /// Matches the wallet generation style:
    pub fn validate_passphrase_confirmation(
        passphrase: &str,
        confirm_passphrase: &str,
    ) -> Result<(), ErrorDetection> {
        if passphrase.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Passphrase cannot be empty".into(),
                tx_id: None,
            });
        }

        if confirm_passphrase.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Confirm passphrase cannot be empty".into(),
                tx_id: None,
            });
        }

        if passphrase.len() > Self::MAX_PASSPHRASE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Passphrase too long: max {} bytes",
                    Self::MAX_PASSPHRASE_BYTES
                ),
                tx_id: None,
            });
        }

        if confirm_passphrase.len() > Self::MAX_PASSPHRASE_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Confirm passphrase too long: max {} bytes",
                    Self::MAX_PASSPHRASE_BYTES
                ),
                tx_id: None,
            });
        }

        if passphrase != confirm_passphrase {
            return Err(ErrorDetection::ValidationError {
                message: "Passphrase confirmation does not match".into(),
                tx_id: None,
            });
        }

        Ok(())
    }

    pub fn validate(&self) -> Result<(), ErrorDetection> {
        Self::validate_exact("kind", self.kind.trim(), DIGITAL_PASSPORT_KIND)?;
        Self::validate_exact("schema", self.schema.trim(), DIGITAL_PASSPORT_SCHEMA)?;

        Self::validate_hex_exact(
            "passport_id_hex",
            self.passport_id_hex.trim(),
            Self::HEX_64_LEN,
        )?;

        Self::validate_wallet("wallet_address", self.wallet_address.trim())?;

        Self::validate_hex_exact(
            "wallet_public_key_hex",
            self.wallet_public_key_hex.trim(),
            Self::PUBLIC_KEY_HEX_LEN,
        )?;

        Self::validate_hex_exact(
            "digital_fingerprint_hex",
            self.digital_fingerprint_hex.trim(),
            Self::HEX_64_LEN,
        )?;

        Self::validate_hex_exact(
            "wallet_signature_hex",
            self.wallet_signature_hex.trim(),
            Self::SIGNATURE_HEX_LEN,
        )?;

        Self::validate_created_at(&self.created_at_utc)?;
        Self::validate_fields(&self.fields)?;

        let public_key = self.public_key_bytes()?;

        wallet_id_matches_pubkey_bytes_checked(&self.wallet_address, &public_key).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("Digital I.D. wallet/public-key binding failed: {e}"),
                tx_id: None,
            }
        })?;

        let proof_bytes = self.proof_payload_json_bytes_unchecked()?;
        let recomputed_fingerprint = RemzarHash::compute_bytes_hash_hex(&proof_bytes);

        if recomputed_fingerprint != self.digital_fingerprint_hex {
            return Err(ErrorDetection::ValidationError {
                message: "Digital I.D. fingerprint mismatch: receipt fields were modified".into(),
                tx_id: None,
            });
        }

        if !self.verify_wallet_signature()? {
            return Err(ErrorDetection::CryptographicError {
                message: "Digital I.D. wallet signature verification failed".into(),
            });
        }

        Ok(())
    }

    /// This is what should be used as NFT content bytes.
    pub fn content_bytes_for_nft(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;
        self.proof_payload_json_bytes_unchecked()
    }

    /// Redacted NFT title. Safe for on-chain/public tx description usage.
    pub fn nft_title(&self) -> String {
        "Digital I.D. Passport".to_string()
    }

    /// Redacted NFT description. Safe for on-chain/public tx description usage.
    pub fn nft_description_redacted(&self) -> String {
        format!(
            "Kind: {} | Schema: {} | Digital fingerprint: {} | Wallet: {} | Created at (UTC): {}",
            self.kind,
            self.schema,
            self.digital_fingerprint_hex,
            self.wallet_address,
            self.created_at_utc
        )
    }

    pub fn to_pretty_json_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;

        let bytes =
            serde_json::to_vec_pretty(self).map_err(|e| ErrorDetection::SerializationError {
                details: format!("serialize DigitalPassport JSON: {e}"),
            })?;

        if bytes.len() > Self::MAX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. JSON too large: max {} bytes",
                    Self::MAX_JSON_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(bytes)
    }

    pub fn write_receipt_files(
        &self,
        audit_dir: &Path,
        pdf_dir: &Path,
    ) -> Result<DigitalPassportReceiptFiles, ErrorDetection> {
        self.validate()?;

        let json_path = self.write_json_file(audit_dir)?;
        let pdf_path = self.write_pdf_file(pdf_dir)?;
        let qr_png_path = self.write_qr_png_file(pdf_dir)?;

        Ok(DigitalPassportReceiptFiles {
            json_path,
            pdf_path,
            qr_png_path,
        })
    }

    pub fn write_json_file(&self, audit_dir: &Path) -> Result<PathBuf, ErrorDetection> {
        self.validate()?;

        let base_dir = Self::resolve_output_dir(audit_dir, "data/digital_id")?;
        let path = base_dir.join(format!("digital_id_{}.json", self.passport_id_hex));

        let bytes = self.to_pretty_json_bytes()?;
        Self::atomic_write(&path, &bytes)?;

        Ok(path)
    }

    pub fn write_pdf_file(&self, pdf_dir: &Path) -> Result<PathBuf, ErrorDetection> {
        self.validate()?;

        let base_dir = Self::resolve_output_dir(pdf_dir, "data/digital_id")?;
        let path = base_dir.join(format!("digital_id_{}.pdf", self.passport_id_hex));

        let bytes = self.build_pdf_bytes()?;
        if bytes.len() > Self::MAX_PDF_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. PDF too large: max {} bytes",
                    Self::MAX_PDF_BYTES
                ),
                tx_id: None,
            });
        }

        Self::atomic_write(&path, &bytes)?;

        Ok(path)
    }

    pub fn write_qr_png_file(&self, qr_dir: &Path) -> Result<PathBuf, ErrorDetection> {
        self.validate()?;

        let base_dir = Self::resolve_output_dir(qr_dir, "data/digital_id")?;
        let path = base_dir.join(format!("digital_id_{}_qr.png", self.passport_id_hex));

        let bytes = self.build_qr_png_bytes()?;
        if bytes.len() > Self::MAX_QR_PNG_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. QR PNG too large: max {} bytes",
                    Self::MAX_QR_PNG_BYTES
                ),
                tx_id: None,
            });
        }

        Self::atomic_write(&path, &bytes)?;

        Ok(path)
    }

    pub fn build_qr_png_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;

        let payload = self.qr_public_payload_json();

        let qr =
            QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M).map_err(|e| {
                ErrorDetection::SerializationError {
                    details: format!("build Digital I.D. QR code: {e}"),
                }
            })?;

        let qr_image = qr
            .render::<Luma<u8>>()
            .quiet_zone(true)
            .min_dimensions(512, 512)
            .build();

        let mut cursor = Cursor::new(Vec::new());

        DynamicImage::ImageLuma8(qr_image)
            .write_to(&mut cursor, ImageFormat::Png)
            .map_err(|e| ErrorDetection::SerializationError {
                details: format!("encode Digital I.D. QR PNG: {e}"),
            })?;

        Ok(cursor.into_inner())
    }

    fn qr_public_payload_json(&self) -> String {
        let payload = format!(
            "Remzar Digital I.D. Verification\n\n\
            Kind: {}\n\
            Schema: {}\n\n\
            Passport ID:\n{}\n\n\
            Wallet Address:\n{}\n\n\
            Digital Fingerprint:\n{}\n\n\
            Created UTC: {}\n\n\
            Privacy Notice:\n\
            This QR code contains public verification data only.",
            self.kind,
            self.schema,
            self.passport_id_hex,
            self.wallet_address,
            self.digital_fingerprint_hex,
            self.created_at_utc,
        );

        payload
    }

    pub fn build_pdf_bytes(&self) -> Result<Vec<u8>, ErrorDetection> {
        self.validate()?;

        const PAGE_W: f32 = 595.0;
        const PAGE_H: f32 = 842.0;
        const MARGIN_L: f32 = 50.0;
        const FONT_SIZE: f32 = 10.0;
        const LEADING: f32 = 13.0;
        const CHARS_PER_LINE: usize = 86;
        const LINES_PER_PAGE: usize = 58;
        const PDF_Y_POSITIONS: [f32; LINES_PER_PAGE] = [
            802.0, 789.0, 776.0, 763.0, 750.0, 737.0, 724.0, 711.0, 698.0, 685.0, 672.0, 659.0,
            646.0, 633.0, 620.0, 607.0, 594.0, 581.0, 568.0, 555.0, 542.0, 529.0, 516.0, 503.0,
            490.0, 477.0, 464.0, 451.0, 438.0, 425.0, 412.0, 399.0, 386.0, 373.0, 360.0, 347.0,
            334.0, 321.0, 308.0, 295.0, 282.0, 269.0, 256.0, 243.0, 230.0, 217.0, 204.0, 191.0,
            178.0, 165.0, 152.0, 139.0, 126.0, 113.0, 100.0, 87.0, 74.0, 61.0,
        ];

        fn pdf_safe(s: &str) -> String {
            s.chars()
                .map(|c| {
                    if c.is_ascii() && !c.is_control() {
                        c
                    } else if c == '\t' {
                        ' '
                    } else {
                        '?'
                    }
                })
                .collect()
        }

        fn shorten_long_proof_value(value: &str) -> String {
            let value = value.trim();

            if value.chars().count() <= 64 {
                return value.to_string();
            }

            let prefix: String = value.chars().take(32).collect();
            let suffix_reversed: String = value.chars().rev().take(32).collect();
            let suffix: String = suffix_reversed.chars().rev().collect();

            format!("{prefix}...{suffix}")
        }

        fn push_wrapped(lines: &mut Vec<String>, label: &str, value: &str) {
            let full = format!("{label}: {}", pdf_safe(value));
            let chars: Vec<char> = full.chars().collect();

            if chars.is_empty() {
                lines.push(format!("{label}:"));
                return;
            }

            for (i, chunk) in chars.chunks(CHARS_PER_LINE).enumerate() {
                let piece = chunk.iter().collect::<String>();
                if i == 0 {
                    lines.push(piece);
                } else {
                    lines.push(format!("  {piece}"));
                }
            }
        }

        fn write_line(c: &mut Content, txt: &str, x: f32, y: f32) {
            c.begin_text();
            c.set_font(Name(b"F1"), FONT_SIZE);
            c.set_leading(LEADING);
            c.set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y]);
            c.show(Str(txt.as_bytes()));
            c.end_text();
        }

        let wallet_public_key_display = shorten_long_proof_value(&self.wallet_public_key_hex);
        let wallet_signature_display = shorten_long_proof_value(&self.wallet_signature_hex);

        let mut lines = Vec::new();

        lines.push("Remzar Blockchain Digital Identification Card".to_string());
        lines.push(String::new());

        push_wrapped(&mut lines, "Kind", &self.kind);
        push_wrapped(&mut lines, "Schema", &self.schema);

        // FULL VALUE - DO NOT SHORTEN
        push_wrapped(&mut lines, "Passport ID", &self.passport_id_hex);

        // FULL VALUE - DO NOT SHORTEN
        push_wrapped(&mut lines, "Wallet Address", &self.wallet_address);

        // SHORTENED FOR PDF DISPLAY ONLY
        push_wrapped(&mut lines, "Wallet Public Key", &wallet_public_key_display);

        // FULL VALUE - DO NOT SHORTEN
        push_wrapped(
            &mut lines,
            "Digital Fingerprint",
            &self.digital_fingerprint_hex,
        );

        // SHORTENED FOR PDF DISPLAY ONLY
        push_wrapped(&mut lines, "Wallet Signature", &wallet_signature_display);

        push_wrapped(&mut lines, "Created UTC", &self.created_at_utc);

        lines.push(String::new());
        lines.push("Identity Fields".to_string());
        lines.push(String::new());

        push_wrapped(
            &mut lines,
            "Name",
            self.fields.name.as_deref().unwrap_or("-"),
        );
        push_wrapped(
            &mut lines,
            "Birth",
            self.fields.birth.as_deref().unwrap_or("-"),
        );
        push_wrapped(&mut lines, "Sex", self.fields.sex.as_deref().unwrap_or("-"));
        push_wrapped(
            &mut lines,
            "Height",
            self.fields.height.as_deref().unwrap_or("-"),
        );
        push_wrapped(
            &mut lines,
            "Nationality",
            self.fields.nationality.as_deref().unwrap_or("-"),
        );
        push_wrapped(
            &mut lines,
            "Country",
            self.fields.country.as_deref().unwrap_or("-"),
        );
        push_wrapped(
            &mut lines,
            "Address",
            self.fields.address.as_deref().unwrap_or("-"),
        );
        push_wrapped(&mut lines, "Job", self.fields.job.as_deref().unwrap_or("-"));

        let pages: Vec<Vec<String>> = lines
            .chunks(LINES_PER_PAGE)
            .map(|chunk| chunk.to_vec())
            .collect();

        let mut pdf = Pdf::new();

        let catalog_id = Ref::new(1);
        let pages_id = Ref::new(2);
        let font_id = Ref::new(3);

        pdf.catalog(catalog_id).pages(pages_id);
        pdf.type1_font(font_id).base_font(Name(b"Courier"));

        let mut page_ids = Vec::new();

        for (i, page_lines) in pages.iter().enumerate() {
            let page_index = i32::try_from(i).map_err(|_| ErrorDetection::ValidationError {
                message: "Digital I.D. PDF has too many pages".into(),
                tx_id: None,
            })?;
            let object_offset =
                page_index
                    .checked_mul(2)
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "Digital I.D. PDF object offset overflow".into(),
                        tx_id: None,
                    })?;
            let page_ref_num = 4_i32.checked_add(object_offset).ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: "Digital I.D. PDF page reference overflow".into(),
                    tx_id: None,
                }
            })?;
            let content_ref_num = 5_i32.checked_add(object_offset).ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: "Digital I.D. PDF content reference overflow".into(),
                    tx_id: None,
                }
            })?;

            let page_id = Ref::new(page_ref_num);
            let cont_id = Ref::new(content_ref_num);

            page_ids.push(page_id);

            let mut content = Content::new();

            for (line_index, line) in page_lines.iter().enumerate() {
                let Some(y) = PDF_Y_POSITIONS.get(line_index).copied() else {
                    break;
                };

                if line.is_empty() {
                    continue;
                }

                write_line(&mut content, line, MARGIN_L, y);
            }

            let stream = content.finish();

            pdf.page(page_id)
                .parent(pages_id)
                .media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H))
                .contents(cont_id)
                .resources()
                .fonts()
                .pair(Name(b"F1"), font_id);

            pdf.stream(cont_id, &stream);
        }

        let page_count =
            i32::try_from(page_ids.len()).map_err(|_| ErrorDetection::ValidationError {
                message: "Digital I.D. PDF has too many pages".into(),
                tx_id: None,
            })?;

        pdf.pages(pages_id).kids(page_ids).count(page_count);

        Ok(pdf.finish())
    }

    pub fn verify_wallet_signature(&self) -> Result<bool, ErrorDetection> {
        let proof_bytes = self.proof_payload_json_bytes_unchecked()?;

        let public_key_bytes = self.public_key_bytes()?;
        let public_key = ml_dsa_65::PublicKey::try_from_bytes(public_key_bytes).map_err(|e| {
            ErrorDetection::CryptographicError {
                message: format!("Invalid ML-DSA-65 public key in Digital I.D.: {e}"),
            }
        })?;

        let signature_vec = hex::decode(&self.wallet_signature_hex).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("wallet_signature_hex is not valid hex: {e}"),
                tx_id: None,
            }
        })?;

        if signature_vec.len() != ml_dsa_65::SIG_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "wallet_signature_hex invalid byte length: expected {}, got {}",
                    ml_dsa_65::SIG_LEN,
                    signature_vec.len()
                ),
                tx_id: None,
            });
        }

        let signature_arr: &[u8; ml_dsa_65::SIG_LEN] = signature_vec
            .as_slice()
            .try_into()
            .map_err(|_| ErrorDetection::ValidationError {
                message: "Failed to convert Digital I.D. signature bytes".into(),
                tx_id: None,
            })?;

        let hashed = RemzarHash::compute_bytes_hash(&proof_bytes);
        Ok(public_key.verify(&hashed, signature_arr, CONSENSUS_CTX))
    }

    fn proof_payload(&self) -> DigitalPassportProofPayload<'_> {
        DigitalPassportProofPayload {
            kind: self.kind.as_str(),
            schema: self.schema.as_str(),
            passport_id_hex: self.passport_id_hex.as_str(),
            wallet_address: self.wallet_address.as_str(),
            wallet_public_key_hex: self.wallet_public_key_hex.as_str(),
            fields: &self.fields,
            created_at_utc: self.created_at_utc.as_str(),
        }
    }

    fn proof_payload_json_bytes_unchecked(&self) -> Result<Vec<u8>, ErrorDetection> {
        let bytes = serde_json::to_vec(&self.proof_payload()).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("serialize DigitalPassport proof payload: {e}"),
            }
        })?;

        if bytes.len() > Self::MAX_JSON_BYTES {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. proof payload too large: max {} bytes",
                    Self::MAX_JSON_BYTES
                ),
                tx_id: None,
            });
        }

        Ok(bytes)
    }

    fn public_key_bytes(&self) -> Result<[u8; ml_dsa_65::PK_LEN], ErrorDetection> {
        let public_vec = hex::decode(&self.wallet_public_key_hex).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("wallet_public_key_hex is not valid hex: {e}"),
                tx_id: None,
            }
        })?;

        if public_vec.len() != ml_dsa_65::PK_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "wallet_public_key_hex invalid byte length: expected {}, got {}",
                    ml_dsa_65::PK_LEN,
                    public_vec.len()
                ),
                tx_id: None,
            });
        }

        public_vec
            .as_slice()
            .try_into()
            .map_err(|_| ErrorDetection::ValidationError {
                message: "Failed to convert Digital I.D. public key bytes".into(),
                tx_id: None,
            })
    }

    fn validate_fields(fields: &DigitalPassportFields) -> Result<(), ErrorDetection> {
        if !fields.has_any_identity_field() {
            return Err(ErrorDetection::ValidationError {
                message: "At least one Digital I.D. identity field must be provided".into(),
                tx_id: None,
            });
        }

        Self::validate_optional_text("name", fields.name.as_deref(), Self::MAX_NAME_BYTES)?;

        if let Some(birth) = &fields.birth {
            Self::validate_birth(birth)?;
        }

        Self::validate_optional_text("sex", fields.sex.as_deref(), Self::MAX_SHORT_FIELD_BYTES)?;
        Self::validate_optional_text(
            "height",
            fields.height.as_deref(),
            Self::MAX_SHORT_FIELD_BYTES,
        )?;
        Self::validate_optional_text(
            "nationality",
            fields.nationality.as_deref(),
            Self::MAX_SHORT_FIELD_BYTES,
        )?;
        Self::validate_optional_text(
            "country",
            fields.country.as_deref(),
            Self::MAX_SHORT_FIELD_BYTES,
        )?;
        Self::validate_optional_text(
            "address",
            fields.address.as_deref(),
            Self::MAX_ADDRESS_BYTES,
        )?;
        Self::validate_optional_text("job", fields.job.as_deref(), Self::MAX_JOB_BYTES)?;

        Ok(())
    }

    fn validate_optional_text(
        field: &str,
        value: Option<&str>,
        max_len: usize,
    ) -> Result<(), ErrorDetection> {
        let Some(value) = value else {
            return Ok(());
        };

        let value = value.trim();

        if value.is_empty() {
            return Ok(());
        }

        if value.len() > max_len {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} too long: max {max_len} bytes"),
                tx_id: None,
            });
        }

        if value.chars().any(|c| c.is_control()) {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} contains control characters"),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn validate_birth(value: &str) -> Result<(), ErrorDetection> {
        let value = value.trim();

        if value.is_empty() {
            return Ok(());
        }

        // Digital I.D. birth is user-entered/self-declared text.
        // We do NOT force real calendar validation here.
        // This means values like "1888-44-55", "unknown", "01/01/1980",
        // or "1980-01-01" can all be stored as typed.
        Self::validate_optional_text("birth", Some(value), Self::MAX_SHORT_FIELD_BYTES)?;

        Ok(())
    }

    fn validate_created_at(value: &str) -> Result<(), ErrorDetection> {
        DateTime::parse_from_rfc3339(value).map_err(|e| ErrorDetection::ValidationError {
            message: format!("created_at_utc must be RFC3339 datetime: {e}"),
            tx_id: None,
        })?;

        Ok(())
    }

    fn validate_wallet(field: &str, value: &str) -> Result<(), ErrorDetection> {
        if value.len() != REMZAR_WALLET_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} wallet length must be {}, got {}",
                    REMZAR_WALLET_LEN,
                    value.len()
                ),
                tx_id: None,
            });
        }

        parse_wallet_address(value).map_err(|_| ErrorDetection::ValidationError {
            message: format!("{field} wallet format invalid; expected 'r' + 128 lowercase hex"),
            tx_id: None,
        })
    }

    fn validate_exact(field: &str, actual: &str, expected: &str) -> Result<(), ErrorDetection> {
        if actual != expected {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} must be '{expected}', got '{actual}'"),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn validate_hex_exact(
        field: &str,
        value: &str,
        exact_len: usize,
    ) -> Result<(), ErrorDetection> {
        if value.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} cannot be empty"),
                tx_id: None,
            });
        }

        if value.len() > Self::MAX_HEX_LEN {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} too long: max {} chars", Self::MAX_HEX_LEN),
                tx_id: None,
            });
        }

        if value.len() != exact_len {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "{field} invalid length: expected {exact_len}, got {}",
                    value.len()
                ),
                tx_id: None,
            });
        }

        if !value.len().is_multiple_of(2) {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} hex length must be even"),
                tx_id: None,
            });
        }

        if !value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ErrorDetection::ValidationError {
                message: format!("{field} must be lowercase hex"),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn resolve_output_dir(input_dir: &Path, default_dir: &str) -> Result<PathBuf, ErrorDetection> {
        let base_dir = if input_dir.as_os_str().is_empty() {
            PathBuf::from(default_dir)
        } else {
            input_dir.to_path_buf()
        };

        fs::create_dir_all(&base_dir).map_err(|e| ErrorDetection::StorageError {
            message: format!(
                "Failed to create Digital I.D. output directory {}: {e}",
                base_dir.display()
            ),
        })?;

        let metadata = fs::metadata(&base_dir).map_err(|e| ErrorDetection::IoError {
            message: format!(
                "Failed to stat Digital I.D. output directory {}: {e}",
                base_dir.display()
            ),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if !metadata.is_dir() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Digital I.D. output path is not a directory: {}",
                    base_dir.display()
                ),
                tx_id: None,
            });
        }

        Ok(base_dir)
    }

    fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ErrorDetection> {
        let parent = path
            .parent()
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("Output path has no parent directory: {}", path.display()),
                tx_id: None,
            })?;

        fs::create_dir_all(parent).map_err(|e| ErrorDetection::StorageError {
            message: format!(
                "Failed to create parent directory {}: {e}",
                parent.display()
            ),
        })?;

        let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
            ErrorDetection::ValidationError {
                message: format!("Output path has invalid file name: {}", path.display()),
                tx_id: None,
            }
        })?;

        if file_name.contains('/') || file_name.contains('\\') || file_name.contains("..") {
            return Err(ErrorDetection::ValidationError {
                message: format!("Unsafe output file name: {file_name}"),
                tx_id: None,
            });
        }

        let nanos = Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_micros());

        let tmp_path = parent.join(format!(".{file_name}.{nanos}.tmp"));

        fs::write(&tmp_path, bytes).map_err(|e| ErrorDetection::IoError {
            message: format!("Failed to write temp file {}: {e}", tmp_path.display()),
            code: e.raw_os_error(),
            source: Some(Box::new(e)),
        })?;

        if let Err(e) = fs::rename(&tmp_path, path) {
            let cleanup_note = match fs::remove_file(&tmp_path) {
                Ok(()) => String::new(),
                Err(cleanup_error) => format!(
                    " Cleanup of temp file {} also failed: {cleanup_error}",
                    tmp_path.display()
                ),
            };

            return Err(ErrorDetection::IoError {
                message: format!(
                    "Failed to move temp file {} to {}: {e}.{cleanup_note}",
                    tmp_path.display(),
                    path.display()
                ),
                code: e.raw_os_error(),
                source: Some(Box::new(e)),
            });
        }

        Ok(())
    }
}
