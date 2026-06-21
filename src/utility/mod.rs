//! Utility and Infrastructure Module
//!
//! This module provides utility components and shared infrastructure
//! used throughout the Remzar project.
//!
//! Included submodules:
//! - Global configuration
//! - Error detection systems
//! - Auditing (PDF and JSON reports)
//! - Logging (including JSON and console loggers)
//! - Hashing and helper utilities

pub mod alpha_001_global_configuration;
pub mod alpha_002_error_detection_system;
pub mod alpha_003_detection_system;
pub mod audit_report_001_hub;
pub mod audit_report_002_pdf;
pub mod audit_report_003_json;
pub mod burn_system;
pub mod certificate_receipt;
pub mod digital_id_receipt;
pub mod hash_system_remzarhash;
pub mod helper;
pub mod logging_data;
pub mod send_file;
pub mod time_policy;
pub mod wallet_qr_code;
//pub mod archive;
