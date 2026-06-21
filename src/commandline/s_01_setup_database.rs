//! src/commandline/s_01_setup_database.rs
//! 01. Setup Database (interactive wrapper)

use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::storage::rocksdb_000_directory::DirectoryDB;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::logging_data::JsonLogger;

use colored::Colorize;
use std::io;

#[derive(Default)]
pub struct S01SetupDatabase;

impl S01SetupDatabase {
    pub fn new() -> Self {
        Self
    }

    pub fn setup_database(
        &mut self,
        opts: &NodeOpts,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        let mut db = match RockDBManager::new(opts) {
            Ok(db) => db,
            Err(e) => {
                let msg = format!("Failed to open CLI RocksDB: {}", e);
                json_logger
                    .log_error_event("database", "OpenCLIDBFailed", &msg)
                    .ok();
                return Err(ErrorDetection::DatabaseError { details: msg });
            }
        };

        match db.get_metadata("status") {
            Ok(Some(status)) if status == b"initialized" => {
                println!(
                    "{}",
                    "✅ CLI database is already fully initialized!".green()
                );
                return Ok(());
            }
            Ok(Some(_)) => {
                println!(
                    "{}",
                    "⚠️ Existing CLI DB found but not fully initialized. Proceeding...".yellow()
                );
            }
            Err(e) => {
                let msg = format!("Failed to get CLI DB status: {}", e);
                json_logger
                    .log_error_event("database", "GetCLIDBStatusFailed", &msg)
                    .ok();
                return Err(ErrorDetection::DatabaseError { details: msg });
            }
            _ => {}
        }

        println!(
            "{}",
            "⚠️ The CLI database is uninitialized. Would you like to create it? (yes/no)".cyan()
        );

        let mut input = String::new();
        if let Err(e) = io::stdin().read_line(&mut input) {
            let msg = format!("Failed to read user input: {}", e);
            json_logger
                .log_error_event("database", "ReadInputFailed", &msg)
                .ok();
            return Err(ErrorDetection::DatabaseError { details: msg });
        }

        let input = input.trim().to_lowercase();

        if input != "yes" {
            println!("{}", "❌ CLI database setup canceled by user.".red());
            return Ok(());
        }

        println!("{}", "🔍 Loading or creating CLI database...".cyan());

        let directory = match DirectoryDB::from_node_opts(opts) {
            Ok(dir) => dir,
            Err(e) => {
                let msg = format!("Failed to initialize directories: {}", e);
                json_logger
                    .log_error_event("database", "InitDirectoriesFailed", &msg)
                    .ok();
                return Err(ErrorDetection::DatabaseError { details: msg });
            }
        };

        if let Err(e) = directory.setup_database(&directory.db_path) {
            let msg = format!("Failed to set up database directory: {}", e);
            json_logger
                .log_error_event("database", "SetupDatabaseDirectoryFailed", &msg)
                .ok();
            return Err(ErrorDetection::StorageError { message: e });
        }

        match db.get_metadata("status") {
            Ok(Some(existing)) if existing == b"initialized" => {
                println!("{}", "✅ CLI DB is already marked as initialized!".green());
            }
            Err(e) => {
                let msg = format!("Failed to get CLI DB status after setup: {}", e);
                json_logger
                    .log_error_event("database", "GetCLIDBStatusAfterSetupFailed", &msg)
                    .ok();
                return Err(ErrorDetection::DatabaseError { details: msg });
            }
            _ => {
                println!("{}", "🔄 Initializing CLI database...".cyan());
                self.initialize_database(&mut db, json_logger)?;
            }
        }

        println!("{}", "✅ CLI database setup complete.".green());
        Ok(())
    }

    fn initialize_database(
        &self,
        db_manager: &mut RockDBManager,
        json_logger: &JsonLogger,
    ) -> Result<(), ErrorDetection> {
        println!("{}", "🔍 Checking meta_data for status...".cyan());
        let metadata_key = "status";

        match db_manager.get_metadata(metadata_key) {
            Ok(Some(existing)) if existing == b"initialized" => {
                println!("{}", "✅ DB was already marked as initialized.".green());
                Ok(())
            }
            Err(e) => {
                json_logger
                    .log_error_event(
                        "database",
                        "GetMetadataFailed",
                        &format!("Failed to get metadata: {}", e),
                    )
                    .ok();
                Err(ErrorDetection::DatabaseError {
                    details: format!("Failed to get metadata: {}", e),
                })
            }
            _ => {
                println!("{}", "📝 Marking DB as initialized...".cyan());
                if let Err(e) = db_manager.store_metadata(metadata_key, b"initialized") {
                    json_logger
                        .log_error_event(
                            "database",
                            "StoreMetadataFailed",
                            &format!("Failed to store metadata: {}", e),
                        )
                        .ok();
                    return Err(ErrorDetection::DatabaseError {
                        details: format!("Failed to store metadata: {}", e),
                    });
                }

                println!("{}", "✅ DB now marked as initialized!".green());
                Ok(())
            }
        }
    }
}
