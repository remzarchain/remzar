use crate::runtime::p2p_006_sync_runtime::NodeOpts;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use directories::ProjectDirs;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DirectoryDB {
    pub wallets_path: PathBuf,
    pub db_path: PathBuf,
    pub blockchain_path: PathBuf,
    pub registry_path: PathBuf,
    pub accountmodel_path: PathBuf,
    pub sidechain_path: PathBuf,
    pub log_path: PathBuf,
    pub audit_reports_path: PathBuf,
    pub peerlist_path: PathBuf,
}

impl DirectoryDB {
    /// Helper; uses the user-supplied CLI directory everywhere.
    pub fn from_node_opts(opts: &NodeOpts) -> Result<Self, String> {
        Self::from_base_dir(Path::new(&opts.data_dir))
    }

    /// Get the OS/user-correct data root, or env override for Docker/dev
    pub fn base_data_dir() -> Result<PathBuf, String> {
        // 1. Check env override (for Docker/K8s/CI)
        if let Ok(dir) = env::var("REMZAR_DATA_DIR") {
            Ok(PathBuf::from(dir))
        } else if let Some(proj_dirs) = ProjectDirs::from("com", "remzar", "remzar-blockchain") {
            Ok(proj_dirs.data_dir().to_path_buf())
        } else {
            Err("Could not determine a suitable data directory for this platform".to_owned())
        }
    }

    /// Create new, using a user-supplied base directory for ALL paths
    pub fn from_base_dir(base: &Path) -> Result<Self, String> {
        Ok(Self {
            wallets_path: base.join(GlobalConfiguration::WALLETS_DIR),
            db_path: base.join(GlobalConfiguration::DATABASE_DIR_NAME),
            blockchain_path: base.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR),
            registry_path: base.join(GlobalConfiguration::REGISTRY_DIR_NAME),
            accountmodel_path: base.join(GlobalConfiguration::ACCOUNTMODEL_DATABASE_DIR),
            sidechain_path: base.join(GlobalConfiguration::SIDECHAIN_DATABASE_DIR),
            log_path: base.join(GlobalConfiguration::LOG_DATABASE_DIR),
            audit_reports_path: base.join(GlobalConfiguration::AUDIT_REPORTS_DIR),
            peerlist_path: base.join(GlobalConfiguration::PEER_LIST_DIR),
        })
    }

    pub fn create_wallets_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.wallets_path)
    }
    pub fn create_db_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.db_path)
    }
    pub fn create_blockchain_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.blockchain_path)
    }
    pub fn create_registry_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.registry_path)
    }
    pub fn create_accountmodel_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.accountmodel_path)
    }
    pub fn create_sidechain_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.sidechain_path)
    }
    pub fn create_log_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.log_path)
    }
    pub fn create_audit_reports_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.audit_reports_path)
    }
    pub fn create_peerlist_directory(&self) -> Result<(), String> {
        Self::create_dir_if_not_exists(&self.peerlist_path)
    }

    pub fn setup_database(&self, target: &Path) -> Result<(), String> {
        if target == self.wallets_path {
            self.create_wallets_directory()
        } else if target == self.db_path {
            self.create_db_directory()
        } else if target == self.blockchain_path {
            self.create_blockchain_directory()
        } else if target == self.registry_path {
            self.create_registry_directory()
        } else if target == self.accountmodel_path {
            self.create_accountmodel_directory()
        } else if target == self.sidechain_path {
            self.create_sidechain_directory()
        } else if target == self.log_path {
            self.create_log_directory()
        } else if target == self.audit_reports_path {
            self.create_audit_reports_directory()
        } else if target == self.peerlist_path {
            self.create_peerlist_directory()
        } else {
            Err(format!(
                "❌ Invalid target for setup_database: {}\nExpected one of:\n\
                - wallets_path: {}\n- db_path: {}\n- blockchain_path: {}\n- registry_path: {}\n\
                - accountmodel_path: {}\n- sidechain_path: {}\n- log_path: {}\n- audit_reports_path: {}\n\
                - peerlist_path: {}",
                target.display(),
                self.wallets_path.display(),
                self.db_path.display(),
                self.blockchain_path.display(),
                self.registry_path.display(),
                self.accountmodel_path.display(),
                self.sidechain_path.display(),
                self.log_path.display(),
                self.audit_reports_path.display(),
                self.peerlist_path.display(),
            ))
        }
    }

    fn create_dir_if_not_exists(path: &Path) -> Result<(), String> {
        // Security: Reject symlinks
        if Self::is_symlink(path) {
            return Err(format!(
                "❌ Refusing to use symlinked directory '{}'. This is not allowed for security reasons.",
                path.display()
            ));
        }
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| {
                format!("❌ Failed to create directory '{}': {}", path.display(), e)
            })?;
            println!("✅ Directory created successfully: {}", path.display());
        } else {
            tracing::debug!("📂 Directory already exists: {}", path.display());
        }
        Self::check_permissions(path)
    }

    fn is_symlink(path: &Path) -> bool {
        fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    }

    fn check_permissions(path: &Path) -> Result<(), String> {
        fs::metadata(path)
            .map_err(|e| {
                format!(
                    "❌ Failed to check metadata for '{}': {}",
                    path.display(),
                    e
                )
            })
            .and_then(|metadata| {
                if metadata.permissions().readonly() {
                    Err(format!(
                        "❌ No write permissions for directory '{}'",
                        path.display()
                    ))
                } else {
                    Ok(())
                }
            })
    }

    pub fn validate_directories(&self) -> Result<(), String> {
        let directories = vec![
            &self.wallets_path,
            &self.db_path,
            &self.blockchain_path,
            &self.registry_path,
            &self.accountmodel_path,
            &self.sidechain_path,
            &self.log_path,
            &self.audit_reports_path,
            &self.peerlist_path,
        ];
        let mut errors = Vec::new();

        for dir in directories {
            if !dir.exists() {
                let msg = format!("❌ Error: Missing directory: {}", dir.display());
                eprintln!("{}", msg);
                errors.push(msg);
            } else if Self::is_symlink(dir) {
                let msg = format!(
                    "❌ Symlink detected: {} (Refusing to use symlinked DB directories)",
                    dir.display()
                );
                eprintln!("{}", msg);
                errors.push(msg);
            } else {
                println!("📂 Found directory: {}", dir.display());
            }

            match Self::check_permissions(dir) {
                Ok(_) => println!("✅ Write permissions OK: {}", dir.display()),
                Err(e) => {
                    let msg = format!("❌ Permission error for '{}': {}", dir.display(), e);
                    eprintln!("{}", msg);
                    errors.push(msg);
                }
            }
        }
        if errors.is_empty() {
            println!("✅ All database directories are valid.");
            Ok(())
        } else {
            Err(errors.join("\n"))
        }
    }
}

impl AsRef<Path> for DirectoryDB {
    fn as_ref(&self) -> &Path {
        &self.db_path
    }
}
